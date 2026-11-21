# -*- coding: utf-8 -*-
"""电子公文交换系统（实验四·密码模块的应用）

20241422 穆弈涵

安全要点（对应要求的"黄金法则"与"密码"）：
  1. 身份鉴别：库里只存 salt 与 SM3 迭代哈希，登录时重算比对
  2. 访问控制：角色→权限矩阵落库，路由用 @require_perm 校验
  3. 安全审计：登录、越权、业务操作全部写 audit_log，只增不改
  4. 密码：正文 SM4-CBC（随机 DEK+IV），DEK 用接收方 SM2 公钥加密成信封，
           摘要 SM3，签名 SM2；私钥用口令派生 KEK 加密后存库，明文只在内存
"""
import os
import functools
import sqlite3
import time
import uuid
from datetime import datetime

from flask import (Flask, request, redirect, url_for, session,
                   render_template, flash, abort)

import db
import crypto_utils as cu

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "lab4-20241422-dev-secret")

# 会话级密钥缓存：session_id -> {"priv": 明文私钥, "kek": KEK}
# 只放内存，进程重启即失效；不写 cookie、不落盘
SESS_KEYS = {}

# 登录失败计数：username -> [次数, 首次失败时间]
FAILED = {}
LOCK_LIMIT, LOCK_SECONDS = 5, 300


# ---------------------------------------------------------------- 通用
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def audit(conn, action, obj_type=None, obj_id=None, result="SUCCESS", detail=None):
    u = session.get("user") or {}
    conn.execute(
        "INSERT INTO audit_log(user_id,username,role,action,object_type,object_id,result,ip,detail)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (u.get("id"), u.get("username"), u.get("role"), action, obj_type,
         None if obj_id is None else str(obj_id), result, request.remote_addr, detail))
    conn.commit()


def current_perms():
    return session.get("perms") or []


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login"))
        return fn(*a, **k)
    return wrapper


def require_perm(code):
    """路由级访问控制：权限不在会话里就拒绝，并写审计"""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **k):
            if not session.get("user"):
                return redirect(url_for("login"))
            if code not in current_perms():
                conn = db.connect()
                audit(conn, "ACCESS_DENIED", "perm", code, "DENIED",
                      "缺少权限：%s" % code)
                conn.close()
                return render_template("403.html", perm=code), 403
            return fn(*a, **k)
        return wrapper
    return deco


@app.before_request
def refresh_perms():
    """每次请求都从库里读当前角色的权限——权限一改立即生效，不用重新登录"""
    if session.get("user"):
        conn = db.connect()
        session["perms"] = [r["perm_code"] for r in conn.execute(
            "SELECT perm_code FROM role_permission WHERE role=?", (session["user"]["role"],))]
        conn.close()

@app.context_processor
def inject_globals():
    return dict(perms=current_perms(), role_label=db.ROLE_LABEL,
                user=session.get("user"))


# ---------------------------------------------------------------- 登录
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    pwd = request.form.get("pwd", "")

    # 失败次数锁定
    rec = FAILED.get(username)
    if rec and rec[0] >= LOCK_LIMIT and time.time() - rec[1] < LOCK_SECONDS:
        left = int(LOCK_SECONDS - (time.time() - rec[1]))
        conn = db.connect()
        audit(conn, "LOGIN_LOCKED", "user", username, "DENIED", "锁定剩余 %d 秒" % left)
        conn.close()
        return render_template("login.html", error="失败次数过多，请 %d 秒后再试" % left,
                               username=username)

    conn = db.connect()
    row = conn.execute("SELECT * FROM user WHERE username=?", (username,)).fetchone()
    if (not row) or (not cu.verify_pwd(pwd, row["pwd_salt"], row["pwd_hash"])):
        cnt = (rec[0] + 1) if rec else 1
        FAILED[username] = [cnt, rec[1] if rec else time.time()]
        audit(conn, "LOGIN_FAIL", "user", username, "FAIL", "第 %d 次" % cnt)
        conn.close()
        return render_template("login.html", error="用户名或口令错误", username=username)

    # 成功：解除计数、派生 KEK、解出私钥放内存
    FAILED.pop(username, None)
    kek = cu.derive_kek(row["pwd_salt"], pwd)
    try:
        priv = cu.unwrap_privkey(row["sm2_priv_enc"], kek)
    except Exception:
        audit(conn, "KEY_UNWRAP_FAIL", "user", username, "FAIL")
        conn.close()
        return render_template("login.html", error="密钥解密失败，请联系安全保密管理员", username=username)

    perms = [r["perm_code"] for r in conn.execute(
        "SELECT perm_code FROM role_permission WHERE role=?", (row["role"],))]
    session.clear()
    session["user"] = {"id": row["id"], "username": row["username"],
                       "real_name": row["real_name"], "role": row["role"],
                       "org_id": row["org_id"]}
    session["perms"] = perms
    sid = uuid.uuid4().hex
    session["sid"] = sid
    SESS_KEYS[sid] = {"priv": priv, "kek": kek}

    audit(conn, "LOGIN_OK", "user", row["username"], "SUCCESS", "角色 %s" % row["role"])
    conn.close()
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    if session.get("user"):
        conn = db.connect()
        audit(conn, "LOGOUT", "user", session["user"]["username"])
        conn.close()
    SESS_KEYS.pop(session.get("sid"), None)
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- 工作台
@app.route("/")
@login_required
def dashboard():
    conn = db.connect()
    stat = {
        "my_drafts": conn.execute("SELECT COUNT(*) FROM doc WHERE sender_id=? AND status='DRAFT'",
                                  (session["user"]["id"],)).fetchone()[0],
        "to_review": conn.execute("SELECT COUNT(*) FROM doc WHERE status='PENDING_REVIEW'").fetchone()[0],
        "to_receive": conn.execute("SELECT COUNT(*) FROM doc WHERE receiver_id=? AND status='SENT'",
                                   (session["user"]["id"],)).fetchone()[0],
        "users": conn.execute("SELECT COUNT(*) FROM user").fetchone()[0],
        "logs": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
    }
    conn.close()
    return render_template("dashboard.html", stat=stat)


# ---------------------------------------------------------------- M2 组织单位
@app.route("/admin/orgs", methods=["GET", "POST"])
@require_perm("org.manage")
def admin_orgs():
    conn = db.connect()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        parent = request.form.get("parent_id") or None
        if not name:
            flash("单位名称不能为空")
        else:
            try:
                conn.execute("INSERT INTO org_unit(name, parent_id) VALUES (?,?)", (name, parent))
                conn.commit()
                audit(conn, "ORG_ADD", "org_unit", name, "SUCCESS", "上级=%s" % (parent or "无"))
                flash("已新增单位：%s" % name)
            except sqlite3.IntegrityError:
                audit(conn, "ORG_ADD", "org_unit", name, "FAIL", "名称重复")
                flash("单位名称已存在")
    orgs = conn.execute(
        "SELECT o.*, (SELECT COUNT(*) FROM user u WHERE u.org_id=o.id) AS user_cnt,"
        " (SELECT name FROM org_unit p WHERE p.id=o.parent_id) AS parent_name"
        " FROM org_unit o ORDER BY o.id").fetchall()
    conn.close()
    return render_template("orgs.html", orgs=orgs)


@app.route("/admin/orgs/<int:oid>/delete", methods=["POST"])
@require_perm("org.manage")
def org_delete(oid):
    conn = db.connect()
    cnt = conn.execute("SELECT COUNT(*) FROM user WHERE org_id=?", (oid,)).fetchone()[0]
    if cnt:
        audit(conn, "ORG_DELETE", "org_unit", oid, "DENIED", "仍有 %d 名用户" % cnt)
        flash("该单位下还有 %d 名用户，不能删除" % cnt)
    else:
        conn.execute("DELETE FROM org_unit WHERE id=?", (oid,))
        conn.commit()
        audit(conn, "ORG_DELETE", "org_unit", oid)
        flash("单位已删除")
    conn.close()
    return redirect(url_for("admin_orgs"))


# ---------------------------------------------------------------- M2 用户管理
def _has_business(conn, uid):
    """该用户是否已经参与过公文业务（三员不得参与业务）"""
    n = conn.execute(
        "SELECT (SELECT COUNT(*) FROM doc WHERE sender_id=?) +"
        "       (SELECT COUNT(*) FROM doc WHERE receiver_id=? )", (uid, uid)).fetchone()[0]
    return n


@app.route("/admin/users")
@require_perm("user.manage")
def admin_users():
    conn = db.connect()
    users = conn.execute(
        "SELECT u.*, o.name AS org_name FROM user u LEFT JOIN org_unit o ON o.id=u.org_id"
        " ORDER BY u.id").fetchall()
    orgs = conn.execute("SELECT * FROM org_unit ORDER BY id").fetchall()
    conn.close()
    return render_template("users.html", users=users, orgs=orgs)


@app.route("/admin/users/new", methods=["GET", "POST"])
@require_perm("user.manage")
def user_new():
    conn = db.connect()
    orgs = conn.execute("SELECT * FROM org_unit ORDER BY id").fetchall()
    if request.method == "GET":
        conn.close()
        return render_template("user_form.html", mode="new", orgs=orgs,
                               roles=db.ROLE_LABEL, user=None)

    username = request.form.get("username", "").strip()
    real_name = request.form.get("real_name", "").strip()
    role = request.form.get("role", "")
    org_id = request.form.get("org_id") or None
    pwd = request.form.get("pwd", "")

    error = None
    if not username or not real_name:
        error = "用户名与姓名不能为空"
    elif role not in db.ROLE_PERMS:
        error = "角色不合法"
    elif len(pwd) < 8:
        error = "初始口令至少 8 位"

    if error:
        conn.close()
        return render_template("user_form.html", mode="new", orgs=orgs,
                               roles=db.ROLE_LABEL, user=None, error=error,
                               form=request.form)

    # 建号即生成密钥对；私钥用该用户口令派生的 KEK 加密
    salt, pwd_hash = cu.make_pwd(pwd)
    priv, pub = cu.sm2_keypair()
    kek = cu.derive_kek(salt, pwd)
    priv_enc = cu.wrap_privkey(priv, kek)
    try:
        conn.execute(
            "INSERT INTO user(username, real_name, role, org_id, pwd_salt, pwd_hash, sm2_pub, sm2_priv_enc)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (username, real_name, role, org_id, salt, pwd_hash, pub, priv_enc))
        conn.commit()
        audit(conn, "USER_ADD", "user", username, "SUCCESS", "角色=%s" % role)
        flash("已创建用户 %s（%s）" % (username, db.ROLE_LABEL[role]))
    except sqlite3.IntegrityError:
        audit(conn, "USER_ADD", "user", username, "FAIL", "用户名重复")
        conn.close()
        return render_template("user_form.html", mode="new", orgs=orgs,
                               roles=db.ROLE_LABEL, user=None, error="用户名已存在",
                               form=request.form)
    conn.close()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/edit", methods=["GET", "POST"])
@require_perm("user.manage")
def user_edit(uid):
    conn = db.connect()
    row = conn.execute("SELECT * FROM user WHERE id=?", (uid,)).fetchone()
    orgs = conn.execute("SELECT * FROM org_unit ORDER BY id").fetchall()
    if not row:
        conn.close()
        flash("用户不存在")
        return redirect(url_for("admin_users"))

    if request.method == "GET":
        conn.close()
        return render_template("user_form.html", mode="edit", orgs=orgs,
                               roles=db.ROLE_LABEL, user=row)

    real_name = request.form.get("real_name", "").strip()
    role = request.form.get("role", "")
    org_id = request.form.get("org_id") or None
    status = request.form.get("status", "ACTIVE")

    error = None
    THREE = ("SYS_ADMIN", "SEC_ADMIN", "AUDITOR")
    if role not in db.ROLE_PERMS:
        error = "角色不合法"
    elif role in THREE and _has_business(conn, uid) > 0:
        # 三员分离的具体落地：参与过公文业务的人不能改成三员
        error = "该用户已参与公文业务，不能调整为三员角色（三员不得参与业务）"
        audit(conn, "USER_EDIT", "user", uid, "DENIED", "三员互斥：已有业务数据")
    elif row["role"] in THREE and role not in THREE and _has_business(conn, uid) > 0:
        error = "该用户已参与公文业务，不能调整为业务岗"
        audit(conn, "USER_EDIT", "user", uid, "DENIED", "业务岗互斥")

    if error:
        conn.close()
        return render_template("user_form.html", mode="edit", orgs=orgs,
                               roles=db.ROLE_LABEL, user=row, error=error)

    conn.execute("UPDATE user SET real_name=?, role=?, org_id=?, status=? WHERE id=?",
                 (real_name, role, org_id, status, uid))
    conn.commit()
    audit(conn, "USER_EDIT", "user", uid, "SUCCESS",
          "角色=%s 状态=%s" % (role, status))
    conn.close()
    flash("已保存用户 %s" % row["username"])
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/reset_pwd", methods=["POST"])
@require_perm("user.manage")
def user_reset_pwd(uid):
    """重置口令：换盐换哈希，同时轮换密钥对（旧私钥作废）"""
    new_pwd = request.form.get("new_pwd", "")
    conn = db.connect()
    row = conn.execute("SELECT * FROM user WHERE id=?", (uid,)).fetchone()
    if not row:
        conn.close()
        flash("用户不存在")
        return redirect(url_for("admin_users"))
    if len(new_pwd) < 8:
        conn.close()
        flash("新口令至少 8 位")
        return redirect(url_for("admin_users"))

    salt, pwd_hash = cu.make_pwd(new_pwd)
    priv, pub = cu.sm2_keypair()
    kek = cu.derive_kek(salt, new_pwd)
    priv_enc = cu.wrap_privkey(priv, kek)
    conn.execute("UPDATE user SET pwd_salt=?, pwd_hash=?, sm2_pub=?, sm2_priv_enc=? WHERE id=?",
                 (salt, pwd_hash, pub, priv_enc, uid))
    conn.commit()
    audit(conn, "USER_RESET_PWD", "user", row["username"], "SUCCESS", "口令与密钥已轮换")
    conn.close()
    flash("已重置 %s 的口令，并轮换其密钥对" % row["username"])
    return redirect(url_for("admin_users"))
# ---------------------------------------------------------------- M3 权限设置（安全保密管理员）
@app.route("/sec/perms", methods=["GET", "POST"])
@require_perm("perm.manage")
def sec_perms():
    conn = db.connect()
    if request.method == "POST":
        # 表单里每个勾选项形如 "ROLE|perm.code"
        chosen = {}
        for code in db.PERM_LABEL:
            chosen[code] = set()
        for key in request.form.getlist("grant"):
            role, code = key.split("|", 1)
            chosen.setdefault(code, set()).add(role)

        before = {}
        for r in conn.execute("SELECT role, perm_code FROM role_permission"):
            before.setdefault(r["role"], set()).add(r["perm_code"])

        for role in db.ROLE_PERMS:
            old = before.get(role, set())
            new = {c for c, roles in chosen.items() if role in roles}
            for code in new - old:
                conn.execute("INSERT OR IGNORE INTO role_permission(role, perm_code) VALUES (?,?)",
                             (role, code))
            for code in old - new:
                conn.execute("DELETE FROM role_permission WHERE role=? AND perm_code=?",
                             (role, code))
        conn.commit()
        diff = []
        for role in db.ROLE_PERMS:
            old = before.get(role, set()); new = {c for c, roles in chosen.items() if role in roles}
            if old != new:
                diff.append("%s %+d" % (role, len(new) - len(old)))
        audit(conn, "PERM_UPDATE", "role_permission", "all", "SUCCESS", "变更：" + (";".join(diff) or "无"))
        flash("权限已保存（立即生效）")
        conn.close()
        return redirect(url_for("sec_perms"))

    grant = {}
    for r in conn.execute("SELECT role, perm_code FROM role_permission"):
        grant.setdefault(r["perm_code"], set()).add(r["role"])
    conn.close()
    return render_template("perms.html", groups=db.PERM_GROUPS, perm_label=db.PERM_LABEL,
                           role_label=db.ROLE_LABEL, grant=grant)


# ---------------------------------------------------------------- M3 密钥管理（安全保密管理员）
@app.route("/sec/keys")
@require_perm("key.manage")
def sec_keys():
    conn = db.connect()
    users = conn.execute(
        "SELECT u.id, u.username, u.real_name, u.role, u.sm2_pub, u.sm2_priv_enc,"
        " length(u.sm2_priv_enc) AS enc_len FROM user u ORDER BY u.id").fetchall()
    keyver = conn.execute("SELECT value FROM sys_config WHERE key='key_version'").fetchone()
    conn.close()
    return render_template("keys.html", users=users,
                           key_version=keyver["value"] if keyver else "1")


@app.route("/sec/keys/rotate", methods=["POST"])
@require_perm("key.manage")
def sec_keys_rotate():
    conn = db.connect()
    row = conn.execute("SELECT value FROM sys_config WHERE key='key_version'").fetchone()
    old = int(row["value"]) if row else 1
    new = old + 1
    conn.execute("INSERT INTO sys_config(key,value) VALUES ('key_version',?)"
                 " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(new),))
    conn.commit()
    audit(conn, "KEY_ROTATE", "sys_config", "key_version", "SUCCESS", "由 %d 升到 %d" % (old, new))
    conn.close()
    flash("系统密钥版本已由 %d 轮换为 %d" % (old, new))
    return redirect(url_for("sec_keys"))


@app.route("/sec/keys/<int:uid>/pub")
@require_perm("key.manage")
def sec_keys_pub(uid):
    """导出用户公钥（公钥本就是公开的，私钥永不导出）"""
    conn = db.connect()
    row = conn.execute("SELECT username, sm2_pub FROM user WHERE id=?", (uid,)).fetchone()
    if row:
        audit(conn, "KEY_EXPORT_PUB", "user", row["username"])
    conn.close()
    if not row:
        abort(404)
    return ("-----BEGIN SM2 PUBLIC KEY-----\n%s\n-----END SM2 PUBLIC KEY-----\n"
            % row["sm2_pub"], 200, {"Content-Type": "text/plain; charset=utf-8"})

if __name__ == "__main__":
    if not os.path.exists(db.DB_PATH):
        db.init_db()
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8000")),
            debug=os.environ.get("DEBUG", "0") == "1")