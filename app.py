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

STATUS_LABEL = {
    "DRAFT": "草稿",
    "PENDING_REVIEW": "待审核",
    "APPROVED": "审核通过",
    "SENT": "已发送",
    "RECEIVED": "已签收",
    "PROCESSED": "已处理",
}

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

# ---------------------------------------------------------------- M4 发文
def _next_doc_no(conn):
    year = datetime.now().year
    n = conn.execute("SELECT COUNT(*) FROM doc WHERE doc_no LIKE ?", ("%d-%%" % year,)).fetchone()[0]
    return "%d-%04d" % (year, n + 1)


def _can_view(conn, doc, uid, role):
    """谁能看这篇公文：发送方、接收方、审核员（待审/已审），三员不可看"""
    if role in ("SYS_ADMIN", "SEC_ADMIN", "AUDITOR"):
        return False
    if doc["sender_id"] == uid or doc["receiver_id"] == uid:
        return True
    if role == "REVIEWER" and doc["status"] in ("PENDING_REVIEW", "APPROVED", "SENT",
                                                "RECEIVED", "PROCESSED"):
        return True
    return False


@app.route("/doc/new", methods=["GET", "POST"])
@require_perm("doc.draft")
def doc_new():
    conn = db.connect()
    users = conn.execute("SELECT id, real_name, role FROM user"
                         " WHERE status='ACTIVE' AND id<>? ORDER BY id",
                         (session["user"]["id"],)).fetchall()
    types = conn.execute("SELECT code,label FROM dict_item WHERE type='DOC_TYPE' ORDER BY sort").fetchall()
    urgs = conn.execute("SELECT code,label FROM dict_item WHERE type='URGENCY' ORDER BY sort").fetchall()

    if request.method == "GET":
        conn.close()
        return render_template("doc_new.html", users=users, types=types, urgs=urgs)

    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    doc_type = request.form.get("doc_type", "NOTICE")
    urgency = request.form.get("urgency", "NORMAL")
    receiver_id = request.form.get("receiver_id", "")

    error = None
    if not title:
        error = "标题不能为空"
    elif not body:
        error = "正文不能为空"
    elif not receiver_id:
        error = "请选择接收人"
    if error:
        conn.close()
        return render_template("doc_new.html", users=users, types=types, urgs=urgs,
                               error=error, form=request.form)

    # 正文加密：随机 DEK + 随机 IV，DEK 用接收方公钥封装（草稿期接收人也看不到，列表只显示 SENT 及之后）
    receiver = conn.execute("SELECT * FROM user WHERE id=?", (receiver_id,)).fetchone()
    dek = os.urandom(16)
    iv = os.urandom(16)
    ct = cu.sm4_encrypt(dek, body.encode("utf-8"), iv)
    kek_cipher = cu.sm2_encrypt(receiver["sm2_pub"], dek)          # 接收方一份
    sender_pub = conn.execute("SELECT sm2_pub FROM user WHERE id=?",
                              (session["user"]["id"],)).fetchone()["sm2_pub"]
    kek_cipher_sender = cu.sm2_encrypt(sender_pub, dek)            # 发送方自己一份

    doc_no = _next_doc_no(conn)
    cur = conn.execute(
        "INSERT INTO doc(doc_no, title, body_cipher, body_iv, sender_id, receiver_id, status)"
        " VALUES (?,?,?,?,?,?, 'DRAFT')",
        (doc_no, title, ct, iv, session["user"]["id"], receiver["id"]))
    did = cur.lastrowid
    conn.execute(
        "INSERT INTO doc_envelope(doc_id, kek_cipher, kek_cipher_sender, signature, signer_id)"
        " VALUES (?,?,?,?,?)",
        (did, kek_cipher, kek_cipher_sender, "", None))
    conn.execute("UPDATE doc SET review_note=? WHERE id=?",
                 ("类型=%s 紧急度=%s" % (doc_type, urgency), did))
    conn.commit()
    audit(conn, "DOC_CREATE", "doc", did, "SUCCESS", "编号 %s，接收人 %s" % (doc_no, receiver["username"]))
    conn.close()
    flash("已保存草稿：%s" % doc_no)
    return redirect(url_for("doc_detail", did=did))


@app.route("/docs/mine")
@require_perm("doc.view_own")
def docs_mine():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    sql = ("SELECT d.*, r.real_name AS receiver_name FROM doc d"
           " LEFT JOIN user r ON r.id=d.receiver_id WHERE d.sender_id=?")
    args = [session["user"]["id"]]
    if q:
        sql += " AND d.title LIKE ?"; args.append("%" + q + "%")
    if status:
        sql += " AND d.status=?"; args.append(status)
    sql += " ORDER BY d.id DESC"
    conn = db.connect()
    docs = conn.execute(sql, args).fetchall()
    conn.close()
    return render_template("doc_list.html", docs=docs, q=q, status=status,
                           status_label=STATUS_LABEL)


@app.route("/doc/<int:did>")
@login_required
def doc_detail(did):
    conn = db.connect()
    d = conn.execute("SELECT d.*, s.real_name AS sender_name, r.real_name AS receiver_name,"
                     " rv.real_name AS reviewer_name"
                     " FROM doc d LEFT JOIN user s ON s.id=d.sender_id"
                     " LEFT JOIN user r ON r.id=d.receiver_id"
                     " LEFT JOIN user rv ON rv.id=d.reviewer_id WHERE d.id=?", (did,)).fetchone()
    if not d:
        conn.close(); abort(404)
    me = session["user"]
    if not _can_view(conn, d, me["id"], me["role"]):
        audit(conn, "DOC_VIEW", "doc", did, "DENIED", "无查看权限")
        conn.close()
        return render_template("403.html", perm="doc.view"), 403
    env = conn.execute("SELECT * FROM doc_envelope WHERE doc_id=?", (did,)).fetchone()
    conn.close()
    return render_template("doc_detail.html", d=d, env=env, status_label=STATUS_LABEL)


@app.route("/doc/<int:did>/body")
@login_required
def doc_body(did):
    """解密查看正文——只对发送方/接收方开放，且必须验签（M6 补）"""
    conn = db.connect()
    d = conn.execute("SELECT * FROM doc WHERE id=?", (did,)).fetchone()
    me = session["user"]
    if not d or not _can_view(conn, d, me["id"], me["role"]):
        audit(conn, "DOC_DECRYPT", "doc", did, "DENIED")
        conn.close(); abort(403)
    kek = SESS_KEYS.get(session.get("sid"))
    if not kek:
        conn.close(); abort(403)
    env = conn.execute("SELECT * FROM doc_envelope WHERE doc_id=?", (did,)).fetchone()
    # 发送方用自己那份信封，接收方用另一份——两把钥匙各开各的门
    if d["sender_id"] == me["id"]:
        sealed = env["kek_cipher_sender"]
    else:
        sealed = env["kek_cipher"]
    try:
        dek = cu.sm2_decrypt(kek["priv"],
                             conn.execute("SELECT sm2_pub FROM user WHERE id=?",
                                          (me["id"],)).fetchone()["sm2_pub"],
                             sealed)
        plain = cu.sm4_decrypt(dek, d["body_iv"], d["body_cipher"]).decode("utf-8")
    except Exception as e:
        audit(conn, "DOC_DECRYPT", "doc", did, "FAIL", str(e))
        conn.close()
        return "解密失败：%s" % e, 500
    audit(conn, "DOC_DECRYPT", "doc", did, "SUCCESS")
    conn.close()
    return plain, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/doc/<int:did>/submit", methods=["POST"])
@require_perm("doc.draft")
def doc_submit(did):
    conn = db.connect()
    d = conn.execute("SELECT * FROM doc WHERE id=?", (did,)).fetchone()
    if d and d["sender_id"] == session["user"]["id"] and d["status"] == "DRAFT":
        conn.execute("UPDATE doc SET status='PENDING_REVIEW', submitted_at=? WHERE id=?", (now(), did))
        conn.commit()
        audit(conn, "DOC_SUBMIT", "doc", did, "SUCCESS", d["doc_no"])
        flash("已提交审核")
    else:
        audit(conn, "DOC_SUBMIT", "doc", did, "DENIED", "状态或归属不符")
        flash("只能提交自己的草稿")
    conn.close()
    return redirect(url_for("doc_detail", did=did))


@app.route("/review")
@require_perm("doc.approve")
def review_list():
    conn = db.connect()
    docs = conn.execute("SELECT d.*, s.real_name AS sender_name FROM doc d"
                        " LEFT JOIN user s ON s.id=d.sender_id"
                        " WHERE d.status='PENDING_REVIEW' ORDER BY d.submitted_at").fetchall()
    conn.close()
    return render_template("review_list.html", docs=docs)


@app.route("/doc/<int:did>/approve", methods=["POST"])
@require_perm("doc.approve")
def doc_approve(did):
    note = request.form.get("note", "").strip()
    conn = db.connect()
    d = conn.execute("SELECT * FROM doc WHERE id=?", (did,)).fetchone()
    if d and d["status"] == "PENDING_REVIEW":
        conn.execute("UPDATE doc SET status='APPROVED', reviewer_id=?, reviewed_at=?, review_note=?"
                     " WHERE id=?", (session["user"]["id"], now(), note, did))
        conn.commit()
        audit(conn, "DOC_APPROVE", "doc", did, "SUCCESS", "意见：%s" % (note or "无"))
        flash("已审核通过")
    else:
        flash("只能审核待审公文")
    conn.close()
    return redirect(url_for("review_list"))


@app.route("/doc/<int:did>/reject", methods=["POST"])
@require_perm("doc.approve")
def doc_reject(did):
    note = request.form.get("note", "").strip()
    conn = db.connect()
    d = conn.execute("SELECT * FROM doc WHERE id=?", (did,)).fetchone()
    if d and d["status"] == "PENDING_REVIEW":
        conn.execute("UPDATE doc SET status='DRAFT', reviewer_id=?, reviewed_at=?, review_note=?"
                     " WHERE id=?", (session["user"]["id"], now(), "退回：" + (note or "无意见"), did))
        conn.commit()
        audit(conn, "DOC_REJECT", "doc", did, "SUCCESS", "退回意见：%s" % (note or "无"))
        flash("已退回起草人")
    conn.close()
    return redirect(url_for("review_list"))


@app.route("/doc/<int:did>/send", methods=["POST"])
@require_perm("doc.send")
def doc_send(did):
    """发送：计算 SM3 摘要（签名在 M6 补），状态置 SENT"""
    conn = db.connect()
    d = conn.execute("SELECT * FROM doc WHERE id=?", (did,)).fetchone()
    if d and d["sender_id"] == session["user"]["id"] and d["status"] == "APPROVED":
        digest = cu.sm3_hex(d["doc_no"].encode() + b"|" + d["body_cipher"])
        conn.execute("UPDATE doc SET status='SENT', sent_at=?, digest=? WHERE id=?",
                     (now(), digest, did))
        conn.commit()
        audit(conn, "DOC_SEND", "doc", did, "SUCCESS", "摘要 %s…" % digest[:16])
        flash("已发送，摘要 %s…" % digest[:16])
    else:
        audit(conn, "DOC_SEND", "doc", did, "DENIED", "状态或归属不符")
        flash("只有审核通过的本人公文才能发送")
    conn.close()
    return redirect(url_for("doc_detail", did=did))
# ---------------------------------------------------------------- M5 收文
@app.route("/inbox")
@require_perm("doc.receive")
def inbox():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    sql = ("SELECT d.*, s.real_name AS sender_name FROM doc d"
           " LEFT JOIN user s ON s.id=d.sender_id"
           " WHERE d.receiver_id=? AND d.status IN ('SENT','RECEIVED','PROCESSED')")
    args = [session["user"]["id"]]
    if q:
        sql += " AND d.title LIKE ?"; args.append("%" + q + "%")
    if status:
        sql += " AND d.status=?"; args.append(status)
    sql += " ORDER BY d.sent_at DESC"
    conn = db.connect()
    docs = conn.execute(sql, args).fetchall()
    conn.close()
    return render_template("inbox.html", docs=docs, q=q, status=status,
                           status_label=STATUS_LABEL)


@app.route("/doc/<int:did>/sign", methods=["POST"])
@require_perm("doc.sign")
def doc_sign(did):
    """签收：只有接收人、且状态为已发送时可签收"""
    conn = db.connect()
    d = conn.execute("SELECT * FROM doc WHERE id=?", (did,)).fetchone()
    if d and d["receiver_id"] == session["user"]["id"] and d["status"] == "SENT":
        conn.execute("UPDATE doc SET status='RECEIVED', received_at=? WHERE id=?", (now(), did))
        conn.commit()
        audit(conn, "DOC_SIGN", "doc", did, "SUCCESS", d["doc_no"])
        flash("已签收")
    else:
        audit(conn, "DOC_SIGN", "doc", did, "DENIED", "非接收人或状态不符")
        flash("只有接收人才能签收已发送的公文")
    conn.close()
    return redirect(url_for("doc_detail", did=did))


@app.route("/doc/<int:did>/process", methods=["POST"])
@require_perm("doc.sign")
def doc_process(did):
    """处理：接收人签收后填写处理意见并办结"""
    note = request.form.get("note", "").strip()
    conn = db.connect()
    d = conn.execute("SELECT * FROM doc WHERE id=?", (did,)).fetchone()
    if d and d["receiver_id"] == session["user"]["id"] and d["status"] == "RECEIVED":
        conn.execute("UPDATE doc SET status='PROCESSED', processed_at=?, review_note=?"
                     " WHERE id=?", (now(), "处理意见：" + (note or "已阅办"), did))
        conn.commit()
        audit(conn, "DOC_PROCESS", "doc", did, "SUCCESS", "意见：%s" % (note or "已阅办"))
        flash("已办结")
    else:
        audit(conn, "DOC_PROCESS", "doc", did, "DENIED", "非接收人或状态不符")
        flash("只有接收人在签收后才能处理")
    conn.close()
    return redirect(url_for("doc_detail", did=did))
if __name__ == "__main__":
    if not os.path.exists(db.DB_PATH):
        db.init_db()
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8000")),
            debug=os.environ.get("DEBUG", "0") == "1")