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


if __name__ == "__main__":
    if not os.path.exists(db.DB_PATH):
        db.init_db()
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "8000")),
            debug=os.environ.get("DEBUG", "0") == "1")