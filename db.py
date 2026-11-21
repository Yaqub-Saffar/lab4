# -*- coding: utf-8 -*-
"""数据库层：建表 + 初始化数据 + 连接管理（SQLite）"""
import os
import sqlite3
import crypto_utils as cu

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.db")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS org_unit (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  name      TEXT NOT NULL UNIQUE,
  parent_id INTEGER REFERENCES org_unit(id)
);

CREATE TABLE IF NOT EXISTS user (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  real_name     TEXT NOT NULL,
  role          TEXT NOT NULL,
  org_id        INTEGER REFERENCES org_unit(id),
  pwd_salt      TEXT NOT NULL,
  pwd_hash      TEXT NOT NULL,
  sm2_pub       TEXT NOT NULL,
  sm2_priv_enc  TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS role_permission (
  role      TEXT NOT NULL,
  perm_code TEXT NOT NULL,
  PRIMARY KEY (role, perm_code)
);

CREATE TABLE IF NOT EXISTS doc (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_no       TEXT UNIQUE,
  title        TEXT NOT NULL,
  body_cipher  BLOB,
  body_iv      BLOB,
  digest       TEXT,
  sender_id    INTEGER REFERENCES user(id),
  receiver_id  INTEGER REFERENCES user(id),
  status       TEXT NOT NULL DEFAULT 'DRAFT',
  review_note  TEXT,
  reviewer_id  INTEGER REFERENCES user(id),
  created_at   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  submitted_at TEXT,
  reviewed_at  TEXT,
  sent_at      TEXT,
  received_at  TEXT,
  processed_at TEXT
);

CREATE TABLE IF NOT EXISTS doc_envelope (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id      INTEGER NOT NULL REFERENCES doc(id),
  kek_cipher  BLOB NOT NULL,
  signature   TEXT NOT NULL,
  signer_id   INTEGER REFERENCES user(id),
  created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  user_id     INTEGER,
  username    TEXT,
  role        TEXT,
  action      TEXT NOT NULL,
  object_type TEXT,
  object_id   TEXT,
  result      TEXT,
  ip          TEXT,
  detail      TEXT
);

CREATE TABLE IF NOT EXISTS sys_config (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS dict_item (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  type  TEXT NOT NULL,
  code  TEXT NOT NULL,
  label TEXT NOT NULL,
  sort  INTEGER DEFAULT 0,
  UNIQUE (type, code)
);
"""

# 角色 → 权限（三员与业务岗严格分离）
ROLE_PERMS = {
    "OPERATOR": ["doc.draft", "doc.view_own", "doc.send", "doc.receive", "doc.sign"],
    "REVIEWER": ["doc.draft", "doc.view_own", "doc.approve", "doc.send", "doc.receive", "doc.sign"],
    "SYS_ADMIN": ["org.manage", "user.manage"],
    "SEC_ADMIN": ["perm.manage", "key.manage"],
    "AUDITOR": ["log.view"],
}

ROLE_LABEL = {
    "OPERATOR": "操作员（科员）",
    "REVIEWER": "审核员（科长）",
    "SYS_ADMIN": "系统管理员",
    "SEC_ADMIN": "安全保密管理员",
    "AUDITOR": "安全审计员",
}


# 权限编码 → 中文说明（权限设置页与文档共用）
PERM_LABEL = {
    "doc.draft": "起草公文",
    "doc.view_own": "查看本人公文",
    "doc.approve": "发文审核",
    "doc.send": "发送公文",
    "doc.receive": "接收公文",
    "doc.sign": "签收 / 处理",
    "org.manage": "组织单位管理",
    "user.manage": "用户账号管理",
    "perm.manage": "角色权限分配",
    "key.manage": "密钥管理",
    "log.view": "审计日志查看",
}

PERM_GROUPS = {
    "公文业务": ["doc.draft", "doc.view_own", "doc.approve", "doc.send", "doc.receive", "doc.sign"],
    "系统管理": ["org.manage", "user.manage"],
    "安全保密": ["perm.manage", "key.manage"],
    "审计监督": ["log.view"],
}
SEED_USERS = [
    ("keyuan", "王五", "OPERATOR", "教务处"),
    ("shenhe", "李四", "REVIEWER", "教务处"),
    ("sysadmin", "系统管理员", "SYS_ADMIN", "信息中心"),
    ("secadmin", "安全保密管理员", "SEC_ADMIN", "信息中心"),
    ("auditor", "安全审计员", "AUDITOR", "信息中心"),
]
SEED_PWD = "Test@1234"


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(force: bool = False):
    if force and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    fresh = not os.path.exists(DB_PATH)
    conn = connect()
    conn.executescript(SCHEMA)
    if fresh:
        # 组织单位
        for name in ("校办公室", "教务处", "信息中心"):
            conn.execute("INSERT OR IGNORE INTO org_unit(name) VALUES (?)", (name,))
        # 权限
        for role, perms in ROLE_PERMS.items():
            for p in perms:
                conn.execute("INSERT OR IGNORE INTO role_permission VALUES (?,?)", (role, p))
        # 用户（每人独立密钥对，私钥用其口令派生的 KEK 加密）
        for username, real, role, org in SEED_USERS:
            salt, pwd_hash = cu.make_pwd(SEED_PWD)
            priv, pub = cu.sm2_keypair()
            kek = cu.derive_kek(salt, SEED_PWD)
            priv_enc = cu.wrap_privkey(priv, kek)
            org_id = conn.execute("SELECT id FROM org_unit WHERE name=?", (org,)).fetchone()[0]
            conn.execute(
                "INSERT INTO user(username, real_name, role, org_id, pwd_salt, pwd_hash, sm2_pub, sm2_priv_enc)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (username, real, role, org_id, salt, pwd_hash, pub, priv_enc))
        # 数据字典
        for typ, code, label, sort in [
            ("DOC_TYPE", "NOTICE", "通知", 1),
            ("DOC_TYPE", "REPORT", "请示报告", 2),
            ("DOC_TYPE", "LETTER", "函件", 3),
            ("URGENCY", "NORMAL", "普通", 1),
            ("URGENCY", "URGENT", "紧急", 2),
        ]:
            conn.execute("INSERT OR IGNORE INTO dict_item(type, code, label, sort) VALUES (?,?,?,?)",
                         (typ, code, label, sort))
        conn.execute("INSERT OR IGNORE INTO sys_config(key,value) VALUES ('key_version','1')")
        conn.commit()
    conn.close()
    return fresh


if __name__ == "__main__":
    created = init_db(force=True)
    print("数据库初始化完成：", DB_PATH)
    print("种子口令：", SEED_PWD)