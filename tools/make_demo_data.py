# -*- coding: utf-8 -*-
"""造演示数据：两篇走完流程的公文 + 一篇待审 + 一次越权尝试"""
import json, os, re, sys
import http.cookiejar, urllib.request, urllib.parse

BASE = "http://127.0.0.1:8000"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "docs_state.json")


def sess(u, p="Test@1234"):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.open(urllib.request.Request(BASE + "/login",
            data=urllib.parse.urlencode({"username": u, "pwd": p}).encode(), method="POST"))
    return op


def post(op, path, data=None):
    return op.open(urllib.request.Request(BASE + path,
            data=urllib.parse.urlencode(data or {}).encode(), method="POST"), timeout=15)


def new_doc(op, title, body, rid=2):
    html = post(op, "/doc/new", {"title": title, "doc_type": "NOTICE", "urgency": "NORMAL",
                                 "receiver_id": rid, "body": body}).read().decode("utf-8")
    m = re.search(r"/doc/(\d+)/body", html)
    return int(m.group(1))


keyuan, shenhe = sess("keyuan"), sess("shenhe")

# A：完整流程 → 已办结
a = new_doc(keyuan, "关于开展实验室安全检查的通知",
            "各部门：\n定于本周五下午 14:00 开展实验室安全检查，请提前整理实验台面、留存设备使用记录。\n特此通知。\n\n校办公室\n2026 年 11 月 21 日")
post(keyuan, "/doc/%d/submit" % a)
post(shenhe, "/doc/%d/approve" % a, {"note": "同意，请各单位配合"})
post(keyuan, "/doc/%d/send" % a)
post(shenhe, "/doc/%d/sign" % a)
post(shenhe, "/doc/%d/process" % a, {"note": "已按要求完成整理"})

# B：已发送待签收（用于收文列表与验签截图）
b = new_doc(keyuan, "关于报送年度密码工作总结的函",
            "密码工作领导小组：\n现将本年度密码工作总结报送如下，请审阅。\n\n一、主要工作\n二、存在问题\n三、下一步打算")

post(keyuan, "/doc/%d/submit" % b)
post(shenhe, "/doc/%d/approve" % b, {"note": "同意报送"})
post(keyuan, "/doc/%d/send" % b)

# C：待审核（用于审核列表截图）
c = new_doc(keyuan, "关于申请采购密码设备的请示",
            "院领导：\n因实验室建设需要，申请采购服务器密码机两台，预算详见附件。\n请批示。")
post(keyuan, "/doc/%d/submit" % c)

# 越权尝试：科员访问用户管理（写进审计，供日志截图）
try:
    keyuan.open(BASE + "/admin/users", timeout=10)
except Exception:
    pass

json.dump({"a": a, "b": b, "c": c}, open(OUT, "w"), ensure_ascii=False)
print("A(已办结)=%d  B(待签收)=%d  C(待审核)=%d" % (a, b, c))