# -*- coding: utf-8 -*-
"""用 Edge DevTools 协议（CDP）给系统页面截图，无需 selenium。

思路：
  1) 以 --headless=new --remote-debugging-port 启动 Edge
  2) 用标准库 socket 与页面 target 做 WebSocket 握手
  3) 通过 HTTP 登录拿到 Flask 会话 cookie，再用 Network.setCookie 注入浏览器
  4) Page.navigate 打开页面，Page.captureScreenshot 取 PNG
"""
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import urllib.parse

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
BASE = "http://127.0.0.1:8000"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "screenshots")
PROFILE = os.path.join(os.environ["TEMP"], "edge-cdp-profile")
DEBUG_PORT = 9333


# ---------------- 极简 WebSocket 客户端 ----------------
class WS:
    def __init__(self, url):
        u = urllib.parse.urlparse(url)
        self.sock = socket.create_connection((u.hostname, u.port), timeout=20)
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n" % (u.path, u.hostname, u.port, key))
        self.sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.sock.recv(4096)
        assert b"101" in buf.split(b"\r\n")[0], buf[:200]

    def send(self, obj):
        payload = json.dumps(obj).encode()
        mask = os.urandom(4)
        n = len(payload)
        header = b"\x81"
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def _recv_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data

    def recv(self):
        b0, b1 = self._recv_exact(2)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._recv_exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._recv_exact(8))[0]
        return json.loads(self._recv_exact(n).decode())

    def call(self, method, **params):
        self.send({"id": _id(), "method": method, "params": params})
        while True:
            msg = self.recv()
            if msg.get("id") == _ID["v"]:
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                return msg.get("result", {})


_ID = {"v": 0}


def _id():
    _ID["v"] += 1
    return _ID["v"]


# ---------------- 登录拿 cookie ----------------
def login_cookie(username, pwd="Test@1234"):
    import http.cookiejar
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    body = urllib.parse.urlencode({"username": username, "pwd": pwd}).encode()
    op.open(urllib.request.Request(BASE + "/login", data=body, method="POST"), timeout=10)
    for c in cj:
        if c.name == "session":
            return c.value
    raise RuntimeError("未拿到 session cookie")


# ---------------- 截图 ----------------
def shot(ws, url, path, cookie=None, wait=1.2, height=900):
    ws.call("Emulation.setDeviceMetricsOverride", width=1280, height=height,
            deviceScaleFactor=1, mobile=False)
    ws.call("Network.enable")
    if cookie:
        ws.call("Network.setCookie", name="session", value=cookie,
                domain="127.0.0.1", path="/")
    ws.call("Page.navigate", url=url)
    time.sleep(wait)
    data = ws.call("Page.captureScreenshot", format="png")["data"]
    with open(path, "wb") as f:
        f.write(base64.b64decode(data))
    print("  saved", os.path.basename(path))


def main():
    os.makedirs(OUT, exist_ok=True)
    # 启动 Edge（无头 + 调试端口）
    proc = subprocess.Popen([EDGE, "--headless=new", "--disable-gpu",
                             "--remote-debugging-port=%d" % DEBUG_PORT,
                             "--user-data-dir=%s" % PROFILE,
                             "--window-size=1280,900", "--no-first-run",
                             "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws_url = None
        for _ in range(40):
            time.sleep(0.5)
            try:
                info = json.load(urllib.request.urlopen(
                    "http://127.0.0.1:%d/json/list" % DEBUG_PORT, timeout=3))
                for t in info:
                    if t.get("type") == "page":
                        ws_url = t["webSocketDebuggerUrl"]
                        break
                if ws_url:
                    break
            except Exception:
                continue
        if not ws_url:
            print("无法连接 Edge 调试端口")
            return 1

        ws = WS(ws_url)
        ws.call("Page.enable", )
        ws.call("Emulation.setDeviceMetricsOverride", width=1280, height=900,
                deviceScaleFactor=1, mobile=False)

        ck = {
            "keyuan": login_cookie("keyuan"),
            "shenhe": login_cookie("shenhe"),
            "sysadmin": login_cookie("sysadmin"),
            "secadmin": login_cookie("secadmin"),
            "auditor": login_cookie("auditor"),
        }
        print("已获取 5 个角色的会话 cookie")

        base_dir = os.path.dirname(os.path.abspath(__file__))
        plans = json.load(open(os.path.join(base_dir, "shots_plan.json"), "r", encoding="utf-8-sig"))
        state_path = os.path.join(base_dir, "docs_state.json")
        state = json.load(open(state_path, "r", encoding="utf-8-sig")) if os.path.exists(state_path) else {}
        for item in plans:
            path = item["path"].format(**state) if "{" in item["path"] else item["path"]
            shot(ws, BASE + path, os.path.join(OUT, item["file"]),
                 ck.get(item.get("role")), item.get("wait", 1.2), item.get("height", 900))
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())