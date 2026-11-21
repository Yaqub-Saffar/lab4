# -*- coding: utf-8 -*-
"""国密工具层（20241422 穆弈涵）

本文件只做一件事：把 SM2/SM3/SM4 的调用封成几个语义明确的函数，
业务代码里不再出现 gmssl 的细节，方便审计"密钥有没有明文存储"。

约定：
  * 口令：pwd_hash = SM3^1000(salt : pwd)，salt 每个用户 16 字节随机
  * 私钥：用 KEK（由口令派生）做 SM4-CBC 加密后以 base64 存库，明文私钥只在内存
  * 正文：每篇公文随机 16 字节 DEK，SM4-CBC 加密，IV 随机随密文一起存
  * 信封：DEK 用接收方 SM2 公钥加密；摘要用 SM3；签名用发送方 SM2 私钥
"""
import os
import base64
from gmssl import sm2, sm3, sm4, func

PWD_ITER = 1000
SALT_BYTES = 16


# ---------------- SM3 ----------------
def sm3_hex(data: bytes) -> str:
    return sm3.sm3_hash(func.bytes_to_list(data))


def _hp(salt_hex: str, pwd: str, iterations: int) -> str:
    """带盐迭代哈希，用于口令与 KEK 派生"""
    h = sm3_hex(salt_hex.encode() + b":" + pwd.encode())
    for _ in range(iterations - 1):
        h = sm3_hex(h.encode())
    return h


def make_pwd(pwd: str):
    salt = os.urandom(SALT_BYTES).hex()
    return salt, _hp(salt, pwd, PWD_ITER)


def verify_pwd(pwd: str, salt: str, expected: str) -> bool:
    return _hp(salt, pwd, PWD_ITER) == expected


# ---------------- SM2 ----------------
def sm2_keypair():
    """生成 (私钥 hex 64 位, 公钥 hex 128 位)"""
    priv = func.random_hex(64)
    tmp = sm2.CryptSM2(private_key=priv, public_key="")
    pub = tmp._kg(int(priv, 16), sm2.default_ecc_table["g"])
    return priv, pub


def sm2_sign(priv: str, pub: str, data: bytes) -> str:
    c = sm2.CryptSM2(private_key=priv, public_key=pub)
    return c.sign(data, func.random_hex(64))


def sm2_verify(pub: str, sig: str, data: bytes) -> bool:
    c = sm2.CryptSM2(private_key="", public_key=pub)
    return bool(c.verify(sig, data))


def sm2_encrypt(pub: str, data: bytes) -> bytes:
    return sm2.CryptSM2(private_key="", public_key=pub).encrypt(data)


def sm2_decrypt(priv: str, pub: str, ct: bytes) -> bytes:
    return sm2.CryptSM2(private_key=priv, public_key=pub).decrypt(ct)


# ---------------- SM4 ----------------
def _pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def _unpad(b: bytes) -> bytes:
    return b[:-b[-1]]


def sm4_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    c = sm4.CryptSM4()
    c.set_key(key, sm4.SM4_ENCRYPT)
    return c.crypt_cbc(iv, _pad(data))


def sm4_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    c = sm4.CryptSM4()
    c.set_key(key, sm4.SM4_DECRYPT)
    return _unpad(c.crypt_cbc(iv, ct))


# ---------------- KEK 与私钥包装 ----------------
def derive_kek(salt_hex: str, pwd: str) -> bytes:
    """由口令派生 32 字节 KEK（取前 16 字节给 SM4 用）"""
    return bytes.fromhex(_hp(salt_hex, pwd, PWD_ITER))


def wrap_privkey(priv_hex: str, kek: bytes) -> str:
    """私钥密文 = base64(IV ‖ SM4-CBC(私钥))，库里只有这一串"""
    iv = os.urandom(16)
    ct = sm4_encrypt(kek[:16], bytes.fromhex(priv_hex), iv)
    return base64.b64encode(iv + ct).decode()


def unwrap_privkey(blob: str, kek: bytes) -> str:
    raw = base64.b64decode(blob)
    return sm4_decrypt(kek[:16], raw[:16], raw[16:]).hex()

# ---------------- 国标 SM2 签名（带 ZA） ----------------
# gmssl 库的 sign/verify 接收的是"已经算好的 e"，而国标要求
# e = SM3(ZA || M)，ZA = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)。
# 下面两个函数补齐 ZA 计算，使签名与 GmSSL / 国密标准真正互通。
SM2_DEFAULT_ID = b"1234567812345678"


def sm2_za(pub_hex: str) -> bytes:
    """用户标识杂凑值 ZA（默认 ID 1234567812345678）"""
    entl = (len(SM2_DEFAULT_ID) * 8).to_bytes(2, "big")
    t = sm2.default_ecc_table
    a = bytes.fromhex(t["a"]); b = bytes.fromhex(t["b"])
    g = bytes.fromhex(t["g"])
    gx, gy = g[:32], g[32:]
    pk = bytes.fromhex(pub_hex)
    px, py = pk[:32], pk[32:]
    return bytes.fromhex(sm3_hex(entl + SM2_DEFAULT_ID + a + b + gx + gy + px + py))


def sm2_hash_msg(pub_hex: str, msg: bytes) -> bytes:
    """国标 e = SM3(ZA || M)"""
    return bytes.fromhex(sm3_hex(sm2_za(pub_hex) + msg))


def sm2_sign_std(priv: str, pub: str, msg: bytes) -> str:
    """按国标签名的 SM2（返回 r||s 的 hex）"""
    e = sm2_hash_msg(pub, msg)
    c = sm2.CryptSM2(private_key=priv, public_key=pub)
    return c.sign(e, func.random_hex(64))


def sm2_verify_std(pub: str, sig: str, msg: bytes) -> bool:
    """按国标验签"""
    e = sm2_hash_msg(pub, msg)
    c = sm2.CryptSM2(private_key="", public_key=pub)
    return bool(c.verify(sig, e))