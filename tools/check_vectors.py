# -*- coding: utf-8 -*-
"""算法正确性自检：SM3 / SM4 国标向量（20241422 穆弈涵）

用法：py tools/check_vectors.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gmssl import sm3, sm4, func
import crypto_utils as cu


def main():
    ok_all = True

    # SM3("abc")
    h = cu.sm3_hex(b"abc")
    exp = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    print("SM3('abc') :", "OK" if h == exp else "FAIL", h)
    ok_all &= (h == exp)

    # SM3("")
    h0 = cu.sm3_hex(b"")
    exp0 = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
    print("SM3('')    :", "OK" if h0 == exp0 else "FAIL", h0)
    ok_all &= (h0 == exp0)

    # SM4 单分组
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    c = sm4.CryptSM4(); c.set_key(key, sm4.SM4_ENCRYPT)
    ct = func.list_to_bytes(c.one_round(c.sk, func.bytes_to_list(key)))
    exp4 = "681edf34d206965e86b3e94f536e4246"
    print("SM4 block  :", "OK" if ct.hex() == exp4 else "FAIL", ct.hex())
    ok_all &= (ct.hex() == exp4)

    # SM2 签名自洽（含 ZA）
    priv, pub = cu.sm2_keypair()
    msg = b"20241422MYH"
    sig = cu.sm2_sign_std(priv, pub, msg)
    good = cu.sm2_verify_std(pub, sig, msg)
    bad = cu.sm2_verify_std(pub, sig, msg + b"x")
    print("SM2 sign   :", "OK" if good and not bad else "FAIL",
          "(正确消息通过=%s，篡改消息拒绝=%s)" % (good, not bad))
    ok_all &= bool(good and not bad)

    print("\n总体:", "全部通过" if ok_all else "存在失败项")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())