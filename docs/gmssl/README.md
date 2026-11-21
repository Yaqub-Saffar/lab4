# GmSSL 交叉验证证据

20241422 穆弈涵　实验四

## 文件

| 文件 | 来源 | 说明 |
|---|---|---|
| `msg.txt` | 手工创建 | 待签名消息 `20241422MYH` |
| `pub.pem` / `key.pem` | GmSSL `sm2keygen` | GmSSL 生成的 SM2 密钥对（私钥为加密 PEM） |
| `sig.der` | GmSSL `sm2sign` | GmSSL 产出的 DER 签名（71 字节） |
| `py_pub.pem` | Python 导出 | 由 Python 生成的 SM2 公钥，拼成标准 SPKI |
| `py_sig.der` | Python 导出 | Python 签名（r‖s 转 DER，71 字节） |

## 验证一：GmSSL 签名 → Python 验签

```bash
# 虚拟机上（openEuler 24.03，GmSSL 3.2.0）
gmssl sm2keygen -pass 123456 -out key.pem -pubout pub.pem
printf '20241422MYH' > msg.txt
gmssl sm3 -in msg.txt
# cfb7506ecfab20e74d9004409a2b44a0927321612a16c467e426f4036cde6b6b
gmssl sm2sign -key key.pem -pass 123456 -id 1234567812345678 -in msg.txt -out sig.der
gmssl sm2verify -pubkey pub.pem -id 1234567812345678 -in msg.txt -sig sig.der
# verify : success
```

Python 侧：解析 `pub.pem` 取出 X‖Y，按国标算 `ZA` 与 `e = SM3(ZA‖M)`，把 DER 签名还原成 r‖s 后验签。
**结果：通过**（见 `docs/量化评估.md` 第六节）。

## 验证二：Python 签名 → GmSSL 验签

```bash
# 虚拟机上
gmssl sm2verify -pubkey py_pub.pem -id 1234567812345678 -in msg.txt -sig py_sig.der
# verify : success
```

Python 侧用 `crypto_utils.sm2_sign_std` 按国标签名（含 ZA），再把 r‖s 编成 DER，
并用 GmSSL 公钥的 SPKI 前缀拼出 `py_pub.pem`。

## 说明：为什么要补 ZA

`gmssl`（Python 包）的 `CryptSM2.sign/verify` 接收的是**已经算好的 e**，本身不做 ZA 计算；
而 GmSSL 命令行与国标要求 `e = SM3(ZA ‖ M)`。
因此 `crypto_utils` 里补了 `sm2_za()` / `sm2_hash_msg()` / `sm2_sign_std()` / `sm2_verify_std()`，
系统内的公文签名与验签都走这一套，才能与 GmSSL 互通。