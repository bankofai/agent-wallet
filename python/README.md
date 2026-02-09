# Agent Wallet SDK (Python)

与 TypeScript 版逻辑对齐：Provider 抽象、Keystore、CLI、加密。

## Provider 抽象

- **BaseProvider**：抽象基类，统一接口：
  - `get_account_info() -> AccountInfo` — 返回 `{"address": str}`（钱包地址）
  - `sign_tx(unsigned_tx) -> SignedTxResult` — 接受未签名交易，完成签名并返回 `{"signed_tx", "signature?"}`
- **TronProvider**：继承 BaseProvider，基于 tronpy，本地私钥签名。
- **FlashProvider**：继承 TronProvider，支持 Privy 远程签名与 Flash 节点。

```python
from wallet import TronProvider, FlashProvider

tron = TronProvider(private_key=os.getenv("TRON_PRIVATE_KEY"))
info = await tron.get_account_info()   # {"address": "T..."}
result = await tron.sign_tx(unsigned_tx)
signed_tx = result["signed_tx"]
```

## Keystore

固定路径的 JSON 文件存储账户信息（私钥、apiKey、secretKey 等），支持读写与可选加密。

- **路径**：默认 `./.keystore.json`，可通过 `KEYSTORE_PATH` 或构造参数 `file_path` 指定。
- **加密**：若提供 `password` 或 `KEYSTORE_PASSWORD`，文件以 AES-256-GCM（scrypt 派生密钥）加密存储，与 TypeScript 版 payload 兼容。

```python
from keystore import Keystore

ks = Keystore(file_path="./.keystore.json", password="secret")
ks.read()
private_key = ks.get("privateKey")
ks.set("apiKey", "xxx")
ks.write()

# 静态方法
data = Keystore.from_file("./.keystore.json", "secret")
Keystore.to_file("./out.json", {"privateKey": "abc"}, "secret")
```

## Keystore 命令行

```bash
# 在 python 目录下
uv run python -m keystore_cli read [key]
uv run python -m keystore_cli write <key> <value>
uv run python -m keystore_cli delete <key>
uv run python -m keystore_cli init

# 安装后可直接
keystore read
keystore write privateKey "hex..."

# 可选
--path ./my.json
--password xxx  或  KEYSTORE_PASSWORD=xxx
```

## 加密说明

- 未设置密码时，keystore 为明文 JSON。
- 设置密码后，写入为 `{ version, salt, iv, tag, data }` 的加密 payload（scrypt + AES-256-GCM），与 TypeScript 版可互相读写。

## 测试

```bash
uv run pytest
```
