# Agent Wallet SDK (Python)

Aligned with the TypeScript SDK: Provider abstraction, Keystore, CLI, and encryption.

## Provider abstraction

- **BaseProvider**: Abstract base class with a unified interface:
  - `get_account_info() -> AccountInfo` — returns `{"address": str}` (wallet address)
  - `sign_tx(unsigned_tx) -> SignedTxResult` — accepts an unsigned transaction, signs it, and returns `{"signed_tx", "signature?"}`
- **TronProvider**: Extends BaseProvider; uses tronpy with local private-key signing.
- **FlashProvider**: Extends TronProvider; supports Privy remote signing and Flash node.

```python
from wallet import TronProvider, FlashProvider

tron = TronProvider(private_key=os.getenv("TRON_PRIVATE_KEY"))
info = await tron.get_account_info()   # {"address": "T..."}
result = await tron.sign_tx(unsigned_tx)
signed_tx = result["signed_tx"]
```

## Keystore

A fixed-path JSON file stores account info (privateKey, apiKey, secretKey, etc.) with optional encryption. Payload format is compatible with the TypeScript keystore.

- **Path**: Default `./.keystore.json`; override via `KEYSTORE_PATH` or the `file_path` argument.
- **Encryption**: If `password` or `KEYSTORE_PASSWORD` is set, the file is encrypted with AES-256-GCM (key derived via scrypt).

```python
from keystore import Keystore

ks = Keystore(file_path="./.keystore.json", password="secret")
ks.read()
private_key = ks.get("privateKey")
ks.set("apiKey", "xxx")
ks.write()

# Static methods
data = Keystore.from_file("./.keystore.json", "secret")
Keystore.to_file("./out.json", {"privateKey": "abc"}, "secret")
```

## Keystore CLI

```bash
# From the python directory
uv run python -m keystore_cli read [key]
uv run python -m keystore_cli write <key> <value>
uv run python -m keystore_cli delete <key>
uv run python -m keystore_cli init

# After install, run directly
keystore read
keystore write privateKey "hex..."

# Optional
--path ./my.json
--password xxx  or  KEYSTORE_PASSWORD=xxx
```

## Encryption

- Without a password, the keystore file is plain JSON.
- With a password, the file is stored as an encrypted payload `{ version, salt, iv, tag, data }` (scrypt + AES-256-GCM); you can read and write the same file from both TypeScript and Python.

## Tests

```bash
uv run pytest
```
