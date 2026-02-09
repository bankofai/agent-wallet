# Agent Wallet SDK (Python)

Aligned with the TypeScript SDK: Provider abstraction, Keystore, CLI, and encryption. The keystore file is cross-language compatible — files written by TypeScript can be read by Python and vice versa.

## Provider abstraction

- **BaseProvider**: Abstract base class with a unified interface:
  - `get_account_info() -> AccountInfo` — returns `{"address": str}` (wallet address)
  - `sign_tx(unsigned_tx) -> SignedTxResult` — accepts an unsigned transaction, signs it, and returns `{"signed_tx", "signature?"}`
- **TronProvider**: Extends BaseProvider; uses tronpy with local private-key signing.
- **FlashProvider**: Extends TronProvider; supports Privy remote signing and Flash node.

```python
from wallet import TronProvider, FlashProvider

# Load credentials from env, constructor args and keystore (~/.agent_wallet/Keystore)
tron = await TronProvider.create(
    private_key=os.getenv("TRON_PRIVATE_KEY"),   # optional, overrides keystore/env
    api_key=os.getenv("TRON_GRID_API_KEY"),      # optional
    keystore_path=os.getenv("KEYSTORE_PATH"),    # optional custom path
    keystore_password=os.getenv("KEYSTORE_PASSWORD"),
)

info = await tron.get_account_info()   # {"address": "T..."}
result = await tron.sign_tx(unsigned_tx)
signed_tx = result["signed_tx"]
```

`FlashProvider` works the same way, and can also pull Privy credentials from the keystore:

```python
flash = await FlashProvider.create(
    rpc_url=os.getenv("TRON_RPC_URL"),
    keystore_password=os.getenv("KEYSTORE_PASSWORD"),
    # Optionally override values that might also live in the keystore:
    privy_app_id=os.getenv("PRIVY_APP_ID"),
    privy_app_secret=os.getenv("PRIVY_APP_SECRET"),
    wallet_id=os.getenv("PRIVY_WALLET_ID"),
)
```

## Keystore

A fixed-path Protobuf file stores account info (privateKey, apiKey, secretKey, etc.) with optional encryption.

- **Path**: Default `~/.agent_wallet/Keystore`; override via `KEYSTORE_PATH` env var or the `file_path` argument.
- **Storage format**: Protobuf wire format (`map<string, string>`), NOT JSON.
- **Encryption**: If `password` or `KEYSTORE_PASSWORD` is set, protobuf bytes are base64-encoded and wrapped in an AES-256-GCM encrypted JSON payload (key derived via scrypt).
- **Atomic writes**: All writes go through a `.tmp` file then `os.replace`, preventing data loss on crash.
- **Backward compatible**: Can still read legacy plain-JSON keystore files.

```python
from keystore import Keystore

ks = Keystore(password="secret")  # defaults to ~/.agent_wallet/Keystore
ks.read()
private_key = ks.get("privateKey")
ks.set("apiKey", "xxx")  # loads existing data first if not yet loaded
ks.write()

# Static helpers
data = Keystore.from_file(os.path.expanduser("~/.agent_wallet/Keystore"), "secret")
Keystore.to_file("/path/to/Keystore", {"privateKey": "abc"}, "secret")
```

## Keystore CLI

Default path is `~/.agent_wallet/Keystore` (same as the library).

```bash
# From the python directory
python -m keystore_cli read [key]
python -m keystore_cli write <key> <value>
python -m keystore_cli delete <key>
python -m keystore_cli init

# After install, run directly
keystore read
keystore write privateKey "hex..."

# Options
--path /custom/path
--password xxx  or  KEYSTORE_PASSWORD=xxx
```

## Encryption

- **Without a password**: keystore is stored as raw protobuf binary.
- **With a password**: protobuf bytes are base64-encoded, then encrypted with scrypt + AES-256-GCM and stored as `{ version, salt, iv, tag, data }`. The same password is required to decrypt on read.
- Salt, IV, and tag lengths are validated on decrypt.

## Tests

```bash
uv run pytest
# or
python -m pytest tests/ -v
```
