# Agent Wallet SDK (TypeScript)

## Provider abstraction

- **BaseProvider**: Abstract base class with a unified interface:
  - `getAccountInfo(): Promise<AccountInfo>` — returns `{ address: string }` (wallet address)
  - `signTx(unsignedTx: unknown): Promise<SignedTxResult>` — accepts an unsigned transaction, signs it, and returns `{ signedTx, signature? }`
- **TronProvider**: Extends BaseProvider; uses TronWeb with local private-key signing.
- **FlashProvider**: Extends TronProvider; supports Privy remote signing and Flash node.

```ts
import { TronProvider, FlashProvider } from './src/wallet';

// Load credentials from env, constructor options and keystore (~/.agent_wallet/Keystore)
const tron = await TronProvider.create({
  privateKey: process.env.TRON_PRIVATE_KEY,   // optional, overrides keystore/env
  apiKey: process.env.TRON_GRID_API_KEY,     // optional
  keystore: {
    password: process.env.KEYSTORE_PASSWORD, // optional encryption password
  },
});

const info = await tron.getAccountInfo();  // { address: 'T...' }
const { signedTx } = await tron.signTx(unsignedTx);
```

`FlashProvider` works the same way, but additionally loads Privy credentials from keystore:

```ts
const flash = await FlashProvider.create({
  keystore: { password: process.env.KEYSTORE_PASSWORD },
  // Optionally override values that might also live in the keystore:
  privyAppId: process.env.PRIVY_APP_ID,
  privyAppSecret: process.env.PRIVY_APP_SECRET,
  walletId: process.env.PRIVY_WALLET_ID,
});
```

## Keystore

A fixed-path Protobuf file stores account info (privateKey, apiKey, secretKey, etc.) with optional encryption. The storage format is cross-language compatible with the Python SDK.

- **Path**: Default `~/.agent_wallet/Keystore`; override via `KEYSTORE_PATH` env var or the `filePath` option.
- **Storage format**: Protobuf wire format (`map<string, string>`), NOT JSON.
- **Encryption**: If `password` or `KEYSTORE_PASSWORD` is set, protobuf bytes are base64-encoded and wrapped in an AES-256-GCM encrypted JSON payload (key derived via scrypt).
- **Atomic writes**: All writes go through a `.tmp` file then `rename`, preventing data loss on crash.
- **Backward compatible**: Can still read legacy plain-JSON keystore files.

```ts
import { Keystore } from './src/keystore';

const ks = new Keystore({ password: 'secret' }); // defaults to ~/.agent_wallet/Keystore
await ks.read();
const privateKey = await ks.get('privateKey');
await ks.set('apiKey', 'xxx');  // note: set() is async — loads existing data first if needed
await ks.write();

// Static helpers
const data = await Keystore.fromFile('/path/to/Keystore', 'secret');
await Keystore.toFile('/path/to/Keystore', { privateKey: 'abc' }, 'secret');
```

## Keystore CLI

Default path is `~/.agent_wallet/Keystore` (same as the library).

```bash
npm run keystore -- read [key]           # read one key or all
npm run keystore -- write <key> <value>  # write one key-value pair
npm run keystore -- delete <key>         # delete one key
npm run keystore -- init                 # create empty keystore

# Options
npm run keystore -- --path /custom/path read
KEYSTORE_PASSWORD=xxx npm run keystore -- write privateKey "hex..."
```

## Encryption

- **Without a password**: keystore is stored as raw protobuf binary.
- **With a password**: protobuf bytes are base64-encoded, then encrypted with scrypt + AES-256-GCM and stored as `{ version, salt, iv, tag, data }`. The same password is required to decrypt on read.
- Salt, IV, and tag lengths are validated on decrypt.

## Tests

```bash
npm test
```
