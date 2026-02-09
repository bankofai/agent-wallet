# Agent Wallet SDK (TypeScript)

## Provider abstraction

- **BaseProvider**: Abstract base class with a unified interface:
  - `getAccountInfo(): Promise<AccountInfo>` — returns `{ address: string }` (wallet address)
  - `signTx(unsignedTx: unknown): Promise<SignedTxResult>` — accepts an unsigned payload, signs it, and returns `{ signedTx, signature? }`
- Providers depend on an abstract **KeystoreBase** type, so you can inject other keystore implementations if needed (default is the file-based `Keystore` at `~/.agent_wallet/Keystore`).
- **TronProvider**: Extends BaseProvider; uses TronWeb with local private-key signing.
- **FlashProvider**: Extends TronProvider; supports Privy remote signing and Flash node.

### Keystore initialization is done via CLI

Create the keystore file and write credentials using the keystore CLI (recommended):

```bash
npm run keystore -- init
npm run keystore -- write privateKey "hex..."
npm run keystore -- write apiKey "tron-grid-api-key"
```

### Provider usage

```ts
import { TronProvider } from './src/wallet';

// Provider holds a keystore instance in the constructor.
// It only *reads* keystore data when you call `await init()`.
const tron = new TronProvider({
  privateKey: process.env.TRON_PRIVATE_KEY, // optional, overrides keystore/env
  apiKey: process.env.TRON_GRID_API_KEY,   // optional
  keystore: { password: process.env.KEYSTORE_PASSWORD },
});
await tron.init();

const info = await tron.getAccountInfo(); // { address: 'T...' }
const signed = await tron.signTx(unsignedTx);
```

### Sign an arbitrary message

```ts
const res = await tron.signTx({ type: 'message', message: 'hello', encoding: 'utf8' });
console.log(res.signature);
```

## Keystore

A fixed-path Protobuf file stores account info (privateKey, apiKey, secretKey, etc.) with optional encryption. The storage format is cross-language compatible with the Python SDK.

- **Path**: Default `~/.agent_wallet/Keystore`; override via `KEYSTORE_PATH` env var or the `filePath` option.
- **Storage format**: Protobuf wire format (`map<string, string>`), NOT JSON.
- **Encryption**: If `password` or `KEYSTORE_PASSWORD` is set, protobuf bytes are base64-encoded and wrapped in an AES-256-GCM encrypted JSON payload (key derived via scrypt).
- **Atomic writes**: All writes go through a `.tmp` file then `rename`, preventing data loss on crash.
- **Backward compatible**: Can still read legacy plain-JSON keystore files.

## Tests

```bash
npm test
```

## Logging

Set `LOG_LEVEL` to control verbosity: `trace|debug|info|warn|error|fatal|silent`.

