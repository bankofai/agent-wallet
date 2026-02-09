# Agent Wallet SDK (TypeScript)

## Provider abstraction

- **BaseProvider**: Abstract base class with a unified interface:
  - `getAccountInfo(): Promise<AccountInfo>` — returns `{ address: string }` (wallet address)
  - `signTx(unsignedTx: unknown): Promise<SignedTxResult>` — accepts an unsigned transaction, signs it, and returns `{ signedTx, signature? }`
- **TronProvider**: Extends BaseProvider; uses TronWeb with local private-key signing.
- **FlashProvider**: Extends TronProvider; supports Privy remote signing and Flash node.

```ts
import { TronProvider, FlashProvider } from './src/wallet';

const tron = new TronProvider(undefined, undefined, undefined, process.env.TRON_PRIVATE_KEY);
const info = await tron.getAccountInfo();  // { address: 'T...' }
const { signedTx } = await tron.signTx(unsignedTx);
```

## Keystore

A fixed-path JSON file stores account info (privateKey, apiKey, secretKey, etc.) with optional encryption.

- **Path**: Default `./.keystore.json`; override via `KEYSTORE_PATH` or the `filePath` option.
- **Encryption**: If `password` or `KEYSTORE_PASSWORD` is set, the file is encrypted with AES-256-GCM (key derived via scrypt).

```ts
import { Keystore } from './src/keystore';

const ks = new Keystore({ filePath: './.keystore.json', password: 'secret' });
await ks.read();
const privateKey = await ks.get('privateKey');
ks.set('apiKey', 'xxx');
await ks.write();

// Static methods
const data = await Keystore.fromFile('./.keystore.json', 'secret');
await Keystore.toFile('./out.json', { privateKey: 'abc' }, 'secret');
```

## Keystore CLI

```bash
npm run keystore -- read [key]           # read one key or all
npm run keystore -- write <key> <value>  # write one key
npm run keystore -- delete <key>         # delete one key
npm run keystore -- init                 # create empty keystore

# Optional
npm run keystore -- --path ./my.json read
KEYSTORE_PASSWORD=xxx npm run keystore -- write privateKey "hex..."
```

## Encryption

- Without a password, the keystore file is plain JSON.
- With a password, the file is stored as an encrypted payload `{ version, salt, iv, tag, data }` (scrypt + AES-256-GCM); the same password is required to decrypt on read.

## Tests

```bash
npm test
```
