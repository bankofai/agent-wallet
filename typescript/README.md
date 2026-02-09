# Agent Wallet SDK (TypeScript)

## Provider 抽象

- **BaseProvider**：抽象基类，统一接口：
  - `getAccountInfo(): Promise<AccountInfo>` — 返回 `{ address: string }`（钱包地址）
  - `signTx(unsignedTx: unknown): Promise<SignedTxResult>` — 接受未签名交易，完成签名并返回 `{ signedTx, signature? }`
- **TronProvider**：继承 BaseProvider，基于 TronWeb，本地私钥签名。
- **FlashProvider**：继承 TronProvider，支持 Privy 远程签名与 Flash 节点。

```ts
import { TronProvider, FlashProvider } from './src/wallet';

const tron = new TronProvider(undefined, undefined, undefined, process.env.TRON_PRIVATE_KEY);
const info = await tron.getAccountInfo();  // { address: 'T...' }
const { signedTx } = await tron.signTx(unsignedTx);
```

## Keystore

固定路径的 JSON 文件存储账户信息（私钥、apiKey、secretKey 等），支持读写与可选加密。

- **路径**：默认 `./.keystore.json`，可通过 `KEYSTORE_PATH` 或构造选项 `filePath` 指定。
- **加密**：若提供 `password` 或 `KEYSTORE_PASSWORD`，文件以 AES-256-GCM（scrypt 派生密钥）加密存储。

```ts
import { Keystore } from './src/keystore';

const ks = new Keystore({ filePath: './.keystore.json', password: 'secret' });
await ks.read();
const privateKey = await ks.get('privateKey');
ks.set('apiKey', 'xxx');
await ks.write();

// 静态方法
const data = await Keystore.fromFile('./.keystore.json', 'secret');
await Keystore.toFile('./out.json', { privateKey: 'abc' }, 'secret');
```

## Keystore 命令行

```bash
npm run keystore -- read [key]           # 读单个 key 或全部
npm run keystore -- write <key> <value>  # 写单个 key
npm run keystore -- delete <key>         # 删除 key
npm run keystore -- init                 # 创建空 keystore

# 可选
npm run keystore -- --path ./my.json read
KEYSTORE_PASSWORD=xxx npm run keystore -- write privateKey "hex..."
```

## 加密说明

- 未设置密码时，keystore 为明文 JSON。
- 设置密码后，写入为 `{ version, salt, iv, tag, data }` 的加密 payload（scrypt + AES-256-GCM），读入时需相同密码解密。

## 测试

```bash
npm test
```
