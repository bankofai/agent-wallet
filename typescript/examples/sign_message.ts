import { TronProvider } from '../src/wallet';

function usage(): never {
  // eslint-disable-next-line no-console
  console.error(
    [
      'Usage:',
      '  LOG_LEVEL=info TRON_PRIVATE_KEY=... node -r ts-node/register examples/sign_message.ts "hello" [utf8|hex]',
      '',
      'Notes:',
      '  - If TRON_PRIVATE_KEY is not set, TronProvider will try to load privateKey from keystore (~/.agent_wallet/Keystore).',
      '  - For encoding=hex, the message must be a hex string (no 0x prefix).',
    ].join('\n')
  );
  process.exit(2);
}

async function main(): Promise<void> {
  const message = process.argv[2];
  const encoding = (process.argv[3] ?? 'utf8') as 'utf8' | 'hex';
  if (!message) usage();
  if (encoding !== 'utf8' && encoding !== 'hex') usage();

  const provider = new TronProvider({
    // All of these are optional; provider can load from env + keystore
    privateKey: process.env.TRON_PRIVATE_KEY,
    apiKey: process.env.TRON_GRID_API_KEY,
    keystore: { password: process.env.KEYSTORE_PASSWORD },
  });
  await provider.init(); // loads credentials from keystore if needed

  const res = await provider.signTx({ type: 'message', message, encoding });
  // eslint-disable-next-line no-console
  console.log(res.signature ?? '');
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(String(e?.message ?? e));
  process.exit(1);
});

