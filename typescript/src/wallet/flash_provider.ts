import { TronProvider, type TronProviderOptions } from './tron_provider';
import { TronWeb } from 'tronweb';

export interface FlashProviderOptions extends TronProviderOptions {
  flashNode?: string;
  privyAppId?: string;
  privyAppSecret?: string;
  walletId?: string;
}

export class FlashProvider extends TronProvider {
  protected flashTronWeb: any;
  protected privyAppId: string;
  protected privyAppSecret: string;
  protected walletId: string;

  constructor(opts: FlashProviderOptions = {}) {
    super(opts);

    this.privyAppId = opts.privyAppId || process.env.PRIVY_APP_ID || '';
    this.privyAppSecret = opts.privyAppSecret || process.env.PRIVY_APP_SECRET || '';
    this.walletId = opts.walletId || process.env.PRIVY_WALLET_ID || '';

    if (this.walletId) {
      this.address = this.walletId;
    }

    const flashNode = opts.flashNode || process.env.TRON_FLASH_RPC_URL || opts.fullNode || process.env.TRON_RPC_URL || 'https://api.trongrid.io';
    const fullNode = opts.fullNode || process.env.TRON_RPC_URL || 'https://api.trongrid.io';

    if (flashNode !== fullNode) {
      const tronOpts: any = {
        fullHost: flashNode,
        privateKey: opts.privateKey || process.env.TRON_PRIVATE_KEY || undefined
      };
      const apiKey = opts.apiKey || process.env.TRON_GRID_API_KEY || '';
      if (apiKey) {
        tronOpts.headers = { "TRON-PRO-API-KEY": apiKey };
      }
      this.flashTronWeb = new TronWeb(tronOpts);
    } else {
      this.flashTronWeb = this.tronWeb;
    }
  }

  /**
   * Load additional Privy credentials from keystore.
   * Keystore keys: privyAppId, privyAppSecret, walletId
   */
  async init(): Promise<this> {
    await super.init();

    const ksPrivyAppId = await this.keystore.get('privyAppId');
    const ksPrivyAppSecret = await this.keystore.get('privyAppSecret');
    const ksWalletId = await this.keystore.get('walletId');

    if (!this.privyAppId && ksPrivyAppId) {
      this.privyAppId = ksPrivyAppId;
    }
    if (!this.privyAppSecret && ksPrivyAppSecret) {
      this.privyAppSecret = ksPrivyAppSecret;
    }
    if (!this.walletId && ksWalletId) {
      this.walletId = ksWalletId;
      this.address = this.walletId;
    }

    return this;
  }

  /**
   * Factory: create and init a FlashProvider in one step.
   */
  static async create(opts: FlashProviderOptions = {}): Promise<FlashProvider> {
    const provider = new FlashProvider(opts);
    await provider.init();
    return provider;
  }

  async sign(transaction: any): Promise<any> {
    if (!this.privyAppId || !this.privyAppSecret || !this.walletId) {
      return super.sign(transaction);
    }

    const txID = transaction.txID;

    const url = `https://auth.privy.io/api/v1/wallets/${encodeURIComponent(this.walletId)}/sign`;
    const auth = btoa(`${this.privyAppId}:${this.privyAppSecret}`);

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        'privy-app-id': this.privyAppId
      },
      body: JSON.stringify({
        method: 'raw_sign',
        params: {
          message: txID,
          encoding: 'hex'
        }
      })
    });

    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      throw new Error(`Privy signing failed (${response.status}): ${errBody || response.statusText}`);
    }

    const data = await response.json();
    const signature = data.signature;

    if (!signature) {
      throw new Error('Privy signing response did not contain a signature');
    }

    const signedTx = JSON.parse(JSON.stringify(transaction));
    if (!signedTx.signature) {
      signedTx.signature = [];
    }
    signedTx.signature.push(signature);

    return signedTx;
  }

  async sendTransaction(toAddress: string, amount: number): Promise<any> {
    if (!this.address) throw new Error("Address not available for signing");
    try {
      const tradeobj = await this.flashTronWeb.transactionBuilder.sendTrx(toAddress, amount, this.address);
      const signedtxn = await this.sign(tradeobj);
      const receipt = await this.flashTronWeb.trx.sendRawTransaction(signedtxn);
      return receipt;
    } catch (error) {
      console.warn("Flash transaction failed", error);
      throw error;
    }
  }
}
