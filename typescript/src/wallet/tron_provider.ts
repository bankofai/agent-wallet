import { TronWeb } from "tronweb";
import * as dotenv from "dotenv";
import { BaseProvider } from "./base_provider";
import type { AccountInfo, SignedTxResult } from "./types";
import type { KeystoreOptions, KeystoreBase } from "../keystore";

dotenv.config();

export interface TronProviderOptions {
  fullNode?: string;
  solidityNode?: string;
  eventServer?: string;
  privateKey?: string;
  apiKey?: string;
  /** Keystore options or a custom keystore implementation. */
  keystore?: KeystoreOptions | KeystoreBase;
}

export class TronProvider extends BaseProvider {
  protected tronWeb: any;
  protected address: string | null = null;
  private _privateKey: string;
  private _apiKey: string;
  private _fullNode: string;
  private _solidityNode: string;
  private _eventServer: string;

  /**
   * Initialize TronProvider.
   * After construction, call `init()` to load credentials from keystore.
   * Or use `TronProvider.create(opts)` for one-step setup.
   */
  constructor(opts: TronProviderOptions = {}) {
    super(opts.keystore);

    this._fullNode =
      opts.fullNode || process.env.TRON_RPC_URL || "https://api.trongrid.io";
    this._solidityNode =
      opts.solidityNode ||
      process.env.TRON_RPC_URL ||
      "https://api.trongrid.io";
    this._eventServer =
      opts.eventServer || process.env.TRON_RPC_URL || "https://api.trongrid.io";
    this._privateKey = opts.privateKey || process.env.TRON_PRIVATE_KEY || "";
    this._apiKey = opts.apiKey || process.env.TRON_GRID_API_KEY || "";

    this._buildTronWeb();
  }

  /** Build / rebuild TronWeb instance from current credentials. */
  private _buildTronWeb(): void {
    const options: any = {
      fullHost: this._fullNode,
      solidityNode: this._solidityNode,
      eventServer: this._eventServer,
      privateKey: this._privateKey || undefined,
    };

    if (this._apiKey) {
      options.headers = { "TRON-PRO-API-KEY": this._apiKey };
    }

    this.tronWeb = new TronWeb(options);

    if (this._privateKey) {
      this.address = this.tronWeb.address.fromPrivateKey(this._privateKey);
    }
  }

  /**
   * Load credentials from keystore, then rebuild TronWeb if new values found.
   * Keystore keys used: privateKey, apiKey, rpcUrl
   */
  async init(): Promise<this> {
    await super.init();

    const ksPrivateKey = await this.keystore.get("privateKey");
    const ksApiKey = await this.keystore.get("apiKey");
    const ksRpcUrl = await this.keystore.get("rpcUrl");

    let changed = false;
    if (!this._privateKey && ksPrivateKey) {
      this._privateKey = ksPrivateKey;
      changed = true;
    }
    if (!this._apiKey && ksApiKey) {
      this._apiKey = ksApiKey;
      changed = true;
    }
    if (ksRpcUrl && ksRpcUrl !== this._fullNode) {
      this._fullNode = ksRpcUrl;
      this._solidityNode = ksRpcUrl;
      this._eventServer = ksRpcUrl;
      changed = true;
    }

    if (changed) {
      this._buildTronWeb();
    }

    return this;
  }

  /**
   * Factory: create and init a TronProvider in one step.
   */
  static async create(opts: TronProviderOptions = {}): Promise<TronProvider> {
    const provider = new TronProvider(opts);
    await provider.init();
    return provider;
  }

  async getAccountInfo(): Promise<AccountInfo> {
    if (!this.address)
      throw new Error("Address not available (no private key or wallet id)");
    return { address: this.address };
  }

  async signTx(unsignedTx: unknown): Promise<SignedTxResult> {
    const signed = await this.sign(unsignedTx as any);
    const sig = (signed as any)?.signature?.[0];
    return {
      signedTx: signed,
      signature: typeof sig === "string" ? sig : undefined,
    };
  }

  async getBalance(address?: string): Promise<number> {
    const addr = address || this.address;
    if (!addr) throw new Error("Address not provided");
    return await this.tronWeb.trx.getBalance(addr);
  }

  async getTrc20Balance(
    walletAddress: string,
    contractAddress: string,
  ): Promise<string> {
    const contract = await this.tronWeb.contract().at(contractAddress);
    const balance = await contract.balanceOf(walletAddress).call();
    return balance.toString();
  }

  async sendTransaction(toAddress: string, amount: number): Promise<any> {
    if (!this.address) throw new Error("Private key not provided for signing");
    const tradeobj = await this.tronWeb.transactionBuilder.sendTrx(
      toAddress,
      amount,
      this.address,
    );
    const signedtxn = await this.sign(tradeobj);
    const receipt = await this.tronWeb.trx.sendRawTransaction(signedtxn);
    return receipt;
  }

  async sign(transaction: any): Promise<any> {
    if (!this.address) throw new Error("Private key not provided for signing");
    return await this.tronWeb.trx.sign(transaction);
  }

  async broadcast(signedTransaction: any): Promise<any> {
    return await this.tronWeb.trx.sendRawTransaction(signedTransaction);
  }
}
