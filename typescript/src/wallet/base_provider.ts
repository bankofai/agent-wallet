import type { AccountInfo, SignedTxResult } from './types';
import { Keystore, type KeystoreOptions } from '../keystore/keystore';

/**
 * Abstract base provider: compatible getAccountInfo and signTx.
 * Subclasses (TronProvider, FlashProvider) implement chain-specific logic.
 *
 * Each provider holds a Keystore instance. Call `init()` to load credentials
 * from keystore, or use the static `create()` factory for one-step setup.
 */
export abstract class BaseProvider {
  /** Keystore instance for reading/writing account credentials. */
  public keystore: Keystore;

  constructor(keystoreOpts?: KeystoreOptions) {
    this.keystore = new Keystore(keystoreOpts);
  }

  /**
   * Load credentials from keystore. Subclasses override to populate
   * chain-specific fields (privateKey, apiKey, etc.) from keystore data.
   * Must be called after construction (constructors cannot be async).
   */
  async init(): Promise<this> {
    await this.keystore.read();
    return this;
  }

  /**
   * Get account info; must include wallet address.
   */
  abstract getAccountInfo(): Promise<AccountInfo>;

  /**
   * Sign an unsigned transaction and return the signed result.
   * @param unsignedTx - Chain-specific unsigned transaction object
   * @returns Signed transaction and optional raw signature
   */
  abstract signTx(unsignedTx: unknown): Promise<SignedTxResult>;
}
