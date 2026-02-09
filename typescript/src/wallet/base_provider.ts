import type { AccountInfo, SignedTxResult } from './types';
import { Keystore, KeystoreBase, type KeystoreOptions } from '../keystore';
import { logger } from '../logger';

/**
 * Abstract base provider: compatible getAccountInfo and signTx.
 * Subclasses (TronProvider, FlashProvider) implement chain-specific logic.
 *
 * Each provider holds a Keystore instance. Call `init()` to load credentials
 * from keystore, or use the static `create()` factory on concrete providers.
 */
export abstract class BaseProvider {
  /** Keystore instance for reading/writing account credentials. */
  public keystore: KeystoreBase;

  constructor(keystore?: KeystoreBase | KeystoreOptions) {
    // Allow injecting a custom keystore implementation.
    if (
      keystore &&
      typeof (keystore as any).read === 'function' &&
      typeof (keystore as any).write === 'function'
    ) {
      this.keystore = keystore as KeystoreBase;
    } else {
      this.keystore = new Keystore(keystore as KeystoreOptions | undefined);
    }
  }

  /**
   * Load credentials from keystore. Subclasses override to populate
   * chain-specific fields (privateKey, apiKey, etc.) from keystore data.
   * Must be called after construction (constructors cannot be async).
   */
  async init(): Promise<this> {
    logger.debug(
      { keystorePath: this.keystore.getPath() },
      'provider keystore init: reading keystore',
    );
    await this.keystore.read();
    logger.debug(
      { keystorePath: this.keystore.getPath() },
      'provider keystore init: loaded',
    );
    return this;
  }

  /** Get account info; must include wallet address. */
  abstract getAccountInfo(): Promise<AccountInfo>;

  /** Sign an arbitrary message (bytes) and return signature string. */
  abstract signMessage(message: Uint8Array): Promise<string>;

  /**
   * Sign an unsigned transaction (or message request) and return the signed result.
   * @param unsignedTx - Chain-specific unsigned payload
   */
  abstract signTx(unsignedTx: unknown): Promise<SignedTxResult>;
}

