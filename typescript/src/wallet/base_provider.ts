import type { AccountInfo, SignedTxResult } from './types';

/**
 * Abstract base provider: compatible getAccountInfo and signTx.
 * Subclasses (TronProvider, FlashProvider) implement chain-specific logic.
 */
export abstract class BaseProvider {
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
