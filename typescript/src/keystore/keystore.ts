import * as fs from 'fs';
import * as path from 'path';
import { encrypt, decrypt, isEncryptedPayload, type EncryptedPayload } from './keystore_crypto';

/** Default keystore filename in current directory */
export const DEFAULT_KEYSTORE_FILENAME = '.keystore.json';

/** Account fields commonly stored (privateKey, apiKey, secretKey, address, etc.) */
export type KeystoreData = Record<string, string>;

const DEFAULT_PATH = path.join(process.cwd(), DEFAULT_KEYSTORE_FILENAME);

export interface KeystoreOptions {
  /** Full path to keystore JSON file. Default: cwd + .keystore.json */
  filePath?: string;
  /** If set, file is encrypted with this password */
  password?: string;
}

/**
 * Keystore: fixed-address JSON file storing account info (privateKey, apiKey, secretKey, etc.)
 * with optional password-based encryption.
 */
export class Keystore {
  private filePath: string;
  private password: string | undefined;
  private data: KeystoreData = {};
  private loaded = false;

  constructor(options: KeystoreOptions = {}) {
    this.filePath = options.filePath ?? process.env.KEYSTORE_PATH ?? DEFAULT_PATH;
    this.password = options.password ?? process.env.KEYSTORE_PASSWORD;
  }

  /** Get the path of the keystore file */
  getPath(): string {
    return this.filePath;
  }

  /** Read from file (decrypt if password was set). Idempotent. */
  async read(): Promise<KeystoreData> {
    if (!fs.existsSync(this.filePath)) {
      this.data = {};
      this.loaded = true;
      return this.data;
    }
    const raw = fs.readFileSync(this.filePath, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (isEncryptedPayload(parsed)) {
      if (!this.password) {
        throw new Error('Keystore is encrypted but no password provided (KEYSTORE_PASSWORD or options.password)');
      }
      const plain = await decrypt(parsed as EncryptedPayload, this.password);
      this.data = JSON.parse(plain) as KeystoreData;
    } else {
      this.data = (parsed as KeystoreData) || {};
    }
    this.loaded = true;
    return this.data;
  }

  /** Ensure data is loaded; throw if file missing and not yet written. */
  private async ensureLoaded(): Promise<void> {
    if (!this.loaded) {
      await this.read();
    }
  }

  /** Get a value by key (e.g. 'privateKey', 'apiKey', 'secretKey'). */
  async get(key: string): Promise<string | undefined> {
    await this.ensureLoaded();
    return this.data[key];
  }

  /** Set a value by key. Does not persist until write() is called. */
  set(key: string, value: string): void {
    this.data[key] = value;
    if (!this.loaded) this.loaded = true;
  }

  /** Get all keys. */
  async keys(): Promise<string[]> {
    await this.ensureLoaded();
    return Object.keys(this.data);
  }

  /** Get full data snapshot. */
  async getAll(): Promise<KeystoreData> {
    await this.ensureLoaded();
    return { ...this.data };
  }

  /** Write current data to file (encrypt if password is set). */
  async write(): Promise<void> {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const json = JSON.stringify(this.data, null, 2);
    if (this.password) {
      const payload = await encrypt(json, this.password);
      fs.writeFileSync(this.filePath, JSON.stringify(payload, null, 2), 'utf8');
    } else {
      fs.writeFileSync(this.filePath, json, 'utf8');
    }
  }

  /** Load from a different path (one-time read). */
  static async fromFile(filePath: string, password?: string): Promise<KeystoreData> {
    const ks = new Keystore({ filePath, password });
    return ks.read();
  }

  /** Save data to a path (one-time write). */
  static async toFile(filePath: string, data: KeystoreData, password?: string): Promise<void> {
    const ks = new Keystore({ filePath, password });
    ks.data = { ...data };
    ks.loaded = true;
    await ks.write();
  }
}
