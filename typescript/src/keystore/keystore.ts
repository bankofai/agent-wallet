import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { encrypt, decrypt, isEncryptedPayload, type EncryptedPayload } from './keystore_crypto';
import { encodeKeystoreData, decodeKeystoreData } from './keystore_proto';
import { logger } from '../logger';

/** Default keystore filename under the user's home directory */
export const DEFAULT_KEYSTORE_FILENAME = 'Keystore';

/** Account fields commonly stored (privateKey, apiKey, secretKey, address, etc.) */
export type KeystoreData = Record<string, string>;

const DEFAULT_PATH = path.join(os.homedir(), '.agent_wallet', DEFAULT_KEYSTORE_FILENAME);

export interface KeystoreOptions {
  /** Full path to keystore file. Default: ~/.agent_wallet/Keystore */
  filePath?: string;
  /** If set, file is encrypted with this password */
  password?: string;
}

/**
 * Keystore base class (abstract).
 * Providers should depend on this type, so you can inject alternative keystore
 * implementations (memory/db/etc.) without changing provider logic.
 */
export abstract class KeystoreBase {
  abstract getPath(): string;
  abstract read(): Promise<KeystoreData>;
  abstract get(key: string): Promise<string | undefined>;
  abstract set(key: string, value: string): Promise<void>;
  abstract keys(): Promise<string[]>;
  abstract getAll(): Promise<KeystoreData>;
  abstract write(): Promise<void>;
}

/**
 * Keystore: fixed-path protobuf file storing account info with optional encryption.
 */
export class Keystore extends KeystoreBase {
  private filePath: string;
  private password: string | undefined;
  private data: KeystoreData = {};
  private loaded = false;

  constructor(options: KeystoreOptions = {}) {
    super();
    this.filePath = options.filePath ?? process.env.KEYSTORE_PATH ?? DEFAULT_PATH;
    this.password = options.password ?? process.env.KEYSTORE_PASSWORD;
  }

  getPath(): string {
    return this.filePath;
  }

  /** Read from file (decrypt if password was set). Supports legacy JSON and new protobuf format. */
  async read(): Promise<KeystoreData> {
    logger.debug({ filePath: this.filePath }, 'keystore: read start');
    if (!fs.existsSync(this.filePath)) {
      this.data = {};
      this.loaded = true;
      logger.debug({ filePath: this.filePath }, 'keystore: file missing, returning empty');
      return this.data;
    }
    const rawBuf = fs.readFileSync(this.filePath);

    // Try JSON first (encrypted or legacy plaintext)
    let parsed: unknown;
    let parsedAsJson = false;
    try {
      const txt = rawBuf.toString('utf8');
      parsed = JSON.parse(txt) as unknown;
      parsedAsJson = true;
    } catch {
      parsedAsJson = false;
    }

    if (parsedAsJson && isEncryptedPayload(parsed)) {
      if (!this.password) {
        throw new Error('Keystore is encrypted but no password provided (KEYSTORE_PASSWORD or options.password)');
      }
      logger.debug({ filePath: this.filePath }, 'keystore: detected encrypted JSON payload');
      const plain = await decrypt(parsed as EncryptedPayload, this.password);
      // Backwards compatibility: plaintext may be JSON or base64-encoded protobuf
      try {
        const maybeJson = JSON.parse(plain) as unknown;
        if (maybeJson && typeof maybeJson === 'object' && !Array.isArray(maybeJson)) {
          this.data = maybeJson as KeystoreData;
        } else {
          throw new Error('not plain object');
        }
      } catch {
        const buf = Buffer.from(plain, 'base64');
        this.data = decodeKeystoreData(buf);
      }
    } else if (parsedAsJson && parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      logger.debug({ filePath: this.filePath }, 'keystore: detected legacy JSON plaintext');
      this.data = parsed as KeystoreData;
    } else {
      logger.debug({ filePath: this.filePath }, 'keystore: detected protobuf binary');
      this.data = decodeKeystoreData(rawBuf);
    }
    this.loaded = true;
    logger.info({ filePath: this.filePath, keys: Object.keys(this.data).length, encrypted: Boolean(this.password) }, 'keystore: read ok');
    return { ...this.data };
  }

  private async ensureLoaded(): Promise<void> {
    if (!this.loaded) {
      await this.read();
    }
  }

  async get(key: string): Promise<string | undefined> {
    await this.ensureLoaded();
    return this.data[key];
  }

  async set(key: string, value: string): Promise<void> {
    await this.ensureLoaded();
    this.data[key] = value;
  }

  async keys(): Promise<string[]> {
    await this.ensureLoaded();
    return Object.keys(this.data);
  }

  async getAll(): Promise<KeystoreData> {
    await this.ensureLoaded();
    return { ...this.data };
  }

  /** Write current data to file (encrypt if password is set) using protobuf storage. Atomic via tmp+rename. */
  async write(): Promise<void> {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const tmpPath = this.filePath + '.tmp';
    const protoBuf = encodeKeystoreData(this.data);
    if (this.password) {
      const plaintext = protoBuf.toString('base64');
      const payload = await encrypt(plaintext, this.password);
      fs.writeFileSync(tmpPath, JSON.stringify(payload, null, 2), 'utf8');
    } else {
      fs.writeFileSync(tmpPath, protoBuf);
    }
    fs.renameSync(tmpPath, this.filePath);
    logger.info({ filePath: this.filePath, keys: Object.keys(this.data).length, encrypted: Boolean(this.password) }, 'keystore: write ok');
  }

  static async fromFile(filePath: string, password?: string): Promise<KeystoreData> {
    const ks = new Keystore({ filePath, password });
    return ks.read();
  }

  static async toFile(filePath: string, data: KeystoreData, password?: string): Promise<void> {
    const ks = new Keystore({ filePath, password });
    ks.data = { ...data };
    ks.loaded = true;
    await ks.write();
  }
}

