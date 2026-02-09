import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LEN = 32;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

export interface EncryptedPayload {
  version: number;
  salt: string;
  iv: string;
  tag: string;
  data: string;
}

/**
 * Derive key from password using scrypt
 */
function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/**
 * Encrypt plaintext with password. Returns payload with salt, iv, tag, data (all hex/base64).
 */
export async function encrypt(plaintext: string, password: string): Promise<EncryptedPayload> {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = await deriveKey(password, salt);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    version: 1,
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: enc.toString('base64')
  };
}

/**
 * Decrypt payload with password. Returns plaintext string.
 */
export async function decrypt(payload: EncryptedPayload, password: string): Promise<string> {
  const key = await deriveKey(password, Buffer.from(payload.salt, 'hex'));
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(payload.iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(payload.tag, 'hex'));
  return decipher.update(payload.data, 'base64', 'utf8') + decipher.final('utf8');
}

/**
 * Check if a JSON object looks like an encrypted payload (has version, salt, iv, tag, data).
 */
export function isEncryptedPayload(obj: unknown): obj is EncryptedPayload {
  const o = obj as Record<string, unknown>;
  return (
    o &&
    typeof o === 'object' &&
    o.version === 1 &&
    typeof o.salt === 'string' &&
    typeof o.iv === 'string' &&
    typeof o.tag === 'string' &&
    typeof o.data === 'string'
  );
}
