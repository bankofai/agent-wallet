import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Keystore } from '../src/keystore/keystore';
import { encrypt, decrypt, isEncryptedPayload } from '../src/keystore/keystore_crypto';
import { encodeKeystoreData, decodeKeystoreData } from '../src/keystore/keystore_proto';

// ---------- helpers ----------

let tmpDir: string;

function tmpFile(name: string): string {
  return path.join(tmpDir, name);
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ks-test-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ============================================================
// Protobuf encode / decode
// ============================================================

describe('keystore_proto', () => {
  it('should roundtrip encode and decode an empty map', () => {
    const buf = encodeKeystoreData({});
    expect(buf.length).toBe(0);
    expect(decodeKeystoreData(buf)).toEqual({});
  });

  it('should roundtrip encode and decode a single entry', () => {
    const data = { privateKey: 'abc123' };
    const buf = encodeKeystoreData(data);
    expect(buf.length).toBeGreaterThan(0);
    expect(decodeKeystoreData(buf)).toEqual(data);
  });

  it('should roundtrip encode and decode multiple entries', () => {
    const data = {
      privateKey: 'deadbeef',
      apiKey: 'my-api-key',
      secretKey: 'super-secret',
      address: 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb',
    };
    const buf = encodeKeystoreData(data);
    expect(decodeKeystoreData(buf)).toEqual(data);
  });

  it('should handle unicode values', () => {
    const data = { note: 'hello world \u{1f600}', key: '\u00e9\u00e8\u00ea' };
    const buf = encodeKeystoreData(data);
    expect(decodeKeystoreData(buf)).toEqual(data);
  });

  it('should throw on truncated buffer', () => {
    const data = { key: 'value' };
    const buf = encodeKeystoreData(data);
    const truncated = buf.subarray(0, buf.length - 3);
    expect(() => decodeKeystoreData(truncated)).toThrow();
  });
});

// ============================================================
// Crypto encrypt / decrypt
// ============================================================

describe('keystore_crypto', () => {
  it('should encrypt and decrypt a plaintext string', async () => {
    const plaintext = 'hello world';
    const password = 'test-password';
    const payload = await encrypt(plaintext, password);
    expect(isEncryptedPayload(payload)).toBe(true);
    expect(payload.version).toBe(1);
    const result = await decrypt(payload, password);
    expect(result).toBe(plaintext);
  });

  it('should fail to decrypt with wrong password', async () => {
    const payload = await encrypt('secret', 'correct-password');
    await expect(decrypt(payload, 'wrong-password')).rejects.toThrow();
  });

  it('should produce different ciphertext for same plaintext (random salt/iv)', async () => {
    const plaintext = 'same input';
    const password = 'pw';
    const a = await encrypt(plaintext, password);
    const b = await encrypt(plaintext, password);
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    // but both decrypt to same value
    expect(await decrypt(a, password)).toBe(plaintext);
    expect(await decrypt(b, password)).toBe(plaintext);
  });

  it('isEncryptedPayload should reject non-payloads', () => {
    expect(isEncryptedPayload(null)).toBeFalsy();
    expect(isEncryptedPayload(42)).toBeFalsy();
    expect(isEncryptedPayload({})).toBeFalsy();
    expect(isEncryptedPayload({ version: 2, salt: '', iv: '', tag: '', data: '' })).toBeFalsy();
    expect(isEncryptedPayload({ version: 1, salt: 'a', iv: 'b', tag: 'c', data: 'd' })).toBe(true);
  });
});

// ============================================================
// Keystore class — unencrypted (protobuf)
// ============================================================

describe('Keystore (unencrypted)', () => {
  it('should read empty data when file does not exist', async () => {
    const ks = new Keystore({ filePath: tmpFile('nonexistent') });
    const data = await ks.read();
    expect(data).toEqual({});
  });

  it('should write and read back data in protobuf format', async () => {
    const fp = tmpFile('ks1');
    const ks = new Keystore({ filePath: fp });
    await ks.read();
    await ks.set('privateKey', 'abc');
    await ks.set('apiKey', 'xyz');
    await ks.write();

    // File should be binary protobuf, not JSON
    const raw = fs.readFileSync(fp);
    expect(() => JSON.parse(raw.toString('utf8'))).toThrow(); // not valid JSON

    // Read back with a fresh instance
    const ks2 = new Keystore({ filePath: fp });
    const data = await ks2.read();
    expect(data).toEqual({ privateKey: 'abc', apiKey: 'xyz' });
  });

  it('should preserve existing data when set() is called without prior read()', async () => {
    const fp = tmpFile('ks-preserve');
    await Keystore.toFile(fp, { existingKey: 'existingVal' });

    // set without explicit read — should auto-load
    const ks = new Keystore({ filePath: fp });
    await ks.set('newKey', 'newVal');
    await ks.write();

    const all = await Keystore.fromFile(fp);
    expect(all).toEqual({ existingKey: 'existingVal', newKey: 'newVal' });
  });

  it('get() should return undefined for missing key', async () => {
    const fp = tmpFile('ks-get');
    await Keystore.toFile(fp, { a: '1' });
    const ks = new Keystore({ filePath: fp });
    expect(await ks.get('a')).toBe('1');
    expect(await ks.get('b')).toBeUndefined();
  });

  it('keys() should return all key names', async () => {
    const fp = tmpFile('ks-keys');
    await Keystore.toFile(fp, { x: '1', y: '2', z: '3' });
    const ks = new Keystore({ filePath: fp });
    expect((await ks.keys()).sort()).toEqual(['x', 'y', 'z']);
  });

  it('getAll() should return a copy that does not affect internal state', async () => {
    const fp = tmpFile('ks-copy');
    await Keystore.toFile(fp, { k: 'v' });
    const ks = new Keystore({ filePath: fp });
    const snapshot = await ks.getAll();
    snapshot['k'] = 'modified';
    expect(await ks.get('k')).toBe('v'); // internal state unchanged
  });

  it('read() should return a copy that does not affect internal state', async () => {
    const fp = tmpFile('ks-readcopy');
    await Keystore.toFile(fp, { k: 'v' });
    const ks = new Keystore({ filePath: fp });
    const data = await ks.read();
    data['k'] = 'modified';
    expect(await ks.get('k')).toBe('v');
  });

  it('write should be atomic (tmp + rename)', async () => {
    const fp = tmpFile('ks-atomic');
    await Keystore.toFile(fp, { a: 'b' });
    // After write, no .tmp file should remain
    expect(fs.existsSync(fp + '.tmp')).toBe(false);
    expect(fs.existsSync(fp)).toBe(true);
  });

  it('should create parent directories on write', async () => {
    const fp = path.join(tmpDir, 'deep', 'nested', 'Keystore');
    await Keystore.toFile(fp, { k: 'v' });
    expect(fs.existsSync(fp)).toBe(true);
    expect(await Keystore.fromFile(fp)).toEqual({ k: 'v' });
  });
});

// ============================================================
// Keystore class — encrypted
// ============================================================

describe('Keystore (encrypted)', () => {
  it('should write and read encrypted keystore', async () => {
    const fp = tmpFile('ks-enc');
    const pw = 'my-password';
    await Keystore.toFile(fp, { secret: 'treasure' }, pw);

    // File should be valid JSON (encrypted payload)
    const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
    expect(isEncryptedPayload(raw)).toBe(true);

    // Read back with correct password
    const data = await Keystore.fromFile(fp, pw);
    expect(data).toEqual({ secret: 'treasure' });
  });

  it('should fail to read encrypted keystore without password', async () => {
    const fp = tmpFile('ks-enc-nopw');
    await Keystore.toFile(fp, { a: 'b' }, 'pw');
    const ks = new Keystore({ filePath: fp });
    await expect(ks.read()).rejects.toThrow(/no password provided/);
  });

  it('should fail to read encrypted keystore with wrong password', async () => {
    const fp = tmpFile('ks-enc-wrong');
    await Keystore.toFile(fp, { a: 'b' }, 'correct');
    const ks = new Keystore({ filePath: fp, password: 'wrong' });
    await expect(ks.read()).rejects.toThrow();
  });

  it('should roundtrip multiple entries through encryption', async () => {
    const fp = tmpFile('ks-enc-multi');
    const pw = 'complex-pw-123!';
    const original = {
      privateKey: 'deadbeefdeadbeef',
      apiKey: 'ak-123456',
      secretKey: 'sk-abcdef',
      address: 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb',
    };
    await Keystore.toFile(fp, original, pw);
    const result = await Keystore.fromFile(fp, pw);
    expect(result).toEqual(original);
  });

  it('set + write should preserve encryption', async () => {
    const fp = tmpFile('ks-enc-set');
    const pw = 'pw';
    await Keystore.toFile(fp, { a: '1' }, pw);

    const ks = new Keystore({ filePath: fp, password: pw });
    await ks.read();
    await ks.set('b', '2');
    await ks.write();

    const data = await Keystore.fromFile(fp, pw);
    expect(data).toEqual({ a: '1', b: '2' });

    // File should still be encrypted
    const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
    expect(isEncryptedPayload(raw)).toBe(true);
  });
});

// ============================================================
// Keystore — legacy JSON backward compatibility
// ============================================================

describe('Keystore (legacy JSON compat)', () => {
  it('should read a legacy unencrypted JSON file', async () => {
    const fp = tmpFile('ks-legacy');
    fs.writeFileSync(fp, JSON.stringify({ oldKey: 'oldVal' }), 'utf8');
    const ks = new Keystore({ filePath: fp });
    const data = await ks.read();
    expect(data).toEqual({ oldKey: 'oldVal' });
  });

  it('should overwrite legacy JSON with protobuf on write', async () => {
    const fp = tmpFile('ks-legacy-overwrite');
    fs.writeFileSync(fp, JSON.stringify({ a: '1' }), 'utf8');

    const ks = new Keystore({ filePath: fp });
    await ks.read();
    await ks.set('b', '2');
    await ks.write();

    // Now the file should be protobuf (not JSON)
    const raw = fs.readFileSync(fp);
    expect(() => JSON.parse(raw.toString('utf8'))).toThrow();

    // But data is preserved
    const result = await Keystore.fromFile(fp);
    expect(result).toEqual({ a: '1', b: '2' });
  });
});
