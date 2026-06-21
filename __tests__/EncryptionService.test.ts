import { describe, it, expect, beforeEach, jest, afterEach } from '@jest/globals';
import crypto from 'crypto';
import { EncryptionService } from '../api/services/EncryptionService.js';
import * as ConfigRepoModule from '../api/repositories/ConfigRepository.js';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

const TEST_KEY_BASE64 = crypto.randomBytes(KEY_LENGTH).toString('base64');

interface MockState {
  encryptionKey: string;
  getAllProjectsFn: () => Promise<unknown[]>;
}

let mockState: MockState;
let spyGetEncryptionKey: jest.SpiedFunction<
  typeof ConfigRepoModule.configRepository.getEncryptionKey
>;
let spySetEncryptionKey: jest.SpiedFunction<
  typeof ConfigRepoModule.configRepository.setEncryptionKey
>;
let spyGetAllProjects: jest.SpiedFunction<
  typeof ConfigRepoModule.configRepository.getAllProjects
>;

function setupMocks() {
  mockState = {
    encryptionKey: '',
    getAllProjectsFn: async () => [],
  };

  spyGetEncryptionKey = jest
    .spyOn(ConfigRepoModule.configRepository, 'getEncryptionKey')
    .mockImplementation(async () => mockState.encryptionKey);

  spySetEncryptionKey = jest
    .spyOn(ConfigRepoModule.configRepository, 'setEncryptionKey')
    .mockImplementation(async (key: string) => {
      mockState.encryptionKey = key;
    });

  spyGetAllProjects = jest
    .spyOn(ConfigRepoModule.configRepository, 'getAllProjects')
    .mockImplementation(async () => mockState.getAllProjectsFn());
}

function teardownMocks() {
  spyGetEncryptionKey?.mockRestore();
  spySetEncryptionKey?.mockRestore();
  spyGetAllProjects?.mockRestore();
}

describe('EncryptionService - Key Management', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  it('should auto-generate and persist a new key when none exists', async () => {
    expect(mockState.encryptionKey).toBe('');

    const service = new EncryptionService();
    const result = await service.encrypt('test');

    expect(result.encrypted).toBeDefined();
    expect(result.iv).toBeDefined();
    expect(result.tag).toBeDefined();
    expect(mockState.encryptionKey).not.toBe('');

    const decodedKey = Buffer.from(mockState.encryptionKey, 'base64');
    expect(decodedKey.length).toBe(KEY_LENGTH);
    expect(spySetEncryptionKey).toHaveBeenCalled();
  });

  it('should reuse existing key across multiple encrypt/decrypt calls', async () => {
    mockState.encryptionKey = TEST_KEY_BASE64;

    const service = new EncryptionService();
    const result1 = await service.encrypt('hello');
    const result2 = await service.encrypt('world');

    expect(mockState.encryptionKey).toBe(TEST_KEY_BASE64);
    expect(spySetEncryptionKey).not.toHaveBeenCalled();

    const decrypted1 = await service.decrypt(result1.encrypted, result1.iv, result1.tag);
    const decrypted2 = await service.decrypt(result2.encrypted, result2.iv, result2.tag);

    expect(decrypted1).toBe('hello');
    expect(decrypted2).toBe('world');
  });
});

describe('EncryptionService - Basic Encrypt/Decrypt', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    mockState.encryptionKey = TEST_KEY_BASE64;
  });

  it('should encrypt and decrypt ASCII text correctly', async () => {
    const service = new EncryptionService();
    const plaintext = 'Hello, World! 12345';
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should encrypt and decrypt empty string correctly', async () => {
    const service = new EncryptionService();
    const plaintext = '';
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should produce different ciphertext for same plaintext (random IV)', async () => {
    const service = new EncryptionService();
    const plaintext = 'consistent text';

    const result1 = await service.encrypt(plaintext);
    const result2 = await service.encrypt(plaintext);

    expect(result1.encrypted).not.toBe(result2.encrypted);
    expect(result1.iv).not.toBe(result2.iv);
    expect(result1.tag).not.toBe(result2.tag);

    const decrypt1 = await service.decrypt(result1.encrypted, result1.iv, result1.tag);
    const decrypt2 = await service.decrypt(result2.encrypted, result2.iv, result2.tag);

    expect(decrypt1).toBe(plaintext);
    expect(decrypt2).toBe(plaintext);
  });

  it('should return valid base64 strings for encrypted, iv, and tag', async () => {
    const service = new EncryptionService();
    const result = await service.encrypt('test data');

    const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;

    expect(result.encrypted).toMatch(base64Regex);
    expect(result.iv).toMatch(base64Regex);
    expect(result.tag).toMatch(base64Regex);

    expect(Buffer.from(result.iv, 'base64').length).toBe(IV_LENGTH);
    expect(Buffer.from(result.tag, 'base64').length).toBe(16);
  });
});

describe('EncryptionService - Special Character Handling', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    mockState.encryptionKey = TEST_KEY_BASE64;
  });

  it('should handle Chinese text correctly', async () => {
    const service = new EncryptionService();
    const plaintext = '数据库密码：配置中心管理系统测试数据！@#￥%……&*';
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should handle mixed Chinese and English text', async () => {
    const service = new EncryptionService();
    const plaintext = 'API Key: sk-abc123def456 这是一个混合中英文的测试配置值 Value@2024';
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should handle emoji characters correctly', async () => {
    const service = new EncryptionService();
    const plaintext = '🎉 Welcome! 🔐 Security Enabled 🔥💯✅ 中文表情😊';
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should handle all special ASCII symbols', async () => {
    const service = new EncryptionService();
    const plaintext = '!@#$%^&*()_+-=[]{}|;\':",./<>?`~\\ \t\n\r';
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should handle Unicode supplementary characters (emoji with ZWJ)', async () => {
    const service = new EncryptionService();
    const plaintext = '👨‍👩‍👧‍👦 Family Emoji + 🧑🏽‍💻 Developer with Skin Tone';
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should handle binary-like strings with null bytes and control chars', async () => {
    const service = new EncryptionService();
    const chars: string[] = [];
    for (let i = 0; i < 128; i++) {
      chars.push(String.fromCharCode(i));
    }
    const plaintext = chars.join('');
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });
});

describe('EncryptionService - Long Text Handling', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    mockState.encryptionKey = TEST_KEY_BASE64;
  });

  function generateLongText(length: number, charset = 'abcdefghijklmnopqrstuvwxyz'): string {
    let result = '';
    for (let i = 0; i < length; i++) {
      result += charset[i % charset.length];
    }
    return result;
  }

  it('should handle 1KB text', async () => {
    const service = new EncryptionService();
    const plaintext = generateLongText(1024);
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
    expect(decrypted.length).toBe(1024);
  });

  it('should handle 10KB text', async () => {
    const service = new EncryptionService();
    const plaintext = generateLongText(10 * 1024);
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should handle 100KB text', async () => {
    const service = new EncryptionService();
    const plaintext = generateLongText(100 * 1024);
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
  });

  it('should handle 1MB text (large config)', async () => {
    const service = new EncryptionService();
    const plaintext = generateLongText(1024 * 1024, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789中文测试😊');
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
    expect(decrypted.length).toBe(plaintext.length);
  }, 30000);

  it('should handle JSON-like long structured data', async () => {
    const service = new EncryptionService();
    const jsonObj: Record<string, unknown> = {
      configs: Array.from({ length: 1000 }, (_, i) => ({
        key: `KEY_${i}`,
        value: `value_${i}_${crypto.randomBytes(20).toString('hex')}`,
        description: `这是第${i}个配置项的描述信息，包含中文内容`,
      })),
    };
    const plaintext = JSON.stringify(jsonObj);
    const result = await service.encrypt(plaintext);
    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);

    expect(decrypted).toBe(plaintext);
    expect(JSON.parse(decrypted)).toEqual(jsonObj);
  });
});

describe('EncryptionService - Error Handling', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    mockState.encryptionKey = TEST_KEY_BASE64;
  });

  it('should throw when decrypting with wrong key', async () => {
    const service = new EncryptionService();
    const plaintext = 'sensitive data';
    const result = await service.encrypt(plaintext);

    mockState.encryptionKey = crypto.randomBytes(KEY_LENGTH).toString('base64');

    await expect(
      service.decrypt(result.encrypted, result.iv, result.tag)
    ).rejects.toThrow();
  });

  it('should throw when decrypting with tampered ciphertext', async () => {
    const service = new EncryptionService();
    const plaintext = 'secret value';
    const result = await service.encrypt(plaintext);

    const encryptedBuf = Buffer.from(result.encrypted, 'base64');
    encryptedBuf[0] ^= 0xFF;
    const tamperedEncrypted = encryptedBuf.toString('base64');

    await expect(
      service.decrypt(tamperedEncrypted, result.iv, result.tag)
    ).rejects.toThrow();
  });

  it('should throw when decrypting with wrong IV', async () => {
    const service = new EncryptionService();
    const result1 = await service.encrypt('data1');
    const result2 = await service.encrypt('data2');

    await expect(
      service.decrypt(result1.encrypted, result2.iv, result1.tag)
    ).rejects.toThrow();
  });

  it('should throw when decrypting with wrong auth tag', async () => {
    const service = new EncryptionService();
    const result1 = await service.encrypt('data1');
    const result2 = await service.encrypt('data2');

    await expect(
      service.decrypt(result1.encrypted, result1.iv, result2.tag)
    ).rejects.toThrow();
  });

  it('should throw when decrypting with invalid base64 encrypted data', async () => {
    const service = new EncryptionService();
    const validIV = crypto.randomBytes(IV_LENGTH).toString('base64');
    const validTag = crypto.randomBytes(16).toString('base64');

    await expect(
      service.decrypt('!!!not-valid-base64!!!', validIV, validTag)
    ).rejects.toThrow();
  });

  it('should throw when decrypting with invalid base64 IV', async () => {
    const service = new EncryptionService();
    const result = await service.encrypt('test');

    await expect(
      service.decrypt(result.encrypted, '!!!invalid!!!', result.tag)
    ).rejects.toThrow();
  });

  it('should throw when decrypting with invalid base64 tag', async () => {
    const service = new EncryptionService();
    const result = await service.encrypt('test');

    await expect(
      service.decrypt(result.encrypted, result.iv, '!!!invalid!!!')
    ).rejects.toThrow();
  });

  it('should throw when IV has incorrect length', async () => {
    const service = new EncryptionService();
    const result = await service.encrypt('test');

    const shortIV = crypto.randomBytes(8).toString('base64');

    await expect(
      service.decrypt(result.encrypted, shortIV, result.tag)
    ).rejects.toThrow();
  });

  it('should throw when decrypting random empty ciphertext with mismatched auth tag', async () => {
    const service = new EncryptionService();
    const validIV = crypto.randomBytes(IV_LENGTH).toString('base64');
    const randomTag = crypto.randomBytes(16).toString('base64');

    await expect(
      service.decrypt('', validIV, randomTag)
    ).rejects.toThrow();
  });
});

describe('EncryptionService - Key Rotation Scenarios', () => {
  let oldKey: string;
  let newKey: string;

  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    oldKey = crypto.randomBytes(KEY_LENGTH).toString('base64');
    newKey = crypto.randomBytes(KEY_LENGTH).toString('base64');
    mockState.encryptionKey = oldKey;
  });

  it('should decrypt data encrypted with old key after switching back to old key', async () => {
    const service = new EncryptionService();
    const oldPlaintext = 'old sensitive config value';
    const oldEncrypted = await service.encrypt(oldPlaintext);

    mockState.encryptionKey = newKey;
    const newPlaintext = 'new sensitive config value';
    const newEncrypted = await service.encrypt(newPlaintext);

    mockState.encryptionKey = oldKey;
    const decryptedOld = await service.decrypt(
      oldEncrypted.encrypted,
      oldEncrypted.iv,
      oldEncrypted.tag
    );
    expect(decryptedOld).toBe(oldPlaintext);

    mockState.encryptionKey = newKey;
    const decryptedNew = await service.decrypt(
      newEncrypted.encrypted,
      newEncrypted.iv,
      newEncrypted.tag
    );
    expect(decryptedNew).toBe(newPlaintext);
  });

  it('should fail when attempting to decrypt old data with new key (requires re-encryption)', async () => {
    const service = new EncryptionService();
    const oldPlaintext = 'data before rotation';
    const oldEncrypted = await service.encrypt(oldPlaintext);

    mockState.encryptionKey = newKey;

    await expect(
      service.decrypt(oldEncrypted.encrypted, oldEncrypted.iv, oldEncrypted.tag)
    ).rejects.toThrow();
  });

  it('should support manual key rotation: decrypt with old, re-encrypt with new', async () => {
    const service = new EncryptionService();
    const plaintext = 'config_value_that_needs_key_rotation';
    const oldEncrypted = await service.encrypt(plaintext);

    mockState.encryptionKey = oldKey;
    const decrypted = await service.decrypt(
      oldEncrypted.encrypted,
      oldEncrypted.iv,
      oldEncrypted.tag
    );
    expect(decrypted).toBe(plaintext);

    mockState.encryptionKey = newKey;
    const reEncrypted = await service.encrypt(decrypted);
    const reDecrypted = await service.decrypt(
      reEncrypted.encrypted,
      reEncrypted.iv,
      reEncrypted.tag
    );

    expect(reDecrypted).toBe(plaintext);
    expect(reEncrypted.encrypted).not.toBe(oldEncrypted.encrypted);
    expect(reEncrypted.iv).not.toBe(oldEncrypted.iv);
    expect(reEncrypted.tag).not.toBe(oldEncrypted.tag);
  });

  it('should use new key for all new encryptions after rotation', async () => {
    const service = new EncryptionService();
    const oldEncrypted = await service.encrypt('before rotation');

    mockState.encryptionKey = newKey;

    const result1 = await service.encrypt('new data 1');
    const result2 = await service.encrypt('new data 2');

    expect(mockState.encryptionKey).toBe(newKey);

    const decrypted1 = await service.decrypt(result1.encrypted, result1.iv, result1.tag);
    const decrypted2 = await service.decrypt(result2.encrypted, result2.iv, result2.tag);

    expect(decrypted1).toBe('new data 1');
    expect(decrypted2).toBe('new data 2');

    mockState.encryptionKey = oldKey;
    const decryptedOld = await service.decrypt(
      oldEncrypted.encrypted,
      oldEncrypted.iv,
      oldEncrypted.tag
    );
    expect(decryptedOld).toBe('before rotation');
  });
});

describe('EncryptionService - Concurrent Operations', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    mockState.encryptionKey = TEST_KEY_BASE64;
  });

  it('should handle 10 concurrent encrypt calls correctly', async () => {
    const service = new EncryptionService();
    const plaintexts = Array.from({ length: 10 }, (_, i) => `concurrent_data_${i}`);

    const encryptedResults = await Promise.all(
      plaintexts.map((p) => service.encrypt(p))
    );

    const decryptedResults = await Promise.all(
      encryptedResults.map((r, i) =>
        service.decrypt(r.encrypted, r.iv, r.tag)
      )
    );

    expect(decryptedResults).toEqual(plaintexts);
  });

  it('should handle 50 concurrent encrypt/decrypt operations without corruption', async () => {
    const service = new EncryptionService();
    const operations = Array.from({ length: 50 }, async (_, i) => {
      const plaintext = `op_${i}_${crypto.randomBytes(16).toString('hex')}`;
      const enc = await service.encrypt(plaintext);
      const dec = await service.decrypt(enc.encrypted, enc.iv, enc.tag);
      return { expected: plaintext, actual: dec };
    });

    const results = await Promise.all(operations);

    for (const r of results) {
      expect(r.actual).toBe(r.expected);
    }
  });

  it('should handle concurrent decrypt calls with different data', async () => {
    const service = new EncryptionService();

    const preEncrypted = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        service.encrypt(`pre_enc_data_${i}_${crypto.randomUUID()}`)
      )
    );

    const concurrentDecrypt = await Promise.all(
      preEncrypted.map((r, i) => ({
        index: i,
        decryptPromise: service.decrypt(r.encrypted, r.iv, r.tag),
      })).map(async (item) => ({
        index: item.index,
        result: await item.decryptPromise,
      }))
    );

    for (const cd of concurrentDecrypt) {
      expect(cd.result).toMatch(new RegExp(`^pre_enc_data_${cd.index}_`));
    }
  });

  it('should handle mixed concurrent encrypt and decrypt operations', async () => {
    const service = new EncryptionService();
    const preEncryptedPairs: Array<{
      plaintext: string;
      encrypted: { encrypted: string; iv: string; tag: string };
    }> = [];

    for (let i = 0; i < 10; i++) {
      const plaintext = `existing_${i}`;
      preEncryptedPairs.push({
        plaintext,
        encrypted: await service.encrypt(plaintext),
      });
    }

    const operations: Promise<boolean>[] = [];

    for (let i = 0; i < 15; i++) {
      operations.push(
        (async () => {
          const plaintext = `new_enc_${i}_${Date.now()}`;
          const enc = await service.encrypt(plaintext);
          const dec = await service.decrypt(enc.encrypted, enc.iv, enc.tag);
          return dec === plaintext;
        })()
      );
    }

    for (const pair of preEncryptedPairs) {
      operations.push(
        service
          .decrypt(pair.encrypted.encrypted, pair.encrypted.iv, pair.encrypted.tag)
          .then((d) => d === pair.plaintext)
      );
    }

    const results = await Promise.all(operations);
    expect(results.every((r) => r)).toBe(true);
  }, 15000);
});

describe('EncryptionService - Security and Correctness', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    mockState.encryptionKey = TEST_KEY_BASE64;
  });

  it('should use AES-256-GCM algorithm with correct parameters', async () => {
    const service = new EncryptionService();
    const plaintext = 'verify algorithm';
    const result = await service.encrypt(plaintext);

    const key = Buffer.from(mockState.encryptionKey, 'base64');
    const iv = Buffer.from(result.iv, 'base64');
    const tag = Buffer.from(result.tag, 'base64');

    expect(key.length).toBe(32);
    expect(iv.length).toBe(16);
    expect(tag.length).toBe(16);

    const decrypted = await service.decrypt(result.encrypted, result.iv, result.tag);
    expect(decrypted).toBe(plaintext);
  });

  it('should have consistent encryption/decryption timing (no obvious timing attack)', async () => {
    const service = new EncryptionService();
    const shortPlaintext = 'x';
    const longPlaintext = crypto.randomBytes(100000).toString('base64');

    await service.encrypt('warmup');
    await service.decrypt(...Object.values(await service.encrypt('warmup')));

    const encryptTimingsShort: number[] = [];
    const encryptTimingsLong: number[] = [];

    for (let i = 0; i < 20; i++) {
      const startShort = process.hrtime.bigint();
      await service.encrypt(shortPlaintext);
      encryptTimingsShort.push(Number(process.hrtime.bigint() - startShort));

      const startLong = process.hrtime.bigint();
      await service.encrypt(longPlaintext);
      encryptTimingsLong.push(Number(process.hrtime.bigint() - startLong));
    }

    const avgShort =
      encryptTimingsShort.reduce((a, b) => a + b, 0) / encryptTimingsShort.length;
    const avgLong =
      encryptTimingsLong.reduce((a, b) => a + b, 0) / encryptTimingsLong.length;

    expect(avgLong).toBeGreaterThan(avgShort);

    const shortVariance =
      encryptTimingsShort.reduce((sum, t) => sum + Math.pow(t - avgShort, 2), 0) /
      encryptTimingsShort.length;
    const shortStdDev = Math.sqrt(shortVariance);

    expect(shortStdDev / avgShort).toBeLessThan(5.0);
  }, 30000);

  it('should detect single-bit tampering anywhere in ciphertext', async () => {
    const service = new EncryptionService();
    const plaintext = 'tamper detection test with enough data';
    const result = await service.encrypt(plaintext);

    const encryptedBytes = Buffer.from(result.encrypted, 'base64');

    for (let byteIdx = 0; byteIdx < Math.min(encryptedBytes.length, 50); byteIdx++) {
      for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
        const tampered = Buffer.from(encryptedBytes);
        tampered[byteIdx] ^= 1 << bitIdx;
        const tamperedBase64 = tampered.toString('base64');

        await expect(
          service.decrypt(tamperedBase64, result.iv, result.tag)
        ).rejects.toThrow();
      }
    }
  }, 30000);

  it('should detect IV tampering (single bit flip)', async () => {
    const service = new EncryptionService();
    const result = await service.encrypt('iv tamper test');

    const ivBytes = Buffer.from(result.iv, 'base64');

    const tampered = Buffer.from(ivBytes);
    tampered[0] ^= 0x01;
    const tamperedIV = tampered.toString('base64');

    await expect(
      service.decrypt(result.encrypted, tamperedIV, result.tag)
    ).rejects.toThrow();
  });

  it('should detect tag tampering (single bit flip)', async () => {
    const service = new EncryptionService();
    const result = await service.encrypt('tag tamper test');

    const tagBytes = Buffer.from(result.tag, 'base64');
    const tampered = Buffer.from(tagBytes);
    tampered[0] ^= 0x80;
    const tamperedTag = tampered.toString('base64');

    await expect(
      service.decrypt(result.encrypted, result.iv, tamperedTag)
    ).rejects.toThrow();
  });

  it('should handle high-entropy random input data correctly', async () => {
    const service = new EncryptionService();

    for (let i = 0; i < 50; i++) {
      const randomData = crypto.randomBytes(256).toString('base64');
      const enc = await service.encrypt(randomData);
      const dec = await service.decrypt(enc.encrypted, enc.iv, enc.tag);
      expect(dec).toBe(randomData);
    }
  });
});

describe('EncryptionService - getEncryptionStatus', () => {
  beforeEach(setupMocks);
  afterEach(teardownMocks);

  beforeEach(() => {
    mockState.encryptionKey = TEST_KEY_BASE64;
  });

  it('should return empty array when no projects exist', async () => {
    mockState.getAllProjectsFn = async () => [];
    const service = new EncryptionService();
    const status = await service.getEncryptionStatus();
    expect(status).toEqual([]);
  });

  it('should return status for all config items across projects', async () => {
    mockState.getAllProjectsFn = async () => [
      {
        name: 'project1',
        environments: [
          {
            name: 'dev',
            configs: [
              { key: 'DB_HOST', value: 'localhost', encrypted: false },
              { key: 'DB_PASS', value: 'enc_val', encrypted: true, iv: 'iv1', tag: 'tag1' },
            ],
          },
          {
            name: 'prod',
            configs: [
              { key: 'API_KEY', value: 'enc_key', encrypted: true, iv: 'iv2', tag: 'tag2' },
            ],
          },
        ],
      },
      {
        name: 'project2',
        environments: [
          {
            name: 'staging',
            configs: [
              { key: 'SECRET', value: 'val', encrypted: false },
            ],
          },
        ],
      },
    ];

    const service = new EncryptionService();
    const status = await service.getEncryptionStatus();

    expect(status).toEqual([
      { project: 'project1', environment: 'dev', key: 'DB_HOST', encrypted: false },
      { project: 'project1', environment: 'dev', key: 'DB_PASS', encrypted: true },
      { project: 'project1', environment: 'prod', key: 'API_KEY', encrypted: true },
      { project: 'project2', environment: 'staging', key: 'SECRET', encrypted: false },
    ]);
  });
});
