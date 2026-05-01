import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  base32Decode,
  base32Encode,
  buildMigrationUrl,
  buildMigrationUrls,
  formatCode,
  hotp,
  parseOtpAuth,
  parseOtpAuthMigration,
  totp,
} from "../src/core/totp.js";

function asciiBytes(text) {
  return new TextEncoder().encode(text);
}

function encodeVarint(value) {
  let current = BigInt(value);
  const out = [];
  while (current >= 0x80n) {
    out.push(Number((current & 0x7fn) | 0x80n));
    current >>= 7n;
  }
  out.push(Number(current));
  return out;
}

function encodeKey(tag, wireType) {
  return encodeVarint((tag << 3) | wireType);
}

function encodeBytesField(tag, bytes) {
  return [...encodeKey(tag, 2), ...encodeVarint(bytes.length), ...bytes];
}

function encodeStringField(tag, text) {
  return encodeBytesField(tag, asciiBytes(text));
}

function encodeVarintField(tag, value) {
  return [...encodeKey(tag, 0), ...encodeVarint(value)];
}

function bytesToB64url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function buildMigrationData(items) {
  const payload = [];
  for (const item of items) {
    const otp = [
      ...encodeBytesField(1, item.secretBytes),
      ...encodeStringField(2, item.name),
      ...encodeStringField(3, item.issuer),
      ...encodeVarintField(4, item.algorithm),
      ...encodeVarintField(5, item.digits),
      ...encodeVarintField(6, item.type),
    ];
    if (item.counter !== undefined) otp.push(...encodeVarintField(7, item.counter));
    payload.push(...encodeBytesField(1, otp));
  }
  return bytesToB64url(payload);
}

// 解析 otpauth-migration:// URL，独立解码出 GA 必需的 batch 元数据。
// 这是与 src/core/totp.js 完全独立的实现，所以能验证我们生成的字节真的合规。
function extractMigrationMeta(uri) {
  const u = new URL(uri);
  const dataParam = u.searchParams.get("data") || "";
  // 兼容 URL-safe / 标准两种 base64
  let s = dataParam.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (s.length % 4)) % 4;
  if (pad) s += "=".repeat(pad);
  const bytes = Uint8Array.from(Buffer.from(s, "base64"));

  let p = 0;
  const out = { version: null, batchSize: null, batchIndex: null, batchId: null, otpCount: 0 };
  function readVarint() {
    let x = 0n, shift = 0n;
    while (p < bytes.length) {
      const b = BigInt(bytes[p++]);
      x |= (b & 0x7fn) << shift;
      if ((b & 0x80n) === 0n) break;
      shift += 7n;
    }
    return Number(x);
  }
  while (p < bytes.length) {
    const key = readVarint();
    const tag = key >>> 3;
    const wt = key & 7;
    if (tag === 1 && wt === 2) {
      const len = readVarint();
      p += len; // 跳过 OtpParameters
      out.otpCount++;
    } else if (tag === 2 && wt === 0) out.version = readVarint();
    else if (tag === 3 && wt === 0) out.batchSize = readVarint();
    else if (tag === 4 && wt === 0) out.batchIndex = readVarint();
    else if (tag === 5 && wt === 0) out.batchId = readVarint();
    else if (wt === 2) { const len = readVarint(); p += len; }
    else if (wt === 0) readVarint();
    else break;
  }
  return out;
}

describe("base32", () => {
  it("round-trips bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 254, 255, 128]);
    expect(base32Decode(base32Encode(bytes))).toEqual(bytes);
  });

  it("ignores padding and whitespace", () => {
    expect(base32Decode("JBSW Y3DP====")).toEqual(asciiBytes("Hello"));
  });
});

describe("hotp/totp vectors", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("matches RFC 4226 HOTP vectors", async () => {
    const secret = asciiBytes("12345678901234567890");
    const expected = [
      "755224",
      "287082",
      "359152",
      "969429",
      "338314",
      "254676",
      "287922",
      "162583",
      "399871",
      "520489",
    ];

    for (const [counter, code] of expected.entries()) {
      await expect(hotp(secret, counter, "SHA-1", 6)).resolves.toBe(code);
    }
  });

  it("matches RFC 6238 TOTP vectors across algorithms", async () => {
    const cases = [
      { timestamp: 59_000, algorithm: "SHA1", secret: "12345678901234567890", code: "94287082" },
      { timestamp: 1_111_111_109_000, algorithm: "SHA1", secret: "12345678901234567890", code: "07081804" },
      { timestamp: 1_111_111_111_000, algorithm: "SHA1", secret: "12345678901234567890", code: "14050471" },
      { timestamp: 1_234_567_890_000, algorithm: "SHA1", secret: "12345678901234567890", code: "89005924" },
      { timestamp: 2_000_000_000_000, algorithm: "SHA1", secret: "12345678901234567890", code: "69279037" },
      { timestamp: 20_000_000_000_000, algorithm: "SHA1", secret: "12345678901234567890", code: "65353130" },
      { timestamp: 59_000, algorithm: "SHA256", secret: "12345678901234567890123456789012", code: "46119246" },
      { timestamp: 1_111_111_109_000, algorithm: "SHA256", secret: "12345678901234567890123456789012", code: "68084774" },
      { timestamp: 1_111_111_111_000, algorithm: "SHA256", secret: "12345678901234567890123456789012", code: "67062674" },
      { timestamp: 1_234_567_890_000, algorithm: "SHA256", secret: "12345678901234567890123456789012", code: "91819424" },
      { timestamp: 2_000_000_000_000, algorithm: "SHA256", secret: "12345678901234567890123456789012", code: "90698825" },
      { timestamp: 20_000_000_000_000, algorithm: "SHA256", secret: "12345678901234567890123456789012", code: "77737706" },
      { timestamp: 59_000, algorithm: "SHA512", secret: "1234567890123456789012345678901234567890123456789012345678901234", code: "90693936" },
      { timestamp: 1_111_111_109_000, algorithm: "SHA512", secret: "1234567890123456789012345678901234567890123456789012345678901234", code: "25091201" },
      { timestamp: 1_111_111_111_000, algorithm: "SHA512", secret: "1234567890123456789012345678901234567890123456789012345678901234", code: "99943326" },
      { timestamp: 1_234_567_890_000, algorithm: "SHA512", secret: "1234567890123456789012345678901234567890123456789012345678901234", code: "93441116" },
      { timestamp: 2_000_000_000_000, algorithm: "SHA512", secret: "1234567890123456789012345678901234567890123456789012345678901234", code: "38618901" },
      { timestamp: 20_000_000_000_000, algorithm: "SHA512", secret: "1234567890123456789012345678901234567890123456789012345678901234", code: "47863826" },
    ];

    for (const testCase of cases) {
      vi.setSystemTime(testCase.timestamp);
      await expect(totp(base32Encode(asciiBytes(testCase.secret)), {
        algorithm: testCase.algorithm,
        digits: 8,
        period: 30,
      })).resolves.toBe(testCase.code);
    }
  });
});

describe("otpauth parsing", () => {
  it("parses single-account otpauth urls", () => {
    expect(parseOtpAuth("otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=sha256&digits=8&period=45"))
      .toEqual({
        type: "totp",
        issuer: "GitHub",
        account: "me@example.com",
        secret: "JBSWY3DPEHPK3PXP",
        algorithm: "SHA256",
        digits: 8,
        period: 45,
        counter: 0,
      });
  });

  it("parses Google Authenticator migration payloads from raw data and URI form", () => {
    const itemASecret = new Uint8Array([1, 2, 3, 4, 5]);
    const itemBSecret = new Uint8Array([10, 20, 30, 40, 50, 60]);
    const data = buildMigrationData([
      {
        secretBytes: itemASecret,
        name: "alice@example.com",
        issuer: "GitHub",
        algorithm: 1,
        digits: 1,
        type: 2,
      },
      {
        secretBytes: itemBSecret,
        name: "backup@example.com",
        issuer: "Example",
        algorithm: 3,
        digits: 2,
        type: 1,
        counter: 7,
      },
    ]);
    const expected = [
      {
        type: "totp",
        issuer: "GitHub",
        account: "alice@example.com",
        secret: base32Encode(itemASecret),
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        counter: 0,
      },
      {
        type: "hotp",
        issuer: "Example",
        account: "backup@example.com",
        secret: base32Encode(itemBSecret),
        algorithm: "SHA512",
        digits: 8,
        period: 30,
        counter: 7,
      },
    ];

    expect(parseOtpAuthMigration(data)).toEqual(expected);
    expect(parseOtpAuthMigration(`otpauth-migration://offline?data=${data}`)).toEqual(expected);
  });

  it("builds Google Authenticator migration URLs that round-trip through the parser", () => {
    const items = [
      {
        type: "totp",
        issuer: "GitHub",
        account: "alice@example.com",
        secret: base32Encode(asciiBytes("12345678901234567890")),
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      },
      {
        type: "hotp",
        issuer: "Example",
        account: "backup@example.com",
        secret: base32Encode(asciiBytes("abcdefghijklmnopqrstuvwxyz123456")),
        algorithm: "SHA512",
        digits: 8,
        counter: 7,
      },
    ];

    expect(parseOtpAuthMigration(buildMigrationUrl(items))).toEqual([
      {
        type: "totp",
        issuer: "GitHub",
        account: "alice@example.com",
        secret: items[0].secret,
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        counter: 0,
      },
      {
        type: "hotp",
        issuer: "Example",
        account: "backup@example.com",
        secret: items[1].secret,
        algorithm: "SHA512",
        digits: 8,
        period: 30,
        counter: 7,
      },
    ]);
  });

  it("splits migration URLs into batches of at most 10 items", () => {
    const items = Array.from({ length: 12 }, (_, i) => ({
      type: "totp",
      issuer: "Demo",
      account: `user-${i}@example.com`,
      secret: base32Encode(asciiBytes(`1234567890123456789${String(i % 10)}`)),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    }));

    const urls = buildMigrationUrls(items);
    expect(urls).toHaveLength(2);
    expect(parseOtpAuthMigration(urls[0])).toHaveLength(10);
    expect(parseOtpAuthMigration(urls[1])).toHaveLength(2);
  });

  it("emits Google Authenticator batch metadata (version/batch_size/index/id) so GA accepts the QR", () => {
    const items = Array.from({ length: 11 }, (_, i) => ({
      type: "totp",
      issuer: "Demo",
      account: `user-${i}@example.com`,
      secret: base32Encode(asciiBytes(`1234567890123456789${String(i % 10)}`)),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    }));
    const urls = buildMigrationUrls(items);
    expect(urls).toHaveLength(2);

    const meta0 = extractMigrationMeta(urls[0]);
    const meta1 = extractMigrationMeta(urls[1]);

    // version 必须是 1，否则 Google Authenticator 拒绝识别
    expect(meta0.version).toBe(1);
    expect(meta1.version).toBe(1);
    // 总分片数 = 2，分片下标分别是 0 / 1
    expect(meta0.batchSize).toBe(2);
    expect(meta1.batchSize).toBe(2);
    expect(meta0.batchIndex).toBe(0);
    expect(meta1.batchIndex).toBe(1);
    // 同一次导出共享同一个 batch_id
    expect(meta0.batchId).toBe(meta1.batchId);
    expect(meta0.batchId).toBeGreaterThan(0);
  });

  it("uses standard base64 with percent-encoding so URL parsers see + as %2B", () => {
    // 强制构造一定包含 + 或 / 的 base64 输出（多账号即可触发）
    const items = Array.from({ length: 5 }, (_, i) => ({
      type: "totp",
      issuer: `Issuer-${i}`,
      account: `user-${i}@example.com`,
      secret: base32Encode(asciiBytes(`secret-bytes-with-padding-${i}`)),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    }));
    const url = buildMigrationUrl(items, { version: 1, batchSize: 1, batchIndex: 0, batchId: 42 });

    // URL 中的 data 参数不应含未编码的 + 或 /，应使用百分号编码
    const dataRaw = url.split("?data=")[1];
    expect(dataRaw).not.toMatch(/[+/]/);
    // 反解出来后能 round-trip
    expect(parseOtpAuthMigration(url)).toHaveLength(5);
  });
});

describe("formatCode", () => {
  it("formats 6 and 8 digit codes for display", () => {
    expect(formatCode("123456")).toBe("123 456");
    expect(formatCode("12345678", 8)).toBe("1234 5678");
  });
});
