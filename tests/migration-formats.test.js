import { afterEach, describe, expect, it, vi } from "vitest";

import {
  decryptAndParseAndOtpBackup,
  detectMigrationFile,
  isLikelyAndOtpEncryptedBackup,
  parseAegisJson,
  parseAndOtpJson,
  parseBitwardenCsv,
  parseBitwardenJson,
} from "../src/core/migration-formats.js";

describe("parseAegisJson", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("imports supported entries and skips unsupported OTP types", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-01T12:00:00Z"));

    const result = parseAegisJson({
      version: 1,
      header: { slots: null, params: null },
      db: {
        version: 3,
        entries: [
          {
            type: "totp",
            name: "me@example.com",
            issuer: "GitHub",
            note: "main",
            favorite: true,
            info: { secret: "JBSWY3DP", algo: "SHA512", digits: 8, period: 45 }
          },
          {
            type: "steam",
            name: "ignored",
            issuer: "Steam",
            info: { secret: "ABCDEFGHIJKLMNOP", algo: "SHA1", digits: 5, period: 30 }
          },
          {
            type: "HOTP",
            name: "ops@example.com",
            issuer: "PagerDuty",
            favorite: "false",
            info: { secret: "jbsw-y3dp====", algo: "sha-256", digits: 7, counter: 9 }
          }
        ]
      }
    });

    expect(result.format).toBe("Aegis JSON");
    expect(result.total).toBe(3);
    expect(result.imported).toBe(2);
    expect(result.skipped).toBe(1);
    expect(result.warnings[0]).toContain("steam");
    expect(result.items[0]).toMatchObject({
      issuer: "GitHub",
      account: "me@example.com",
      note: "main",
      pinned: true,
      secret: "JBSWY3DP",
      algorithm: "SHA512",
      digits: 8,
      period: 45,
    });
    expect(result.items[1]).toMatchObject({
      type: "hotp",
      issuer: "PagerDuty",
      account: "ops@example.com",
      pinned: false,
      secret: "JBSWY3DP",
      algorithm: "SHA256",
      digits: 7,
      counter: 9,
    });
  });
});

describe("parseAndOtpJson", () => {
  it("normalizes grouped secrets and case-insensitive HOTP fields", () => {
    const result = parseAndOtpJson([
      {
        secret: "jbsw y3dp====",
        issuer: "GitLab",
        label: "dev@example.com",
        digits: "8",
        counter: "12",
        type: "hotp",
        algorithm: "sha512"
      },
      {
        secret: "ABCDEFGHIJKLMNOP",
        issuer: "Steam",
        label: "ignored",
        type: "steam"
      }
    ]);

    expect(result.format).toBe("andOTP JSON");
    expect(result.total).toBe(2);
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(1);
    expect(result.warnings[0]).toContain("steam");
    expect(result.items[0]).toMatchObject({
      type: "hotp",
      issuer: "GitLab",
      account: "dev@example.com",
      secret: "JBSWY3DP",
      algorithm: "SHA512",
      digits: 8,
      counter: 12,
    });
  });
});

describe("parseBitwardenCsv", () => {
  it("extracts TOTP secrets from both raw secret and otpauth uri rows", () => {
    const csv = [
      "folder,favorite,type,name,notes,login_username,login_password,login_totp",
      'Work,1,login,GitHub,primary,me@example.com,pass123,JBSWY3DP',
      'Personal,0,login,Google,,me@gmail.com,," OTPAUTH://TOTP/Google:me@gmail.com?secret=nb2w 45df oiza====&issuer=Google&algorithm=SHA256&digits=8&period=60 "',
      'Other,0,login,NoOTP,n/a,foo@example.com,,',
    ].join("\n");

    const result = parseBitwardenCsv(csv);

    expect(result.format).toBe("Bitwarden CSV");
    expect(result.total).toBe(3);
    expect(result.imported).toBe(2);
    expect(result.skipped).toBe(1);
    expect(result.items[0]).toMatchObject({
      issuer: "GitHub",
      account: "me@example.com",
      password: "pass123",
      note: "primary",
      pinned: true,
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
    expect(result.items[1]).toMatchObject({
      issuer: "Google",
      account: "me@gmail.com",
      secret: "NB2W45DFOIZA",
      algorithm: "SHA256",
      digits: 8,
      period: 60,
    });
  });
});

describe("parseBitwardenJson", () => {
  it("normalizes string favorite flags explicitly", () => {
    const result = parseBitwardenJson({
      encrypted: false,
      items: [
        {
          name: "GitHub",
          favorite: "false",
          login: { username: "me@example.com", totp: "JBSWY3DP" },
        },
        {
          name: "Google",
          favorite: "yes",
          login: { username: "me@gmail.com", totp: "otpauth://totp/Google:me@gmail.com?secret=NB2W45DFOIZA&issuer=Google" },
        },
      ],
    });

    expect(result.format).toBe("Bitwarden JSON");
    expect(result.items).toHaveLength(2);
    expect(result.items[0]).toMatchObject({
      issuer: "GitHub",
      account: "me@example.com",
      pinned: false,
    });
    expect(result.items[1]).toMatchObject({
      issuer: "Google",
      account: "me@gmail.com",
      pinned: true,
    });
  });
});

describe("detectMigrationFile", () => {
  it("flags encrypted Aegis vaults as unsupported", () => {
    const result = detectMigrationFile({
      fileName: "aegis-export.json",
      text: JSON.stringify({
        version: 1,
        header: { slots: [{}], params: { nonce: "00", tag: "00" } },
        db: "ciphertext"
      })
    });

    expect(result).toMatchObject({
      kind: "unsupported",
      format: "Aegis 加密 Vault"
    });
  });
});

describe("decryptAndParseAndOtpBackup", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("decrypts password-protected andOTP backups", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-01T12:00:00Z"));

    const password = "backup-pass";
    const payload = JSON.stringify([
      {
        secret: "JBSWY3DP",
        issuer: "GitHub",
        label: "me@example.com",
        digits: 6,
        period: 30,
        type: "TOTP",
        algorithm: "SHA1"
      }
    ]);
    const bytes = await buildAndOtpBackup(payload, password, 12000);
    const padded = new Uint8Array(bytes.length + 4);
    padded.set([222, 173], 0);
    padded.set(bytes, 2);
    padded.set([190, 239], bytes.length + 2);
    const view = new DataView(padded.buffer, 2, bytes.length);

    expect(isLikelyAndOtpEncryptedBackup(view, "andotp-backup.bin")).toBe(true);

    const result = await decryptAndParseAndOtpBackup(view, password);

    expect(result.format).toBe("andOTP 加密备份");
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toMatchObject({
      issuer: "GitHub",
      account: "me@example.com",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
  });
});

async function buildAndOtpBackup(plainText, password, iterations) {
  const salt = new Uint8Array(12).fill(7);
  const iv = new Uint8Array(12).fill(9);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-1" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plainText)
  ));
  const out = new Uint8Array(4 + salt.length + iv.length + encrypted.length);
  new DataView(out.buffer).setInt32(0, iterations, false);
  out.set(salt, 4);
  out.set(iv, 16);
  out.set(encrypted, 28);
  return out;
}
