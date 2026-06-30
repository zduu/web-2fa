import { afterEach, describe, expect, it, vi } from "vitest";

import { importFingerprint, normalizeImportedItem, normalizeImportedPinned } from "../src/core/imports.js";

describe("normalizeImportedItem", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("trims and normalizes imported account data", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-01T12:00:00Z"));

    expect(normalizeImportedItem({
      issuer: " GitHub ",
      account: " me@example.com ",
      secret: " jbsw y3dp==== ",
      algorithm: "sha512",
      digits: "8",
      period: "45",
      password: 123,
    })).toEqual({
      type: "totp",
      issuer: "GitHub",
      account: "me@example.com",
      password: "",
      secret: "JBSWY3DP",
      algorithm: "SHA512",
      digits: 8,
      period: 45,
      counter: 0,
      updatedAt: new Date("2026-05-01T12:00:00Z").getTime(),
      deleted: false,
      pinned: false,
      note: "",
      shares: [],
    });
  });

  it("normalizes invalid OTP parameters on import", () => {
    expect(normalizeImportedItem({
      type: "steam",
      secret: "jbsw y3dp",
      algorithm: "md5",
      digits: "abc",
      period: "0",
      counter: "-10",
    })).toMatchObject({
      type: "totp",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 6,
      period: 5,
      counter: 0,
    });
  });

  it("parses imported pinned flags explicitly instead of truthifying strings", () => {
    expect(normalizeImportedPinned(true)).toBe(true);
    expect(normalizeImportedPinned(1)).toBe(true);
    expect(normalizeImportedPinned(" true ")).toBe(true);
    expect(normalizeImportedPinned("yes")).toBe(true);
    expect(normalizeImportedPinned("1")).toBe(true);
    expect(normalizeImportedPinned(false)).toBe(false);
    expect(normalizeImportedPinned(0)).toBe(false);
    expect(normalizeImportedPinned("false")).toBe(false);
    expect(normalizeImportedPinned("0")).toBe(false);
    expect(normalizeImportedPinned("")).toBe(false);

    expect(normalizeImportedItem({
      secret: "JBSWY3DP",
      pinned: "false",
    })).toMatchObject({ pinned: false });
    expect(normalizeImportedItem({
      secret: "JBSWY3DP",
      pinned: "1",
    })).toMatchObject({ pinned: true });
  });
});

describe("importFingerprint", () => {
  it("treats semantically equal imports as the same item", () => {
    const a = importFingerprint({
      type: "totp",
      secret: "jbsw y3dp",
      issuer: "GitHub",
      account: "me@example.com",
      algorithm: "sha1",
      digits: 6,
      period: 30,
    });
    const b = importFingerprint({
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
      algorithm: "SHA1",
      digits: "6",
      period: "30",
    });

    expect(a).toBe(b);
  });

  it("distinguishes HOTP counters from TOTP periods", () => {
    expect(importFingerprint({
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
      period: 30,
    })).not.toBe(importFingerprint({
      type: "hotp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
      counter: 30,
    }));
  });

  it("uses normalized OTP parameters for duplicate detection", () => {
    const a = importFingerprint({
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
      algorithm: "md5",
      digits: "abc",
      period: "0",
    });
    const b = importFingerprint({
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
      algorithm: "SHA1",
      digits: 6,
      period: 5,
    });

    expect(a).toBe(b);
  });
});
