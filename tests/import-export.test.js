import { describe, expect, it } from "vitest";

import {
  applyImportedItemOverwrite,
  formatImportPreviewMeta,
  formatImportPreviewTitle,
  normalizeExportItem,
  parseEncryptedImportKdfIterations,
} from "../src/ui/import-export.js";

describe("applyImportedItemOverwrite", () => {
  it("normalizes overwritten OTP fields and merges share metadata", () => {
    const existing = {
      id: "item-1",
      type: "totp",
      issuer: "Old",
      account: "old@example.com",
      password: "keep-me",
      secret: "OLDSECRET",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      shares: [{ sid: " sid-a " }, { sid: "sid-b", k: "old-key" }],
    };

    const result = applyImportedItemOverwrite(existing, {
      type: "steam",
      issuer: " GitHub ",
      account: " me@example.com ",
      password: 123,
      secret: " jbsw y3dp==== ",
      algorithm: "SHA-1",
      digits: "2",
      period: "3",
      counter: "-4",
      deleted: 0,
      updatedAt: "42",
      shares: [{ sid: "sid-a", k: "new-key" }, { sid: " sid-c " }, { sid: " " }],
    }, 1000);

    expect(result).toBe(existing);
    expect(existing).toMatchObject({
      id: "item-1",
      type: "totp",
      issuer: "GitHub",
      account: "me@example.com",
      password: "keep-me",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 4,
      period: 5,
      counter: 0,
      deleted: false,
      updatedAt: 42,
      shares: [
        { sid: "sid-a", k: "new-key" },
        { sid: "sid-b", k: "old-key" },
        { sid: "sid-c", k: undefined },
      ],
    });
  });

  it("falls back from invalid imported timestamps when overwriting", () => {
    const existing = {
      id: "item-1",
      password: "keep-me",
      secret: "OLDSECRET",
      updatedAt: 10,
    };

    applyImportedItemOverwrite(existing, {
      secret: "JBSWY3DP",
      updatedAt: "1e999",
    }, 1000);

    expect(existing.updatedAt).toBe(1000);
  });

  it("overwrites note and pinned metadata when import records include them", () => {
    const existing = {
      id: "item-1",
      secret: "OLDSECRET",
      note: "old note",
      pinned: false,
    };

    applyImportedItemOverwrite(existing, {
      secret: "JBSWY3DP",
      note: "new note",
      pinned: true,
    }, 1000);

    expect(existing).toMatchObject({
      note: "new note",
      pinned: true,
    });
  });

  it("keeps local note and pinned metadata when old import records omit them", () => {
    const existing = {
      id: "item-1",
      secret: "OLDSECRET",
      note: "local note",
      pinned: true,
    };

    applyImportedItemOverwrite(existing, {
      secret: "JBSWY3DP",
    }, 1000);

    expect(existing).toMatchObject({
      note: "local note",
      pinned: true,
    });
  });
});

describe("formatImportPreviewMeta", () => {
  it("formats normalized OTP metadata for import previews", () => {
    expect(formatImportPreviewMeta({
      type: "HOTP",
      algorithm: "sha-512",
      digits: "99",
      period: "2",
      counter: "-4",
    })).toBe("HOTP · SHA512 · 10位 · counter 0");

    expect(formatImportPreviewMeta({
      type: "totp",
      algorithm: "md5",
      digits: "abc",
      period: "3",
    })).toBe("TOTP · SHA1 · 6位 · 5s");
  });
});

describe("formatImportPreviewTitle", () => {
  it("formats trimmed issuer and account display titles", () => {
    expect(formatImportPreviewTitle({
      issuer: " GitHub ",
      account: " me@example.com ",
    })).toBe("GitHub · me@example.com");
    expect(formatImportPreviewTitle({ issuer: " GitHub " })).toBe("GitHub");
    expect(formatImportPreviewTitle({ account: " me@example.com " })).toBe("me@example.com");
    expect(formatImportPreviewTitle({ issuer: " ", account: "" })).toBe("");
  });
});

describe("parseEncryptedImportKdfIterations", () => {
  it("parses exported PBKDF2 descriptors without using algorithm digits as iterations", () => {
    expect(parseEncryptedImportKdfIterations("PBKDF2-SHA256-200k")).toBe(200_000);
    expect(parseEncryptedImportKdfIterations("PBKDF2-SHA256-600000")).toBe(600_000);
    expect(parseEncryptedImportKdfIterations("PBKDF2-SHA256-10m")).toBe(10_000_000);
  });

  it("falls back for missing or unsafe KDF iteration descriptors", () => {
    expect(parseEncryptedImportKdfIterations("PBKDF2-SHA256")).toBe(200_000);
    expect(parseEncryptedImportKdfIterations("PBKDF2-SHA256-999m")).toBe(200_000);
    expect(parseEncryptedImportKdfIterations(null)).toBe(200_000);
    expect(parseEncryptedImportKdfIterations("PBKDF2-SHA256-600k", "bad")).toBe(600_000);
  });
});

describe("normalizeExportItem", () => {
  it("exports normalized OTP fields without dropping metadata", () => {
    expect(normalizeExportItem({
      id: "item-1",
      type: "HOTP",
      issuer: " GitHub ",
      account: " me@example.com ",
      password: 123,
      note: "primary",
      pinned: true,
      secret: " jbsw-y3dp==== ",
      algorithm: "sha-256",
      digits: "8",
      counter: "4",
      shares: [" sid-a ", { sid: " sid-b ", k: "key-b" }, { bad: true }],
    }, 1000)).toMatchObject({
      id: "item-1",
      type: "hotp",
      issuer: "GitHub",
      account: "me@example.com",
      password: "",
      note: "primary",
      pinned: true,
      secret: "JBSWY3DP",
      algorithm: "SHA256",
      digits: 8,
      counter: 4,
      updatedAt: 1000,
      shares: [{ sid: "sid-a" }, { sid: "sid-b", k: "key-b" }],
    });
  });

  it("falls back from invalid timestamps during export normalization", () => {
    expect(normalizeExportItem({
      secret: "JBSWY3DP",
      updatedAt: "1e999",
    }, 1000)).toMatchObject({
      updatedAt: 1000,
    });
  });
});
