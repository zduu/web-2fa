import { describe, expect, it } from "vitest";

import { ensureItemDefaults } from "../src/core/storage.js";

describe("ensureItemDefaults", () => {
  it("normalizes stored items and share references", () => {
    expect(ensureItemDefaults({
      type: "hotp",
      secret: " abcd ef12 ",
      algorithm: "sha256",
      digits: "8",
      counter: "12",
      pinned: 1,
      deleted: 0,
      note: null,
      shares: ["sid-a", { sid: "sid-b", k: "key-b" }, { sid: "sid-c" }, { nope: true }],
    })).toEqual({
      type: "hotp",
      secret: "ABCDEF12",
      algorithm: "SHA256",
      digits: 8,
      period: 30,
      counter: 12,
      password: "",
      updatedAt: expect.any(Number),
      deleted: false,
      pinned: true,
      note: "",
      shares: [
        { sid: "sid-a" },
        { sid: "sid-b", k: "key-b" },
        { sid: "sid-c", k: undefined },
      ],
    });
  });

  it("fills missing defaults for totp items", () => {
    expect(ensureItemDefaults({ secret: "jbsw y3dp" })).toMatchObject({
      type: "totp",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      pinned: false,
      deleted: false,
      shares: [],
    });
  });
});
