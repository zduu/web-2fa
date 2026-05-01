import { describe, expect, it } from "vitest";

import { mergeItems } from "../src/sync/sync.js";
import { normalizeProjectItemOrder } from "../src/sync/projects.js";

describe("mergeItems", () => {
  it("keeps the latest version while merging share metadata", () => {
    const result = mergeItems(
      [
        {
          type: "totp",
          secret: "jbswy3dp",
          issuer: "GitHub",
          account: "me@example.com",
          algorithm: "SHA1",
          digits: 6,
          period: 30,
          updatedAt: 10,
          shares: [{ sid: "sid-a" }],
        },
        {
          type: "totp",
          secret: "MFRGGZDFMZTWQ2LK",
          issuer: "Google",
          account: "me@example.com",
          updatedAt: 50,
          shares: [{ sid: "sid-x" }],
        },
      ],
      [
        {
          type: "totp",
          secret: "JBSWY3DP",
          issuer: "GitHub",
          account: "me@example.com",
          algorithm: "sha256",
          digits: 8,
          period: 45,
          updatedAt: 20,
          shares: [{ sid: "sid-a", k: "share-key" }, { sid: "sid-b" }],
        },
        {
          type: "totp",
          secret: "MFRGGZDFMZTWQ2LK",
          issuer: "Google",
          account: "me@example.com",
          updatedAt: 40,
          shares: [{ sid: "sid-y" }],
        },
      ],
    );

    expect(result).toHaveLength(2);
    expect(result).toContainEqual(expect.objectContaining({
      issuer: "GitHub",
      algorithm: "SHA256",
      digits: 8,
      period: 45,
      updatedAt: 20,
      shares: [
        { sid: "sid-a", k: "share-key" },
        { sid: "sid-b" },
      ],
    }));
    expect(result).toContainEqual(expect.objectContaining({
      issuer: "Google",
      updatedAt: 50,
      shares: [
        { sid: "sid-x" },
        { sid: "sid-y" },
      ],
    }));
  });
});

describe("normalizeProjectItemOrder", () => {
  it("keeps explicit order, removes stale ids, and appends new items lexicographically", () => {
    const result = normalizeProjectItemOrder(
      ["b", "ghost", "a"],
      [
        { id: "a", issuer: "GitHub", account: "me@example.com" },
        { id: "b", issuer: "Google", account: "me@example.com" },
        { id: "c", issuer: "AWS", account: "ops@example.com" },
        { id: "d", issuer: "Zoom", account: "team@example.com", deleted: true },
      ],
    );

    expect(result).toEqual(["b", "a", "c"]);
  });
});
