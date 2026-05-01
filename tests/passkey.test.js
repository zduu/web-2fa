import { describe, expect, it } from "vitest";

import {
  unwrapBytesWithPasskeyPrf,
  wrapBytesWithPasskeyPrf,
} from "../src/core/passkey.js";

describe("passkey wrapping helpers", () => {
  it("fails to unwrap when the salt changes", async () => {
    const prf = new Uint8Array(32).fill(3);
    const saltA = new Uint8Array(16).fill(9);
    const saltB = new Uint8Array(16).fill(8);
    const dek = new Uint8Array(32).fill(7);

    const wrapped = await wrapBytesWithPasskeyPrf(dek, prf, saltA);

    await expect(unwrapBytesWithPasskeyPrf(wrapped, prf, saltB)).rejects.toThrow();
  });

  it("round-trips wrapped DEK bytes with PRF-derived AES-GCM", async () => {
    const prf = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const dek = crypto.getRandomValues(new Uint8Array(32));

    const wrapped = await wrapBytesWithPasskeyPrf(dek, prf, salt);
    const unwrapped = await unwrapBytesWithPasskeyPrf(wrapped, prf, salt);

    expect(unwrapped).toEqual(dek);
  });
});
