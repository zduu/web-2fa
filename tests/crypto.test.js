import { afterEach, describe, expect, it } from "vitest";

import { b64url, fromB64, fromB64url, pemFingerprint, toB64 } from "../src/core/crypto.js";

describe("base64 byte helpers", () => {
  const originalBtoa = globalThis.btoa;
  const originalAtob = globalThis.atob;

  afterEach(() => {
    if (originalBtoa === undefined) delete globalThis.btoa;
    else globalThis.btoa = originalBtoa;
    if (originalAtob === undefined) delete globalThis.atob;
    else globalThis.atob = originalAtob;
  });

  it("round-trips small byte arrays", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    expect(fromB64(toB64(bytes))).toEqual(bytes);
  });

  it("encodes ArrayBuffer views using their byte range", () => {
    const bytes = new Uint8Array([10, 11, 12, 13, 14, 15]);
    const view = new DataView(bytes.buffer, 2, 3);
    const uint16 = new Uint16Array(bytes.buffer, 2, 1);

    expect(fromB64(toB64(view))).toEqual(new Uint8Array([12, 13, 14]));
    expect(fromB64(toB64(uint16))).toEqual(new Uint8Array(bytes.buffer, 2, 2));
    expect(fromB64(toB64(bytes.buffer))).toEqual(bytes);
  });

  it("encodes large byte arrays without spreading them into one call", () => {
    const bytes = new Uint8Array(200_000);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 256;

    const roundTrip = fromB64(toB64(bytes));
    expect(roundTrip).toHaveLength(bytes.length);
    expect(roundTrip.slice(0, 1024)).toEqual(bytes.slice(0, 1024));
    expect(roundTrip.slice(-1024)).toEqual(bytes.slice(-1024));
  });

  it("round-trips URL-safe base64 and tolerates empty input", () => {
    const bytes = new Uint8Array([251, 252, 253, 254, 255]);
    const encoded = b64url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(fromB64url(encoded)).toEqual(bytes);
    expect(fromB64url(`${encoded}=`)).toEqual(bytes);
    expect(fromB64url(null)).toEqual(new Uint8Array());
  });

  it("falls back to Buffer when browser base64 globals are unavailable", () => {
    delete globalThis.btoa;
    delete globalThis.atob;

    const bytes = new Uint8Array([0, 31, 32, 127, 128, 255]);
    expect(fromB64(toB64(bytes))).toEqual(bytes);
    expect(fromB64url(b64url(bytes))).toEqual(bytes);
  });

  it("uses the same base64 fallback for PEM fingerprint input", async () => {
    delete globalThis.btoa;
    delete globalThis.atob;

    await expect(pemFingerprint("AQIDBAUGBwg=")).resolves.toMatch(/^[0-9a-f:]{47}$/);
  });
});
