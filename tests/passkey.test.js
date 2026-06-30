import { afterEach, describe, expect, it } from "vitest";

import {
  createLocalUnlockPasskey,
  evaluatePasskeyPrf,
  hasPasskeyPrfPrerequisites,
  getPasskeyPrfSupport,
  unwrapBytesWithPasskeyPrf,
  wrapBytesWithPasskeyPrf,
} from "../src/core/passkey.js";

describe("passkey wrapping helpers", () => {
  const originalWindowDescriptor = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalNavigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const originalLocationDescriptor = Object.getOwnPropertyDescriptor(globalThis, "location");
  const originalPublicKeyCredentialDescriptor = Object.getOwnPropertyDescriptor(globalThis, "PublicKeyCredential");

  function restoreGlobalProperty(name, descriptor) {
    if (descriptor) {
      Object.defineProperty(globalThis, name, descriptor);
    } else {
      delete globalThis[name];
    }
  }

  afterEach(() => {
    restoreGlobalProperty("window", originalWindowDescriptor);
    restoreGlobalProperty("navigator", originalNavigatorDescriptor);
    restoreGlobalProperty("location", originalLocationDescriptor);
    restoreGlobalProperty("PublicKeyCredential", originalPublicKeyCredentialDescriptor);
  });

  it("reports passkey prerequisites as unavailable instead of throwing without navigator", () => {
    globalThis.window = { isSecureContext: true };
    globalThis.PublicKeyCredential = class {};
    delete globalThis.navigator;

    expect(hasPasskeyPrfPrerequisites()).toBe(false);
  });

  it("treats blocked passkey capability globals as unsupported", async () => {
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { isSecureContext: true },
    });
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { credentials: { create: async () => null, get: async () => null } },
    });
    Object.defineProperty(globalThis, "PublicKeyCredential", {
      configurable: true,
      get() {
        throw new Error("blocked");
      },
    });

    expect(hasPasskeyPrfPrerequisites()).toBe(false);
    await expect(getPasskeyPrfSupport()).resolves.toMatchObject({ supported: false });
  });

  it("returns a support error when evaluating PRF without credential APIs", async () => {
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { isSecureContext: true },
    });
    delete globalThis.navigator;

    await expect(evaluatePasskeyPrf("AQIDBA")).rejects.toThrow("需要 HTTPS 安全上下文和系统 Passkey 支持。");
  });

  it("creates passkey options without requiring a global location hostname", async () => {
    const rawId = new Uint8Array([1, 2, 3, 4]);
    const prf = new Uint8Array(32).fill(6);
    const create = async (options) => ({
      rawId,
      response: { getTransports: () => ["internal"] },
      getClientExtensionResults: () => ({ prf: { results: { first: prf.buffer } } }),
      options,
    });
    globalThis.window = { isSecureContext: true };
    globalThis.PublicKeyCredential = class {
      static async getClientCapabilities() {
        return { "extension:prf": true, userVerifyingPlatformAuthenticator: true };
      }
    };
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { credentials: { create, get: async () => null } },
    });
    delete globalThis.location;

    const result = await createLocalUnlockPasskey({ label: "Local" });

    expect(result).toMatchObject({ label: "Local", transports: ["internal"] });
    expect(result.prfOutput).toEqual(prf);
    expect(result.credentialId).toBe("AQIDBA");
  });

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
