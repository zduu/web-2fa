import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { state } from "../src/core/storage.js";
import {
  getVaultEnabled,
  getVaultPubkey,
  getVaultPubkeys,
  escrowSecrets,
  migrateSecrets,
  recoverSecrets,
  LS_VAULT_ENABLED,
  LS_VAULT_PUBKEY,
  LS_VAULT_PUBKEYS,
  normalizeVaultPubkeys,
  normalizeVaultSyncIds,
  setVaultEnabled,
  setVaultPubkey,
  setVaultPubkeys,
} from "../src/sync/vault.js";

async function createRsaKeyPairPems() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  return {
    publicPem: formatPem("PUBLIC KEY", spki),
    privatePem: formatPem("PRIVATE KEY", pkcs8),
  };
}

function formatPem(label, buffer) {
  const b64 = Buffer.from(new Uint8Array(buffer)).toString("base64");
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END ${label}-----`;
}

function installLocalStorage(storage) {
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: storage,
  });
}

function createLocalStorage() {
  const store = new Map();
  return {
    getItem: (key) => store.has(key) ? store.get(key) : null,
    setItem: (key, value) => { store.set(key, String(value)); },
    removeItem: (key) => { store.delete(key); },
    clear: () => { store.clear(); },
  };
}

beforeEach(() => {
  installLocalStorage(createLocalStorage());
});

afterEach(() => {
  vi.restoreAllMocks();
  state.globalToken = "";
  state.syncProjects = [];
  delete globalThis.localStorage;
});

describe("vault public key settings", () => {
  it("normalizes public key entries deterministically", () => {
    const input = [
      { id: " admin key ", name: " Admin ", pem: "  -----BEGIN PUBLIC KEY-----\na\n-----END PUBLIC KEY-----  " },
      { id: "admin key", name: "", pem: "pem-b" },
      { id: "!!!", name: "Ignored", pem: "" },
      { name: "Ops", pem: "pem-c" },
    ];

    expect(normalizeVaultPubkeys(input)).toEqual([
      { id: "admin_key", name: "Admin", pem: "-----BEGIN PUBLIC KEY-----\na\n-----END PUBLIC KEY-----" },
      { id: "admin_key_2", name: "公钥 2", pem: "pem-b" },
      { id: "vault_key_3", name: "Ops", pem: "pem-c" },
    ]);
    expect(normalizeVaultPubkeys(input)).toEqual(normalizeVaultPubkeys(input));
  });

  it("persists normalized multi-key config and legacy first-key compatibility", () => {
    setVaultPubkeys([
      { id: "main", name: "Main", pem: " pem-a " },
      { id: "backup", name: "Backup", pem: " pem-b " },
    ]);

    expect(JSON.parse(localStorage.getItem(LS_VAULT_PUBKEYS))).toEqual([
      { id: "main", name: "Main", pem: "pem-a" },
      { id: "backup", name: "Backup", pem: "pem-b" },
    ]);
    expect(localStorage.getItem(LS_VAULT_PUBKEY)).toBe("pem-a");
    expect(getVaultPubkeys()).toEqual([
      { id: "main", name: "Main", pem: "pem-a" },
      { id: "backup", name: "Backup", pem: "pem-b" },
    ]);
    expect(getVaultPubkey()).toBe("pem-a");
  });

  it("falls back to the legacy public key when new config is damaged or empty", () => {
    localStorage.setItem(LS_VAULT_PUBKEY, " legacy-pem ");
    localStorage.setItem(LS_VAULT_PUBKEYS, "{bad json");
    expect(getVaultPubkeys()).toEqual([
      { id: "legacy", name: "默认公钥", pem: "legacy-pem" },
    ]);

    localStorage.setItem(LS_VAULT_PUBKEYS, JSON.stringify([{ pem: "   " }]));
    expect(getVaultPubkeys()).toEqual([
      { id: "legacy", name: "默认公钥", pem: "legacy-pem" },
    ]);
  });

  it("clears vault settings when disabled or given no usable public keys", () => {
    setVaultEnabled(true);
    expect(localStorage.getItem(LS_VAULT_ENABLED)).toBe("1");
    expect(getVaultEnabled()).toBe(true);

    setVaultEnabled(false);
    expect(localStorage.getItem(LS_VAULT_ENABLED)).toBeNull();

    setVaultPubkey("pem-a");
    setVaultPubkeys([{ pem: "   " }]);
    expect(localStorage.getItem(LS_VAULT_PUBKEY)).toBeNull();
    expect(localStorage.getItem(LS_VAULT_PUBKEYS)).toBeNull();
    expect(getVaultPubkeys()).toEqual([]);
  });

  it("uses safe defaults when localStorage is unavailable", () => {
    installLocalStorage({
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
      removeItem: () => { throw new Error("blocked"); },
    });

    expect(getVaultEnabled()).toBe(false);
    expect(getVaultPubkeys()).toEqual([]);
    expect(() => setVaultEnabled(true)).not.toThrow();
    expect(() => setVaultPubkey("pem-a")).not.toThrow();
  });
});

describe("vault sync id handling", () => {
  it("normalizes sync ids with the same route rules as sync APIs", () => {
    expect(normalizeVaultSyncIds([
      " good ",
      "sync:nested",
      "demo\nid",
      "",
      null,
      "legacy",
    ])).toEqual(["good", "legacy"]);
  });

  it("counts invalid migration sync ids as failures without fetching them", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Not found", { status: 404 }));
    const progress = vi.fn();

    await expect(migrateSecrets({
      syncIds: ["sync:nested", " good "],
      oldSecrets: ["old-secret"],
      newSecret: "new-secret",
      onProgress: progress,
    })).resolves.toEqual({ ok: 0, fail: 2 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/sync/good");
    expect(progress).toHaveBeenNthCalledWith(1, 1, 2);
    expect(progress).toHaveBeenNthCalledWith(2, 2, 2);
  });

  it("does not count vault 200 responses with X-Note as escrow successes", async () => {
    state.globalToken = "admin-token";
    const { publicPem } = await createRsaKeyPairPems();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Not configured", {
      status: 200,
      headers: { "X-Note": "kv-missing" },
    }));

    await expect(escrowSecrets({
      syncIds: ["good"],
      secret: "sync-secret",
      pubKeyPem: publicPem,
    })).resolves.toEqual({ ok: 0, fail: 1 });
  });

  it("skips vault 200 responses with X-Note during recovery", async () => {
    state.globalToken = "admin-token";
    const { privatePem } = await createRsaKeyPairPems();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Not configured", {
      status: 200,
      headers: { "X-Note": "kv-missing" },
    }));

    await expect(recoverSecrets({
      syncIds: ["good"],
      privKeyPem: privatePem,
    })).resolves.toEqual([]);
  });
});
