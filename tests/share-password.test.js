import { afterEach, describe, expect, it, vi } from "vitest";

import { b64url, fromB64url } from "../src/core/crypto.js";
import {
  isSupportedShareKeyBundleVersion,
  normalizeSharePasswordIterations,
  SHARE_PASSWORD_ITERATIONS,
  wrapShareKeyWithPassword,
  unwrapShareKeyWithPassword,
} from "../src/core/share-password.js";
import {
  collectLocalShares,
  createShareLink,
  deleteRemoteShareResources,
  fetchCloudShares,
  fetchCloudShareRecords,
  fetchCloudShareStats,
  fetchSharedMeta,
  formatShareLabel,
  formatShareResultStatus,
  normalizeShareIds,
  probeShare,
  revokeShare,
  sharePayloadChanged,
} from "../src/share/share.js";
import { state } from "../src/core/storage.js";

function installLocalStorage() {
  const store = new Map();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      getItem: (key) => store.has(key) ? store.get(key) : null,
      setItem: (key, value) => { store.set(key, String(value)); },
      removeItem: (key) => { store.delete(key); },
      clear: () => { store.clear(); },
    },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  state.globalToken = "";
  state.items = [];
  state.syncProjects = [];
  state.currentProjectId = null;
  delete globalThis.localStorage;
});

describe("share password protection", () => {
  it("round-trips arbitrary bytes through b64url helpers", () => {
    const bytes = new Uint8Array(Array.from({ length: 31 }, (_, i) => (i * 17) % 256));
    expect(fromB64url(b64url(bytes))).toEqual(bytes);
  });

  it("wraps and unwraps a share key with a receiver password", async () => {
    const keyRaw = crypto.getRandomValues(new Uint8Array(32));
    const bundle = await wrapShareKeyWithPassword(keyRaw, "correct horse battery staple");
    const unwrapped = await unwrapShareKeyWithPassword(bundle, "correct horse battery staple");
    expect(unwrapped).toEqual(keyRaw);
  });

  it("normalizes password-protected share KDF iterations", async () => {
    expect(normalizeSharePasswordIterations("200000.9")).toBe(200000);
    expect(normalizeSharePasswordIterations("999")).toBe(SHARE_PASSWORD_ITERATIONS);
    expect(normalizeSharePasswordIterations("10000001")).toBe(SHARE_PASSWORD_ITERATIONS);
    expect(normalizeSharePasswordIterations("1e999")).toBe(SHARE_PASSWORD_ITERATIONS);

    const keyRaw = crypto.getRandomValues(new Uint8Array(32));
    const bundle = await wrapShareKeyWithPassword(keyRaw, "receiver pass", "200000.9");
    expect(bundle.iter).toBe(200000);
  });

  it("rejects unsupported password-protected share bundle versions", async () => {
    expect(isSupportedShareKeyBundleVersion(undefined)).toBe(true);
    expect(isSupportedShareKeyBundleVersion(null)).toBe(true);
    expect(isSupportedShareKeyBundleVersion(1)).toBe(true);
    expect(isSupportedShareKeyBundleVersion(2)).toBe(false);

    const keyRaw = crypto.getRandomValues(new Uint8Array(32));
    const bundle = await wrapShareKeyWithPassword(keyRaw, "receiver pass");

    await expect(unwrapShareKeyWithPassword({ ...bundle, v: 2 }, "receiver pass"))
      .rejects.toThrow("invalid-bundle");
  });

  it("stores share decrypt material by default for admin cross-device convenience", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    const result = await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: " GitHub ",
      account: " me@example.com ",
    }, null, { projectName: " Work ", itemId: " item-1 " });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toContain("/api/share-code/");
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toContain("/api/sharekey/");
    const body = JSON.parse(init.body);
    expect(body.k).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(body.label).toBe("GitHub · me@example.com");
    expect(body.projectName).toBe("Work");
    expect(body.itemId).toBe("item-1");
    expect(body.issuer).toBe("GitHub");
    expect(body.account).toBe("me@example.com");
    expect(body.requiresPassword).toBe(false);
    expect(result.recoveryStored).toBe(true);
  });

  it("normalizes share ttl, max access, and stored creation timestamps", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    }, "60.9", { maxAccess: "1000000000", createdAt: "1e999" });

    expect(fetchMock.mock.calls[0][0]).toContain("ttl=60");
    expect(fetchMock.mock.calls[0][0]).toContain("max=1000000");
    const escrowBody = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(Number.isSafeInteger(escrowBody.createdAt)).toBe(true);
    expect(escrowBody.createdAt).toBeGreaterThan(0);
    expect(escrowBody.maxAccess).toBe(1_000_000);
  });

  it("encrypts normalized OTP payload values into share records", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    const result = await createShareLink({
      id: "item-1",
      type: "TOTP",
      secret: " jbsw y3dp==== ",
      algorithm: "SHA-1",
      digits: "2",
      period: "3",
      issuer: " GitHub ",
      account: " me@example.com ",
    }, null, { note: "receiver note" });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const key = await crypto.subtle.importKey(
      "raw",
      fromB64url(result.k),
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64url(body.iv) },
      key,
      fromB64url(body.ct)
    );

    expect(JSON.parse(new TextDecoder().decode(plain))).toEqual({
      type: "totp",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 4,
      period: 5,
      label: "GitHub · me@example.com",
      note: "receiver note",
    });
  });

  it("formats share labels from trimmed issuer and account fields", () => {
    expect(formatShareLabel({ issuer: " GitHub ", account: " me@example.com " })).toBe("GitHub · me@example.com");
    expect(formatShareLabel({ issuer: " GitHub " })).toBe("GitHub");
    expect(formatShareLabel({ account: " me@example.com " })).toBe("me@example.com");
    expect(formatShareLabel({ issuer: " ", account: "" })).toBe("");
  });

  it("surfaces share recovery storage status in result copy", () => {
    expect(formatShareResultStatus(" GitHub ", true, true))
      .toBe("“GitHub” 的分享链接已复制，可直接扫码打开");
    expect(formatShareResultStatus(" GitHub ", false, true))
      .toBe("“GitHub” 的分享链接已生成，可扫码或手动复制");
    expect(formatShareResultStatus(" GitHub ", true, false))
      .toBe("“GitHub” 的分享链接已复制，但后台恢复材料未保存");
    expect(formatShareResultStatus(" ", false, false))
      .toBe("“分享” 的分享链接已生成，但后台恢复材料未保存");
  });

  it("compares share payloads using normalized OTP and label fields", () => {
    expect(sharePayloadChanged({
      type: "TOTP",
      secret: " jbsw-y3dp==== ",
      algorithm: "SHA-1",
      digits: "2",
      period: "3",
      issuer: " GitHub ",
      account: " me@example.com ",
    }, {
      type: "totp",
      secret: "JBSWY3DP",
      algorithm: "SHA1",
      digits: 4,
      period: 5,
      issuer: "GitHub",
      account: "me@example.com",
    })).toBe(false);

    expect(sharePayloadChanged({
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    }, {
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "ops@example.com",
    })).toBe(true);
  });

  it("can explicitly opt out of server-side share key storage", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    const result = await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    }, null, { storeKey: false });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toContain("/api/share-code/");
    expect(result.recoveryStored).toBe(false);
  });

  it("reports failed server-side share key storage without failing link creation", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("OK", { status: 200 }))
      .mockResolvedValueOnce(new Response("Not configured", {
        status: 200,
        headers: { "X-Note": "kv-missing" },
      }));

    const result = await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    });

    expect(result.link).toContain("/shared.html?sid=");
    expect(result.recoveryStored).toBe(false);
  });

  it("does not create share links when the primary share write returns an error note", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Not configured", {
      status: 200,
      headers: { "X-Note": "kv-missing" },
    }));

    await expect(createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    })).rejects.toThrow("AUTH_KV");
  });

  it("stores only the password-wrapped share bundle when protected escrow is enabled", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    await createShareLink({
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      issuer: "GitHub",
      account: "me@example.com",
    }, null, { storeKey: true, password: "receiver pass" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toContain("/api/sharekey/");
    const body = JSON.parse(init.body);
    expect(body.k).toBe("");
    expect(body.requiresPassword).toBe(true);
    expect(body.protectedBundle).toMatchObject({
      s: expect.any(String),
      iv: expect.any(String),
      wk: expect.any(String),
      iter: expect.any(Number),
    });
  });

  it("normalizes and deduplicates local share references", () => {
    state.items = [{
      id: "item-1",
      issuer: "GitHub",
      account: "me@example.com",
      shares: [" sid-a ", { sid: " " }],
    }];
    state.syncProjects = [{
      id: "project-1",
      name: " Work ",
      itemsData: [{
        id: "item-2",
        issuer: "GitLab",
        account: "dev@example.com",
        shares: [{ sid: "sid-a", k: "key-a" }, { sid: " sid-b ", k: "key-b" }],
      }],
    }];

    expect(collectLocalShares()).toEqual([
      {
        sid: "sid-a",
        k: "key-a",
        itemId: "item-1",
        label: "GitHub · me@example.com",
        projectName: null,
      },
      {
        sid: "sid-b",
        k: "key-b",
        itemId: "item-2",
        label: "GitLab · dev@example.com",
        projectName: "Work",
      },
    ]);
  });

  it("normalizes cloud share recovery metadata when fetched", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      k: "share-key",
      label: " GitHub · me@example.com ",
      projectName: " Work ",
      itemId: " item-1 ",
      issuer: " GitHub ",
      account: " me@example.com ",
      createdAt: "42",
      ttl: "default",
      requiresPassword: "false",
      protectedBundle: {
        s: " salt ",
        iv: " iv ",
        wk: " wrapped ",
        iter: "200000",
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    await expect(fetchSharedMeta("sid-a")).resolves.toMatchObject({
      sid: "sid-a",
      k: "share-key",
      label: "GitHub · me@example.com",
      projectName: "Work",
      itemId: "item-1",
      issuer: "GitHub",
      account: "me@example.com",
      createdAt: 42,
      ttl: "default",
      requiresPassword: false,
      protectedBundle: {
        s: "salt",
        iv: "iv",
        wk: "wrapped",
        iter: 200000,
      },
    });
  });

  it("normalizes cloud share ids from list responses", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      sids: [" sid-a ", "", null, "sid-b", "sid-a"],
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    await expect(fetchCloudShares()).resolves.toEqual(["sid-a", "sid-b"]);
  });

  it("surfaces missing KV bindings when loading cloud shares", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ sids: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Note": "kv-missing" },
    }));

    await expect(fetchCloudShares()).rejects.toThrow("AUTH_KV");
  });

  it("normalizes and deduplicates share id lists", () => {
    expect(normalizeShareIds([" sid-a ", "sid-a", "", null, "sid-b"])).toEqual(["sid-a", "sid-b"]);
    expect(normalizeShareIds("sid-a")).toEqual([]);
  });

  it("skips network calls for empty share ids", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    await expect(probeShare(" ")).resolves.toBe(false);
    await expect(fetchSharedMeta(" ")).resolves.toBeNull();
    await expect(fetchCloudShareStats([" ", null])).resolves.toEqual(new Map());
    await expect(revokeShare(" ")).resolves.toBe(false);

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not report share probes with error notes as existing shares", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("Not configured", {
      status: 200,
      headers: { "X-Note": "kv-missing" },
    }));

    await expect(probeShare("sid-a")).resolves.toBe(false);
  });

  it("normalizes malformed cloud share stats", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      items: [
        { sid: " sid-a ", accessCount: "1e999", lastAccessAt: "1e999", accessUserAgentSample: 123 },
        { sid: " sid-b ", accessCount: "2.9", lastAccessAt: "42.9", accessUserAgentSample: " UA\u0000 Browser\n " },
      ],
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    const stats = await fetchCloudShareStats(["sid-a", " sid-a ", "sid-b"]);

    expect(fetchMock.mock.calls[0][0]).toBe("/api/share/stat?sid=sid-a&sid=sid-b");
    expect(stats.get("sid-a")).toEqual({
      accessCount: 0,
      lastAccessAt: null,
      accessUserAgentSample: "",
    });
    expect(stats.get("sid-b")).toEqual({
      accessCount: 2,
      lastAccessAt: 42,
      accessUserAgentSample: "UA Browser",
    });
  });

  it("surfaces missing KV bindings when loading cloud share stats", async () => {
    state.globalToken = "admin-token";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ items: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Note": "kv-missing" },
    }));

    await expect(fetchCloudShareStats(["sid-a"])).rejects.toThrow("AUTH_KV");
  });

  it("normalizes malformed cloud share record metadata before sorting", async () => {
    state.globalToken = "admin-token";
    const responses = [
      { sids: ["sid-b", "sid-a"] },
      { items: [{ sid: "sid-b", accessCount: "1e999", lastAccessAt: "1e999" }] },
      { k: "kb", label: " B ", createdAt: "1e999", protectedBundle: { s: "s", iv: "iv", wk: "wk", iter: "1e999" } },
      { k: "ka", label: " A ", createdAt: "100.9", protectedBundle: { s: "s", iv: "iv", wk: "wk", iter: "200000.9" } },
    ];
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      const body = responses.shift();
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    });

    await expect(fetchCloudShareRecords()).resolves.toMatchObject([
      {
        sid: "sid-a",
        k: "ka",
        label: "A",
        createdAt: 100,
        accessCount: 0,
        lastAccessAt: null,
        protectedBundle: { iter: 200000 },
      },
      {
        sid: "sid-b",
        k: "kb",
        label: "B",
        createdAt: null,
        accessCount: 0,
        lastAccessAt: null,
        protectedBundle: { iter: null },
      },
    ]);
  });

  it("removes normalized local share references when revoked", async () => {
    installLocalStorage();
    state.items = [{
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      shares: [" sid-a ", { sid: "sid-b", k: "key-b" }],
    }];
    state.syncProjects = [{
      id: "project-1",
      itemsData: [{
        id: "item-2",
        type: "totp",
        secret: "JBSWY3DP",
        shares: [{ sid: " sid-a ", k: "key-a" }],
      }],
    }];
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("OK", { status: 200 }));

    await revokeShare(" sid-a ");

    expect(fetchMock.mock.calls[0][0]).toContain("/api/share/sid-a");
    expect(fetchMock.mock.calls[1][0]).toContain("/api/sharekey/sid-a");
    expect(state.items[0].shares).toEqual([{ sid: "sid-b", k: "key-b" }]);
    expect(state.syncProjects[0].itemsData[0].shares).toEqual([]);
  });

  it("keeps local share references when primary share deletion returns an error note", async () => {
    installLocalStorage();
    state.items = [{
      id: "item-1",
      type: "totp",
      secret: "JBSWY3DP",
      shares: [{ sid: "sid-a", k: "key-a" }],
    }];
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("Server Error", {
        status: 200,
        headers: { "X-Note": "error" },
      }))
      .mockResolvedValueOnce(new Response("OK", { status: 200 }));

    await expect(revokeShare("sid-a")).rejects.toThrow("删除分享失败");

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][0]).toContain("/api/sharekey/sid-a");
    expect(state.items[0].shares).toEqual([{ sid: "sid-a", k: "key-a" }]);
  });

  it("still attempts to delete share recovery material when share deletion fails", async () => {
    state.globalToken = "admin-token";
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("Missing", { status: 404 }))
      .mockResolvedValueOnce(new Response("OK", { status: 200 }));

    await expect(deleteRemoteShareResources(" sid-a ")).rejects.toThrow("HTTP 404");

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toContain("/api/share/sid-a");
    expect(fetchMock.mock.calls[1][0]).toContain("/api/sharekey/sid-a");
    expect(fetchMock.mock.calls[1][1].headers).toEqual({ "X-Token": "admin-token" });
  });
});
