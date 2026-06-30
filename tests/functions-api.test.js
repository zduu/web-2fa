import { describe, expect, it, vi } from "vitest";

import { getAccessGateState, saveAccessGateConfig } from "../functions/_lib/access-gate.js";
import {
  isAuthed,
  needsAuthForRead,
  needsAuthForWrite,
  timingSafeEqualString,
} from "../functions/_lib/auth.js";
import { normalizeKvSuffix, normalizeRouteId } from "../functions/_lib/ids.js";
import {
  normalizeHttpStatus,
  normalizeLimit,
  normalizeNonNegativeInteger,
  normalizeOptionalNonNegativeSafeInteger,
  normalizeOptionalTimestamp,
} from "../functions/_lib/numbers.js";
import { isCipherPayload, isVaultPayload } from "../functions/_lib/payload.js";
import { normalizeShareKeyPayload } from "../functions/_lib/share-key.js";
import { parseOptionalShareTtl, parseShareOptions } from "../functions/_lib/share-options.js";
import { getAllowedOrigin } from "../functions/_middleware.js";
import {
  onRequestGet as onAdminAccessGateGetRequest,
  onRequestPut as onAdminAccessGatePutRequest,
} from "../functions/api/admin/access-gate.js";
import { onRequestGet as onAdminAuditRequest } from "../functions/api/admin/audit.js";
import { onRequestPost as onAdminListAllRequest } from "../functions/api/admin/list-all.js";
import {
  onRequestGet as onGateGetRequest,
  onRequestPost as onGatePostRequest,
} from "../functions/api/gate.js";
import { onRequestGet as onHealthRequest } from "../functions/api/health.js";
import { onRequest as onShareRequest } from "../functions/api/share/[id].js";
import { onRequestGet as onShareListRequest } from "../functions/api/share/list.js";
import { onRequestGet as onShareStatRequest } from "../functions/api/share/stat.js";
import { onRequest as onShareKeyRequest } from "../functions/api/sharekey/[id].js";
import { onRequest as onSyncBackupRequest } from "../functions/api/sync-backup/[id].js";
import { onRequestGet as onSyncTrashRequest } from "../functions/api/sync-trash.js";
import { onRequest as onSyncRequest } from "../functions/api/sync/[id].js";
import { onRequest as onVaultRequest } from "../functions/api/vault/[id].js";

function authedPutContext(body, put = vi.fn(async () => {}), path = "/api/demo/id") {
  return authedContext({ method: "PUT", body, put, path });
}

function authedContext({
  method = "GET",
  body,
  put = vi.fn(async () => {}),
  get = vi.fn(async () => null),
  del = vi.fn(async () => {}),
  list = vi.fn(async () => ({ keys: [], list_complete: true })),
  path = "/api/demo/id",
  params = { id: "demo" },
} = {}) {
  return {
    request: new Request(`https://example.com${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-Token": "secret-token",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
    env: {
      ADMIN_KEY: "secret-token",
      AUTH_KV: {
        get,
        put,
        delete: del,
        list,
      },
    },
    params,
  };
}

describe("Functions API encrypted payload validation", () => {
  it("compares configured secrets without accepting length mismatches", () => {
    expect(timingSafeEqualString("secret-token", "secret-token")).toBe(true);
    expect(timingSafeEqualString("secret-token", "secret")).toBe(false);
    expect(timingSafeEqualString("secret", "secret-token")).toBe(false);
    expect(timingSafeEqualString("secret-token", "secret-tokem")).toBe(false);
    expect(timingSafeEqualString("secret-token", null)).toBe(false);
  });

  it("ignores blank auth environment keys and trims configured secrets", () => {
    expect(needsAuthForWrite({ ADMIN_KEY: "   ", SYNC_TOKEN: "" })).toBe(false);
    expect(needsAuthForRead({ ADMIN_KEY: "   ", SYNC_TOKEN: "" })).toBe(false);

    expect(needsAuthForWrite({ ADMIN_KEY: " secret-token " })).toBe(true);
    expect(needsAuthForRead({ ADMIN_KEY: " secret-token ", SYNC_MODE: " open " })).toBe(false);
    expect(needsAuthForRead({ ADMIN_KEY: " secret-token ", SYNC_MODE: " strict " })).toBe(true);

    expect(isAuthed({ ADMIN_KEY: " secret-token " }, "secret-token")).toBe(true);
    expect(isAuthed({ ADMIN_KEY: "   " }, "   ")).toBe(false);
  });

  it("allows localhost development origins by default but keeps configured CORS strict", () => {
    expect(getAllowedOrigin("http://localhost:5173", {})).toBe("http://localhost:5173");
    expect(getAllowedOrigin("https://127.0.0.1:8788", {})).toBe("https://127.0.0.1:8788");
    expect(getAllowedOrigin("http://[::1]:4173", {})).toBe("http://[::1]:4173");
    expect(getAllowedOrigin("https://app.example.com", {})).toBe("");

    expect(getAllowedOrigin("http://localhost:5173", { CORS_ORIGIN: "https://app.example.com" })).toBe("");
    expect(getAllowedOrigin("https://app.example.com", { CORS_ORIGIN: "https://app.example.com" })).toBe("https://app.example.com");
  });

  it("normalizes malformed numeric API fields to stable finite values", () => {
    expect(normalizeNonNegativeInteger("12.9")).toBe(12);
    expect(normalizeNonNegativeInteger("1e999")).toBe(0);
    expect(normalizeOptionalNonNegativeSafeInteger("1710000000000")).toBe(1710000000000);
    expect(normalizeOptionalNonNegativeSafeInteger("12.5")).toBeNull();
    expect(normalizeOptionalTimestamp("1710000000000.9")).toBe(1710000000000);
    expect(normalizeOptionalTimestamp("-1")).toBeNull();
    expect(normalizeHttpStatus("201.8")).toBe(201);
    expect(normalizeHttpStatus("1e999")).toBeNull();
    expect(normalizeLimit(null, { fallback: 100, min: 1, max: 200 })).toBe(100);
    expect(normalizeLimit("2.9", { fallback: 100, min: 1, max: 200 })).toBe(2);
    expect(normalizeLimit("1e999", { fallback: 100, min: 1, max: 200 })).toBe(100);
    expect(normalizeNonNegativeInteger("bad", { fallback: "7.9", max: "5.9" })).toBe(5);
    expect(normalizeNonNegativeInteger("bad", { fallback: "bad", max: "bad" })).toBe(0);
    expect(normalizeLimit("", { fallback: "bad", min: "2.9", max: "bad" })).toBe(100);
    expect(normalizeLimit("999", { fallback: "bad", min: "2.9", max: "bad" })).toBe(200);
    expect(normalizeLimit("1", { fallback: 10, min: 5, max: 3 })).toBe(5);
  });

  it("normalizes route ids and rejects KV namespace-like ids", () => {
    expect(normalizeRouteId(" demo ")).toBe("demo");
    expect(normalizeRouteId("")).toBe("");
    expect(normalizeRouteId("demo\nx")).toBe("");
    expect(normalizeRouteId("sync:demo")).toBe("");
    expect(normalizeKvSuffix(" share: demo ", "share:")).toBe("demo");
    expect(normalizeKvSuffix("share:share:demo", "share:")).toBe("");
  });

  it("accepts only non-empty string cipher fields", () => {
    expect(isCipherPayload({ iv: "iv", ct: "ciphertext" })).toBe(true);
    expect(isCipherPayload({ iv: " ", ct: "ciphertext" })).toBe(false);
    expect(isCipherPayload({ iv: "iv", ct: "" })).toBe(false);
    expect(isCipherPayload({ iv: 1, ct: "ciphertext" })).toBe(false);
    expect(isCipherPayload(null)).toBe(false);
  });

  it("accepts current and legacy vault ciphertext shapes", () => {
    const cipher = { ek: "encrypted-key", iv: "iv", ct: "ciphertext" };

    expect(isVaultPayload({ v: 2, recipients: [{ kid: "admin", name: "Admin", cipher }] })).toBe(true);
    expect(isVaultPayload(cipher)).toBe(true);
    expect(isVaultPayload({ v: 2, recipients: [{ kid: "admin", cipher: { ...cipher, ek: "" } }] })).toBe(false);
    expect(isVaultPayload({ v: 2, recipients: [] })).toBe(false);
  });

  it("normalizes share ttl and access limit query options", () => {
    expect(parseShareOptions({ defaultTtl: "30", maxParam: "3.9" })).toEqual({
      permanent: false,
      ttl: 60,
      maxAccess: 3,
    });
    expect(parseShareOptions({ defaultTtl: "86400", ttlParam: "perm", maxParam: "999999999" })).toEqual({
      permanent: true,
      ttl: 0,
      maxAccess: 1_000_000,
    });
    expect(parseShareOptions({ defaultTtl: "bad", ttlParam: "3600", maxParam: "-1" })).toEqual({
      permanent: false,
      ttl: 3600,
      maxAccess: 0,
    });
    expect(parseShareOptions({ defaultTtl: "bad" })).toEqual({
      permanent: false,
      ttl: 86400,
      maxAccess: 0,
    });
    expect(parseShareOptions({ defaultTtl: "0" })).toEqual({
      permanent: true,
      ttl: 0,
      maxAccess: 0,
    });
    expect(parseOptionalShareTtl(null)).toBeUndefined();
    expect(parseOptionalShareTtl("30")).toBe(60);
    expect(parseOptionalShareTtl("perm")).toBe(0);
  });

  it("accepts only usable share recovery key payloads", () => {
    expect(normalizeShareKeyPayload({ k: " share-key ", label: " GitHub " })).toEqual({
      k: "share-key",
      label: "GitHub",
    });
    expect(normalizeShareKeyPayload({ k: "share-key", requiresPassword: "false" })).toEqual({
      k: "share-key",
      requiresPassword: false,
    });
    expect(normalizeShareKeyPayload({
      k: "",
      requiresPassword: true,
      createdAt: "1710000000000.9",
      maxAccess: "3.9",
      protectedBundle: {
        s: " salt ",
        iv: " iv ",
        wk: " wrapped ",
        iter: "200000.9",
      },
    })).toEqual({
      k: "",
      requiresPassword: true,
      createdAt: 1710000000000,
      maxAccess: 3,
      protectedBundle: {
        s: "salt",
        iv: "iv",
        wk: "wrapped",
        iter: 200000,
      },
    });
    expect(normalizeShareKeyPayload({ k: "" })).toBeNull();
    expect(normalizeShareKeyPayload({ k: "", requiresPassword: true, protectedBundle: { s: "s", iv: "", wk: "wk" } })).toBeNull();
  });

  it("rejects sync payloads with non-string cipher fields", async () => {
    const put = vi.fn(async () => {});
    const res = await onSyncRequest(authedPutContext({ iv: 123, ct: { nested: true } }, put));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
  });

  it("prunes malformed and oldest sync backup keys after writing a new version", async () => {
    const put = vi.fn(async () => {});
    const del = vi.fn(async () => {});
    const get = vi.fn(async (key) => key === "sync:demo" ? JSON.stringify({ v: 1, iv: "old-iv", ct: "old-ct" }) : null);
    const list = vi.fn(async () => ({
      keys: [
        { name: "syncbak:demo:bad" },
        { name: "syncbak:demo:1000" },
        { name: "syncbak:demo:1001" },
        { name: "syncbak:demo:1002" },
        { name: "syncbak:demo:1003" },
        { name: "syncbak:demo:1004" },
        { name: "syncbak:demo:1005" },
      ],
      list_complete: true,
    }));

    const res = await onSyncRequest(authedContext({
      method: "PUT",
      body: { v: 1, iv: "iv", ct: "ciphertext" },
      get,
      put,
      del,
      list,
      path: "/api/sync/demo",
    }));

    expect(res.status).toBe(200);
    expect(del).toHaveBeenCalledWith("syncbak:demo:bad");
    expect(del).toHaveBeenCalledWith("syncbak:demo:1000");
    expect(del).not.toHaveBeenCalledWith("syncbak:demo:1005");
  });

  it("marks missing sync records as no-store", async () => {
    const res = await onSyncRequest(authedContext({
      get: vi.fn(async () => null),
      path: "/api/sync/demo",
    }));

    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("marks missing sync KV bindings as service unavailable", async () => {
    const getRes = await onSyncRequest({
      request: new Request("https://example.com/api/sync/demo"),
      env: {},
      params: { id: "demo" },
    });
    const putRes = await onSyncRequest({
      request: new Request("https://example.com/api/sync/demo", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iv: "iv", ct: "ciphertext" }),
      }),
      env: {},
      params: { id: "demo" },
    });

    for (const res of [getRes, putRes]) {
      expect(res.status).toBe(503);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      expect(res.headers.get("X-Note")).toBe("kv-missing");
      await expect(res.text()).resolves.toBe("Not configured");
    }
  });

  it("does not report failed sync soft deletes as successful", async () => {
    const get = vi.fn(async (key) => key === "sync:demo" ? JSON.stringify({ v: 1, iv: "iv", ct: "ciphertext" }) : null);
    const put = vi.fn(async (key) => {
      if (key === "synctomb:demo") throw new Error("kv down");
    });
    const del = vi.fn(async () => {});
    const res = await onSyncRequest(authedContext({
      method: "DELETE",
      get,
      put,
      del,
      path: "/api/sync/demo",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
    expect(del).not.toHaveBeenCalledWith("sync:demo");
  });

  it("requires list support for hard sync deletes so backups can be purged", async () => {
    const del = vi.fn(async () => {});
    const res = await onSyncRequest({
      request: new Request("https://example.com/api/sync/demo?hard=1", {
        method: "DELETE",
        headers: { "X-Token": "secret-token" },
      }),
      env: {
        ADMIN_KEY: "secret-token",
        AUTH_KV: { delete: del },
      },
      params: { id: "demo" },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.text()).resolves.toBe("Not configured");
    expect(del).not.toHaveBeenCalled();
  });

  it("does not report failed hard sync deletes as successful", async () => {
    const del = vi.fn(async (key) => {
      if (key === "synctomb:demo") throw new Error("kv down");
    });
    const res = await onSyncRequest(authedContext({
      method: "DELETE",
      del,
      list: vi.fn(async () => ({ keys: [], list_complete: true })),
      path: "/api/sync/demo?hard=1",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
    expect(del).toHaveBeenCalledWith("sync:demo");
    expect(del).toHaveBeenCalledWith("synctomb:demo");
  });

  it("rejects share payloads with blank cipher fields", async () => {
    const put = vi.fn(async () => {});
    const res = await onShareRequest(authedPutContext({ iv: " ", ct: "ciphertext" }, put));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
  });

  it("marks missing share records as no-store", async () => {
    const res = await onShareRequest(authedContext({
      get: vi.fn(async () => null),
      path: "/api/share/demo",
    }));

    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("marks missing share KV bindings as no-store", async () => {
    const res = await onShareRequest({
      request: new Request("https://example.com/api/share/demo"),
      env: {},
      params: { id: "demo" },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.text()).resolves.toBe("Not configured");
  });

  it("normalizes malformed share payload versions before returning them", async () => {
    const res = await onShareRequest(authedContext({
      method: "GET",
      get: vi.fn(async () => JSON.stringify({
        v: "1e999",
        iv: "iv",
        ct: "ciphertext",
        ttl: 0,
        expireAt: 0,
      })),
      path: "/api/share/demo",
    }));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      v: 1,
      iv: "iv",
      ct: "ciphertext",
    });
  });

  it("stores share payloads with normalized ttl and max access", async () => {
    const put = vi.fn(async () => {});
    const res = await onShareRequest(authedPutContext(
      { iv: "iv", ct: "ciphertext" },
      put,
      "/api/share/demo?ttl=30&max=3.9",
    ));

    expect(res.status).toBe(200);
    expect(put).toHaveBeenCalledTimes(1);
    const [key, raw, options] = put.mock.calls[0];
    expect(key).toBe("share:demo");
    expect(JSON.parse(raw)).toMatchObject({
      iv: "iv",
      ct: "ciphertext",
      max: 3,
      ttl: 60,
    });
    expect(options).toEqual({ expirationTtl: 60 });
  });

  it("normalizes route ids before writing cloud records", async () => {
    const put = vi.fn(async () => {});
    const res = await onShareRequest(authedContext({
      method: "PUT",
      body: { iv: "iv", ct: "ciphertext" },
      put,
      path: "/api/share/%20demo%20",
      params: { id: " demo " },
    }));

    expect(res.status).toBe(200);
    expect(put.mock.calls[0][0]).toBe("share:demo");
  });

  it("rejects route ids that would collide with KV namespaces", async () => {
    const put = vi.fn(async () => {});
    const share = await onShareRequest(authedContext({
      method: "PUT",
      body: { iv: "iv", ct: "ciphertext" },
      put,
      path: "/api/share/share%3Ademo",
      params: { id: "share:demo" },
    }));
    const sync = await onSyncRequest(authedContext({
      method: "PUT",
      body: { iv: "iv", ct: "ciphertext" },
      put,
      path: "/api/sync/demo%0Ax",
      params: { id: "demo\nx" },
    }));

    expect(share.status).toBe(400);
    expect(sync.status).toBe(400);
    expect(sync.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
  });

  it("treats stale share records as expired even before KV purges them", async () => {
    const del = vi.fn(async () => {});
    const put = vi.fn(async () => {});
    const get = vi.fn(async () => JSON.stringify({
      v: 1,
      iv: "iv",
      ct: "ciphertext",
      ttl: 60,
      expireAt: Date.now() - 1_000,
    }));
    const res = await onShareRequest(authedContext({
      method: "GET",
      get,
      put,
      del,
      path: "/api/share/demo",
    }));

    expect(res.status).toBe(410);
    expect(res.headers.get("X-Share-Reason")).toBe("expired");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
    expect(del).toHaveBeenCalledWith("share:demo");
    expect(del).toHaveBeenCalledWith("sharekey:demo");
    expect(del).toHaveBeenCalledWith("sharestat:demo");
  });

  it("does not report failed primary share deletes as successful revokes", async () => {
    const del = vi.fn(async (key) => {
      if (key === "share:demo") throw new Error("kv down");
    });
    const res = await onShareRequest(authedContext({
      method: "DELETE",
      del,
      path: "/api/share/demo",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
    expect(del).toHaveBeenCalledWith("share:demo");
  });

  it("sanitizes share access user agent samples before storing stats", async () => {
    const put = vi.fn(async () => {});
    const get = vi.fn(async () => JSON.stringify({
      v: 1,
      iv: "iv",
      ct: "ciphertext",
      count: 0,
      ttl: 0,
      expireAt: 0,
    }));
    const res = await onShareRequest({
      request: {
        method: "GET",
        url: "https://example.com/api/share/demo",
        headers: { get: (name) => name === "User-Agent" ? " App\u0000 Browser\nUA\t " : null },
      },
      env: {
        AUTH_KV: { get, put, delete: vi.fn(async () => {}) },
      },
      params: { id: "demo" },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("X-Access-Remaining")).toBe("unlimited");
    expect(put).toHaveBeenCalledWith("sharestat:demo", expect.any(String));
    expect(JSON.parse(put.mock.calls[0][1])).toMatchObject({
      accessCount: 1,
      accessUserAgentSample: "App Browser UA",
    });
  });

  it("stores share recovery keys with normalized ttl", async () => {
    const put = vi.fn(async () => {});
    const body = { k: "share-key" };
    const res = await onShareKeyRequest(authedPutContext(body, put, "/api/sharekey/demo?ttl=30"));

    expect(res.status).toBe(200);
    expect(put).toHaveBeenCalledWith("sharekey:demo", JSON.stringify(body), { expirationTtl: 60 });
  });

  it("does not report failed share recovery key writes as successful", async () => {
    const put = vi.fn(async () => {
      throw new Error("kv down");
    });
    const res = await onShareKeyRequest(authedPutContext({ k: "share-key" }, put, "/api/sharekey/demo"));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
  });

  it("rejects unusable share recovery key payloads before storing", async () => {
    const put = vi.fn(async () => {});
    const res = await onShareKeyRequest(authedPutContext({
      k: "",
      requiresPassword: true,
      protectedBundle: { s: "salt", iv: "", wk: "wrapped" },
    }, put, "/api/sharekey/demo"));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
  });

  it("marks missing share recovery keys as no-store", async () => {
    const res = await onShareKeyRequest(authedContext({
      get: vi.fn(async () => null),
      path: "/api/sharekey/demo",
    }));

    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("marks missing share recovery key KV bindings as no-store", async () => {
    const res = await onShareKeyRequest({
      request: new Request("https://example.com/api/sharekey/demo", {
        headers: { "X-Token": "secret-token" },
      }),
      env: { ADMIN_KEY: "secret-token" },
      params: { id: "demo" },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.text()).resolves.toBe("Not configured");
  });

  it("does not report failed share recovery key deletes as successful", async () => {
    const del = vi.fn(async () => {
      throw new Error("kv down");
    });
    const res = await onShareKeyRequest(authedContext({
      method: "DELETE",
      del,
      path: "/api/sharekey/demo",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
    expect(del).toHaveBeenCalledWith("sharekey:demo");
  });

  it("stores normalized password-protected share recovery bundles", async () => {
    const put = vi.fn(async () => {});
    const res = await onShareKeyRequest(authedPutContext({
      k: "",
      label: " GitHub ",
      requiresPassword: true,
      createdAt: "1710000000000.9",
      maxAccess: "3.9",
      protectedBundle: {
        s: " salt ",
        iv: " iv ",
        wk: " wrapped ",
        iter: "200000.9",
      },
    }, put, "/api/sharekey/demo?ttl=30"));

    expect(res.status).toBe(200);
    expect(put).toHaveBeenCalledTimes(1);
    const [key, raw, options] = put.mock.calls[0];
    expect(key).toBe("sharekey:demo");
    expect(JSON.parse(raw)).toEqual({
      k: "",
      label: "GitHub",
      requiresPassword: true,
      createdAt: 1710000000000,
      maxAccess: 3,
      protectedBundle: {
        s: "salt",
        iv: "iv",
        wk: "wrapped",
        iter: 200000,
      },
    });
    expect(options).toEqual({ expirationTtl: 60 });
  });

  it("normalizes malformed access gate timestamps from KV config", async () => {
    const gate = await getAccessGateState({
      ACCESS_GATE: "gate-password",
      AUTH_KV: {
        get: vi.fn(async () => JSON.stringify({ version: 1, enabled: true, updatedAt: "1e999" })),
        put: vi.fn(async () => {}),
      },
    });

    expect(gate).toMatchObject({
      enabled: true,
      hasRuntimeConfig: true,
      updatedAt: null,
    });
  });

  it("normalizes access gate runtime booleans from older KV config", async () => {
    const gate = await getAccessGateState({
      ACCESS_GATE: "gate-password",
      AUTH_KV: {
        get: vi.fn(async () => JSON.stringify({ version: "1e999", enabled: "false", updatedAt: "1000.9" })),
        put: vi.fn(async () => {}),
      },
    });

    expect(gate).toMatchObject({
      enabled: false,
      source: "kv",
      hasRuntimeConfig: true,
      updatedAt: 1000,
    });
  });

  it("trims configured access gate passwords before verification", async () => {
    const gate = await getAccessGateState({
      ACCESS_GATE: " gate-password ",
      AUTH_KV: {
        get: vi.fn(async () => null),
        put: vi.fn(async () => {}),
      },
    });
    const reference = await getAccessGateState({
      ACCESS_GATE: "gate-password",
      AUTH_KV: {
        get: vi.fn(async () => null),
        put: vi.fn(async () => {}),
      },
    });

    expect(gate).toMatchObject({
      enabled: true,
      source: "env",
      passwordConfigured: true,
    });
    expect(gate.cookieValue).toBe(reference.cookieValue);
    await expect(gate.verifyPassword("gate-password")).resolves.toBe(true);
    await expect(gate.verifyPassword(" gate-password ")).resolves.toBe(true);
    await expect(gate.verifyPassword({ password: "gate-password" })).resolves.toBe(false);
  });

  it("marks unauthorized admin access gate reads as no-store", async () => {
    const res = await onAdminAccessGateGetRequest({
      request: new Request("https://example.com/api/admin/access-gate", {
        headers: { "X-Token": "wrong-token" },
      }),
      env: { ADMIN_KEY: "secret-token" },
    });

    expect(res.status).toBe(401);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    await expect(res.json()).resolves.toMatchObject({ success: false });
  });

  it("requires a boolean true to enable the admin access gate", async () => {
    const put = vi.fn(async () => {});
    const res = await onAdminAccessGatePutRequest({
      request: new Request("https://example.com/api/admin/access-gate", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Token": "secret-token",
        },
        body: JSON.stringify({ enabled: "false" }),
      }),
      env: {
        ADMIN_KEY: "secret-token",
        ACCESS_GATE: "gate-password",
        AUTH_KV: {
          get: vi.fn(async () => null),
          put,
        },
      },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(put).toHaveBeenCalledTimes(1);
    expect(JSON.parse(put.mock.calls[0][1])).toMatchObject({ enabled: false });
    await expect(res.json()).resolves.toMatchObject({ success: true, enabled: false });
  });

  it("marks missing access gate KV bindings as no-store", async () => {
    const res = await onAdminAccessGatePutRequest({
      request: new Request("https://example.com/api/admin/access-gate", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Token": "secret-token",
        },
        body: JSON.stringify({ enabled: true }),
      }),
      env: {
        ADMIN_KEY: "secret-token",
        ACCESS_GATE: "gate-password",
      },
    });

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "AUTH_KV missing" });
  });

  it("requires boolean true when saving access gate config directly", async () => {
    const put = vi.fn(async () => {});
    const gate = await saveAccessGateConfig({
      ACCESS_GATE: "gate-password",
      AUTH_KV: {
        get: vi.fn(async () => null),
        put,
      },
    }, { enabled: "false" });

    expect(gate.enabled).toBe(false);
    expect(put).toHaveBeenCalledTimes(1);
    expect(JSON.parse(put.mock.calls[0][1])).toMatchObject({ enabled: false });
  });

  it("keeps access gate runtime cache scoped to each KV binding", async () => {
    const firstGet = vi.fn(async () => JSON.stringify({ version: 1, enabled: false, updatedAt: 1000 }));
    const secondGet = vi.fn(async () => null);

    const first = await getAccessGateState({
      ACCESS_GATE: "gate-password",
      AUTH_KV: { get: firstGet, put: vi.fn(async () => {}) },
    });
    const second = await getAccessGateState({
      ACCESS_GATE: "gate-password",
      AUTH_KV: { get: secondGet, put: vi.fn(async () => {}) },
    });

    expect(first).toMatchObject({
      enabled: false,
      hasRuntimeConfig: true,
      source: "kv",
    });
    expect(second).toMatchObject({
      enabled: true,
      hasRuntimeConfig: false,
      source: "env",
    });
    expect(firstGet).toHaveBeenCalledTimes(1);
    expect(secondGet).toHaveBeenCalledTimes(1);
  });

  it("builds access gate cookie tags without browser base64 globals", async () => {
    const originalBtoa = globalThis.btoa;
    try {
      delete globalThis.btoa;
      const gate = await getAccessGateState({
        ACCESS_GATE: "gate-password",
        AUTH_KV: {
          get: vi.fn(async () => null),
          put: vi.fn(async () => {}),
        },
      });

      expect(gate.enabled).toBe(true);
      expect(gate.cookieValue).toHaveLength(43);
      expect(gate.cookieValue).toMatch(/^[A-Za-z0-9_-]+$/);
    } finally {
      if (originalBtoa === undefined) delete globalThis.btoa;
      else globalThis.btoa = originalBtoa;
    }
  });

  it("rejects mismatched access gate cookies without caching the response", async () => {
    const res = await onGateGetRequest({
      request: new Request("https://example.com/api/gate", {
        headers: { Cookie: "cf_gate=short" },
      }),
      env: {
        ACCESS_GATE: "gate-password",
        AUTH_KV: {
          get: vi.fn(async () => null),
          put: vi.fn(async () => {}),
        },
      },
    });

    expect(res.status).toBe(403);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("marks access gate login failures as no-store", async () => {
    const cases = [
      {
        env: {},
        body: JSON.stringify({ password: "anything" }),
        status: 400,
      },
      {
        env: { ACCESS_GATE: "gate-password" },
        body: "{",
        status: 400,
      },
      {
        env: { ACCESS_GATE: "gate-password" },
        body: JSON.stringify({ password: "wrong" }),
        status: 401,
      },
    ];

    for (const item of cases) {
      const res = await onGatePostRequest({
        request: new Request("https://example.com/api/gate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: item.body,
        }),
        env: item.env,
      });

      expect(res.status).toBe(item.status);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
    }
  });

  it("trims access gate login passwords before verification", async () => {
    const res = await onGatePostRequest({
      request: new Request("https://example.com/api/gate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: " gate-password " }),
      }),
      env: {
        ACCESS_GATE: "gate-password",
        AUTH_KV: {
          get: vi.fn(async () => null),
          put: vi.fn(async () => {}),
        },
      },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Set-Cookie")).toContain("cf_gate=");
  });

  it("reports normalized share ttl in health checks", async () => {
    const res = await onHealthRequest({
      env: {
        AUTH_KV: { get: vi.fn(async () => null), put: vi.fn(async () => {}) },
        ADMIN_KEY: "secret-token",
        SHARE_TTL: "30",
      },
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      shareTtl: 60,
      sharePermanentByDefault: false,
    });
  });

  it("reports normalized auth configuration in health checks", async () => {
    const res = await onHealthRequest({
      env: {
        AUTH_KV: { get: vi.fn(async () => null), put: vi.fn(async () => {}) },
        ADMIN_KEY: "   ",
        SYNC_TOKEN: "",
        SYNC_MODE: " open ",
      },
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      ok: true,
      adminConfigured: false,
      syncMode: "open",
    });
  });

  it("normalizes malformed share stat records before returning them", async () => {
    const records = new Map([
      ["sharestat:bad", JSON.stringify({ accessCount: "1e999", lastAccessAt: "1e999", accessUserAgentSample: 123 })],
      ["sharestat:good", JSON.stringify({ accessCount: "2.9", lastAccessAt: "1710000000000.9", accessUserAgentSample: " Vitest\u0000 UA\n " })],
    ]);
    const res = await onShareStatRequest(authedContext({
      get: vi.fn(async (key) => records.get(key) || null),
      list: vi.fn(async () => ({
        keys: [{ name: "sharestat:bad" }, { name: "sharestat:good" }],
        list_complete: true,
      })),
      path: "/api/share/stat?sid=bad&sid=good",
    }));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      items: [
        { sid: "bad", accessCount: 0, lastAccessAt: null, accessUserAgentSample: "" },
        { sid: "good", accessCount: 2, lastAccessAt: 1710000000000, accessUserAgentSample: "Vitest UA" },
      ],
    });
  });

  it("marks missing share stat KV bindings as service unavailable", async () => {
    const res = await onShareStatRequest({
      request: new Request("https://example.com/api/share/stat?sid=sid-a", {
        headers: { "X-Token": "secret-token" },
      }),
      env: { ADMIN_KEY: "secret-token" },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "AUTH_KV missing" });
  });

  it("normalizes cloud share ids in list and stat responses", async () => {
    const records = new Map([
      ["sharestat: sid-a ", JSON.stringify({ accessCount: "2.9", lastAccessAt: "1710000000000.9" })],
      ["sharestat:other", JSON.stringify({ accessCount: 9, lastAccessAt: 1710000000001 })],
    ]);
    const shareList = await onShareListRequest(authedContext({
      list: vi.fn(async () => ({
        keys: [{ name: "share: sid-a " }, { name: "share: " }, { name: "share:sid-b" }, { name: "share:share:nested" }],
        list_complete: true,
      })),
      path: "/api/share/list",
    }));
    const shareStat = await onShareStatRequest(authedContext({
      get: vi.fn(async (key) => records.get(key) || null),
      list: vi.fn(async () => ({
        keys: [{ name: "sharestat: sid-a " }, { name: "sharestat:other" }, { name: "sharestat: " }, { name: "sharestat:share:nested" }],
        list_complete: true,
      })),
      path: "/api/share/stat?sid=%20sid-a%20",
    }));

    expect(shareList.status).toBe(200);
    await expect(shareList.json()).resolves.toEqual({ sids: ["sid-a", "sid-b"] });
    expect(shareStat.status).toBe(200);
    await expect(shareStat.json()).resolves.toEqual({
      items: [{ sid: "sid-a", accessCount: 2, lastAccessAt: 1710000000000, accessUserAgentSample: "" }],
    });
  });

  it("does not report share stat list failures as empty successful stats", async () => {
    const res = await onShareStatRequest(authedContext({
      get: vi.fn(async () => null),
      list: vi.fn(async () => { throw new Error("kv down"); }),
      path: "/api/share/stat?sid=sid-a",
    }));

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "Server Error", items: [] });
  });

  it("normalizes malformed audit records before returning them", async () => {
    const records = new Map([
      ["audit:bad", JSON.stringify({ ts: "1e999", method: "POST", path: "/api/bad", status: "1e999", ipSummary: "ip", uaSample: "ua" })],
      ["audit:good", JSON.stringify({ ts: "1710000000000.9", method: "DELETE", path: "/api/share/demo?token=secret&token=again&sid=sid-a", status: "201.8", ipSummary: "ip2", uaSample: " Vitest\u0000 UA\n " })],
    ]);
    const res = await onAdminAuditRequest(authedContext({
      get: vi.fn(async (key) => records.get(key) || null),
      list: vi.fn(async () => ({
        keys: [{ name: "audit:bad" }, { name: "audit:good" }],
        list_complete: true,
      })),
      path: "/api/admin/audit?limit=2.9",
    }));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      success: true,
      items: [
        { ts: 1710000000000, method: "DELETE", path: "/api/share/demo?token=redacted&sid=redacted", status: 201, ipSummary: "ip2", uaSample: "Vitest UA" },
        { ts: null, method: "POST", path: "/api/bad", status: null, ipSummary: "ip", uaSample: "ua" },
      ],
    });
  });

  it("marks missing admin audit KV bindings as service unavailable", async () => {
    const res = await onAdminAuditRequest({
      request: new Request("https://example.com/api/admin/audit", {
        headers: { "X-Token": "secret-token" },
      }),
      env: { ADMIN_KEY: "secret-token" },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "AUTH_KV missing" });
  });

  it("does not report audit list failures as empty successful logs", async () => {
    const res = await onAdminAuditRequest(authedContext({
      get: vi.fn(async () => null),
      list: vi.fn(async () => { throw new Error("kv down"); }),
      path: "/api/admin/audit",
    }));

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "Server Error" });
  });

  it("rejects vault payloads without a recoverable ciphertext", async () => {
    const put = vi.fn(async () => {});
    const res = await onVaultRequest(authedPutContext({ v: 2, recipients: [{ kid: "admin" }] }, put, "/api/vault/demo"));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
  });

  it("marks missing vault ciphertext as no-store", async () => {
    const res = await onVaultRequest(authedContext({
      get: vi.fn(async () => null),
      path: "/api/vault/demo",
    }));

    expect(res.status).toBe(404);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });

  it("marks missing vault KV methods with a kv-missing note", async () => {
    const getRes = await onVaultRequest({
      request: new Request("https://example.com/api/vault/demo"),
      env: {},
      params: { id: "demo" },
    });
    const putRes = await onVaultRequest({
      request: new Request("https://example.com/api/vault/demo", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ v: 2, recipients: [{ kid: "admin", cipher: { ek: "encrypted-key", iv: "iv", ct: "ciphertext" } }] }),
      }),
      env: { AUTH_KV: { get: vi.fn(async () => null) } },
      params: { id: "demo" },
    });
    const deleteRes = await onVaultRequest({
      request: new Request("https://example.com/api/vault/demo", { method: "DELETE" }),
      env: { AUTH_KV: { get: vi.fn(async () => null) } },
      params: { id: "demo" },
    });

    for (const res of [getRes, putRes, deleteRes]) {
      expect(res.status).toBe(200);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      expect(res.headers.get("X-Note")).toBe("kv-missing");
      await expect(res.text()).resolves.toBe("Not configured");
    }
  });

  it("stores valid vault ciphertext payloads", async () => {
    const put = vi.fn(async () => {});
    const body = { v: 2, recipients: [{ kid: "admin", cipher: { ek: "encrypted-key", iv: "iv", ct: "ciphertext" } }] };
    const res = await onVaultRequest(authedPutContext(body, put, "/api/vault/demo"));

    expect(res.status).toBe(200);
    expect(put).toHaveBeenCalledWith("vault:demo", JSON.stringify(body));
  });

  it("does not report vault KV read failures as missing ciphertext", async () => {
    const res = await onVaultRequest(authedContext({
      get: vi.fn(async () => { throw new Error("kv down"); }),
      path: "/api/vault/demo",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
  });

  it("does not report failed vault writes as successful", async () => {
    const put = vi.fn(async () => { throw new Error("kv down"); });
    const body = { v: 2, recipients: [{ kid: "admin", cipher: { ek: "encrypted-key", iv: "iv", ct: "ciphertext" } }] };
    const res = await onVaultRequest(authedPutContext(body, put, "/api/vault/demo"));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
  });

  it("does not report failed vault deletes as successful", async () => {
    const del = vi.fn(async () => { throw new Error("kv down"); });
    const res = await onVaultRequest(authedContext({
      method: "DELETE",
      del,
      path: "/api/vault/demo",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
    expect(del).toHaveBeenCalledWith("vault:demo");
  });

  it("rejects invalid sync backup restore timestamps", async () => {
    const put = vi.fn(async () => {});
    const res = await onSyncBackupRequest(authedContext({
      method: "POST",
      put,
      path: "/api/sync-backup/demo?ts=12.5",
    }));

    expect(res.status).toBe(400);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
  });

  it("marks missing sync backup KV bindings as service unavailable", async () => {
    const getRes = await onSyncBackupRequest({
      request: new Request("https://example.com/api/sync-backup/demo"),
      env: {},
      params: { id: "demo" },
    });
    const postRes = await onSyncBackupRequest({
      request: new Request("https://example.com/api/sync-backup/demo?ts=1710000000000", {
        method: "POST",
      }),
      env: {},
      params: { id: "demo" },
    });

    for (const res of [getRes, postRes]) {
      expect(res.status).toBe(503);
      expect(res.headers.get("Cache-Control")).toBe("no-store");
      expect(res.headers.get("X-Note")).toBe("kv-missing");
      await expect(res.text()).resolves.toBe("Not configured");
    }
  });

  it("requires list support when reading sync backups", async () => {
    const res = await onSyncBackupRequest({
      request: new Request("https://example.com/api/sync-backup/demo", {
        headers: { "X-Token": "secret-token" },
      }),
      env: {
        ADMIN_KEY: "secret-token",
        AUTH_KV: { get: vi.fn(async () => null) },
      },
      params: { id: "demo" },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.text()).resolves.toBe("Not configured");
  });

  it("normalizes sync trash tombstone timestamps", async () => {
    const records = new Map([
      ["synctomb:bad", JSON.stringify({ deletedAt: "1e999" })],
      ["synctomb:good", JSON.stringify({ deletedAt: "1710000000000.9" })],
    ]);
    const res = await onSyncTrashRequest(authedContext({
      get: vi.fn(async (key) => records.get(key) || null),
      list: vi.fn(async () => ({
        keys: [{ name: "synctomb:bad" }, { name: "synctomb:good" }, { name: "synctomb:sync:nested" }],
        list_complete: true,
      })),
      path: "/api/sync-trash",
    }));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      items: [
        { syncId: "good", deletedAt: 1710000000000 },
        { syncId: "bad", deletedAt: null },
      ],
    });
  });

  it("marks missing sync trash KV bindings as service unavailable", async () => {
    const res = await onSyncTrashRequest({
      request: new Request("https://example.com/api/sync-trash", {
        headers: { "X-Token": "secret-token" },
      }),
      env: { ADMIN_KEY: "secret-token" },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "AUTH_KV missing" });
  });

  it("does not report sync trash list failures as an empty trash", async () => {
    const res = await onSyncTrashRequest(authedContext({
      get: vi.fn(async () => null),
      list: vi.fn(async () => { throw new Error("kv down"); }),
      path: "/api/sync-trash",
    }));

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "Server Error", items: [] });
  });

  it("lists only safe integer sync backup timestamps", async () => {
    const records = new Map([
      ["synctomb:demo", JSON.stringify({ deletedAt: "1e999" })],
    ]);
    const res = await onSyncBackupRequest(authedContext({
      get: vi.fn(async (key) => records.get(key) || null),
      list: vi.fn(async () => ({
        keys: [
          { name: "syncbak:demo:1710000000000" },
          { name: "syncbak:demo:12.5" },
          { name: "syncbak:demo:-1" },
          { name: "syncbak:demo:1e999" },
          { name: "syncbak:demo:1710000000001" },
        ],
        list_complete: true,
      })),
      path: "/api/sync-backup/demo",
    }));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      id: "demo",
      tombstone: { deletedAt: null },
      backups: [
        { ts: 1710000000001, key: "syncbak:demo:1710000000001" },
        { ts: 1710000000000, key: "syncbak:demo:1710000000000" },
      ],
    });
  });

  it("does not report sync backup list failures as empty backups", async () => {
    const res = await onSyncBackupRequest(authedContext({
      get: vi.fn(async () => null),
      list: vi.fn(async () => { throw new Error("kv down"); }),
      path: "/api/sync-backup/demo",
    }));

    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.json()).resolves.toMatchObject({
      success: false,
      error: "Server Error",
      id: "demo",
      backups: [],
    });
  });

  it("rejects malformed sync backup payloads before restore", async () => {
    const put = vi.fn(async () => {});
    const get = vi.fn(async (key) => key === "syncbak:demo:1710000000000" ? JSON.stringify({ iv: 123, ct: "ciphertext" }) : null);
    const res = await onSyncBackupRequest(authedContext({
      method: "POST",
      get,
      put,
      path: "/api/sync-backup/demo?ts=1710000000000",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(put).not.toHaveBeenCalled();
  });

  it("reports sync backup read failures with explicit error notes", async () => {
    const put = vi.fn(async () => {});
    const res = await onSyncBackupRequest(authedContext({
      method: "POST",
      get: vi.fn(async () => { throw new Error("kv down"); }),
      put,
      path: "/api/sync-backup/demo?ts=1710000000000",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
    expect(put).not.toHaveBeenCalled();
  });

  it("does not report failed sync backup restores as successful", async () => {
    const payload = JSON.stringify({ v: 1, iv: "iv", ct: "ciphertext" });
    const put = vi.fn(async () => { throw new Error("kv down"); });
    const get = vi.fn(async (key) => key === "syncbak:demo:1710000000000" ? payload : null);
    const res = await onSyncBackupRequest(authedContext({
      method: "POST",
      get,
      put,
      path: "/api/sync-backup/demo?ts=1710000000000",
    }));

    expect(res.status).toBe(500);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("error");
    await expect(res.text()).resolves.toBe("Server Error");
    expect(put).toHaveBeenCalledWith("sync:demo", payload, { expirationTtl: 60 * 60 * 24 * 365 });
  });

  it("restores valid sync backup ciphertext payloads", async () => {
    const put = vi.fn(async () => {});
    const payload = JSON.stringify({ v: 1, iv: "iv", ct: "ciphertext" });
    const get = vi.fn(async (key) => key === "syncbak:demo:1710000000000" ? payload : null);
    const res = await onSyncBackupRequest(authedContext({
      method: "POST",
      get,
      put,
      path: "/api/sync-backup/demo?ts=1710000000000",
    }));

    expect(res.status).toBe(200);
    expect(put).toHaveBeenCalledWith("sync:demo", payload, { expirationTtl: 60 * 60 * 24 * 365 });
  });

  it("marks unauthorized admin list-all responses as no-store", async () => {
    const res = await onAdminListAllRequest({
      request: new Request("https://example.com/api/admin/list-all", {
        method: "POST",
        headers: { "X-Token": "wrong-token" },
      }),
      env: {
        ADMIN_KEY: "secret-token",
        AUTH_KV: {
          get: vi.fn(async () => null),
          list: vi.fn(async () => ({ keys: [], list_complete: true })),
        },
      },
    });

    expect(res.status).toBe(401);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("Content-Type")).toBe("application/json; charset=utf-8");
  });

  it("treats blank admin list-all keys as unconfigured", async () => {
    const res = await onAdminListAllRequest({
      request: new Request("https://example.com/api/admin/list-all", { method: "POST" }),
      env: {
        ADMIN_KEY: "   ",
        SYNC_TOKEN: "",
        KV_ADMIN_KEY: "   ",
        AUTH_KV: {
          get: vi.fn(async () => null),
          list: vi.fn(async () => ({ keys: [], list_complete: true })),
        },
      },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("X-Note")).toBe("admin_key_missing");
    await expect(res.json()).resolves.toMatchObject({ success: false });
  });

  it("marks missing admin list-all KV bindings as service unavailable", async () => {
    const res = await onAdminListAllRequest({
      request: new Request("https://example.com/api/admin/list-all", {
        method: "POST",
        headers: { "X-Token": "secret-token" },
      }),
      env: { ADMIN_KEY: "secret-token" },
    });

    expect(res.status).toBe(503);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(res.headers.get("X-Note")).toBe("kv-missing");
    await expect(res.json()).resolves.toMatchObject({ success: false, error: "AUTH_KV missing" });
  });

  it("marks malformed cloud sync records in admin list-all", async () => {
    const records = new Map([
      ["sync:good", JSON.stringify({ v: "2.9", iv: "iv", ct: "ciphertext" })],
      ["sync:bad", JSON.stringify({ v: "1e999", iv: 123, ct: "ciphertext" })],
    ]);
    const res = await onAdminListAllRequest(authedContext({
      method: "POST",
      get: vi.fn(async (key) => records.get(key) || null),
      list: vi.fn(async () => ({
        keys: [
          { name: "sync:good", metadata: { updatedAt: "1000.9" } },
          { name: "sync:bad", metadata: { updatedAt: "1e999" } },
          { name: "sync:sync:nested", metadata: { updatedAt: "1001" } },
        ],
        list_complete: true,
      })),
      path: "/api/admin/list-all",
    }));

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.projects).toEqual(expect.arrayContaining([
      expect.objectContaining({
        syncId: "good",
        metadata: expect.objectContaining({ version: 2, hasData: true, valid: true, updatedAt: 1000 }),
      }),
      expect.objectContaining({
        syncId: "bad",
        metadata: expect.objectContaining({ version: 1, hasData: false, valid: false, updatedAt: null }),
      }),
    ]));
    expect(body.projects.map((project) => project.syncId)).not.toContain("sync:nested");
  });
});
