import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { verifyAdminKey } from "../src/admin/unlock.js";

function setRuntimeConfig(config = {}) {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { __APP_RUNTIME__: config },
  });
}

beforeEach(() => {
  setRuntimeConfig({});
});

afterEach(() => {
  vi.restoreAllMocks();
  delete globalThis.window;
});

describe("admin unlock", () => {
  it("falls back to share-list probing when admin list-all is unavailable", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 503 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ sids: [] }), { status: 200 }));

    await expect(verifyAdminKey("admin-token")).resolves.toEqual({ ok: true });
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      "/api/admin/list-all",
      "/api/share/list",
    ]);
  });

  it("falls back when admin list-all reports missing admin-key configuration", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({
        success: false,
        error: "No admin key configured on server",
      }), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Note": "admin_key_missing" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ sids: [] }), { status: 200 }));

    await expect(verifyAdminKey("admin-token")).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not accept admin list-all success-false responses as valid keys", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify({
      success: false,
      error: "Server Error",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    await expect(verifyAdminKey("admin-token")).resolves.toEqual({
      ok: false,
      msg: "Server Error",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not accept non-2xx share-list fallback responses", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 503 }))
      .mockResolvedValueOnce(new Response("Server Error", { status: 500 }));

    await expect(verifyAdminKey("admin-token")).resolves.toEqual({
      ok: false,
      msg: "HTTP 500",
    });
  });

  it("does not accept share-list fallback responses with error notes", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 503 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ sids: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Note": "kv-missing" },
      }));

    await expect(verifyAdminKey("admin-token")).resolves.toEqual({
      ok: false,
      msg: "服务端未绑定 AUTH_KV",
    });
  });

  it("does not accept share-list fallback list-error notes", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 503 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ sids: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Note": "list-error" },
      }));

    await expect(verifyAdminKey("admin-token")).resolves.toEqual({
      ok: false,
      msg: "Admin Key 验证失败",
    });
  });
});
