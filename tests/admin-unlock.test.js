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

  it("still treats non-admin-key-missing 200 responses as valid (server errors don't invalidate the key)", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify({
      success: false,
      error: "Server Error",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));

    // 200 且非 admin_key_missing → 鉴权已通过（服务端内部错误不影响 Key 有效性）
    await expect(verifyAdminKey("admin-token")).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("treats non-401 share-list fallback as key-verified (server errors don't invalidate the key)", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 503 }))
      .mockResolvedValueOnce(new Response("Server Error", { status: 500 }));

    // 500 不是 401 → Key 正确，服务端内部错误不影响判断
    await expect(verifyAdminKey("admin-token")).resolves.toEqual({ ok: true });
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

  it("treats unknown X-Note headers in share-list as non-blocking", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: false }), { status: 503 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ sids: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Note": "list-error" },
      }));

    // 未知 X-Note 不影响 Key 有效性判断（只有 kv-missing 需要特殊提示）
    await expect(verifyAdminKey("admin-token")).resolves.toEqual({ ok: true });
  });
});
