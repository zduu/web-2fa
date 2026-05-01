import { afterEach, describe, expect, it, vi } from "vitest";

import { shouldAuditRequest, writeAuditLog } from "../functions/_lib/audit.js";

describe("shouldAuditRequest", () => {
  it("audits API write methods except the audit endpoint itself", () => {
    expect(shouldAuditRequest(new Request("https://example.com/api/share/demo", { method: "PUT" }))).toBe(true);
    expect(shouldAuditRequest(new Request("https://example.com/api/admin/list-all", { method: "POST" }))).toBe(true);
    expect(shouldAuditRequest(new Request("https://example.com/api/admin/audit", { method: "POST" }))).toBe(false);
  });

  it("ignores reads and non-api routes", () => {
    expect(shouldAuditRequest(new Request("https://example.com/api/share/demo", { method: "GET" }))).toBe(false);
    expect(shouldAuditRequest(new Request("https://example.com/shared.html", { method: "DELETE" }))).toBe(false);
  });
});

describe("writeAuditLog", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("writes a normalized audit record into AUTH_KV", async () => {
    const put = vi.fn(async () => {});
    vi.spyOn(Date, "now").mockReturnValue(1710000000000);
    vi.spyOn(Math, "random").mockReturnValue(0.123456);

    await writeAuditLog(
      { AUTH_KV: { put } },
      new Request("https://example.com/api/share/demo?foo=1", {
        method: "DELETE",
        headers: {
          "CF-Connecting-IP": "203.0.113.9",
          "User-Agent": "Vitest Browser UA",
        },
      }),
      new Response(null, { status: 401 }),
    );

    expect(put).toHaveBeenCalledTimes(1);
    const [key, raw, options] = put.mock.calls[0];
    expect(key).toMatch(/^audit:1710000000000:/);
    expect(options).toEqual({ expirationTtl: 30 * 24 * 3600 });
    expect(JSON.parse(raw)).toMatchObject({
      ts: 1710000000000,
      method: "DELETE",
      path: "/api/share/demo?foo=1",
      status: 401,
      uaSample: "Vitest Browser UA",
    });
    expect(JSON.parse(raw).ipSummary).toMatch(/^[0-9a-f]{12}$/);
  });
});
