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
      {
        url: "https://example.com/api/share/demo?foo=secret&foo=again&token=super-secret",
        method: "DELETE",
        headers: {
          get(name) {
            if (name === "CF-Connecting-IP") return "203.0.113.9";
            if (name === "User-Agent") return " Vitest\u0000 Browser\nUA\t ";
            return null;
          },
        },
      },
      new Response(null, { status: 401 }),
    );

    expect(put).toHaveBeenCalledTimes(1);
    const [key, raw, options] = put.mock.calls[0];
    expect(key).toMatch(/^audit:1710000000000:/);
    expect(options).toEqual({ expirationTtl: 30 * 24 * 3600 });
    expect(JSON.parse(raw)).toMatchObject({
      ts: 1710000000000,
      method: "DELETE",
      path: "/api/share/demo?foo=redacted&token=redacted",
      status: 401,
      uaSample: "Vitest Browser UA",
    });
    expect(raw).not.toContain("super-secret");
    expect(raw).not.toContain("again");
    expect(JSON.parse(raw).ipSummary).toMatch(/^[0-9a-f]{12}$/);
  });
});
