// 审计日志（管理员）
// 鉴权：X-KV-Admin-Key 或 X-Token

import { isAdminAuthed } from "../../_lib/auth.js";
import { hasKvMethods, kvMissingJsonResponse } from "../../_lib/kv.js";
import { normalizeHttpStatus, normalizeLimit, normalizeOptionalTimestamp } from "../../_lib/numbers.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  if (!isAdminAuthed(env, request)) {
    return new Response(JSON.stringify({ success: false, error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  const url = new URL(request.url);
  const limit = normalizeLimit(url.searchParams.get("limit"), { fallback: 100, min: 1, max: 200 });
  const items = [];

  if (!hasKvMethods(env, ["list", "get"])) {
    return kvMissingJsonResponse();
  }

  try {
    let cursor;
    do {
      const res = await env.AUTH_KV.list({ prefix: "audit:", cursor });
      for (const k of res.keys) {
        let raw = null;
        try { raw = JSON.parse(await env.AUTH_KV.get(k.name) || "null"); } catch {}
        if (!raw) continue;
        items.push({
          ts: normalizeOptionalTimestamp(raw.ts),
          method: typeof raw.method === "string" ? raw.method : "",
          path: sanitizeAuditPath(raw.path),
          status: normalizeHttpStatus(raw.status),
          ipSummary: typeof raw.ipSummary === "string" ? raw.ipSummary : "",
          uaSample: sanitizeAuditUserAgent(raw.uaSample),
        });
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch {
    return json({ success: false, error: "Server Error" }, 200, { "X-Note": "error" });
  }

  items.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));

  return json({ success: true, items: items.slice(0, limit) });
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

function sanitizeAuditPath(value) {
  const text = String(value || "");
  if (!text) return "";
  try {
    const url = new URL(text, "https://audit.local");
    const queryKeys = Array.from(new Set(url.searchParams.keys()));
    const redactedSearch = queryKeys.length
      ? `?${queryKeys.map((key) => `${encodeURIComponent(key)}=redacted`).join("&")}`
      : "";
    return `${url.pathname}${redactedSearch}`.slice(0, 200);
  } catch {
    return text.split("?")[0].slice(0, 200);
  }
}

function sanitizeAuditUserAgent(value) {
  if (typeof value !== "string") return "";
  const text = value.replace(/[\x00-\x1F\x7F]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.slice(0, 160) : "";
}
