// 分享访问统计（管理员）
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";
import { normalizeKvSuffix } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingJsonResponse } from "../../_lib/kv.js";
import { normalizeNonNegativeInteger, normalizeOptionalTimestamp } from "../../_lib/numbers.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
  if (!hasKvMethods(env, ["list", "get"])) return kvMissingJsonResponse();

  const url = new URL(request.url);
  const wanted = new Set(url.searchParams.getAll("sid").map((v) => normalizeKvSuffix(v)).filter(Boolean));
  const items = [];

  try {
    let cursor;
    do {
      const res = await env.AUTH_KV.list({ prefix: "sharestat:", cursor });
      for (const k of res.keys) {
        const sid = normalizeKvSuffix(k.name, "sharestat:");
        if (!sid) continue;
        if (wanted.size && !wanted.has(sid)) continue;
        let raw = null;
        try { raw = JSON.parse(await env.AUTH_KV.get(k.name) || "null"); } catch {}
        if (!raw) continue;
        items.push({
          sid,
          accessCount: normalizeNonNegativeInteger(raw.accessCount),
          lastAccessAt: normalizeOptionalTimestamp(raw.lastAccessAt),
          accessUserAgentSample: sanitizeUserAgent(raw.accessUserAgentSample),
        });
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch {
    return json({ success: false, error: "Server Error", items: [] }, 200, { "X-Note": "error" });
  }

  return json({ items });
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

function sanitizeUserAgent(value) {
  if (typeof value !== "string") return "";
  const text = String(value || "").replace(/[\x00-\x1F\x7F]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.slice(0, 160) : "";
}
