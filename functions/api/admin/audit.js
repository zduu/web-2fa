// 审计日志（管理员）
// 鉴权：X-KV-Admin-Key 或 X-Token

import { isAdminAuthed } from "../../_lib/auth.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  if (!isAdminAuthed(env, request)) {
    return new Response(JSON.stringify({ success: false, error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  const url = new URL(request.url);
  const limit = Math.max(1, Math.min(200, Number(url.searchParams.get("limit") || 100) || 100));
  const items = [];

  try {
    let cursor;
    do {
      const res = await env.AUTH_KV.list({ prefix: "audit:", cursor });
      for (const k of res.keys) {
        let raw = null;
        try { raw = JSON.parse(await env.AUTH_KV.get(k.name) || "null"); } catch {}
        if (!raw) continue;
        items.push({
          ts: Number(raw.ts || 0) || null,
          method: typeof raw.method === "string" ? raw.method : "",
          path: typeof raw.path === "string" ? raw.path : "",
          status: Number(raw.status || 0) || null,
          ipSummary: typeof raw.ipSummary === "string" ? raw.ipSummary : "",
          uaSample: typeof raw.uaSample === "string" ? raw.uaSample : "",
        });
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch {}

  items.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));

  return new Response(JSON.stringify({ success: true, items: items.slice(0, limit) }), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
