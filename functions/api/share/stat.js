// 分享访问统计（管理员）
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();

  const url = new URL(request.url);
  const wanted = new Set(url.searchParams.getAll("sid").map((v) => String(v || "").trim()).filter(Boolean));
  const items = [];

  try {
    let cursor;
    do {
      const res = await env.AUTH_KV.list({ prefix: "sharestat:", cursor });
      for (const k of res.keys) {
        const sid = k.name.startsWith("sharestat:") ? k.name.slice("sharestat:".length) : k.name;
        if (wanted.size && !wanted.has(sid)) continue;
        let raw = null;
        try { raw = JSON.parse(await env.AUTH_KV.get(k.name) || "null"); } catch {}
        if (!raw) continue;
        items.push({
          sid,
          accessCount: Math.max(0, Number(raw.accessCount || 0)),
          lastAccessAt: Number(raw.lastAccessAt || 0) || null,
          accessUserAgentSample: typeof raw.accessUserAgentSample === "string" ? raw.accessUserAgentSample : "",
        });
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
  } catch {}

  return new Response(JSON.stringify({ items }), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
