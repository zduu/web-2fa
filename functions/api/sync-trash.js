// 列出所有 synctomb:* 项目（已软删除待恢复）
import { isAuthed, needsAuthForWrite, unauthorized } from "../_lib/auth.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
  const out = [];
  try {
    let cursor;
    do {
      const r = await env.AUTH_KV.list({ prefix: "synctomb:", cursor });
      for (const k of r.keys) {
        const id = k.name.slice("synctomb:".length);
        let tomb = null;
        try { tomb = JSON.parse(await env.AUTH_KV.get(k.name) || "null"); } catch {}
        out.push({ syncId: id, deletedAt: tomb?.deletedAt || null });
      }
      cursor = r.list_complete ? undefined : r.cursor;
    } while (cursor);
  } catch {}
  out.sort((a, b) => Number(b.deletedAt || 0) - Number(a.deletedAt || 0));
  return new Response(JSON.stringify({ items: out }), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
