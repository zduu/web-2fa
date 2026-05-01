// 列出云端分享 SID
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
  try {
    const out = [];
    let cursor;
    do {
      if (!env.AUTH_KV || !env.AUTH_KV.list) {
        return new Response(JSON.stringify({ sids: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Note": "kv-missing" },
        });
      }
      const res = await env.AUTH_KV.list({ prefix: "share:", cursor });
      for (const k of res.keys) {
        const name = k.name.startsWith("share:") ? k.name.slice("share:".length) : k.name;
        out.push(name);
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
    return new Response(JSON.stringify({ sids: out }), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  } catch {
    return new Response(JSON.stringify({ sids: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Note": "list-error" },
    });
  }
}
