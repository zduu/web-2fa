// 列出所有 synctomb:* 项目（已软删除待恢复）
import { isAuthed, needsAuthForWrite, unauthorized } from "../_lib/auth.js";
import { normalizeKvSuffix } from "../_lib/ids.js";
import { hasKvMethods, kvMissingJsonResponse } from "../_lib/kv.js";
import { normalizeOptionalTimestamp } from "../_lib/numbers.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
  if (!hasKvMethods(env, ["list", "get"])) return kvMissingJsonResponse();
  const out = [];
  try {
    let cursor;
    do {
      const r = await env.AUTH_KV.list({ prefix: "synctomb:", cursor });
      for (const k of r.keys) {
        const id = normalizeKvSuffix(k.name, "synctomb:");
        if (!id) continue;
        let tomb = null;
        try { tomb = JSON.parse(await env.AUTH_KV.get(k.name) || "null"); } catch {}
        out.push({ syncId: id, deletedAt: normalizeOptionalTimestamp(tomb?.deletedAt) });
      }
      cursor = r.list_complete ? undefined : r.cursor;
    } while (cursor);
  } catch {
    return json({ success: false, error: "Server Error", items: [] }, 200, { "X-Note": "error" });
  }
  out.sort((a, b) => (b.deletedAt || 0) - (a.deletedAt || 0));
  return json({ items: out });
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}
