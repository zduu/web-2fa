// 列出云端分享 SID
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN
function isAuthed(env, token) {
  if (!token) return false;
  if (env.ADMIN_KEY && token === env.ADMIN_KEY) return true;
  if (env.SYNC_TOKEN && token === env.SYNC_TOKEN) return true;
  return false;
}
function needsAuth(env) { return !!(env.ADMIN_KEY || env.SYNC_TOKEN); }

export async function onRequestGet(context) {
  const { env, request } = context;
  const tokenHeader = request.headers.get('X-Token');
  if (needsAuth(env) && !isAuthed(env, tokenHeader)) return new Response('Unauthorized', { status: 401 });
  try {
    const out = [];
    let cursor = undefined;
    do {
      if (!env.AUTH_KV || !env.AUTH_KV.list) {
        return new Response(JSON.stringify({ sids: [] }), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Note': 'kv-missing' } });
      }
      const res = await env.AUTH_KV.list({ prefix: 'share:', cursor });
      for (const k of res.keys) {
        const name = k.name.startsWith('share:') ? k.name.slice('share:'.length) : k.name;
        out.push(name);
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);
    return new Response(JSON.stringify({ sids: out }), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
  } catch {
    return new Response(JSON.stringify({ sids: [] }), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Note': 'list-error' } });
  }
}
