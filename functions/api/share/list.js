export async function onRequestGet(context) {
  const { env, request } = context;
  const needToken = !!env.SYNC_TOKEN;
  const tokenHeader = request.headers.get('X-Token');
  if (needToken && tokenHeader !== env.SYNC_TOKEN) return new Response('Unauthorized', { status: 401 });
  try {
    const out = [];
    let cursor = undefined;
    do {
      if (!env.AUTH_KV || !env.AUTH_KV.list) {
        // KV not configured: treat as no shares instead of 500
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
  } catch (e) {
    // Return empty list on runtime errors to avoid noisy 500s in UI
    return new Response(JSON.stringify({ sids: [] }), { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Note': 'list-error' } });
  }
}
