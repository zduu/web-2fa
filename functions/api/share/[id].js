export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response('Missing id', { status: 400 });
  const key = `share:${id}`;
  const url = new URL(request.url);
  const ttlParam = url.searchParams.get('ttl');
  // default TTL from env; if <=0 or invalid => permanent by default
  let defaultTtl = Number(env.SHARE_TTL ?? 86400);
  let defaultPermanent = !(Number.isFinite(defaultTtl) && defaultTtl > 0);
  let usePermanent = defaultPermanent;
  let useTtl = defaultTtl;

  if (ttlParam) {
    const s = ttlParam.toLowerCase();
    if (s === 'perm' || s === 'permanent' || s === 'infinite' || s === 'forever' || s === '0') {
      usePermanent = true;
    } else {
      const n = Number(s);
      if (Number.isFinite(n) && n > 0) {
        usePermanent = false; useTtl = Math.round(n);
      }
    }
  }
  const needToken = !!env.SYNC_TOKEN;
  const tokenHeader = request.headers.get('X-Token');

  if (request.method === 'GET' || request.method === 'HEAD') {
    const value = await env.AUTH_KV.get(key);
    if (!value) return new Response('Not found', { status: 404 });
    return request.method === 'HEAD'
      ? new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store' } })
      : new Response(value, { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
  }

  if (request.method === 'PUT' || request.method === 'POST') {
    if (needToken && tokenHeader !== env.SYNC_TOKEN) return new Response('Unauthorized', { status: 401 });
    const text = await request.text();
    try {
      const obj = JSON.parse(text);
      if (!obj || typeof obj !== 'object' || !obj.iv || !obj.ct) throw new Error('invalid');
    } catch {
      return new Response('Bad Request', { status: 400 });
    }
    if (usePermanent) {
      await env.AUTH_KV.put(key, text);
    } else {
      await env.AUTH_KV.put(key, text, { expirationTtl: useTtl });
    }
    return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  }

  if (request.method === 'DELETE') {
    if (needToken && tokenHeader !== env.SYNC_TOKEN) return new Response('Unauthorized', { status: 401 });
    await env.AUTH_KV.delete(key);
    // also delete stored key if present
    try { await env.AUTH_KV.delete(`sharekey:${id}`); } catch {}
    return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  }

  return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, HEAD, PUT, POST' } });
}
