export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response('Missing id', { status: 400 });

  const key = `sync:${id}`;
  const tokenHeader = request.headers.get('X-Token');
  const needToken = !!env.SYNC_TOKEN;

  if (request.method === 'GET') {
    if (needToken && tokenHeader !== env.SYNC_TOKEN) {
      return new Response('Unauthorized', { status: 401 });
    }
    const value = await env.AUTH_KV.get(key);
    if (!value) return new Response('Not found', { status: 404 });
    return new Response(value, { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
  }

  if (request.method === 'PUT' || request.method === 'POST') {
    if (needToken && tokenHeader !== env.SYNC_TOKEN) return new Response('Unauthorized', { status: 401 });
    const text = await request.text();
    try {
      // Validate JSON payload shape: { v, iv, ct }
      const obj = JSON.parse(text);
      if (!obj || typeof obj !== 'object' || !obj.iv || !obj.ct) throw new Error('invalid');
    } catch {
      return new Response('Bad Request', { status: 400 });
    }
    await env.AUTH_KV.put(key, text, { expirationTtl: 60 * 60 * 24 * 365 }); // 1 year
    return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  }

  return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, PUT, POST' } });
}
