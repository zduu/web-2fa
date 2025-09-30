export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response('Missing id', { status: 400 });
  const key = `vault:${id}`;

  // Require SYNC_TOKEN if configured (reuse server token for auth)
  const needToken = !!env.SYNC_TOKEN;
  const tokenHeader = request.headers.get('X-Token');
  if (needToken && tokenHeader !== env.SYNC_TOKEN) {
    return new Response('Unauthorized', { status: 401 });
  }

  if (!env.AUTH_KV || !env.AUTH_KV.get) {
    // KV not configured: avoid 500s
    return new Response('Not configured', { status: 200, headers: { 'Cache-Control': 'no-store', 'X-Note': 'kv-missing' } });
  }

  try {
    if (request.method === 'GET') {
      const value = await env.AUTH_KV.get(key);
      if (!value) return new Response('Not found', { status: 404 });
      return new Response(value, { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
    }

    if (request.method === 'PUT' || request.method === 'POST') {
      const text = await request.text();
      // Store as-is (already encrypted on client)
      await env.AUTH_KV.put(key, text);
      return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
    }

    if (request.method === 'DELETE') {
      await env.AUTH_KV.delete(key);
      return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
    }

    return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, PUT, POST, DELETE' } });
  } catch (e) {
    // Avoid 500 noise
    return new Response('Error', { status: 200, headers: { 'Cache-Control': 'no-store', 'X-Note': 'error' } });
  }
}

