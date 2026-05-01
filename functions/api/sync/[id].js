// 同步存储端点
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN 任一即可（向后兼容）
// strict 模式（默认）：GET 也需鉴权；open 模式：GET 开放

function isAuthed(env, token) {
  if (!token) return false;
  if (env.ADMIN_KEY && token === env.ADMIN_KEY) return true;
  if (env.SYNC_TOKEN && token === env.SYNC_TOKEN) return true;
  return false;
}

function needsAuthForRead(env) {
  // SYNC_MODE = "strict" (default) | "open"
  // strict: read requires auth; open: read is public
  // If neither ADMIN_KEY nor SYNC_TOKEN configured, read is public regardless
  if (!env.ADMIN_KEY && !env.SYNC_TOKEN) return false;
  const mode = (env.SYNC_MODE || "strict").toLowerCase();
  return mode !== "open";
}

function needsAuthForWrite(env) {
  // Write requires auth if any token is configured
  return !!(env.ADMIN_KEY || env.SYNC_TOKEN);
}

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response('Missing id', { status: 400 });

  const key = `sync:${id}`;
  const tokenHeader = request.headers.get('X-Token');

  if (request.method === 'GET') {
    if (needsAuthForRead(env) && !isAuthed(env, tokenHeader)) {
      return new Response('Unauthorized', { status: 401 });
    }
    const value = await env.AUTH_KV.get(key);
    if (!value) return new Response('Not found', { status: 404 });
    return new Response(value, { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
  }

  if (request.method === 'PUT' || request.method === 'POST') {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) {
      return new Response('Unauthorized', { status: 401 });
    }
    const text = await request.text();
    try {
      const obj = JSON.parse(text);
      if (!obj || typeof obj !== 'object' || !obj.iv || !obj.ct) throw new Error('invalid');
    } catch {
      return new Response('Bad Request', { status: 400 });
    }
    await env.AUTH_KV.put(key, text, { expirationTtl: 60 * 60 * 24 * 365 });
    return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  }

  if (request.method === 'DELETE') {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) {
      return new Response('Unauthorized', { status: 401 });
    }
    await env.AUTH_KV.delete(key);
    return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  }

  return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, PUT, POST, DELETE' } });
}
