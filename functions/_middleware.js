export const onRequest = async (ctx) => {
  const { request, env } = ctx;
  const url = new URL(request.url);
  const path = url.pathname;

  const gate = env.ACCESS_GATE;
  if (!gate) return await ctx.next();

  // Always allow these paths
  const allowPrefixes = [
    "/api/gate",
    "/shared.html",
    "/shared.js",
    "/api/share/", // GET/HEAD allowed below, writes will be gated
    "/manifest.webmanifest",
    "/icon.svg",
    "/icon-maskable.svg",
    "/styles.css",
    "/sw.js",
    "/favicon.ico",
  ];
  if (allowPrefixes.some((p) => path.startsWith(p))) {
    return await ctx.next();
  }

  // Gate only protects APIs and site interaction; static pages are allowed to load.
  // For APIs, require cookie except for share GET/HEAD.
  const cookie = request.headers.get('Cookie') || '';
  const want = await sha256b64url(gate);
  const got = parseCookie(cookie).get('cf_gate');
  const hasCookie = !!(got && timingSafeEqual(got, want));

  if (path.startsWith('/api/')) {
    // Allow sharekey with valid X-Token regardless of cookie
    if (path.startsWith('/api/sharekey/')) {
      const token = request.headers.get('X-Token');
      if (env.SYNC_TOKEN && token === env.SYNC_TOKEN) return await ctx.next();
      // otherwise require cookie
      if (!hasCookie) return new Response('Unauthorized', { status: 401, headers: { 'Cache-Control': 'no-store', 'X-Gate': 'required' } });
      return await ctx.next();
    }
    // Allow vault with valid X-Token regardless of cookie (optional feature)
    if (path.startsWith('/api/vault/')) {
      const token = request.headers.get('X-Token');
      if (env.SYNC_TOKEN && token === env.SYNC_TOKEN) return await ctx.next();
      if (!hasCookie) return new Response('Unauthorized', { status: 401, headers: { 'Cache-Control': 'no-store', 'X-Gate': 'required' } });
      return await ctx.next();
    }
    // Allow share GET/HEAD without cookie; for PUT/DELETE allow if X-Token matches SYNC_TOKEN
    if (path.startsWith('/api/share/')) {
      if (request.method === 'GET' || request.method === 'HEAD') return await ctx.next();
      const token = request.headers.get('X-Token');
      if (token && env.SYNC_TOKEN && token === env.SYNC_TOKEN) return await ctx.next();
      if (!hasCookie) return new Response('Unauthorized', { status: 401, headers: { 'Cache-Control': 'no-store', 'X-Gate': 'required' } });
      return await ctx.next();
    }
    // Other APIs require cookie
    if (!hasCookie) return new Response('Unauthorized', { status: 401, headers: { 'Cache-Control': 'no-store', 'X-Gate': 'required' } });
    return await ctx.next();
  }

  // For HTML/JS assets and app shell, let them load (front-end shows login modal if gated)
  return await ctx.next();
};

function parseCookie(str) {
  const map = new Map();
  str.split(/;\s*/).forEach(kv => {
    const i = kv.indexOf('='); if (i === -1) return;
    const k = kv.slice(0, i).trim(); const v = kv.slice(i + 1).trim();
    if (k) map.set(k, v);
  });
  return map;
}

async function sha256b64url(text) {
  const data = new TextEncoder().encode(text);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  let b64 = btoa(String.fromCharCode(...hash));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const len = Math.max(a.length, b.length);
  let diff = 0;
  for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  return diff === 0 && a.length === b.length;
}
