export async function onRequestGet(context) {
  const { request, env } = context;
  const gate = env.ACCESS_GATE;
  if (!gate) return new Response(null, { status: 204, headers: { 'Cache-Control': 'no-store' } });
  const cookie = request.headers.get('Cookie') || '';
  const want = await sha256b64url(gate);
  const got = parseCookie(cookie).get('cf_gate');
  if (got && timingSafeEqual(got, want)) return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  return new Response('Forbidden', { status: 403, headers: { 'Cache-Control': 'no-store' } });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const gate = env.ACCESS_GATE;
  if (!gate) return new Response('Disabled', { status: 400 });
  let body;
  try { body = await request.json(); } catch { return new Response('Bad Request', { status: 400 }); }
  const pass = (body && body.password) || '';
  if (pass !== gate) return new Response('Unauthorized', { status: 401 });
  const value = await sha256b64url(gate);
  const headers = new Headers();
  headers.set('Set-Cookie', `cf_gate=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7*24*3600}`);
  headers.set('Cache-Control', 'no-store');
  return new Response('OK', { status: 200, headers });
}

export async function onRequestDelete(context) {
  // logout
  const headers = new Headers();
  headers.set('Set-Cookie', `cf_gate=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  headers.set('Cache-Control', 'no-store');
  return new Response('OK', { status: 200, headers });
}

async function sha256b64url(text) {
  const data = new TextEncoder().encode(text);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  let b64 = btoa(String.fromCharCode(...hash));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function parseCookie(str) {
  const map = new Map();
  str.split(/;\s*/).forEach(kv => {
    const i = kv.indexOf('='); if (i === -1) return;
    const k = kv.slice(0, i).trim(); const v = kv.slice(i + 1).trim();
    if (k) map.set(k, v);
  });
  return map;
}
