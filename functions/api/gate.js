import {
  buildAccessGateClearCookie,
  buildAccessGateCookie,
  getAccessGateState,
  readAccessGateCookie,
} from "../_lib/access-gate.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const gate = await getAccessGateState(env);
  if (!gate.enabled) return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  const got = readAccessGateCookie(request);
  if (got && timingSafeEqual(got, gate.cookieValue)) {
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }
  return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store" } });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const gate = await getAccessGateState(env);
  if (!gate.enabled) return new Response("Disabled", { status: 400 });
  let body;
  try { body = await request.json(); } catch { return new Response("Bad Request", { status: 400 }); }
  const pass = (body && body.password) || "";
  if (!(await gate.verifyPassword(pass))) return new Response("Unauthorized", { status: 401 });
  const headers = new Headers();
  headers.set("Set-Cookie", buildAccessGateCookie(gate.cookieValue));
  headers.set("Cache-Control", "no-store");
  return new Response("OK", { status: 200, headers });
}

export async function onRequestDelete(context) {
  const headers = new Headers();
  headers.set("Set-Cookie", buildAccessGateClearCookie());
  headers.set("Cache-Control", "no-store");
  return new Response("OK", { status: 200, headers });
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  return diff === 0;
}
