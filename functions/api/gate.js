import {
  buildAccessGateClearCookie,
  buildAccessGateCookie,
  getAccessGateState,
  readAccessGateCookie,
} from "../_lib/access-gate.js";
import { timingSafeEqualString } from "../_lib/auth.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const gate = await getAccessGateState(env);
  if (!gate.enabled) return noStoreResponse(null, 204);
  const got = readAccessGateCookie(request);
  if (got && timingSafeEqualString(got, gate.cookieValue)) {
    return noStoreResponse("OK");
  }
  return noStoreResponse("Forbidden", 403);
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const gate = await getAccessGateState(env);
  if (!gate.enabled) return noStoreResponse("Disabled", 400);
  let body;
  try { body = await request.json(); } catch { return noStoreResponse("Bad Request", 400); }
  const pass = (body && body.password) || "";
  if (!(await gate.verifyPassword(pass))) return noStoreResponse("Unauthorized", 401);
  const headers = new Headers();
  headers.set("Set-Cookie", buildAccessGateCookie(gate.cookieValue));
  return noStoreResponse("OK", 200, headers);
}

export async function onRequestDelete(context) {
  const headers = new Headers();
  headers.set("Set-Cookie", buildAccessGateClearCookie());
  return noStoreResponse("OK", 200, headers);
}

function noStoreResponse(body, status = 200, headers = new Headers()) {
  const nextHeaders = new Headers(headers);
  nextHeaders.set("Cache-Control", "no-store");
  return new Response(body, { status, headers: nextHeaders });
}
