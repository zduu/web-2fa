import {
  buildAccessGateClearCookie,
  buildAccessGateCookie,
  createAccessGateSession,
  getAccessGateState,
  readAccessGateCookie,
  revokeAccessGateSession,
  verifyAccessGateSession,
} from "../_lib/access-gate.js";
import { clearGateFailures, getGateRateLimit, recordGateFailure } from "../_lib/gate-rate-limit.js";
import { readRequestJson, requestTooLarge } from "../_lib/request-body.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const gate = await getAccessGateState(env);
  if (!gate.enabled) return noStoreResponse(null, 204);
  const got = readAccessGateCookie(request);
  if (await verifyAccessGateSession(env, gate, got)) {
    return noStoreResponse("OK");
  }
  return noStoreResponse("Forbidden", 403);
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const gate = await getAccessGateState(env);
  if (!gate.enabled) return noStoreResponse("Disabled", 400);
  const rate = await getGateRateLimit(env, request);
  if (rate.limited) return noStoreResponse("Too Many Requests", 429, new Headers({ "Retry-After": String(rate.retryAfter) }));
  let body;
  try { body = await readRequestJson(request, 4096); }
  catch (error) {
    try { return requestTooLarge(error); } catch { return noStoreResponse("Bad Request", 400); }
  }
  const pass = (body && body.password) || "";
  if (!(await gate.verifyPassword(pass))) {
    await recordGateFailure(env, rate);
    return noStoreResponse("Unauthorized", 401);
  }
  await clearGateFailures(env, rate);
  const session = await createAccessGateSession(env, gate);
  const headers = new Headers();
  headers.set("Set-Cookie", buildAccessGateCookie(session));
  return noStoreResponse("OK", 200, headers);
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  await revokeAccessGateSession(env, readAccessGateCookie(request));
  const headers = new Headers();
  headers.set("Set-Cookie", buildAccessGateClearCookie());
  return noStoreResponse("OK", 200, headers);
}

function noStoreResponse(body, status = 200, headers = new Headers()) {
  const nextHeaders = new Headers(headers);
  nextHeaders.set("Cache-Control", "no-store");
  return new Response(body, { status, headers: nextHeaders });
}
