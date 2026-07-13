import { isAdminAuthed } from "../../_lib/auth.js";
import {
  buildAccessGateClearCookie,
  buildAccessGateCookie,
  createAccessGateSession,
  getAccessGateState,
  saveAccessGateConfig,
} from "../../_lib/access-gate.js";
import { hasKvMethods, kvMissingJsonResponse } from "../../_lib/kv.js";
import { readRequestJson, requestTooLarge } from "../../_lib/request-body.js";

export async function onRequestGet(context) {
  const { env, request } = context;
  if (!isAdminAuthed(env, request)) {
    return json({ success: false, error: "Unauthorized" }, 401);
  }

  const gate = await getAccessGateState(env);
  return json({
    success: true,
    enabled: gate.enabled,
    source: gate.source,
    hasRuntimeConfig: gate.hasRuntimeConfig,
    editable: gate.editable,
    passwordConfigured: gate.passwordConfigured,
    updatedAt: gate.updatedAt,
  });
}

export async function onRequestPut(context) {
  const { env, request } = context;
  if (!isAdminAuthed(env, request)) {
    return json({ success: false, error: "Unauthorized" }, 401);
  }

  let body;
  try { body = await readRequestJson(request, 4096); }
  catch (error) {
    try { return requestTooLarge(error); }
    catch { return json({ success: false, error: "Bad Request" }, 400); }
  }

  if (!hasKvMethods(env, ["get", "put"])) {
    return kvMissingJsonResponse(400);
  }

  const enabled = body?.enabled === true;
  let gate;
  try {
    gate = await saveAccessGateConfig(env, { enabled });
  } catch (e) {
    return json({ success: false, error: e.message || "Save failed" }, 400);
  }

  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  const session = gate.enabled ? await createAccessGateSession(env, gate) : "";
  headers.set("Set-Cookie", gate.enabled ? buildAccessGateCookie(session) : buildAccessGateClearCookie());

  return new Response(JSON.stringify({
    success: true,
    enabled: gate.enabled,
    source: gate.source,
    hasRuntimeConfig: gate.hasRuntimeConfig,
    editable: gate.editable,
    passwordConfigured: gate.passwordConfigured,
    updatedAt: gate.updatedAt,
  }), {
    status: 200,
    headers,
  });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
