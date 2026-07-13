// Vault 端点（RSA 密钥托管的密文存储）
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";
import { normalizeRouteId } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingTextResponse } from "../../_lib/kv.js";
import { isVaultPayload } from "../../_lib/payload.js";
import { readRequestText, requestTooLarge } from "../../_lib/request-body.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);
  const key = `vault:${id}`;

  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();

  try {
    if (request.method === "GET") {
      if (!hasKvMethods(env, ["get"])) return kvMissingTextResponse(200);
      const value = await env.AUTH_KV.get(key);
      if (!value) return noStoreResponse("Not found", 404);
      return new Response(value, { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
    }

    if (request.method === "PUT" || request.method === "POST") {
      if (!hasKvMethods(env, ["put"])) return kvMissingTextResponse(200);
      let text;
      try { text = await readRequestText(request, 512 * 1024); }
      catch (error) { return requestTooLarge(error); }
      try {
        const body = JSON.parse(text);
        if (!isVaultPayload(body)) throw new Error("invalid");
      } catch {
        return noStoreResponse("Bad Request", 400);
      }
      await env.AUTH_KV.put(key, text);
      return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
    }

    if (request.method === "DELETE") {
      if (!hasKvMethods(env, ["delete"])) return kvMissingTextResponse(200);
      await env.AUTH_KV.delete(key);
      return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
    }

    return noStoreResponse("Method Not Allowed", 405, { Allow: "GET, PUT, POST, DELETE" });
  } catch {
    return noStoreResponse("Server Error", 500, { "X-Note": "error" });
  }
}

function noStoreResponse(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: { ...headers, "Cache-Control": "no-store" },
  });
}
