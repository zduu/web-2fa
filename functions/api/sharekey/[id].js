// 分享密钥端点（管理员视角的密钥托管）
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";
import { normalizeRouteId } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingTextResponse } from "../../_lib/kv.js";
import { normalizeShareKeyPayload } from "../../_lib/share-key.js";
import { readRequestText, requestTooLarge } from "../../_lib/request-body.js";
import { parseOptionalShareTtl } from "../../_lib/share-options.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);
  const key = `sharekey:${id}`;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();

  const url = new URL(request.url);
  const ttl = parseOptionalShareTtl(url.searchParams.get("ttl"));

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
      try { text = await readRequestText(request, 64 * 1024); }
      catch (error) { return requestTooLarge(error); }
      let payload;
      try {
        const obj = JSON.parse(text);
        payload = normalizeShareKeyPayload(obj);
        if (!payload) throw new Error("invalid");
      } catch {
        return noStoreResponse("Bad Request", 400);
      }
      const body = JSON.stringify(payload);
      if (ttl === 0 || ttl === undefined) {
        await env.AUTH_KV.put(key, body);
      } else {
        await env.AUTH_KV.put(key, body, { expirationTtl: ttl });
      }
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
