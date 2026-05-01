// Vault 端点（RSA 密钥托管的密文存储）
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response("Missing id", { status: 400 });
  const key = `vault:${id}`;

  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();

  if (!env.AUTH_KV || !env.AUTH_KV.get) {
    return new Response("Not configured", { status: 200, headers: { "Cache-Control": "no-store", "X-Note": "kv-missing" } });
  }

  try {
    if (request.method === "GET") {
      const value = await env.AUTH_KV.get(key);
      if (!value) return new Response("Not found", { status: 404 });
      return new Response(value, { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
    }

    if (request.method === "PUT" || request.method === "POST") {
      const text = await request.text();
      await env.AUTH_KV.put(key, text);
      return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
    }

    if (request.method === "DELETE") {
      await env.AUTH_KV.delete(key);
      return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
    }

    return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, PUT, POST, DELETE" } });
  } catch {
    return new Response("Error", { status: 200, headers: { "Cache-Control": "no-store", "X-Note": "error" } });
  }
}
