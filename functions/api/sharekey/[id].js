// 分享密钥端点（管理员视角的密钥托管）
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response("Missing id", { status: 400 });
  const key = `sharekey:${id}`;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();

  const url = new URL(request.url);
  const ttlParam = url.searchParams.get("ttl");
  let ttl;
  if (ttlParam) {
    const s = ttlParam.toLowerCase();
    if (s === "perm" || s === "0" || s === "permanent") ttl = 0;
    else { const n = Number(s); if (Number.isFinite(n) && n > 0) ttl = Math.round(n); }
  }

  if (request.method === "GET") {
    const value = await env.AUTH_KV.get(key);
    if (!value) return new Response("Not found", { status: 404 });
    return new Response(value, { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
  }

  if (request.method === "PUT" || request.method === "POST") {
    const text = await request.text();
    try {
      const obj = JSON.parse(text);
      if (!obj || typeof obj !== "object" || typeof obj.k !== "string") throw new Error("invalid");
    } catch {
      return new Response("Bad Request", { status: 400 });
    }
    if (ttl === 0 || ttl === undefined) {
      await env.AUTH_KV.put(key, text);
    } else {
      await env.AUTH_KV.put(key, text, { expirationTtl: ttl });
    }
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  if (request.method === "DELETE") {
    await env.AUTH_KV.delete(key);
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, PUT, POST, DELETE" } });
}
