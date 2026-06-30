// 分享端点
// 写权限鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN
// 读权限：始终公开（密钥通过 URL 片段传递，没密钥也解不开）
// 4.2 限次：写入时可指定 max；GET 时累加 count，超过 max 自动 DELETE

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";
import { normalizeRouteId } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingTextResponse } from "../../_lib/kv.js";
import { normalizeNonNegativeInteger, normalizeOptionalTimestamp, normalizePositiveInteger } from "../../_lib/numbers.js";
import { isCipherPayload } from "../../_lib/payload.js";
import { parseShareOptions } from "../../_lib/share-options.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);
  const key = `share:${id}`;
  const url = new URL(request.url);
  const { permanent: usePermanent, ttl: useTtl, maxAccess } = parseShareOptions({
    defaultTtl: env.SHARE_TTL,
    ttlParam: url.searchParams.get("ttl"),
    maxParam: url.searchParams.get("max"),
  });

  const tokenHeader = request.headers.get("X-Token");

  if (request.method === "GET" || request.method === "HEAD") {
    if (!hasKvMethods(env, ["get"])) return kvMissingTextResponse(200);
    const value = await env.AUTH_KV.get(key);
    if (!value) return noStoreResponse("Not found", 404);
    let payload;
    try { payload = JSON.parse(value); } catch { payload = null; }
    if (!isCipherPayload(payload)) return noStoreResponse("Bad data", 500);

    const max = normalizeNonNegativeInteger(payload.max, { max: 1_000_000 });
    const count = normalizeNonNegativeInteger(payload.count);
    const ttl = normalizeNonNegativeInteger(payload.ttl);
    const expireAt = normalizeOptionalTimestamp(payload.expireAt);

    if (expireAt && expireAt <= Date.now()) {
      await cleanupShare(env, id);
      return noStoreResponse("Gone", 410, { "X-Share-Reason": "expired" });
    }

    // 已超额
    if (max > 0 && count >= max) {
      await cleanupShare(env, id);
      return noStoreResponse("Gone", 410, { "X-Share-Reason": "max-access-exceeded" });
    }

    // GET 时累加访问计数（HEAD 不算）
    if (request.method === "GET") {
      const now = Date.now();
      const nextCount = count + 1;
      const next = { ...payload, count: nextCount, lastAccessAt: now };
      const userAgentSample = sanitizeUserAgent(request.headers.get("User-Agent"));
      try {
        await writeShareStat(env, id, {
          accessCount: nextCount,
          lastAccessAt: now,
          accessUserAgentSample: userAgentSample,
        }, payload.expireAt);
        if (max > 0 && next.count >= max) {
          // 这次返回内容，但删除（最后一次）
          await cleanupShare(env, id);
        } else if (ttl > 0) {
          // 保持原 TTL（KV TTL 是绝对时间，重写时需基于 expirationAt）
          const remain = expireAt ? Math.max(60, Math.floor((expireAt - Date.now()) / 1000)) : ttl;
          await env.AUTH_KV.put(key, JSON.stringify(next), { expirationTtl: remain });
        } else {
          await env.AUTH_KV.put(key, JSON.stringify(next));
        }
      } catch (e) {
        // 数据已返回给客户端，KV 写入失败不影响响应；
        // 但 maxAccess 限制可能被绕过，记录日志便于排查
        console.error(`share/${id}: KV write failed after response`, e?.message || e);
      }
    }

    // 返回前端只需要 iv/ct
    const out = { v: normalizePositiveInteger(payload.v) || 1, iv: payload.iv, ct: payload.ct };
    return request.method === "HEAD"
      ? new Response(null, { status: 200, headers: { "Cache-Control": "no-store", "X-Access-Remaining": formatAccessRemaining(max, count) } })
      : new Response(JSON.stringify(out), { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Access-Remaining": formatAccessRemaining(max, count + 1) } });
  }

  if (request.method === "PUT" || request.method === "POST") {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    if (!hasKvMethods(env, ["put"])) return kvMissingTextResponse(200);
    const text = await request.text();
    let body;
    try {
      body = JSON.parse(text);
      if (!isCipherPayload(body)) throw new Error("invalid");
    } catch {
      return noStoreResponse("Bad Request", 400);
    }
    const expireAt = usePermanent ? 0 : (Date.now() + useTtl * 1000);
    const stored = {
      v: 1,
      iv: body.iv,
      ct: body.ct,
      max: maxAccess,
      count: 0,
      ttl: usePermanent ? 0 : useTtl,
      expireAt,
      createdAt: Date.now(),
    };
    if (usePermanent) {
      await env.AUTH_KV.put(key, JSON.stringify(stored));
    } else {
      await env.AUTH_KV.put(key, JSON.stringify(stored), { expirationTtl: useTtl });
    }
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  if (request.method === "DELETE") {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    if (!hasKvMethods(env, ["delete"])) return kvMissingTextResponse(200);
    try {
      await cleanupShare(env, id, { strictPrimary: true });
    } catch {
      return noStoreResponse("Server Error", 500, { "X-Note": "error" });
    }
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  return noStoreResponse("Method Not Allowed", 405, { Allow: "GET, HEAD, PUT, POST, DELETE" });
}

function noStoreResponse(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: { ...headers, "Cache-Control": "no-store" },
  });
}

async function cleanupShare(env, id, { strictPrimary = false } = {}) {
  try {
    await env.AUTH_KV.delete(`share:${id}`);
  } catch (error) {
    if (strictPrimary) throw error;
  }
  try { await env.AUTH_KV.delete(`sharecode:${id}`); } catch {}
  try { await env.AUTH_KV.delete(`sharekey:${id}`); } catch {}
  try { await env.AUTH_KV.delete(`sharestat:${id}`); } catch {}
}

async function writeShareStat(env, id, stat, expireAt = 0) {
  const key = `sharestat:${id}`;
  const body = JSON.stringify({
    accessCount: normalizeNonNegativeInteger(stat?.accessCount),
    lastAccessAt: normalizeOptionalTimestamp(stat?.lastAccessAt),
    accessUserAgentSample: sanitizeUserAgent(stat?.accessUserAgentSample),
  });
  const normalizedExpireAt = normalizeOptionalTimestamp(expireAt);
  const remain = normalizedExpireAt ? Math.max(60, Math.floor((normalizedExpireAt - Date.now()) / 1000)) : 0;
  if (remain > 0) await env.AUTH_KV.put(key, body, { expirationTtl: remain });
  else await env.AUTH_KV.put(key, body);
}

function sanitizeUserAgent(value) {
  if (typeof value !== "string") return "";
  const text = String(value || "").replace(/[\x00-\x1F\x7F]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.slice(0, 160) : "";
}

function formatAccessRemaining(max, used) {
  return max > 0 ? String(Math.max(0, max - used)) : "unlimited";
}
