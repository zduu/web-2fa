// 分享端点
// 写权限鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN
// 读权限：始终公开（密钥通过 URL 片段传递，没密钥也解不开）
// 4.2 限次：写入时可指定 max；GET 时累加 count，超过 max 自动 DELETE

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response("Missing id", { status: 400 });
  const key = `share:${id}`;
  const url = new URL(request.url);
  const ttlParam = url.searchParams.get("ttl");
  const maxParam = url.searchParams.get("max");

  let defaultTtl = Number(env.SHARE_TTL ?? 86400);
  let defaultPermanent = !(Number.isFinite(defaultTtl) && defaultTtl > 0);
  let usePermanent = defaultPermanent;
  let useTtl = defaultTtl;

  if (ttlParam) {
    const s = ttlParam.toLowerCase();
    if (s === "perm" || s === "permanent" || s === "infinite" || s === "forever" || s === "0") {
      usePermanent = true;
    } else {
      const n = Number(s);
      if (Number.isFinite(n) && n > 0) {
        usePermanent = false; useTtl = Math.round(n);
      }
    }
  }

  let maxAccess = 0; // 0 = 无限
  if (maxParam) {
    const n = Number(maxParam);
    if (Number.isFinite(n) && n > 0) maxAccess = Math.round(n);
  }

  const tokenHeader = request.headers.get("X-Token");

  if (request.method === "GET" || request.method === "HEAD") {
    const value = await env.AUTH_KV.get(key);
    if (!value) return new Response("Not found", { status: 404 });
    let payload;
    try { payload = JSON.parse(value); } catch { payload = null; }
    if (!payload) return new Response("Bad data", { status: 500 });

    const max = Number(payload.max || 0);
    const count = Number(payload.count || 0);
    const ttl = Number(payload.ttl || 0);

    // 已超额
    if (max > 0 && count >= max) {
      await cleanupShare(env, id);
      return new Response("Gone", { status: 410, headers: { "X-Share-Reason": "max-access-exceeded" } });
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
          const remain = payload.expireAt ? Math.max(60, Math.floor((payload.expireAt - Date.now()) / 1000)) : ttl;
          await env.AUTH_KV.put(key, JSON.stringify(next), { expirationTtl: remain });
        } else {
          await env.AUTH_KV.put(key, JSON.stringify(next));
        }
      } catch {}
    }

    // 返回前端只需要 iv/ct
    const out = { v: payload.v || 1, iv: payload.iv, ct: payload.ct };
    return request.method === "HEAD"
      ? new Response(null, { status: 200, headers: { "Cache-Control": "no-store", "X-Access-Remaining": max > 0 ? String(Math.max(0, max - count)) : "∞" } })
      : new Response(JSON.stringify(out), { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Access-Remaining": max > 0 ? String(Math.max(0, max - count - 1)) : "∞" } });
  }

  if (request.method === "PUT" || request.method === "POST") {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    const text = await request.text();
    let body;
    try {
      body = JSON.parse(text);
      if (!body || typeof body !== "object" || !body.iv || !body.ct) throw new Error("invalid");
    } catch {
      return new Response("Bad Request", { status: 400 });
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
    await cleanupShare(env, id);
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD, PUT, POST, DELETE" } });
}

async function cleanupShare(env, id) {
  try { await env.AUTH_KV.delete(`share:${id}`); } catch {}
  try { await env.AUTH_KV.delete(`sharekey:${id}`); } catch {}
  try { await env.AUTH_KV.delete(`sharestat:${id}`); } catch {}
}

async function writeShareStat(env, id, stat, expireAt = 0) {
  const key = `sharestat:${id}`;
  const body = JSON.stringify({
    accessCount: Math.max(0, Number(stat?.accessCount || 0)),
    lastAccessAt: Number(stat?.lastAccessAt || 0) || null,
    accessUserAgentSample: sanitizeUserAgent(stat?.accessUserAgentSample),
  });
  const remain = Number(expireAt || 0) > 0 ? Math.max(60, Math.floor((Number(expireAt) - Date.now()) / 1000)) : 0;
  if (remain > 0) await env.AUTH_KV.put(key, body, { expirationTtl: remain });
  else await env.AUTH_KV.put(key, body);
}

function sanitizeUserAgent(value) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text ? text.slice(0, 160) : "";
}
