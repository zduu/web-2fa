// 同步存储端点
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN（向后兼容）
// strict 模式（默认）：GET 也需鉴权；open 模式：GET 开放
//
// 6.6 PUT 时把旧值另存为 syncbak:<id>:<ts>，仅保留最近 5 个版本（TTL 30 天）
// 6.7 DELETE 改为软删除（同时打 tombstone）；可在管理员页恢复

import {
  isAuthed, needsAuthForRead, needsAuthForWrite, unauthorized,
} from "../../_lib/auth.js";

const BACKUP_KEEP = 5;
const BACKUP_TTL = 60 * 60 * 24 * 30; // 30 天
const TOMBSTONE_TTL = 60 * 60 * 24 * 7; // 7 天

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response("Missing id", { status: 400 });

  const key = `sync:${id}`;
  const tombKey = `synctomb:${id}`;
  const tokenHeader = request.headers.get("X-Token");

  if (request.method === "GET") {
    if (needsAuthForRead(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    const value = await env.AUTH_KV.get(key);
    if (!value) {
      // 检查是否有 tombstone（已软删除）
      const tomb = await env.AUTH_KV.get(tombKey);
      if (tomb) return new Response("Gone (deleted)", { status: 410, headers: { "X-Note": "soft-deleted" } });
      return new Response("Not found", { status: 404 });
    }
    return new Response(value, { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
  }

  if (request.method === "PUT" || request.method === "POST") {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    const text = await request.text();
    try {
      const obj = JSON.parse(text);
      if (!obj || typeof obj !== "object" || !obj.iv || !obj.ct) throw new Error("invalid");
    } catch {
      return new Response("Bad Request", { status: 400 });
    }

    // 6.6 备份旧值
    try {
      const prev = await env.AUTH_KV.get(key);
      if (prev) {
        const ts = Date.now();
        await env.AUTH_KV.put(`syncbak:${id}:${ts}`, prev, { expirationTtl: BACKUP_TTL });
        // 截断旧备份
        await pruneBackups(env, id);
      }
    } catch {}

    // 写入；同时清掉 tombstone（如果有）
    await env.AUTH_KV.put(key, text, { expirationTtl: 60 * 60 * 24 * 365 });
    try { await env.AUTH_KV.delete(tombKey); } catch {}
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  if (request.method === "DELETE") {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    const url = new URL(request.url);
    const hard = url.searchParams.get("hard") === "1";

    if (hard) {
      // 真删除：清密文 + 备份 + tombstone
      await env.AUTH_KV.delete(key);
      try { await env.AUTH_KV.delete(tombKey); } catch {}
      try { await pruneBackups(env, id, true); } catch {}
      return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
    }

    // 软删除：把当前值移到备份，写 tombstone（7 天 TTL），删 sync:
    try {
      const prev = await env.AUTH_KV.get(key);
      if (prev) {
        const ts = Date.now();
        await env.AUTH_KV.put(`syncbak:${id}:${ts}`, prev, { expirationTtl: BACKUP_TTL });
        await pruneBackups(env, id);
      }
      await env.AUTH_KV.put(tombKey, JSON.stringify({ deletedAt: Date.now() }), { expirationTtl: TOMBSTONE_TTL });
      await env.AUTH_KV.delete(key);
    } catch {}
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store", "X-Note": "soft-delete" } });
  }

  return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, PUT, POST, DELETE" } });
}

// 保留最近 BACKUP_KEEP 个备份；keepNone=true 则全删
async function pruneBackups(env, id, keepNone = false) {
  if (!env.AUTH_KV.list) return;
  const prefix = `syncbak:${id}:`;
  const out = [];
  let cursor;
  do {
    const r = await env.AUTH_KV.list({ prefix, cursor });
    out.push(...r.keys.map(k => k.name));
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor);
  out.sort(); // 按 ts 升序
  const keep = keepNone ? 0 : BACKUP_KEEP;
  const toDelete = out.length > keep ? out.slice(0, out.length - keep) : [];
  await Promise.all(toDelete.map(k => env.AUTH_KV.delete(k).catch(() => {})));
}
