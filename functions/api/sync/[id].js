// 同步存储端点
// 鉴权：X-Token 匹配 ADMIN_KEY 或 SYNC_TOKEN（向后兼容）
// strict 模式（默认）：GET 也需鉴权；open 模式：GET 开放
//
// 6.6 PUT 时把旧值另存为 syncbak:<id>:<ts>，仅保留最近 5 个版本（TTL 30 天）
// 6.7 DELETE 改为软删除（同时打 tombstone）；可在管理员页恢复

import {
  isAuthed, needsAuthForRead, needsAuthForWrite, unauthorized,
} from "../../_lib/auth.js";
import { normalizeRouteId } from "../../_lib/ids.js";
import { backupSyncPayloadToGithub, GithubBackupError } from "../../_lib/github-backup.js";
import { hasKvMethods, kvMissingTextResponse } from "../../_lib/kv.js";
import { normalizeOptionalNonNegativeSafeInteger } from "../../_lib/numbers.js";
import { isCipherPayload } from "../../_lib/payload.js";

const BACKUP_KEEP = 5;
const BACKUP_TTL = 60 * 60 * 24 * 30; // 30 天
const TOMBSTONE_TTL = 60 * 60 * 24 * 7; // 7 天

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);

  const key = `sync:${id}`;
  const tombKey = `synctomb:${id}`;
  const tokenHeader = request.headers.get("X-Token");

  if (request.method === "GET") {
    if (needsAuthForRead(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    if (!hasKvMethods(env, ["get"])) return kvMissingTextResponse();
    const value = await env.AUTH_KV.get(key);
    if (!value) {
      // 检查是否有 tombstone（已软删除）
      const tomb = await env.AUTH_KV.get(tombKey);
      if (tomb) return noStoreResponse("Gone (deleted)", 410, { "X-Note": "soft-deleted" });
      return noStoreResponse("Not found", 404);
    }
    return new Response(value, { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
  }

  if (request.method === "PUT" || request.method === "POST") {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    if (!hasKvMethods(env, ["put"])) return kvMissingTextResponse();
    const text = await request.text();
    let body;
    try {
      body = JSON.parse(text);
      if (!isCipherPayload(body)) throw new Error("invalid");
    } catch {
      return noStoreResponse("Bad Request", 400);
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
    const headers = { "Cache-Control": "no-store" };
    try {
      await backupSyncPayloadToGithub(env, id, body);
    } catch (error) {
      if (error instanceof GithubBackupError) {
        headers["X-Note"] = error.note;
        headers["X-Backup-Status"] = "failed";
      } else {
        console.error("GitHub 备份异常:", error);
        headers["X-Note"] = "github-backup-failed";
        headers["X-Backup-Status"] = "failed";
      }
    }
    return new Response("OK", { status: 200, headers });
  }

  if (request.method === "DELETE") {
    if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
    const url = new URL(request.url);
    const hard = url.searchParams.get("hard") === "1";
    const requiredMethods = hard ? ["delete", "list"] : ["get", "put", "delete"];
    if (!hasKvMethods(env, requiredMethods)) return kvMissingTextResponse();

    if (hard) {
      // 真删除：清密文 + 备份 + tombstone
      try {
        await env.AUTH_KV.delete(key);
        await env.AUTH_KV.delete(tombKey);
        await pruneBackups(env, id, true);
      } catch {
        return noStoreResponse("Server Error", 500, { "X-Note": "error" });
      }
      return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
    }

    // 软删除：把当前值移到备份，写 tombstone（7 天 TTL），删 sync:
    try {
      const prev = await env.AUTH_KV.get(key);
      if (prev) {
        const ts = Date.now();
        await env.AUTH_KV.put(`syncbak:${id}:${ts}`, prev, { expirationTtl: BACKUP_TTL });
        try { await pruneBackups(env, id); } catch {}
      }
      await env.AUTH_KV.put(tombKey, JSON.stringify({ deletedAt: Date.now() }), { expirationTtl: TOMBSTONE_TTL });
      await env.AUTH_KV.delete(key);
    } catch {
      return noStoreResponse("Server Error", 500, { "X-Note": "error" });
    }
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store", "X-Note": "soft-delete" } });
  }

  return noStoreResponse("Method Not Allowed", 405, { Allow: "GET, PUT, POST, DELETE" });
}

function noStoreResponse(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: { ...headers, "Cache-Control": "no-store" },
  });
}

// 保留最近 BACKUP_KEEP 个备份；keepNone=true 则全删
async function pruneBackups(env, id, keepNone = false) {
  if (!env.AUTH_KV.list) return;
  const prefix = `syncbak:${id}:`;
  const entries = [];
  let cursor;
  do {
    const r = await env.AUTH_KV.list({ prefix, cursor });
    entries.push(...r.keys.map((k) => ({
      name: k.name,
      ts: normalizeOptionalNonNegativeSafeInteger(k.name.slice(prefix.length)),
    })));
    cursor = r.list_complete ? undefined : r.cursor;
  } while (cursor);

  const toDelete = [];
  if (keepNone) {
    toDelete.push(...entries.map((entry) => entry.name));
  } else {
    const valid = [];
    for (const entry of entries) {
      if (entry.ts === null) toDelete.push(entry.name);
      else valid.push(entry);
    }
    valid.sort((a, b) => b.ts - a.ts);
    toDelete.push(...valid.slice(BACKUP_KEEP).map((entry) => entry.name));
  }

  await Promise.all(toDelete.map(k => env.AUTH_KV.delete(k).catch(() => {})));
}
