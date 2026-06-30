// 列出某 syncId 的备份与 tombstone；从备份恢复
// GET  /api/sync-backup/<id>             返回 { tombstone, backups: [{ts, key}] }
// POST /api/sync-backup/<id>?ts=...      用指定备份恢复 sync:<id>（清 tombstone）

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";
import { normalizeRouteId } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingTextResponse } from "../../_lib/kv.js";
import { normalizeOptionalNonNegativeSafeInteger, normalizeOptionalTimestamp } from "../../_lib/numbers.js";
import { isCipherPayload } from "../../_lib/payload.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);

  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();

  const tombKey = `synctomb:${id}`;
  const prefix = `syncbak:${id}:`;

  if (request.method === "GET") {
    if (!hasKvMethods(env, ["get", "list"])) return kvMissingTextResponse();
    try {
      const tombRaw = await env.AUTH_KV.get(tombKey);
      let tombstone = null;
      if (tombRaw) {
        try {
          const parsed = JSON.parse(tombRaw);
          tombstone = { deletedAt: normalizeOptionalTimestamp(parsed?.deletedAt) };
        } catch {}
      }
      const backups = [];
      let cursor;
      do {
        const r = await env.AUTH_KV.list({ prefix, cursor });
        for (const k of r.keys) {
          const ts = normalizeOptionalNonNegativeSafeInteger(k.name.slice(prefix.length));
          if (ts !== null) backups.push({ ts, key: k.name });
        }
        cursor = r.list_complete ? undefined : r.cursor;
      } while (cursor);
      backups.sort((a, b) => b.ts - a.ts);
      return jsonNoStoreResponse({ id, tombstone, backups });
    } catch {
      return jsonNoStoreResponse({ success: false, error: "Server Error", id, tombstone: null, backups: [] }, 200, { "X-Note": "error" });
    }
  }

  if (request.method === "POST") {
    if (!hasKvMethods(env, ["get", "put"])) return kvMissingTextResponse();
    const url = new URL(request.url);
    const ts = normalizeOptionalNonNegativeSafeInteger(url.searchParams.get("ts"));
    if (ts === null) return noStoreResponse("ts required", 400);
    const bakKey = `${prefix}${ts}`;
    try {
      const value = await env.AUTH_KV.get(bakKey);
      if (!value) return noStoreResponse("Backup not found", 404);
      let payload;
      try { payload = JSON.parse(value); } catch { payload = null; }
      if (!isCipherPayload(payload)) return noStoreResponse("Bad backup", 500);
      await env.AUTH_KV.put(`sync:${id}`, value, { expirationTtl: 60 * 60 * 24 * 365 });
      try { await env.AUTH_KV.delete(tombKey); } catch {}
      return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
    } catch {
      return noStoreResponse("Server Error", 500, { "X-Note": "error" });
    }
  }

  return noStoreResponse("Method Not Allowed", 405, { Allow: "GET, POST" });
}

function noStoreResponse(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: { ...headers, "Cache-Control": "no-store" },
  });
}

function jsonNoStoreResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}
