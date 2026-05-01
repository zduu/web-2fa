// 列出某 syncId 的备份与 tombstone；从备份恢复
// GET  /api/sync-backup/<id>             返回 { tombstone, backups: [{ts, key}] }
// POST /api/sync-backup/<id>?ts=...      用指定备份恢复 sync:<id>（清 tombstone）

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";

export async function onRequest(context) {
  const { request, env, params } = context;
  const id = params.id;
  if (!id) return new Response("Missing id", { status: 400 });

  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();

  const tombKey = `synctomb:${id}`;
  const prefix = `syncbak:${id}:`;

  if (request.method === "GET") {
    const tombRaw = await env.AUTH_KV.get(tombKey);
    let tombstone = null;
    if (tombRaw) { try { tombstone = JSON.parse(tombRaw); } catch {} }
    const backups = [];
    if (env.AUTH_KV.list) {
      let cursor;
      do {
        const r = await env.AUTH_KV.list({ prefix, cursor });
        for (const k of r.keys) {
          const ts = Number(k.name.slice(prefix.length));
          if (Number.isFinite(ts)) backups.push({ ts, key: k.name });
        }
        cursor = r.list_complete ? undefined : r.cursor;
      } while (cursor);
    }
    backups.sort((a, b) => b.ts - a.ts);
    return new Response(JSON.stringify({ id, tombstone, backups }), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  }

  if (request.method === "POST") {
    const url = new URL(request.url);
    const ts = Number(url.searchParams.get("ts"));
    if (!Number.isFinite(ts)) return new Response("ts required", { status: 400 });
    const bakKey = `${prefix}${ts}`;
    const value = await env.AUTH_KV.get(bakKey);
    if (!value) return new Response("Backup not found", { status: 404 });
    await env.AUTH_KV.put(`sync:${id}`, value, { expirationTtl: 60 * 60 * 24 * 365 });
    try { await env.AUTH_KV.delete(tombKey); } catch {}
    return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, POST" } });
}
