// List all sync projects in KV (admin function)
// 鉴权：X-KV-Admin-Key 匹配任一管理员密钥（含 KV_ADMIN_KEY/ADMIN_KEY/SYNC_TOKEN），
// 或 X-Token 匹配 ADMIN_KEY/SYNC_TOKEN

import { hasConfiguredAdminKey, isAdminAuthed } from "../../_lib/auth.js";
import { normalizeKvSuffix } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingJsonResponse } from "../../_lib/kv.js";
import { normalizeOptionalTimestamp, normalizePositiveInteger } from "../../_lib/numbers.js";
import { isCipherPayload } from "../../_lib/payload.js";

export async function onRequestPost(context) {
  const { env, request } = context;

  if (!hasConfiguredAdminKey(env)) {
    return json({
      success: false,
      error: "No admin key configured on server (ADMIN_KEY, SYNC_TOKEN, or KV_ADMIN_KEY required)",
    }, 200, { "X-Note": "admin_key_missing" });
  }

  if (!isAdminAuthed(env, request)) {
    return json({
      success: false,
      error: "Unauthorized: Invalid or missing admin key",
    }, 401);
  }

  if (!hasKvMethods(env, ["list", "get"])) {
    return kvMissingJsonResponse();
  }

  try {
    const syncProjects = [];
    let cursor;
    do {
      const res = await env.AUTH_KV.list({ prefix: "sync:", cursor });
      for (const k of res.keys) {
        const syncId = normalizeKvSuffix(k.name, "sync:");
        if (!syncId) continue;
        const value = await env.AUTH_KV.get(k.name);
        if (!value) continue;
        try {
          const data = JSON.parse(value);
          const valid = isCipherPayload(data);
          syncProjects.push({
            syncId,
            metadata: {
              version: normalizePositiveInteger(data.v) || 1,
              hasData: valid,
              valid,
              updatedAt: normalizeOptionalTimestamp(k.metadata?.updatedAt),
            },
            encryptedData: data,
          });
        } catch {
          continue;
        }
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);

    return json({
      success: true,
      total: syncProjects.length,
      projects: syncProjects,
    });
  } catch (e) {
    console.error("Error listing all projects:", e);
    return json({ success: false, error: "Server Error" }, 200, { "X-Note": "error" });
  }
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}
