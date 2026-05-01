// List all sync projects in KV (admin function)
// 鉴权：X-KV-Admin-Key 匹配任一管理员密钥（含 KV_ADMIN_KEY/ADMIN_KEY/SYNC_TOKEN），
// 或 X-Token 匹配 ADMIN_KEY/SYNC_TOKEN

import { isAdminAuthed } from "../../_lib/auth.js";

export async function onRequestPost(context) {
  const { env, request } = context;

  if (!env.KV_ADMIN_KEY && !env.ADMIN_KEY) {
    return new Response(JSON.stringify({
      success: false,
      error: "No admin key configured on server (ADMIN_KEY or KV_ADMIN_KEY required)",
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Note": "admin_key_missing" },
    });
  }

  if (!isAdminAuthed(env, request)) {
    return new Response(JSON.stringify({
      success: false,
      error: "Unauthorized: Invalid or missing admin key",
    }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    const syncProjects = [];
    let cursor;
    do {
      const res = await env.AUTH_KV.list({ prefix: "sync:", cursor });
      for (const k of res.keys) {
        const syncId = k.name.startsWith("sync:") ? k.name.slice("sync:".length) : k.name;
        const value = await env.AUTH_KV.get(k.name);
        if (!value) continue;
        try {
          const data = JSON.parse(value);
          syncProjects.push({
            syncId,
            metadata: {
              version: data.v || 1,
              hasData: !!(data.iv && data.ct),
              updatedAt: k.metadata?.updatedAt || null,
            },
            encryptedData: data,
          });
        } catch {
          continue;
        }
      }
      cursor = res.list_complete ? undefined : res.cursor;
    } while (cursor);

    return new Response(JSON.stringify({
      success: true,
      total: syncProjects.length,
      projects: syncProjects,
    }), {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  } catch (e) {
    console.error("Error listing all projects:", e);
    return new Response(JSON.stringify({ success: false, error: "Server Error" }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Note": "error" },
    });
  }
}
