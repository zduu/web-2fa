// 健康检查：返回服务端能力清单（不暴露 secret）
// 公开端点，但通过 ACCESS_GATE 时仍要 cookie
import { getAccessGateState } from "../_lib/access-gate.js";

export async function onRequestGet(context) {
  const { env } = context;
  const kv = !!(env.AUTH_KV && env.AUTH_KV.get && env.AUTH_KV.put);
  const adminConfigured = !!(env.ADMIN_KEY || env.SYNC_TOKEN);
  const mode = (env.SYNC_MODE || "strict").toLowerCase();
  const shareTtlRaw = env.SHARE_TTL ?? "86400";
  const shareTtl = Number(shareTtlRaw);
  const gate = await getAccessGateState(env);

  const body = {
    ok: kv && (adminConfigured || mode === "open"),
    kv: kv ? "ok" : "missing",
    adminConfigured,
    syncMode: mode === "open" ? "open" : "strict",
    shareTtl: Number.isFinite(shareTtl) ? shareTtl : 86400,
    sharePermanentByDefault: !(Number.isFinite(shareTtl) && shareTtl > 0),
    accessGate: gate.enabled,
    accessGateSource: gate.source,
    serverTime: new Date().toISOString(),
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
