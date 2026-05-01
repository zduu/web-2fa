// 共享的鉴权工具：用于所有 /api/* Functions
// 1. 集中维护 ADMIN_KEY / SYNC_TOKEN / KV_ADMIN_KEY 的兼容关系
// 2. 用恒时比较降低时序攻击面（敏感字符串对比）

export function timingSafeEqualString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// 候选密钥按优先级返回（用于 X-Token / X-KV-Admin-Key 的多字段兼容）
function configuredAdminKeys(env) {
  const out = [];
  if (env.ADMIN_KEY) out.push(env.ADMIN_KEY);
  if (env.SYNC_TOKEN && env.SYNC_TOKEN !== env.ADMIN_KEY) out.push(env.SYNC_TOKEN);
  if (env.KV_ADMIN_KEY && env.KV_ADMIN_KEY !== env.ADMIN_KEY && env.KV_ADMIN_KEY !== env.SYNC_TOKEN) {
    out.push(env.KV_ADMIN_KEY);
  }
  return out;
}

// 标准 X-Token 鉴权：匹配 ADMIN_KEY 或 SYNC_TOKEN
export function isAuthed(env, token) {
  if (!token) return false;
  if (env.ADMIN_KEY && timingSafeEqualString(token, env.ADMIN_KEY)) return true;
  if (env.SYNC_TOKEN && timingSafeEqualString(token, env.SYNC_TOKEN)) return true;
  return false;
}

// 管理员鉴权（list-all 等）：另接受 X-KV-Admin-Key 头
export function isAdminAuthed(env, request) {
  const xToken = request.headers.get("X-Token");
  if (isAuthed(env, xToken)) return true;
  const xKvAdmin = request.headers.get("X-KV-Admin-Key");
  if (!xKvAdmin) return false;
  for (const k of configuredAdminKeys(env)) {
    if (timingSafeEqualString(xKvAdmin, k)) return true;
  }
  return false;
}

// 是否需要写鉴权（任意管理员密钥已配置）
export function needsAuthForWrite(env) {
  return !!(env.ADMIN_KEY || env.SYNC_TOKEN);
}

// 是否需要读鉴权（strict 模式且管理员密钥已配置）
export function needsAuthForRead(env) {
  if (!env.ADMIN_KEY && !env.SYNC_TOKEN) return false;
  const mode = (env.SYNC_MODE || "strict").toLowerCase();
  return mode !== "open";
}

export function unauthorized() {
  return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
}
