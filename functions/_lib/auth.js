// 共享的鉴权工具：用于所有 /api/* Functions
// 1. 集中维护 ADMIN_KEY / SYNC_TOKEN / KV_ADMIN_KEY 的兼容关系
// 2. 用恒时比较降低时序攻击面（敏感字符串对比）

export function timingSafeEqualString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

function normalizeSecret(value) {
  return typeof value === "string" ? value.trim() : "";
}

function configuredSecrets(...values) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const secret = normalizeSecret(value);
    if (!secret || seen.has(secret)) continue;
    seen.add(secret);
    out.push(secret);
  }
  return out;
}

// 候选密钥按优先级返回（用于 X-Token / X-KV-Admin-Key 的多字段兼容）
function configuredAdminKeys(env) {
  return configuredSecrets(env.ADMIN_KEY, env.SYNC_TOKEN, env.KV_ADMIN_KEY);
}

export function getSyncMode(env) {
  const mode = String(env.SYNC_MODE || "strict").trim().toLowerCase();
  return mode === "open" ? "open" : "strict";
}

export function hasConfiguredAdminKey(env) {
  return configuredAdminKeys(env).length > 0;
}

// 标准 X-Token 鉴权：匹配 ADMIN_KEY 或 SYNC_TOKEN
export function isAuthed(env, token) {
  if (typeof token !== "string" || !token) return false;
  for (const secret of configuredSecrets(env.ADMIN_KEY, env.SYNC_TOKEN)) {
    if (timingSafeEqualString(token, secret)) return true;
  }
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
  return configuredSecrets(env.ADMIN_KEY, env.SYNC_TOKEN).length > 0;
}

// 是否需要读鉴权（strict 模式且管理员密钥已配置）
export function needsAuthForRead(env) {
  if (!needsAuthForWrite(env)) return false;
  return getSyncMode(env) !== "open";
}

export function unauthorized() {
  return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
}
