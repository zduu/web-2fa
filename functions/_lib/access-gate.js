import { timingSafeEqualString } from "./auth.js";

export const ACCESS_GATE_COOKIE = "cf_gate";

const ACCESS_GATE_KV_KEY = "config:access-gate";
const ACCESS_GATE_CACHE_TTL_MS = 5000;

let runtimeGateCache = {
  expiresAt: 0,
  value: null,
  pending: null,
};

export async function getAccessGateState(env) {
  const runtime = await loadRuntimeAccessGate(env);
  return runtimeToState(env, runtime);
}

export async function saveAccessGateConfig(env, { enabled }) {
  ensureGateConfigStore(env);
  const configuredPassword = getConfiguredGatePassword(env);
  if (enabled && !configuredPassword) {
    throw new Error("Cloudflare Pages 环境变量 ACCESS_GATE 未配置，无法启用访问口令");
  }

  const next = {
    version: 1,
    enabled: !!enabled,
    updatedAt: Date.now(),
  };
  await env.AUTH_KV.put(ACCESS_GATE_KV_KEY, JSON.stringify(next));
  runtimeGateCache = { expiresAt: Date.now() + ACCESS_GATE_CACHE_TTL_MS, value: next, pending: null };
  return runtimeToState(env, next);
}

export function buildAccessGateCookie(cookieValue) {
  return `${ACCESS_GATE_COOKIE}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 3600}`;
}

export function buildAccessGateClearCookie() {
  return `${ACCESS_GATE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function readAccessGateCookie(request) {
  const cookie = request.headers.get("Cookie") || "";
  return parseCookie(cookie).get(ACCESS_GATE_COOKIE) || "";
}

function hasGateConfigStore(env) {
  return !!(env.AUTH_KV && env.AUTH_KV.get && env.AUTH_KV.put);
}

function ensureGateConfigStore(env) {
  if (!hasGateConfigStore(env)) {
    throw new Error("服务端未绑定 AUTH_KV，无法站内修改访问口令");
  }
}

async function loadRuntimeAccessGate(env) {
  if (!hasGateConfigStore(env)) return null;

  const now = Date.now();
  if (runtimeGateCache.pending) return runtimeGateCache.pending;
  if (runtimeGateCache.expiresAt > now) return runtimeGateCache.value;

  runtimeGateCache.pending = env.AUTH_KV.get(ACCESS_GATE_KV_KEY)
    .then((raw) => {
      const parsed = parseRuntimeGate(raw);
      runtimeGateCache = {
        expiresAt: Date.now() + ACCESS_GATE_CACHE_TTL_MS,
        value: parsed,
        pending: null,
      };
      return parsed;
    })
    .catch(() => {
      runtimeGateCache = {
        expiresAt: Date.now() + ACCESS_GATE_CACHE_TTL_MS,
        value: null,
        pending: null,
      };
      return null;
    });

  return runtimeGateCache.pending;
}

function parseRuntimeGate(raw) {
  if (!raw) return null;
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return null; }
  if (!parsed || typeof parsed !== "object" || typeof parsed.enabled !== "boolean") return null;

  return {
    version: Number(parsed.version || 1) || 1,
    enabled: !!parsed.enabled,
    updatedAt: Number(parsed.updatedAt || 0) || null,
  };
}

async function runtimeToState(env, runtime) {
  const configuredPassword = getConfiguredGatePassword(env);
  const passwordConfigured = !!configuredPassword;
  const hasRuntimeConfig = !!runtime;
  const explicitEnabled = hasRuntimeConfig ? !!runtime.enabled : null;
  const enabled = explicitEnabled === null ? passwordConfigured : (explicitEnabled && passwordConfigured);
  const source = hasRuntimeConfig ? "kv" : (passwordConfigured ? "env" : "none");

  if (!enabled) {
    return {
      enabled: false,
      source,
      hasRuntimeConfig,
      editable: hasGateConfigStore(env),
      passwordConfigured,
      updatedAt: Number(runtime?.updatedAt || 0) || null,
      cookieValue: "",
      verifyPassword: async () => false,
    };
  }

  return {
    enabled: true,
    source,
    hasRuntimeConfig,
    editable: hasGateConfigStore(env),
    passwordConfigured,
    updatedAt: Number(runtime?.updatedAt || 0) || null,
    cookieValue: await cookieTagFor(configuredPassword),
    verifyPassword: async (password) => timingSafeEqualString(String(password || ""), configuredPassword),
  };
}

async function cookieTagFor(password) {
  return await sha256b64url(`gate-cookie:${password}`);
}

async function sha256b64url(text) {
  const data = new TextEncoder().encode(text);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return bytesToB64url(hash);
}

function parseCookie(str) {
  const map = new Map();
  str.split(/;\s*/).forEach((kv) => {
    const i = kv.indexOf("=");
    if (i === -1) return;
    const k = kv.slice(0, i).trim();
    const v = kv.slice(i + 1).trim();
    if (k) map.set(k, v);
  });
  return map;
}

function bytesToB64url(bytes) {
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function getConfiguredGatePassword(env) {
  const raw = typeof env.ACCESS_GATE === "string" ? env.ACCESS_GATE : "";
  return raw.trim() ? raw : "";
}
