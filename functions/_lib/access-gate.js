import { timingSafeEqualString } from "./auth.js";
import { normalizeOptionalTimestamp, normalizePositiveInteger } from "./numbers.js";

export const ACCESS_GATE_COOKIE = "cf_gate";

const ACCESS_GATE_KV_KEY = "config:access-gate";
const ACCESS_GATE_SESSION_PREFIX = "gatesession:";
const ACCESS_GATE_CACHE_TTL_MS = 5000;
const ACCESS_GATE_SESSION_TTL_SECONDS = 7 * 24 * 3600;

let runtimeGateCache = {
  expiresAt: 0,
  value: null,
  pending: null,
  store: null,
};

export async function getAccessGateState(env) {
  const runtime = await loadRuntimeAccessGate(env);
  return runtimeToState(env, runtime);
}

export async function saveAccessGateConfig(env, { enabled }) {
  ensureGateConfigStore(env);
  const shouldEnable = enabled === true;
  const configuredPassword = getConfiguredGatePassword(env);
  if (shouldEnable && !configuredPassword) {
    throw new Error("Cloudflare Pages 环境变量 ACCESS_GATE 未配置，无法启用访问口令");
  }

  const next = {
    version: 1,
    enabled: shouldEnable,
    updatedAt: Date.now(),
  };
  await env.AUTH_KV.put(ACCESS_GATE_KV_KEY, JSON.stringify(next));
  runtimeGateCache = {
    expiresAt: Date.now() + ACCESS_GATE_CACHE_TTL_MS,
    value: next,
    pending: null,
    store: env.AUTH_KV,
  };
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

export async function createAccessGateSession(env, gate) {
  if (!env?.AUTH_KV?.put) return gate.cookieValue;
  const token = randomToken();
  const key = await accessGateSessionKey(token);
  await env.AUTH_KV.put(key, JSON.stringify({ tag: gate.cookieValue }), {
    expirationTtl: ACCESS_GATE_SESSION_TTL_SECONDS,
  });
  return token;
}

export async function verifyAccessGateSession(env, gate, token) {
  if (!token) return false;
  if (!env?.AUTH_KV?.get) return timingSafeEqualString(token, gate.cookieValue);
  let raw;
  try { raw = await env.AUTH_KV.get(await accessGateSessionKey(token)); }
  catch { return false; }
  if (!raw) return false;
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return false; }
  return timingSafeEqualString(parsed?.tag, gate.cookieValue);
}

export async function revokeAccessGateSession(env, token) {
  if (!token || !env?.AUTH_KV?.delete) return;
  try { await env.AUTH_KV.delete(await accessGateSessionKey(token)); } catch {}
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
  const store = env.AUTH_KV;
  if (runtimeGateCache.store === store && runtimeGateCache.pending) return runtimeGateCache.pending;
  if (runtimeGateCache.store === store && runtimeGateCache.expiresAt > now) return runtimeGateCache.value;

  runtimeGateCache.pending = store.get(ACCESS_GATE_KV_KEY)
    .then((raw) => {
      const parsed = parseRuntimeGate(raw);
      runtimeGateCache = {
        expiresAt: Date.now() + ACCESS_GATE_CACHE_TTL_MS,
        value: parsed,
        pending: null,
        store,
      };
      return parsed;
    })
    .catch(() => {
      runtimeGateCache = {
        expiresAt: Date.now() + ACCESS_GATE_CACHE_TTL_MS,
        value: null,
        pending: null,
        store,
      };
      return null;
    });

  return runtimeGateCache.pending;
}

function parseRuntimeGate(raw) {
  if (!raw) return null;
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return null; }
  if (!parsed || typeof parsed !== "object") return null;
  const enabled = normalizeRuntimeGateEnabled(parsed.enabled);
  if (enabled === null) return null;

  return {
    version: normalizePositiveInteger(parsed.version) || 1,
    enabled,
    updatedAt: normalizeOptionalTimestamp(parsed.updatedAt),
  };
}

function normalizeRuntimeGateEnabled(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes" || normalized === "y") return true;
    if (normalized === "false" || normalized === "0" || normalized === "no" || normalized === "n") return false;
  }
  return null;
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
      updatedAt: normalizeOptionalTimestamp(runtime?.updatedAt),
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
    updatedAt: normalizeOptionalTimestamp(runtime?.updatedAt),
    cookieValue: await cookieTagFor(
      configuredPassword,
      getGateCookieSecret(env),
      normalizeOptionalTimestamp(runtime?.updatedAt) || 0,
    ),
    verifyPassword: async (password) => timingSafeEqualString(normalizeGatePasswordInput(password), configuredPassword),
  };
}

async function cookieTagFor(password, secret, generation) {
  return await sha256b64url(`gate-cookie:v2:${secret}:${generation}:${password}`);
}

async function accessGateSessionKey(token) {
  return `${ACCESS_GATE_SESSION_PREFIX}${await sha256b64url(`session:${token}`)}`;
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToB64url(bytes);
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
  if (typeof btoa !== "function" && typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  const bin = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function getConfiguredGatePassword(env) {
  const raw = typeof env.ACCESS_GATE === "string" ? env.ACCESS_GATE : "";
  return raw.trim();
}

function getGateCookieSecret(env) {
  const candidates = [env.GATE_COOKIE_SECRET, env.ADMIN_KEY, env.SYNC_TOKEN, env.KV_ADMIN_KEY];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) return candidate.trim();
  }
  return "no-server-secret";
}

function normalizeGatePasswordInput(value) {
  return typeof value === "string" ? value.trim() : "";
}
