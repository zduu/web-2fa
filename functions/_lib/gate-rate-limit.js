const PREFIX = "gaterate:";
const WINDOW_SECONDS = 5 * 60;
const BLOCK_SECONDS = 15 * 60;
const MAX_FAILURES = 5;

export async function getGateRateLimit(env, request) {
  const key = await rateKey(env, request);
  if (!key || !env?.AUTH_KV?.get) return { limited: false, key: "", retryAfter: 0 };
  let record;
  try { record = parseRecord(await env.AUTH_KV.get(key)); } catch { record = null; }
  const now = Date.now();
  if (!record || record.expiresAt <= now) return { limited: false, key, retryAfter: 0 };
  if (record.blockedUntil > now) {
    return { limited: true, key, retryAfter: Math.max(1, Math.ceil((record.blockedUntil - now) / 1000)) };
  }
  return { limited: false, key, retryAfter: 0, record };
}

export async function recordGateFailure(env, state) {
  if (!state?.key || !env?.AUTH_KV?.put) return;
  const now = Date.now();
  const previous = state.record && state.record.expiresAt > now ? state.record : null;
  const failures = (previous?.failures || 0) + 1;
  const blockedUntil = failures >= MAX_FAILURES ? now + BLOCK_SECONDS * 1000 : 0;
  const record = { failures, blockedUntil, expiresAt: now + (blockedUntil ? BLOCK_SECONDS : WINDOW_SECONDS) * 1000 };
  try {
    await env.AUTH_KV.put(state.key, JSON.stringify(record), {
      expirationTtl: blockedUntil ? BLOCK_SECONDS : WINDOW_SECONDS,
    });
  } catch {}
}

export async function clearGateFailures(env, state) {
  if (!state?.key || !env?.AUTH_KV?.delete) return;
  try { await env.AUTH_KV.delete(state.key); } catch {}
}

async function rateKey(env, request) {
  const ip = String(request.headers.get("CF-Connecting-IP") || "").trim();
  if (!ip) return "";
  const salt = String(env.GATE_RATE_LIMIT_SALT || env.ADMIN_KEY || env.SYNC_TOKEN || env.ACCESS_GATE || "");
  const data = new TextEncoder().encode(`gate-rate:${salt}:${ip}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return PREFIX + Array.from(digest.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("");
}

function parseRecord(raw) {
  if (!raw) return null;
  let value;
  try { value = JSON.parse(raw); } catch { return null; }
  const failures = Math.max(0, Math.trunc(Number(value?.failures)) || 0);
  const blockedUntil = Math.max(0, Math.trunc(Number(value?.blockedUntil)) || 0);
  const expiresAt = Math.max(0, Math.trunc(Number(value?.expiresAt)) || 0);
  return { failures, blockedUntil, expiresAt };
}
