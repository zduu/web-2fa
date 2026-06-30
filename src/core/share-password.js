// 分享口令保护：可选地用 PBKDF2 + AES-GCM 包裹分享密钥。
// 不设置口令时仍走原始 #k=... 方案，保持兼容。

import { b64url, fromB64url, deriveKey } from "./crypto.js";

export const SHARE_PASSWORD_ITERATIONS = 200_000;
export const SHARE_PASSWORD_MIN_ITERATIONS = 1_000;
export const SHARE_PASSWORD_MAX_ITERATIONS = 10_000_000;

export async function wrapShareKeyWithPassword(keyRaw, password, iterations = SHARE_PASSWORD_ITERATIONS) {
  const secret = String(password || "").trim();
  if (!secret) return null;
  const normalizedIterations = normalizeSharePasswordIterations(iterations);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(secret, salt, normalizedIterations);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, keyRaw));
  return {
    v: 1,
    s: b64url(salt),
    iv: b64url(iv),
    wk: b64url(ct),
    iter: normalizedIterations,
  };
}

export async function unwrapShareKeyWithPassword(bundle, password) {
  const secret = String(password || "").trim();
  if (!secret) throw new Error("missing-password");
  if (!bundle || typeof bundle !== "object") throw new Error("missing-bundle");
  if (!isSupportedShareKeyBundleVersion(bundle.v)) throw new Error("invalid-bundle");
  const salt = fromB64url(bundle.s || "");
  const iv = fromB64url(bundle.iv || "");
  const ct = fromB64url(bundle.wk || "");
  if (!salt.length || !iv.length || !ct.length) throw new Error("invalid-bundle");
  const key = await deriveKey(secret, salt, normalizeSharePasswordIterations(bundle.iter));
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}

export function normalizeSharePasswordIterations(value) {
  const iterations = Math.trunc(Number(value));
  if (
    !Number.isFinite(iterations) ||
    iterations < SHARE_PASSWORD_MIN_ITERATIONS ||
    iterations > SHARE_PASSWORD_MAX_ITERATIONS
  ) {
    return SHARE_PASSWORD_ITERATIONS;
  }
  return iterations;
}

export function isSupportedShareKeyBundleVersion(value) {
  return value === undefined || value === null || value === 1;
}
