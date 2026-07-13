// 分享验证码端点（服务端生成 TOTP，接收方拿不到 secret）
// GET /api/share-code/<id>，codeKey 优先通过 X-Share-Code-Key 传递
// 旧版 ?k=<codeKey> 链接继续兼容；服务端只返回验证码和剩余秒数

import { isAuthed, needsAuthForWrite, unauthorized } from "../../_lib/auth.js";
import { normalizeRouteId } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingTextResponse } from "../../_lib/kv.js";
import { normalizeNonNegativeInteger, normalizeOptionalTimestamp, normalizePositiveInteger } from "../../_lib/numbers.js";
import { readRequestText, requestTooLarge } from "../../_lib/request-body.js";
import { parseShareOptions } from "../../_lib/share-options.js";

// 内联 base32 解码（避免跨模块依赖）
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Decode(input) {
  const clean = (input || "").toUpperCase().replace(/=+$/g, "").replace(/[\s-]+/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const c of clean) {
    const idx = BASE32_ALPHABET.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// 内联 base64url 解码
function fromB64url(s) {
  s = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (s.length % 4)) % 4;
  if (pad) s += "=".repeat(pad);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hotp(secretBytes, counter, algo, digits) {
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  const hi = Math.floor(counter / 2 ** 32);
  const lo = counter >>> 0;
  view.setUint32(0, hi);
  view.setUint32(4, lo);

  const key = await crypto.subtle.importKey(
    "raw", secretBytes, { name: "HMAC", hash: { name: algo } }, false, ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuf));
  const offset = sig[sig.length - 1] & 0xf;
  const code = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16)
    | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  const mod = 10 ** digits;
  return (code % mod).toString().padStart(digits, "0");
}

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);

  if (!hasKvMethods(env, ["get", "put", "delete"])) return kvMissingTextResponse(200);

  const url = new URL(request.url);
  const codeKeyB64 = request.headers.get("X-Share-Code-Key") || url.searchParams.get("k");
  if (!codeKeyB64) return noStoreResponse("Missing code key", 400);

  const value = await env.AUTH_KV.get(`sharecode:${id}`);
  if (!value) return noStoreResponse("Not found", 404);

  let codePayload;
  try { codePayload = JSON.parse(value); } catch { codePayload = null; }
  if (!codePayload || !codePayload.iv || !codePayload.ct) {
    return noStoreResponse("Bad data", 500);
  }

  const max = normalizeNonNegativeInteger(codePayload.max, { max: 1_000_000 });
  const count = normalizeNonNegativeInteger(codePayload.count);
  const ttl = normalizeNonNegativeInteger(codePayload.ttl);
  const expireAt = normalizeOptionalTimestamp(codePayload.expireAt);

  if (expireAt && expireAt <= Date.now()) {
    try { await cleanupShareCode(env, id, { strictPrimary: true }); }
    catch { return noStoreResponse("Server Error", 500, { "X-Note": "error" }); }
    return noStoreResponse("Gone", 410, { "X-Share-Reason": "expired" });
  }
  if (max > 0 && count >= max) {
    try { await cleanupShareCode(env, id, { strictPrimary: true }); }
    catch { return noStoreResponse("Server Error", 500, { "X-Note": "error" }); }
    return noStoreResponse("Gone", 410, { "X-Share-Reason": "max-access-exceeded" });
  }

  let secretData;
  try {
    const keyRaw = fromB64url(codeKeyB64);
    const iv = fromB64url(codePayload.iv);
    const ct = fromB64url(codePayload.ct);
    const key = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-GCM" }, false, ["decrypt"]);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
    secretData = JSON.parse(new TextDecoder().decode(pt));
  } catch {
    return noStoreResponse("解密失败，链接可能已损坏或已撤销", 410);
  }

  if (!secretData.secret) return noStoreResponse("Bad data", 500);

  // 计算当前 TOTP
  const algorithm = String(secretData.algorithm || "SHA1").toUpperCase();
  const algo = algorithm === "SHA256" ? "SHA-256" : algorithm === "SHA512" ? "SHA-512" : "SHA-1";
  const digits = Math.min(10, Math.max(4, Math.trunc(Number(secretData.digits)) || 6));
  const period = Math.max(5, Math.trunc(Number(secretData.period)) || 30);
  const step = Math.floor(Date.now() / 1000 / period);
  const secondsLeft = period - (Math.floor(Date.now() / 1000) % period);
  const issuedStep = normalizePositiveInteger(codePayload.issuedStep);
  if (issuedStep !== null && issuedStep !== step) {
    try { await cleanupShareCode(env, id, { strictPrimary: true }); }
    catch { return noStoreResponse("Server Error", 500, { "X-Note": "error" }); }
    return noStoreResponse("Gone", 410, { "X-Share-Reason": "code-window-expired" });
  }

  let code;
  try {
    code = await hotp(base32Decode(secretData.secret), step, algo, digits);
  } catch {
    return noStoreResponse("Server Error", 500, { "X-Note": "error" });
  }

  const nextCount = count + 1;
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Access-Remaining": formatAccessRemaining(max, nextCount),
  };
  const now = Date.now();
  const stat = {
    accessCount: nextCount,
    lastAccessAt: now,
    accessUserAgentSample: sanitizeUserAgent(request.headers.get("User-Agent")),
  };
  try {
    if (max > 0 && nextCount >= max) {
      try { await writeShareStat(env, id, stat, expireAt); } catch {}
      await cleanupShareCode(env, id, { strictPrimary: true });
    } else {
      const next = { ...codePayload, count: nextCount, issuedStep: step, lastAccessAt: now };
      if (ttl > 0) {
        const remain = expireAt ? Math.max(60, Math.floor((expireAt - Date.now()) / 1000)) : ttl;
        await env.AUTH_KV.put(`sharecode:${id}`, JSON.stringify(next), { expirationTtl: remain });
      } else {
        await env.AUTH_KV.put(`sharecode:${id}`, JSON.stringify(next));
      }
      try { await writeShareStat(env, id, stat, expireAt); } catch {}
    }
  } catch (error) {
    console.error(`share-code/${id}: KV write failed before response`, error?.message || error);
    return noStoreResponse("Server Error", 500, { "X-Note": "error" });
  }

  return new Response(JSON.stringify({
    code,
    secondsLeft,
    digits,
    algorithm: secretData.algorithm || "SHA1",
    period,
    label: secretData.label || "",
    note: secretData.note || "",
  }), {
    status: 200,
    headers,
  });
}

export async function onRequestPut(context) {
  const { request, env, params } = context;
  const tokenHeader = request.headers.get("X-Token");
  if (needsAuthForWrite(env) && !isAuthed(env, tokenHeader)) return unauthorized();
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);
  if (!hasKvMethods(env, ["put"])) return kvMissingTextResponse(200);

  let text;
  try { text = await readRequestText(request, 256 * 1024); }
  catch (error) { return requestTooLarge(error); }
  let body;
  try {
    body = JSON.parse(text);
    if (!body || !body.iv || !body.ct) throw new Error("invalid");
  } catch {
    return noStoreResponse("Bad Request", 400);
  }

  const url = new URL(request.url);
  const { permanent: usePermanent, ttl: useTtl, maxAccess } = parseShareOptions({
    defaultTtl: env.SHARE_TTL,
    ttlParam: url.searchParams.get("ttl"),
    maxParam: url.searchParams.get("max"),
  });
  const stored = {
    v: 1,
    iv: body.iv,
    ct: body.ct,
    max: maxAccess,
    count: 0,
    ttl: usePermanent ? 0 : useTtl,
    expireAt: usePermanent ? 0 : (Date.now() + useTtl * 1000),
    createdAt: Date.now(),
  };
  if (usePermanent) {
    await env.AUTH_KV.put(`sharecode:${id}`, JSON.stringify(stored));
  } else {
    await env.AUTH_KV.put(`sharecode:${id}`, JSON.stringify(stored), { expirationTtl: useTtl });
  }
  return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
}

function noStoreResponse(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: { ...headers, "Cache-Control": "no-store" },
  });
}

async function cleanupShareCode(env, id, { strictPrimary = false } = {}) {
  try {
    await env.AUTH_KV.delete(`sharecode:${id}`);
  } catch (error) {
    if (strictPrimary) throw error;
  }
  try { await env.AUTH_KV.delete(`sharekey:${id}`); } catch {}
  try { await env.AUTH_KV.delete(`sharestat:${id}`); } catch {}
}

async function writeShareStat(env, id, stat, expireAt = 0) {
  if (!hasKvMethods(env, ["put"])) return;
  const key = `sharestat:${id}`;
  const body = JSON.stringify({
    accessCount: normalizeNonNegativeInteger(stat?.accessCount),
    lastAccessAt: normalizeOptionalTimestamp(stat?.lastAccessAt),
    accessUserAgentSample: sanitizeUserAgent(stat?.accessUserAgentSample),
  });
  const normalizedExpireAt = normalizeOptionalTimestamp(expireAt);
  const remain = normalizedExpireAt ? Math.max(60, Math.floor((normalizedExpireAt - Date.now()) / 1000)) : 0;
  if (remain > 0) await env.AUTH_KV.put(key, body, { expirationTtl: remain });
  else await env.AUTH_KV.put(key, body);
}

function sanitizeUserAgent(value) {
  if (typeof value !== "string") return "";
  const text = String(value || "").replace(/[\x00-\x1F\x7F]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.slice(0, 160) : "";
}

function formatAccessRemaining(max, used) {
  return max > 0 ? String(Math.max(0, max - used)) : "unlimited";
}
