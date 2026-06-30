// 分享验证码端点（服务端生成 TOTP，接收方拿不到 secret）
// GET /api/share-code/<id>?k=<codeKey>
// 服务端用 codeKey 解密 secret，计算当前 TOTP，只返回验证码和剩余秒数

import { normalizeRouteId } from "../../_lib/ids.js";
import { hasKvMethods, kvMissingTextResponse } from "../../_lib/kv.js";
import { normalizeOptionalTimestamp } from "../../_lib/numbers.js";

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

  if (!hasKvMethods(env, ["get"])) return kvMissingTextResponse(200);

  const url = new URL(request.url);
  const codeKeyB64 = url.searchParams.get("k");
  if (!codeKeyB64) return noStoreResponse("Missing code key", 400);

  const value = await env.AUTH_KV.get(`sharecode:${id}`);
  if (!value) return noStoreResponse("Not found", 404);

  let codePayload;
  try { codePayload = JSON.parse(value); } catch { codePayload = null; }
  if (!codePayload || !codePayload.iv || !codePayload.ct) {
    return noStoreResponse("Bad data", 500);
  }

  // 解密 secret
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

  let code;
  try {
    code = await hotp(base32Decode(secretData.secret), step, algo, digits);
  } catch {
    return noStoreResponse("Server Error", 500, { "X-Note": "error" });
  }

  return new Response(JSON.stringify({
    code,
    secondsLeft,
    digits,
    algorithm: secretData.algorithm || "SHA1",
    period,
  }), {
    status: 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export async function onRequestPut(context) {
  const { request, env, params } = context;
  // 写入鉴权由 _middleware.js 通过 X-Token 控制
  const id = normalizeRouteId(params.id);
  if (!id) return noStoreResponse("Missing id", 400);
  if (!hasKvMethods(env, ["put"])) return kvMissingTextResponse(200);

  const text = await request.text();
  let body;
  try {
    body = JSON.parse(text);
    if (!body || !body.iv || !body.ct) throw new Error("invalid");
  } catch {
    return noStoreResponse("Bad Request", 400);
  }

  const stored = { v: 1, iv: body.iv, ct: body.ct };
  const url = new URL(request.url);
  const ttlParam = url.searchParams.get("ttl");
  if (ttlParam === "perm" || ttlParam === "0") {
    await env.AUTH_KV.put(`sharecode:${id}`, JSON.stringify(stored));
  } else {
    const ttl = Math.max(60, Math.floor(Number(ttlParam)) || 86400);
    await env.AUTH_KV.put(`sharecode:${id}`, JSON.stringify(stored), { expirationTtl: ttl });
  }
  return new Response("OK", { status: 200, headers: { "Cache-Control": "no-store" } });
}

function noStoreResponse(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: { ...headers, "Cache-Control": "no-store" },
  });
}
