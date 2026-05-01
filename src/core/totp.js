// TOTP / HOTP 算法 + otpauth + Google Authenticator migration 解析
// 移植自原 app.js 第 59-281 行，逻辑一致以保证算法等价性

export function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = (input || "").toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0, value = 0;
  const out = [];
  for (const c of clean) {
    const idx = alphabet.indexOf(c);
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

export function base32Encode(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "", bits = 0, value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

export async function hotp(secretBytes, counter, algo = "SHA-1", digits = 6) {
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  const hi = Math.floor(counter / 2 ** 32);
  const lo = counter >>> 0;
  view.setUint32(0, hi);
  view.setUint32(4, lo);

  const key = await crypto.subtle.importKey(
    "raw", secretBytes,
    { name: "HMAC", hash: { name: algo } },
    false, ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuf));

  const offset = sig[sig.length - 1] & 0xf;
  const code =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const mod = 10 ** digits;
  return (code % mod).toString().padStart(digits, "0");
}

export async function totp(secretBase32, { algorithm = "SHA1", digits = 6, period = 30 } = {}) {
  const algo = algorithm.toUpperCase();
  const hash = algo === "SHA256" ? "SHA-256" : algo === "SHA512" ? "SHA-512" : "SHA-1";
  const step = Math.max(5, Number(period) || 30);
  const counter = Math.floor(Date.now() / 1000 / step);
  return hotp(base32Decode(secretBase32), counter, hash, Number(digits) || 6);
}

export function secondsLeft(period = 30) {
  const step = Math.max(5, Number(period) || 30);
  const s = Math.floor(Date.now() / 1000);
  return step - (s % step);
}

export async function codeForItem(item) {
  if (item.type === "hotp") {
    const algo = item.algorithm === "SHA512" ? "SHA-512"
      : item.algorithm === "SHA256" ? "SHA-256" : "SHA-1";
    return hotp(base32Decode(item.secret), item.counter || 0, algo, item.digits || 6);
  }
  return totp(item.secret, item);
}

export function formatCode(text, digits) {
  const s = String(text || "");
  if ((digits || s.length) >= 8 && s.length >= 8) return s.slice(0, 4) + " " + s.slice(4, 8);
  if (s.length >= 6) return s.slice(0, 3) + " " + s.slice(3, 6);
  return s;
}

// ---------- otpauth ----------
export function parseOtpAuth(uri) {
  try {
    if (!uri || !uri.startsWith("otpauth://")) return null;
    const u = new URL(uri);
    const type = u.hostname;
    const label = decodeURIComponent(u.pathname.replace(/^\//, ""));
    let issuer = u.searchParams.get("issuer") || "";
    let account = label;
    if (label.includes(":")) {
      const [maybeIssuer, acct] = label.split(":");
      if (!issuer) issuer = maybeIssuer;
      account = acct;
    }
    const secret = (u.searchParams.get("secret") || "").replace(/\s+/g, "");
    const algorithm = (u.searchParams.get("algorithm") || "SHA1").toUpperCase();
    const digits = Number(u.searchParams.get("digits") || 6);
    const period = Number(u.searchParams.get("period") || 30);
    const counter = Number(u.searchParams.get("counter") || 0);
    return { type, issuer, account, secret, algorithm, digits, period, counter };
  } catch {
    return null;
  }
}

export function buildOtpAuthUrl(item) {
  const type = (item.type || "totp").toLowerCase();
  const issuer = item.issuer || "";
  const account = item.account || "";
  const label = issuer ? `${issuer}:${account}` : (account || "");
  const params = new URLSearchParams();
  params.set("secret", (item.secret || "").replace(/\s+/g, "").toUpperCase());
  if (issuer) params.set("issuer", issuer);
  if (item.algorithm) params.set("algorithm", (item.algorithm || "SHA1").toUpperCase());
  if (item.digits) params.set("digits", String(item.digits));
  if (type === "totp") {
    if (item.period) params.set("period", String(item.period));
  } else if (type === "hotp") {
    params.set("counter", String(item.counter || 0));
  }
  return `otpauth://${type}/${encodeURIComponent(label)}?${params.toString()}`;
}

// ---------- otpauth-migration (protobuf) ----------
function toB64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function bytesToB64url(bytes) {
  return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromB64(b64) {
  const bin = atob(b64 || "");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (s.length % 4)) % 4;
  if (pad) s += "=".repeat(pad);
  return fromB64(s);
}

function encodeVarint(value) {
  let current = BigInt(Math.max(0, Number(value || 0)));
  const out = [];
  while (current >= 0x80n) {
    out.push(Number((current & 0x7fn) | 0x80n));
    current >>= 7n;
  }
  out.push(Number(current));
  return out;
}

function encodeKey(tag, wireType) {
  return encodeVarint((tag << 3) | wireType);
}

function encodeBytesField(tag, bytes) {
  return [...encodeKey(tag, 2), ...encodeVarint(bytes.length), ...bytes];
}

function encodeStringField(tag, text) {
  return encodeBytesField(tag, new TextEncoder().encode(String(text || "")));
}

function encodeVarintField(tag, value) {
  return [...encodeKey(tag, 0), ...encodeVarint(value)];
}

function readVarint(buf, p) {
  let x = 0n, s = 0n; let i = p;
  while (i < buf.length) {
    const b = BigInt(buf[i++]);
    x |= (b & 0x7fn) << s;
    if ((b & 0x80n) === 0n) break;
    s += 7n;
  }
  return { value: x, pos: i };
}

function readBytes(buf, p) {
  const { value: lenBig, pos } = readVarint(buf, p);
  const len = Number(lenBig);
  const start = pos; const end = start + len;
  return { bytes: buf.slice(start, end), pos: end };
}

function parseOtpParameters(bytes) {
  const out = { secret: null, name: "", issuer: "", algorithm: 1, digits: 1, type: 2, counter: 0 };
  let p = 0;
  while (p < bytes.length) {
    const { value: keyBig, pos: p1 } = readVarint(bytes, p); p = p1;
    const key = Number(keyBig);
    const tag = key >>> 3; const wt = key & 7;
    if (tag === 1 && wt === 2) { const r = readBytes(bytes, p); p = r.pos; out.secret = r.bytes; }
    else if (tag === 2 && wt === 2) { const r = readBytes(bytes, p); p = r.pos; out.name = new TextDecoder().decode(r.bytes); }
    else if (tag === 3 && wt === 2) { const r = readBytes(bytes, p); p = r.pos; out.issuer = new TextDecoder().decode(r.bytes); }
    else if (tag === 4 && wt === 0) { const r = readVarint(bytes, p); p = r.pos; out.algorithm = Number(r.value); }
    else if (tag === 5 && wt === 0) { const r = readVarint(bytes, p); p = r.pos; out.digits = Number(r.value); }
    else if (tag === 6 && wt === 0) { const r = readVarint(bytes, p); p = r.pos; out.type = Number(r.value); }
    else if (tag === 7 && wt === 0) { const r = readVarint(bytes, p); p = r.pos; out.counter = Number(r.value); }
    else {
      if (wt === 2) { const r = readBytes(bytes, p); p = r.pos; }
      else if (wt === 0) { const r = readVarint(bytes, p); p = r.pos; }
      else break;
    }
  }
  return out;
}

function parseMigrationPayload(buf) {
  const items = [];
  let p = 0;
  while (p < buf.length) {
    const { value: keyBig, pos: p1 } = readVarint(buf, p); p = p1;
    const key = Number(keyBig);
    const tag = key >>> 3; const wt = key & 7;
    if (tag === 1 && wt === 2) {
      const r = readBytes(buf, p); p = r.pos;
      const param = parseOtpParameters(r.bytes);
      const algo = param.algorithm === 2 ? "SHA256" : param.algorithm === 3 ? "SHA512" : "SHA1";
      const digits = param.digits === 2 ? 8 : 6;
      const type = param.type === 1 ? "hotp" : "totp";
      if (!param.secret) continue;
      items.push({
        type, issuer: param.issuer || "", account: param.name || "",
        secret: base32Encode(param.secret), algorithm: algo, digits,
        period: 30, counter: param.counter || 0
      });
    } else if (wt === 2) { const r = readBytes(buf, p); p = r.pos; }
    else if (wt === 0) { const r = readVarint(buf, p); p = r.pos; }
    else break;
  }
  return items;
}

function normalizeMigrationAlgorithm(value) {
  const algo = String(value || "SHA1").toUpperCase();
  if (algo === "SHA256") return 2;
  if (algo === "SHA512") return 3;
  return 1;
}

function normalizeMigrationDigits(value) {
  return Number(value || 6) >= 8 ? 2 : 1;
}

function normalizeMigrationType(value) {
  return String(value || "totp").toLowerCase() === "hotp" ? 1 : 2;
}

export function buildMigrationPayload(items = [], opts = {}) {
  const {
    version = 1,
    batchSize = 1,
    batchIndex = 0,
    batchId = 0,
  } = opts || {};

  const payload = [];
  for (const raw of Array.isArray(items) ? items : []) {
    if (!raw || raw.deleted) continue;
    const secret = String(raw.secret || "").replace(/\s+/g, "").toUpperCase();
    const secretBytes = base32Decode(secret);
    if (!secretBytes.length) continue;
    const otp = [
      ...encodeBytesField(1, secretBytes),
      ...encodeStringField(2, raw.account || ""),
      ...encodeStringField(3, raw.issuer || ""),
      ...encodeVarintField(4, normalizeMigrationAlgorithm(raw.algorithm)),
      ...encodeVarintField(5, normalizeMigrationDigits(raw.digits)),
      ...encodeVarintField(6, normalizeMigrationType(raw.type)),
    ];
    if (normalizeMigrationType(raw.type) === 1) {
      otp.push(...encodeVarintField(7, Number(raw.counter || 0)));
    }
    payload.push(...encodeBytesField(1, otp));
  }
  if (!payload.length) return "";

  // Google Authenticator 协议必需的 batch 元数据：
  //   version       (tag 2): 协议版本，固定 1
  //   batch_size    (tag 3): 总分片数（>=1），缺失时 GA 报"出了点问题"
  //   batch_index   (tag 4): 当前分片下标（从 0 起）
  //   batch_id      (tag 5): 同一次导出的所有分片共享的随机 int32 标识
  payload.push(...encodeVarintField(2, Math.max(1, Number(version) || 1)));
  payload.push(...encodeVarintField(3, Math.max(1, Number(batchSize) || 1)));
  payload.push(...encodeVarintField(4, Math.max(0, Number(batchIndex) || 0)));
  payload.push(...encodeVarintField(5, Math.max(0, Number(batchId) || 0)));
  // Google 自己的导出使用标准 base64（带 padding），URL 中再做 percent-encoding。
  // 部分 GA 版本对 URL-safe base64（-/_、无 padding）不兼容。
  return toB64(new Uint8Array(payload));
}

export function buildMigrationUrl(items = [], opts = {}) {
  const data = buildMigrationPayload(items, opts);
  if (!data) return "";
  // 必须 percent-encode：标准 base64 含 +/= 字符，
  // 直接拼到 URL 会被解析端误读（+ 在 query 中表示空格）。
  return `otpauth-migration://offline?data=${encodeURIComponent(data)}`;
}

export function buildMigrationUrls(items = [], chunkSize = 10) {
  const list = Array.isArray(items) ? items.filter((it) => it && !it.deleted && it.secret) : [];
  const size = Math.max(1, Math.min(10, Number(chunkSize || 10)));
  const totalBatches = Math.max(1, Math.ceil(list.length / size));
  // 同一次导出的所有分片共享同一个 batch_id，让 Google Authenticator 把它们识别为一组。
  const batchId = generateBatchId();
  const out = [];
  for (let i = 0; i < list.length; i += size) {
    const url = buildMigrationUrl(list.slice(i, i + size), {
      version: 1,
      batchSize: totalBatches,
      batchIndex: Math.floor(i / size),
      batchId,
    });
    if (url) out.push(url);
  }
  return out;
}

function generateBatchId() {
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    // 保持非负 int32，protobuf int32 范围 [-2^31, 2^31-1]，
    // 取低 31 位即可，与 Google 自己生成的 batch_id 范围一致。
    return buf[0] & 0x7fffffff;
  }
  return Math.floor(Math.random() * 0x7fffffff);
}

export function parseOtpAuthMigration(uriOrData) {
  try {
    let dataParam = "";
    if (uriOrData.startsWith("otpauth-migration://")) {
      const u = new URL(uriOrData);
      dataParam = u.searchParams.get("data") || "";
    } else {
      dataParam = uriOrData.trim();
    }
    if (!dataParam) return [];
    return parseMigrationPayload(b64urlToBytes(dataParam));
  } catch {
    return [];
  }
}
