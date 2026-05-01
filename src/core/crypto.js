// 加密原语：AES-GCM + PBKDF2 + RSA-OAEP + Base64 工具
// 移植自原 app.js 第 287-303、1974-1979、1996-2008、2306-2343 行

export function toB64(arr) {
  return btoa(String.fromCharCode.apply(null, Array.from(arr)));
}

export function fromB64(b64) {
  const bin = atob(b64 || "");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64url(bytes) {
  return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (s.length % 4)) % 4;
  if (pad) s += "=".repeat(pad);
  return fromB64(s);
}

// ---------- KDF / AES-GCM ----------
// 5.12 默认迭代 600k（OWASP 2023 推荐）；旧 meta 中存了 iter 字段则按它解密
export const KDF_ITERATIONS_DEFAULT = 600_000;

export async function deriveKey(password, salt, iterations = KDF_ITERATIONS_DEFAULT) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]
  );
}

export async function deriveSyncKey(secret, id) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]
  );
  const salt = enc.encode(`sync:${id}`);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt", "decrypt"]
  );
}

export async function syncEncrypt(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt));
  return { v: 1, iv: toB64(iv), ct: toB64(ct) };
}

export async function syncDecrypt(payload, key) {
  const iv = fromB64(payload.iv);
  const ct = fromB64(payload.ct);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

// ---------- RSA-OAEP (Vault) ----------
function decodePemOrB64(str) {
  let s = String(str || "").trim();
  if (s.includes("BEGIN")) {
    s = s.replace(/-----BEGIN [^-]+-----/g, "")
         .replace(/-----END [^-]+-----/g, "")
         .replace(/\s+/g, "");
  }
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

export async function importRsaPublicKey(pemOrB64) {
  return crypto.subtle.importKey(
    "spki", decodePemOrB64(pemOrB64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false, ["encrypt"]
  );
}

// 7.3 公钥指纹（SHA-256 取前 16 字节，hex 冒号分隔）
export async function pemFingerprint(pemOrB64) {
  try {
    const buf = decodePemOrB64(pemOrB64);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
    const slice = hash.slice(0, 16);
    return Array.from(slice).map(b => b.toString(16).padStart(2, "0")).join(":");
  } catch {
    return "";
  }
}

export async function importRsaPrivateKey(pemOrB64) {
  return crypto.subtle.importKey(
    "pkcs8", decodePemOrB64(pemOrB64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false, ["decrypt"]
  );
}

export async function rsaEncryptSecret(pubKey, secret, id) {
  const aesKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  const aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(JSON.stringify({ t: "sync-secret", id, v: 1, secret }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, pt));
  const ek = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, aesKeyRaw));
  return { v: 1, algo: "RSA-OAEP+AES-GCM", ek: toB64(ek), iv: toB64(iv), ct: toB64(ct), id, ts: Date.now() };
}

export async function rsaDecryptSecret(privKey, obj) {
  try {
    const aesKeyRaw = new Uint8Array(fromB64(obj.ek));
    const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privKey, aesKeyRaw);
    const aesKey = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
    const iv = new Uint8Array(fromB64(obj.iv));
    const ct = new Uint8Array(fromB64(obj.ct));
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct));
    const j = JSON.parse(new TextDecoder().decode(pt));
    return j && j.secret ? String(j.secret) : "";
  } catch {
    return "";
  }
}
