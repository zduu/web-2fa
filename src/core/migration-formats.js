import { normalizeImportedItem } from "./imports.js";
import { parseOtpAuth } from "./totp.js";

const BOM = /^\uFEFF/;
const ANDOTP_HEADER_BYTES = 28;

export function detectMigrationFile({ fileName = "", text = "", bytes = null, json = undefined } = {}) {
  const parsedJson = json === undefined ? safeJsonParse(text) : json;

  if (parsedJson !== null) {
    const aegis = parseAegisJson(parsedJson);
    if (aegis) return aegis;

    const andOtp = parseAndOtpJson(parsedJson);
    if (andOtp) return andOtp;

    const bitwarden = parseBitwardenJson(parsedJson);
    if (bitwarden) return bitwarden;
  }

  const csv = parseBitwardenCsv(text);
  if (csv) return csv;

  if (isLikelyAndOtpEncryptedBackup(bytes, fileName)) {
    return { kind: "andotp-encrypted", format: "andOTP 加密备份" };
  }

  return null;
}

export function parseAegisJson(input) {
  const obj = typeof input === "string" ? safeJsonParse(input) : input;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;

  const db = obj.db;
  const hasAegisShape = Number(obj.version) === 1 && ("db" in obj || "header" in obj);
  if (hasAegisShape && typeof db === "string") {
    return {
      kind: "unsupported",
      format: "Aegis 加密 Vault",
      error: "暂不支持直接导入加密的 Aegis Vault，请先在 Aegis 中导出未加密 JSON。"
    };
  }

  const entries = Array.isArray(db?.entries) ? db.entries : Array.isArray(obj.entries) ? obj.entries : null;
  if (!entries) return null;

  const items = [];
  const skippedTypes = new Set();
  let skippedInvalid = 0;

  for (const entry of entries) {
    const type = String(entry?.type || "totp").toLowerCase();
    if (type !== "totp" && type !== "hotp") {
      skippedTypes.add(type || "unknown");
      continue;
    }
    const info = entry?.info || {};
    const secret = String(info.secret || "").trim();
    if (!secret) {
      skippedInvalid++;
      continue;
    }
    items.push(normalizeImportedItem({
      type,
      issuer: entry?.issuer || "",
      account: entry?.name || "",
      note: entry?.note || "",
      pinned: !!entry?.favorite,
      secret,
      algorithm: info.algo || "SHA1",
      digits: info.digits || 6,
      period: type === "totp" ? (info.period || 30) : 30,
      counter: type === "hotp" ? (info.counter || 0) : 0,
    }));
  }

  return makeItemsResult("Aegis JSON", entries.length, items, skippedTypes, skippedInvalid);
}

export function parseBitwardenCsv(text) {
  const rows = parseCsvRows(text);
  if (!rows.length) return null;
  const headers = rows[0].map((cell) => String(cell || "").trim());
  const headerMap = new Map(headers.map((header, index) => [header.toLowerCase(), index]));
  if (!headerMap.has("name")) return null;
  if (!headerMap.has("login_totp") && !headerMap.has("totp")) return null;

  const items = [];
  let skippedInvalid = 0;

  for (const row of rows.slice(1)) {
    if (!row.some((cell) => String(cell || "").trim())) continue;
    const rawTotp = readCsvValue(row, headerMap, ["login_totp", "totp"]);
    if (!rawTotp) { skippedInvalid++; continue; }
    const parsed = parseBitwardenOtpField(rawTotp);
    if (!parsed) { skippedInvalid++; continue; }
    items.push(normalizeImportedItem({
      type: parsed.type || "totp",
      issuer: parsed.issuer || readCsvValue(row, headerMap, ["name"]) || "",
      account: parsed.account || readCsvValue(row, headerMap, ["login_username", "username"]) || "",
      password: readCsvValue(row, headerMap, ["login_password", "password"]) || "",
      note: readCsvValue(row, headerMap, ["notes"]) || "",
      pinned: readCsvValue(row, headerMap, ["favorite"]) === "1",
      secret: parsed.secret,
      algorithm: parsed.algorithm || "SHA1",
      digits: parsed.digits || 6,
      period: parsed.period || 30,
      counter: parsed.counter || 0,
    }));
  }

  return {
    kind: "items",
    format: "Bitwarden CSV",
    total: rows.length > 0 ? rows.length - 1 : 0,
    imported: items.length,
    skipped: Math.max(0, rows.length - 1 - items.length),
    items,
    warnings: buildWarnings([], skippedInvalid, items.length, "Bitwarden 导出中没有可识别的 TOTP/HOTP 字段。"),
  };
}

export function parseBitwardenJson(input) {
  const obj = typeof input === "string" ? safeJsonParse(input) : input;
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  if (obj.encrypted === true && !Array.isArray(obj.items)) {
    return {
      kind: "unsupported",
      format: "Bitwarden 加密 JSON",
      error: "暂不支持直接导入加密的 Bitwarden JSON，请先导出未加密 JSON 或 CSV。"
    };
  }
  const itemsRaw = Array.isArray(obj.items) ? obj.items : null;
  if (!itemsRaw) return null;

  const items = [];
  let skippedInvalid = 0;
  for (const entry of itemsRaw) {
    const rawTotp = entry?.login?.totp;
    if (!rawTotp) { skippedInvalid++; continue; }
    const parsed = parseBitwardenOtpField(rawTotp);
    if (!parsed) { skippedInvalid++; continue; }
    items.push(normalizeImportedItem({
      type: parsed.type || "totp",
      issuer: parsed.issuer || entry?.name || "",
      account: parsed.account || entry?.login?.username || "",
      password: entry?.login?.password || "",
      note: entry?.notes || "",
      pinned: !!entry?.favorite,
      secret: parsed.secret,
      algorithm: parsed.algorithm || "SHA1",
      digits: parsed.digits || 6,
      period: parsed.period || 30,
      counter: parsed.counter || 0,
    }));
  }

  return {
    kind: "items",
    format: "Bitwarden JSON",
    total: itemsRaw.length,
    imported: items.length,
    skipped: Math.max(0, itemsRaw.length - items.length),
    items,
    warnings: buildWarnings([], skippedInvalid, items.length, "Bitwarden 导出中没有可识别的 TOTP/HOTP 条目。"),
  };
}

export function parseAndOtpJson(input) {
  const arr = typeof input === "string" ? safeJsonParse(input) : input;
  if (!Array.isArray(arr)) return null;
  const looksLikeAndOtp = arr.every((entry) => entry && typeof entry === "object" && "secret" in entry && "label" in entry);
  if (!looksLikeAndOtp) return null;

  const items = [];
  const skippedTypes = new Set();
  let skippedInvalid = 0;

  for (const entry of arr) {
    const type = String(entry?.type || "TOTP").toLowerCase();
    if (type !== "totp" && type !== "hotp") {
      skippedTypes.add(type || "unknown");
      continue;
    }
    const secret = String(entry?.secret || "").trim();
    if (!secret) {
      skippedInvalid++;
      continue;
    }
    items.push(normalizeImportedItem({
      type,
      issuer: entry?.issuer || "",
      account: entry?.label || "",
      secret,
      algorithm: entry?.algorithm || "SHA1",
      digits: entry?.digits || 6,
      period: type === "totp" ? (entry?.period || 30) : 30,
      counter: type === "hotp" ? (entry?.counter || 0) : 0,
    }));
  }

  return makeItemsResult("andOTP JSON", arr.length, items, skippedTypes, skippedInvalid);
}

export async function decryptAndParseAndOtpBackup(input, password) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!isLikelyAndOtpEncryptedBackup(bytes, "")) {
    throw new Error("文件看起来不是 andOTP 加密备份。");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const iterations = view.getInt32(0, false);
  const salt = bytes.slice(4, 16);
  const iv = bytes.slice(16, 28);
  const payload = bytes.slice(28);
  if (!password) throw new Error("请输入 andOTP 备份密码。");

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-1" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, payload);
    const text = new TextDecoder().decode(new Uint8Array(plain));
    const parsed = parseAndOtpJson(text);
    if (!parsed) throw new Error("解密成功，但备份内容不是可识别的 andOTP JSON。");
    return { ...parsed, format: "andOTP 加密备份" };
  } catch {
    throw new Error("andOTP 备份解密失败，请检查密码后重试。");
  }
}

export function isLikelyAndOtpEncryptedBackup(input, fileName = "") {
  const bytes = input instanceof Uint8Array ? input : (input ? new Uint8Array(input) : null);
  if (!bytes || bytes.byteLength <= ANDOTP_HEADER_BYTES) return false;
  const iterations = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(0, false);
  if (!Number.isFinite(iterations) || iterations < 1000 || iterations > 10_000_000) return false;
  if (!fileName) return true;
  if (/\.(aes|crypt|bin)$/i.test(fileName || "")) return true;
  if (/andotp/i.test(fileName || "")) return true;
  return false;
}

function makeItemsResult(format, total, items, skippedTypes, skippedInvalid) {
  return {
    kind: "items",
    format,
    total,
    imported: items.length,
    skipped: Math.max(0, total - items.length),
    items,
    warnings: buildWarnings(
      skippedTypes,
      skippedInvalid,
      items.length,
      `${format} 中没有可导入的 TOTP/HOTP 条目。`
    ),
  };
}

function buildWarnings(skippedTypes, skippedInvalid, importedCount, emptyFallback) {
  const warnings = [];
  const types = Array.from(skippedTypes || []);
  if (types.length) {
    warnings.push(`已跳过当前应用不支持的类型：${types.join(" / ")}。`);
  }
  if (skippedInvalid > 0) {
    warnings.push(`已跳过 ${skippedInvalid} 条缺少可识别密钥或格式不完整的记录。`);
  }
  if (!importedCount && !warnings.length) {
    warnings.push(emptyFallback);
  }
  return warnings;
}

function parseBitwardenOtpField(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) return null;
  if (value.startsWith("otpauth://")) {
    const parsed = parseOtpAuth(value);
    if (!parsed) return null;
    return {
      type: String(parsed.type || "totp").toLowerCase(),
      issuer: parsed.issuer || "",
      account: parsed.account || "",
      secret: parsed.secret || "",
      algorithm: parsed.algorithm || "SHA1",
      digits: parsed.digits || 6,
      period: parsed.period || 30,
      counter: parsed.counter || 0,
    };
  }
  return {
    type: "totp",
    secret: value,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
  };
}

function parseCsvRows(text) {
  const src = stripBom(text);
  if (!src.trim()) return [];
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === "\"") {
        if (src[i + 1] === "\"") {
          field += "\"";
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }

    if (ch === "\"") {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (ch !== "\r") {
      field += ch;
    }
  }

  row.push(field);
  if (row.length > 1 || String(row[0] || "").trim()) rows.push(row);
  return rows;
}

function readCsvValue(row, headerMap, names) {
  for (const name of names) {
    const idx = headerMap.get(name);
    if (idx == null) continue;
    return String(row[idx] || "").trim();
  }
  return "";
}

function safeJsonParse(text) {
  const trimmed = stripBom(text).trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function stripBom(text) {
  return String(text || "").replace(BOM, "");
}
