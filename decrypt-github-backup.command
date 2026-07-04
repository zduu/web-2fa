#!/bin/zsh

set -u

SCRIPT_DIR="${0:A:h}"
cd "$SCRIPT_DIR" || exit 1

if ! command -v node >/dev/null 2>&1; then
  echo "未找到 node。请先安装 Node.js 后重试。"
  echo
  echo "按回车关闭窗口..."
  read -r _
  exit 1
fi

TMP_JS="$(mktemp -t web2fa-decrypt.XXXXXX).mjs"
cleanup() {
  rm -f "$TMP_JS"
}
trap cleanup EXIT

cat > "$TMP_JS" <<'WEB2FA_STANDALONE_NODE'
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import path from "node:path";
import { webcrypto } from "node:crypto";
import { createInterface } from "node:readline";
import { Writable } from "node:stream";

const subtle = globalThis.crypto?.subtle || webcrypto.subtle;
const DEFAULT_BACKUP_FILE = ".web-2fa-backup/sync/google.web2fa-backup.json";
const DEFAULT_OUTPUT_DIR = "decrypted-backups";
const RESERVED_SYNC_ID_PREFIXES = ["sync:", "syncbak:", "synctomb:", "share:", "sharekey:", "sharestat:", "vault:", "audit:"];
let scriptedAnswers = null;
let scriptedAnswerIndex = 0;

main().catch((error) => {
  console.error(`\n${error?.message || error}`);
  process.exitCode = 1;
});

async function main() {
  console.log("web-2fa GitHub 备份本地解密");
  console.log("不会连接 Cloudflare / GitHub，只读取本地备份文件。");
  console.log("可以把备份 JSON 文件拖进这个窗口来填路径。\n");
  if (!process.stdin.isTTY) scriptedAnswers = readFileSync(0, "utf8").split(/\r?\n/);

  const backupPath = await promptBackupFile();
  const backup = await readBackupDocument(backupPath);
  if (backup.syncId) console.log(`备份内 Sync ID: ${backup.syncId}`);
  const syncIdOverride = await promptText("Sync ID 覆盖值，留空使用备份文件里的 syncId: ");
  const syncId = normalizeSyncRouteId(syncIdOverride || backup.syncId);
  if (!syncId) throw new Error("缺少有效 Sync ID。请重新运行并手动输入 Sync ID。");

  const secret = await promptSecret("原来的 Sync Secret（输入不可见）: ");
  if (!secret) throw new Error("Sync Secret 不能为空。");
  const format = await promptFormat();
  const outputDir = normalizePathInput(await promptText(`输出目录 [${DEFAULT_OUTPUT_DIR}]: `)) || DEFAULT_OUTPUT_DIR;

  let decrypted;
  try {
    const key = await deriveSyncKey(secret, syncId);
    decrypted = await syncDecrypt(backup.payload, key);
  } catch {
    throw new Error("解密失败。请确认 Sync ID 和 Sync Secret 与备份文件匹配。");
  }

  const items = (Array.isArray(decrypted?.items) ? decrypted.items : []).map(ensureItemDefaults);
  const activeItems = items.filter((item) => !item.deleted);
  const output = renderOutput({ items, activeItems, format, syncId });
  const resolvedOutputDir = path.resolve(process.cwd(), outputDir);
  await mkdir(resolvedOutputDir, { recursive: true });
  const outputPath = path.join(resolvedOutputDir, `web-2fa-decrypted-${sanitizeFilePart(syncId)}-${Date.now()}${output.ext}`);
  await writeFile(outputPath, output.content, "utf8");

  console.log(`\n解密完成：共 ${items.length} 条，活跃 ${activeItems.length} 条。`);
  console.log(`输出文件：${outputPath}`);
  console.log("请妥善保管输出文件，它包含真实 2FA Secret。");
}

async function promptBackupFile() {
  while (true) {
    const input = await promptText(`备份文件路径 [${DEFAULT_BACKUP_FILE}]: `);
    const file = normalizePathInput(input) || DEFAULT_BACKUP_FILE;
    const resolved = path.resolve(process.cwd(), file);
    try {
      await readFile(resolved, "utf8");
      return resolved;
    } catch {
      const retry = await promptText(`找不到文件：${resolved}\n重新输入？[Y/n]: `);
      if (retry.trim().toLowerCase() === "n") return resolved;
    }
  }
}

async function readBackupDocument(file) {
  let parsed;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`读取备份文件失败：${file}\n${error?.message || error}`);
  }
  const payload = isCipherPayload(parsed?.payload) ? parsed.payload : parsed;
  if (!isCipherPayload(payload)) throw new Error("备份文件格式不正确：缺少 payload.iv / payload.ct。");
  return { syncId: normalizeText(parsed?.syncId), payload };
}

async function deriveSyncKey(secret, id) {
  const enc = new TextEncoder();
  const baseKey = await subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode(`sync:${id}`), iterations: 200000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

async function syncDecrypt(payload, key) {
  const iv = Buffer.from(String(payload.iv || ""), "base64");
  const ct = Buffer.from(String(payload.ct || ""), "base64");
  const pt = await subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

function renderOutput({ items, activeItems, format, syncId }) {
  if (format === "otpauth") {
    return { ext: ".txt", content: activeItems.map((item) => buildExportRecord(item, syncId).otpauth).join("\n") + "\n" };
  }
  if (format === "csv") {
    const header = ["type", "issuer", "account", "password", "secret", "algorithm", "digits", "period", "counter", "project", "otpauth"];
    const rows = [header.join(",")].concat(activeItems.map((item) => {
      const record = buildExportRecord(item, syncId);
      return [
        record.type, record.issuer, record.account, record.password, record.secret,
        record.algorithm, String(record.digits), String(record.period),
        record.type === "hotp" ? String(record.counter) : "", record.project, record.otpauth,
      ].map(csvEscape).join(",");
    }));
    return { ext: ".csv", content: rows.join("\n") + "\n" };
  }
  return {
    ext: ".json",
    content: `${JSON.stringify({
      syncId,
      items: items.map((item) => ({
        ...item,
        otpauth: item.deleted ? "" : buildExportRecord(item, syncId).otpauth,
      })),
    }, null, 2)}\n`,
  };
}

function buildExportRecord(item, syncId) {
  const otp = normalizeOtpPayload(item);
  const record = {
    type: otp.type,
    issuer: String(item?.issuer || "").trim(),
    account: String(item?.account || "").trim(),
    password: typeof item?.password === "string" ? item.password : "",
    secret: otp.secret,
    algorithm: otp.algorithm,
    digits: otp.digits,
    period: normalizeOtpPeriod(item?.period ?? 30),
    counter: otp.type === "hotp" ? otp.counter : undefined,
    project: syncId,
  };
  return { ...record, otpauth: buildOtpAuthUrl(record) };
}

function ensureItemDefaults(item) {
  const out = { ...(item || {}) };
  out.issuer = String(out.issuer || "").trim();
  out.account = String(out.account || "").trim();
  out.password = typeof out.password === "string" ? out.password : "";
  out.secret = normalizeOtpSecret(out.secret);
  out.type = normalizeOtpType(out.type);
  out.algorithm = normalizeOtpAlgorithm(out.algorithm);
  out.digits = normalizeOtpDigits(out.digits || 6);
  out.period = normalizeOtpPeriod(out.period || 30);
  out.counter = normalizeHotpCounter(out.counter ?? 0);
  out.updatedAt = normalizeTimestamp(out.updatedAt);
  out.deleted = normalizeBoolean(out.deleted);
  out.pinned = normalizeBoolean(out.pinned);
  out.note = typeof out.note === "string" ? out.note : "";
  out.shares = Array.isArray(out.shares) ? out.shares : [];
  return out;
}

function buildOtpAuthUrl(item) {
  const type = normalizeOtpType(item?.type);
  const issuer = String(item?.issuer || "").trim();
  const account = String(item?.account || "").trim();
  const label = issuer ? `${issuer}:${account}` : account;
  const params = new URLSearchParams();
  params.set("secret", normalizeOtpSecret(item?.secret));
  if (issuer) params.set("issuer", issuer);
  params.set("algorithm", normalizeOtpAlgorithm(item?.algorithm));
  params.set("digits", String(normalizeOtpDigits(item?.digits)));
  if (type === "totp") params.set("period", String(normalizeOtpPeriod(item?.period)));
  else params.set("counter", String(normalizeHotpCounter(item?.counter)));
  return `otpauth://${type}/${encodeURIComponent(label)}?${params.toString()}`;
}

async function promptFormat() {
  while (true) {
    const value = (await promptText("输出格式：1=完整 JSON，2=otpauth，3=CSV [1]: ")).trim().toLowerCase();
    if (!value || value === "1" || value === "json") return "json";
    if (value === "2" || value === "otpauth") return "otpauth";
    if (value === "3" || value === "csv") return "csv";
    console.log("请输入 1、2 或 3。");
  }
}

function promptText(question) {
  if (scriptedAnswers) {
    process.stdout.write(question);
    return Promise.resolve(scriptedAnswers[scriptedAnswerIndex++] || "");
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (answer) => {
    rl.close();
    resolve(answer);
  }));
}

function promptSecret(question) {
  if (scriptedAnswers) {
    process.stdout.write(question);
    return Promise.resolve((scriptedAnswers[scriptedAnswerIndex++] || "").trim());
  }
  if (!process.stdin.isTTY) return promptText(question);
  const output = new Writable({
    write(chunk, encoding, callback) {
      if (!output.muted) process.stdout.write(chunk, encoding);
      callback();
    },
  });
  const rl = createInterface({ input: process.stdin, output, terminal: true });
  output.muted = false;
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      output.muted = false;
      process.stdout.write("\n");
      rl.close();
      resolve(answer.trim());
    });
    output.muted = true;
  });
}

function normalizePathInput(value) {
  let text = String(value || "").trim();
  if (!text) return "";
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) text = text.slice(1, -1);
  if (text.startsWith("file://")) {
    try { text = decodeURIComponent(new URL(text).pathname); } catch {}
  }
  return text.replace(/\\ /g, " ");
}

function isCipherPayload(value) {
  return !!value && typeof value === "object"
    && typeof value.iv === "string" && value.iv.trim()
    && typeof value.ct === "string" && value.ct.trim();
}

function normalizeSyncRouteId(value) {
  const id = normalizeText(value);
  if (!id) return "";
  if (/[\x00-\x1F\x7F]/.test(id)) return "";
  if (RESERVED_SYNC_ID_PREFIXES.some((prefix) => id.startsWith(prefix))) return "";
  return id;
}

function normalizeText(value) { return String(value || "").trim(); }
function normalizeOtpSecret(value) { return String(value || "").replace(/[\s-]+/g, "").toUpperCase().replace(/=+$/g, ""); }
function normalizeOtpType(value) { return String(value || "totp").toLowerCase() === "hotp" ? "hotp" : "totp"; }
function normalizeOtpAlgorithm(value) {
  const algo = String(value || "SHA1").replace(/[-_\s]/g, "").toUpperCase();
  if (algo === "SHA256") return "SHA256";
  if (algo === "SHA512") return "SHA512";
  return "SHA1";
}
function normalizeOtpDigits(value) {
  const digits = Math.trunc(Number(value));
  if (!Number.isFinite(digits)) return 6;
  return Math.min(10, Math.max(4, digits));
}
function normalizeOtpPeriod(value) {
  const period = Math.trunc(Number(value));
  if (!Number.isFinite(period)) return 30;
  return Math.max(5, period);
}
function normalizeHotpCounter(value) {
  const counter = Math.trunc(Number(value));
  if (!Number.isFinite(counter)) return 0;
  return Math.max(0, counter);
}
function normalizeOtpPayload(item = {}) {
  const type = normalizeOtpType(item?.type);
  const payload = {
    type,
    secret: normalizeOtpSecret(item?.secret),
    algorithm: normalizeOtpAlgorithm(item?.algorithm),
    digits: normalizeOtpDigits(item?.digits || 6),
  };
  if (type === "hotp") payload.counter = normalizeHotpCounter(item?.counter ?? 0);
  else payload.period = normalizeOtpPeriod(item?.period || 30);
  return payload;
}
function normalizeBoolean(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0 || value == null) return false;
  return ["1", "true", "yes", "y"].includes(String(value).trim().toLowerCase());
}
function normalizeTimestamp(value) {
  const ts = Math.trunc(Number(value));
  return Number.isFinite(ts) && ts > 0 && ts <= Number.MAX_SAFE_INTEGER ? ts : Date.now();
}
function sanitizeFilePart(name) {
  const cleaned = String(name || "").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 64);
  return /[A-Za-z0-9]/.test(cleaned) ? cleaned : "part";
}
function csvEscape(value) {
  const text = String(value ?? "");
  if (/[",\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}
WEB2FA_STANDALONE_NODE

node "$TMP_JS"
exit_code=$?

echo
echo "按回车关闭窗口..."
read -r _
exit "$exit_code"
