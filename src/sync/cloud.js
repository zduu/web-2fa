// 云端浏览（管理员）：列出所有 sync:* + 全部解密 + 多格式导出

import { state, getGlobalToken, ensureItemDefaults } from "../core/storage.js";
import { deriveSyncKey, syncDecrypt } from "../core/crypto.js";
import { buildOtpAuthUrl, normalizeOtpPayload, normalizeOtpPeriod } from "../core/totp.js";
import { downloadBlob, sanitizeFilePart } from "../ui/toast.js";
import { getSyncEndpoint, normalizeSyncRouteId } from "./sync.js";
import { apiUrl } from "../core/runtime.js";

export async function listAllCloudProjects() {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const res = await fetch(apiUrl("/api/admin/list-all"), {
    method: "POST",
    headers: { "X-KV-Admin-Key": token, "X-Token": token, "Content-Type": "application/json" }
  });
  if (res.status === 401) {
    const e = new Error("Admin Key 无效"); e.code = "unauth"; throw e;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  throwForCloudListNote(res, data);
  if (!data.success) throw new Error(data.error || "加载失败");
  return Array.isArray(data.projects) ? data.projects : [];
}

function throwForCloudListNote(response, data) {
  const note = response?.headers?.get?.("X-Note") || "";
  if (!note) return;
  if (note === "kv-missing") throw new Error("服务端未绑定 AUTH_KV");
  if (typeof data?.error === "string" && data.error.trim()) throw new Error(data.error.trim());
  throw new Error("加载失败");
}

export async function decryptCloudAll({ projects, secrets, concurrency = 5 }) {
  // try every secret per project, first success wins
  const allProjects = Array.isArray(projects) ? projects : [];
  if (!allProjects.length) return { items: [], failed: 0 };
  const targetProjects = getDecryptableCloudProjects(allProjects);
  const secretList = normalizeCloudSecrets(secrets);
  if (!secretList.length) return { items: [], failed: allProjects.length };
  const aggregated = [];
  let failed = allProjects.length - targetProjects.length;
  const token = getGlobalToken();
  let index = 0;
  const workerCount = Math.min(normalizeCloudConcurrency(concurrency), targetProjects.length);
  async function worker() {
    while (index < targetProjects.length) {
      const i = index++;
      const proj = targetProjects[i];
      const id = normalizeCloudSyncId(proj.syncId);
      try {
        const res = await fetch(getSyncEndpoint(id), {
          headers: { "X-Token": token, "Cache-Control": "no-cache" }
        });
        if (!res.ok) { failed++; continue; }
        const payload = await res.json();
        const attempts = secretList.map(sec => (async () => {
          const key = await deriveSyncKey(sec, id);
          const obj = await syncDecrypt(payload, key);
          return (obj.items || []).map(ensureItemDefaults).map(it => ({ ...it, _projectName: cloudProjectName(id) }));
        })());
        let items = null;
        try {
          items = (typeof Promise.any === "function")
            ? await Promise.any(attempts)
            : await new Promise((resolve, reject) => {
                let pending = attempts.length;
                attempts.forEach(p => Promise.resolve(p).then(resolve).catch(() => { if (--pending === 0) reject(new Error("all-failed")); }));
              });
        } catch { items = null; }
        if (Array.isArray(items)) aggregated.push(...items);
        else failed++;
      } catch { failed++; }
    }
  }
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return { items: aggregated, failed };
}

export function isDecryptableCloudProject(project) {
  return !!normalizeCloudSyncId(project?.syncId) && !isFalseLikeMetadataValue(project?.metadata?.valid);
}

export function getDecryptableCloudProjects(projects) {
  return (Array.isArray(projects) ? projects : []).filter(isDecryptableCloudProject);
}

function isFalseLikeMetadataValue(value) {
  if (value === false || value === 0) return true;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized === "false" || normalized === "0" || normalized === "no" || normalized === "n";
  }
  return false;
}

export function normalizeCloudConcurrency(value, fallback = 5) {
  const normalizedFallback = Math.min(10, Math.max(1, Math.trunc(Number(fallback)) || 5));
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n)) return normalizedFallback;
  return Math.min(10, Math.max(1, n));
}

export function normalizeCloudSecrets(secrets) {
  if (!Array.isArray(secrets)) return [];
  return secrets
    .map((secret) => String(secret || "").trim())
    .filter(Boolean);
}

export function exportDecrypted({ items, format = "otpauth", split = false, selected = null }) {
  const files = buildDecryptedExportFiles({ items, format, split, selected });
  for (const file of files) downloadBlob(file.filename, file.blob);
  return files.length;
}

export function buildDecryptedExportFiles({ items, format = "otpauth", split = false, selected = null, ts = Date.now() } = {}) {
  const exportFormat = normalizeExportFormat(format);
  const exportTs = normalizeExportTimestamp(ts);
  const allItems = Array.isArray(items) ? items : [];
  let valid = allItems.filter(it => !it.deleted);
  if (selected && selected.size) {
    const selectedProjects = new Set(Array.from(selected, cloudProjectName));
    valid = valid.filter(it => selectedProjects.has(cloudProjectName(it._projectName)));
  }
  if (!valid.length) return [];
  const groups = split ? groupBy(valid, it => cloudProjectName(it._projectName)) : { all: valid };
  const files = [];

  if (exportFormat === "json") {
    for (const [key, arr] of Object.entries(groups)) {
      const payload = arr.map(buildDecryptedExportRecord);
      files.push({
        filename: `cloud-decrypted-${sanitizeFilePart(split ? key : "all")}-${exportTs}.json`,
        blob: new Blob([JSON.stringify({ items: payload }, null, 2)], { type: "application/json" }),
      });
    }
  } else if (exportFormat === "otpauth") {
    for (const [key, arr] of Object.entries(groups)) {
      const lines = arr.map(it => buildDecryptedExportRecord(it).otpauth).join("\n") + "\n";
      files.push({
        filename: `cloud-decrypted-otpauth-${sanitizeFilePart(split ? key : "all")}-${exportTs}.txt`,
        blob: new Blob([lines], { type: "text/plain" }),
      });
    }
  } else if (exportFormat === "csv") {
    const header = ["type", "issuer", "account", "password", "secret", "algorithm", "digits", "period", "counter", "project", "otpauth"];
    for (const [key, arr] of Object.entries(groups)) {
      const rows = [header.join(",")].concat(arr.map(it => {
        const record = buildDecryptedExportRecord(it);
        const cols = [
          record.type,
          record.issuer,
          record.account,
          record.password,
          record.secret,
          record.algorithm,
          String(record.digits),
          String(record.period),
          record.type === "hotp" ? String(record.counter) : "",
          record.project,
          record.otpauth,
        ];
        return cols.map(csvEscape).join(",");
      }));
      files.push({
        filename: `cloud-decrypted-${sanitizeFilePart(split ? key : "all")}-${exportTs}.csv`,
        blob: new Blob([rows.join("\n") + "\n"], { type: "text/csv" }),
      });
    }
  }

  return files;
}

export function buildDecryptedExportRecord(it) {
  const otp = normalizeOtpPayload(it);
  const record = {
    type: otp.type,
    issuer: String(it?.issuer || "").trim(),
    account: String(it?.account || "").trim(),
    password: typeof it?.password === "string" ? it.password : "",
    secret: otp.secret,
    algorithm: otp.algorithm,
    digits: otp.digits,
    period: normalizeOtpPeriod(it?.period ?? 30),
    counter: otp.type === "hotp" ? otp.counter : undefined,
    project: cloudProjectName(it?._projectName),
  };
  return {
    ...record,
    otpauth: buildOtpAuthUrl(record),
  };
}

function groupBy(arr, fn) {
  const map = {};
  for (const it of arr) {
    const k = String(fn(it));
    (map[k] ||= []).push(it);
  }
  return map;
}

function cloudProjectName(value) {
  return String(value || "").trim() || "unknown";
}

function normalizeCloudSyncId(value) {
  return normalizeSyncRouteId(value);
}

function normalizeExportFormat(value) {
  const format = String(value || "otpauth").trim().toLowerCase();
  return ["json", "otpauth", "csv"].includes(format) ? format : "";
}

function normalizeExportTimestamp(value) {
  const ts = Math.trunc(Number(value));
  if (Number.isSafeInteger(ts) && ts > 0) return ts;
  return Date.now();
}

function csvEscape(v) {
  const s = String(v ?? "");
  if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
