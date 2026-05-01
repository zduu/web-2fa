// 云端浏览（管理员）：列出所有 sync:* + 全部解密 + 多格式导出

import { state, getGlobalToken, ensureItemDefaults } from "../core/storage.js";
import { deriveSyncKey, syncDecrypt } from "../core/crypto.js";
import { buildOtpAuthUrl } from "../core/totp.js";
import { downloadBlob, sanitizeFilePart } from "../ui/toast.js";
import { getSyncEndpoint } from "./sync.js";

export async function listAllCloudProjects() {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const res = await fetch("/api/admin/list-all", {
    method: "POST",
    headers: { "X-KV-Admin-Key": token, "X-Token": token, "Content-Type": "application/json" }
  });
  if (res.status === 401) {
    const e = new Error("Admin Key 无效"); e.code = "unauth"; throw e;
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "加载失败");
  return Array.isArray(data.projects) ? data.projects : [];
}

export async function decryptCloudAll({ projects, secrets, concurrency = 5 }) {
  // try every secret per project, first success wins
  if (!projects || !projects.length) return { items: [], failed: 0 };
  const aggregated = [];
  let failed = 0;
  const token = getGlobalToken();
  let index = 0;
  async function worker() {
    while (index < projects.length) {
      const i = index++;
      const proj = projects[i];
      const id = proj.syncId;
      try {
        const res = await fetch(getSyncEndpoint(id), {
          headers: { "X-Token": token, "Cache-Control": "no-cache" }
        });
        if (!res.ok) { failed++; continue; }
        const payload = await res.json();
        const attempts = secrets.map(sec => (async () => {
          const key = await deriveSyncKey(sec, id);
          const obj = await syncDecrypt(payload, key);
          return (obj.items || []).map(ensureItemDefaults).map(it => ({ ...it, _projectName: id }));
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
        if (items && items.length) aggregated.push(...items); else failed++;
      } catch { failed++; }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, projects.length) }, () => worker()));
  return { items: aggregated, failed };
}

export function exportDecrypted({ items, format = "otpauth", split = false, selected = null }) {
  let valid = items.filter(it => !it.deleted);
  if (selected && selected.size) {
    valid = valid.filter(it => selected.has(it._projectName));
  }
  const groups = split ? groupBy(valid, it => (it._projectName || "unknown")) : { all: valid };
  const ts = Date.now();

  if (format === "json") {
    for (const [key, arr] of Object.entries(groups)) {
      const payload = arr.map(it => ({
        type: it.type || "totp",
        issuer: it.issuer || "",
        account: it.account || "",
        password: typeof it.password === "string" ? it.password : "",
        secret: (it.secret || "").replace(/\s+/g, "").toUpperCase(),
        algorithm: (it.algorithm || "SHA1").toUpperCase(),
        digits: Number(it.digits || 6),
        period: Number(it.period || 30),
        counter: it.type === "hotp" ? Number(it.counter || 0) : undefined,
        project: it._projectName || "",
        otpauth: buildOtpAuthUrl(it),
      }));
      downloadBlob(
        `cloud-decrypted-${sanitizeFilePart(split ? key : "all")}-${ts}.json`,
        new Blob([JSON.stringify({ items: payload }, null, 2)], { type: "application/json" })
      );
    }
  } else if (format === "otpauth") {
    for (const [key, arr] of Object.entries(groups)) {
      const lines = arr.map(buildOtpAuthUrl).join("\n") + "\n";
      downloadBlob(
        `cloud-decrypted-otpauth-${sanitizeFilePart(split ? key : "all")}-${ts}.txt`,
        new Blob([lines], { type: "text/plain" })
      );
    }
  } else if (format === "csv") {
    const header = ["type", "issuer", "account", "password", "secret", "algorithm", "digits", "period", "counter", "project", "otpauth"];
    for (const [key, arr] of Object.entries(groups)) {
      const rows = [header.join(",")].concat(arr.map(it => {
        const cols = [
          it.type || "totp",
          it.issuer || "",
          it.account || "",
          typeof it.password === "string" ? it.password : "",
          (it.secret || "").replace(/\s+/g, "").toUpperCase(),
          (it.algorithm || "SHA1").toUpperCase(),
          String(Number(it.digits || 6)),
          String(Number(it.period || 30)),
          it.type === "hotp" ? String(Number(it.counter || 0)) : "",
          it._projectName || "",
          buildOtpAuthUrl(it),
        ];
        return cols.map(csvEscape).join(",");
      }));
      downloadBlob(
        `cloud-decrypted-${sanitizeFilePart(split ? key : "all")}-${ts}.csv`,
        new Blob([rows.join("\n") + "\n"], { type: "text/csv" })
      );
    }
  }
}

function groupBy(arr, fn) {
  const map = {};
  for (const it of arr) {
    const k = String(fn(it));
    (map[k] ||= []).push(it);
  }
  return map;
}

function csvEscape(v) {
  const s = String(v ?? "");
  if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
