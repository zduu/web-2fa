// 密钥托管：RSA-OAEP + AES-GCM 二级加密
// 用管理员公钥加密 Sync Secret 后写入云端 vault:<syncId>
// 用管理员私钥本地解密找回

import { state, getGlobalToken, saveSyncProjects } from "../core/storage.js";
import { importRsaPublicKey, importRsaPrivateKey, rsaEncryptSecret, rsaDecryptSecret } from "../core/crypto.js";
import { deriveSyncKey, syncEncrypt, syncDecrypt } from "../core/crypto.js";
import { getSyncEndpoint, normalizeSyncRouteId } from "./sync.js";
import { ensureItemDefaults } from "../core/storage.js";
import { apiUrl } from "../core/runtime.js";

export const LS_VAULT_ENABLED = "vault.enabled";
export const LS_VAULT_PUBKEY = "vault.pubkey";
export const LS_VAULT_PUBKEYS = "vault.pubkeys";

export function getVaultEnabled() {
  try { return localStorage.getItem(LS_VAULT_ENABLED) === "1"; }
  catch { return false; }
}
export function setVaultEnabled(v) {
  try {
    if (v) localStorage.setItem(LS_VAULT_ENABLED, "1");
    else localStorage.removeItem(LS_VAULT_ENABLED);
  } catch {}
}
export function getVaultPubkeys() {
  try {
    const raw = localStorage.getItem(LS_VAULT_PUBKEYS);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        const normalized = normalizeVaultPubkeys(parsed);
        if (normalized.length) return normalized;
      }
    }
  } catch {}
  let legacy = "";
  try { legacy = localStorage.getItem(LS_VAULT_PUBKEY) || ""; }
  catch { legacy = ""; }
  if (!legacy.trim()) return [];
  return normalizeVaultPubkeys([{ id: "legacy", name: "默认公钥", pem: legacy }]);
}
export function getVaultPubkey() { return getVaultPubkeys()[0]?.pem || ""; }
export function setVaultPubkey(v) {
  setVaultPubkeys(v ? [{ id: "legacy", name: "默认公钥", pem: v }] : []);
}
export function setVaultPubkeys(list) {
  const normalized = normalizeVaultPubkeys(list);
  try {
    if (normalized.length) {
      localStorage.setItem(LS_VAULT_PUBKEYS, JSON.stringify(normalized));
      localStorage.setItem(LS_VAULT_PUBKEY, normalized[0].pem);
    } else {
      localStorage.removeItem(LS_VAULT_PUBKEYS);
      localStorage.removeItem(LS_VAULT_PUBKEY);
    }
  } catch {}
}

export function normalizeVaultPubkeys(list) {
  const usedIds = new Set();
  const entries = Array.isArray(list) ? list : [];
  const normalized = [];
  for (const entry of entries) {
    const pem = String(entry?.pem || "").trim();
    if (!pem) continue;
    const index = normalized.length;
    normalized.push({
      id: normalizeVaultPubkeyId(entry?.id, index, usedIds),
      name: String(entry?.name || "").trim() || `公钥 ${index + 1}`,
      pem,
    });
  }
  return normalized;
}

function normalizeVaultPubkeyId(value, index, usedIds) {
  const raw = String(value || "")
    .trim()
    .replace(/\s+/g, "_")
    .replace(/[^A-Za-z0-9_-]/g, "")
    .slice(0, 64);
  const base = raw || `vault_key_${index + 1}`;
  let id = base;
  let suffix = 2;
  while (usedIds.has(id)) {
    id = `${base}_${suffix}`;
    suffix++;
  }
  usedIds.add(id);
  return id;
}

export function normalizeVaultSyncIds(syncIds) {
  return vaultSyncIdEntries(syncIds).map((entry) => entry.id).filter(Boolean);
}

function vaultSyncIdEntries(syncIds) {
  const values = Array.isArray(syncIds) ? syncIds : [];
  return values.map((value) => ({ id: normalizeSyncRouteId(value) }));
}

export async function escrowSecrets({ syncIds, secret, pubKeys, pubKeyPem, onProgress }) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const keys = normalizeVaultPubkeys(pubKeys?.length ? pubKeys : [{ name: "默认公钥", pem: pubKeyPem }]);
  if (!keys.length) throw new Error("请至少提供一把 RSA 公钥");
  const imported = await Promise.all(keys.map(async (entry) => ({
    ...entry,
    key: await importRsaPublicKey(entry.pem),
  })));
  let ok = 0, fail = 0;
  let i = 0;
  const ids = vaultSyncIdEntries(syncIds);
  for (const { id } of ids) {
    try {
      if (!id) throw new Error("invalid-sync-id");
      const recipients = [];
      for (const entry of imported) {
        const cipher = await rsaEncryptSecret(entry.key, secret, id);
        recipients.push({ kid: entry.id, name: entry.name, cipher });
      }
      const r = await fetch(apiUrl(`/api/vault/${encodeURIComponent(id)}`), {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Token": token },
        body: JSON.stringify({ v: 2, recipients }),
      });
      if (isVaultResponseOk(r)) ok++; else fail++;
    } catch { fail++; }
    i++;
    try { onProgress?.(i, ids.length); } catch {}
  }
  return { ok, fail };
}

export async function recoverSecrets({ syncIds, privKeyPem, onProgress }) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const priv = await importRsaPrivateKey(privKeyPem);
  const recovered = [];
  let i = 0;
  const ids = vaultSyncIdEntries(syncIds);
  for (const { id } of ids) {
    try {
      if (!id) throw new Error("invalid-sync-id");
      const r = await fetch(apiUrl(`/api/vault/${encodeURIComponent(id)}`), {
        headers: { "X-Token": token, "Cache-Control": "no-store" }
      });
      if (!isVaultResponseOk(r)) continue;
      const j = await r.json();
      let sec = "";
      if (Array.isArray(j?.recipients)) {
        for (const recipient of j.recipients) {
          sec = await rsaDecryptSecret(priv, recipient?.cipher || recipient);
          if (sec) break;
        }
      } else {
        sec = await rsaDecryptSecret(priv, j);
      }
      if (sec) recovered.push({ id, secret: sec });
    } catch {}
    i++;
    try { onProgress?.(i, ids.length); } catch {}
  }
  return recovered;
}

export async function migrateSecrets({ syncIds, oldSecrets, newSecret, onProgress }) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  let ok = 0, fail = 0;
  let i = 0;
  const ids = vaultSyncIdEntries(syncIds);
  for (const { id } of ids) {
    try {
      if (!id) throw new Error("invalid-sync-id");
      const res = await fetch(getSyncEndpoint(id), {
        headers: { "X-Token": token, "Cache-Control": "no-store" }
      });
      if (!res.ok) { fail++; }
      else {
        const payload = await res.json();
        let plain = null;
        for (const sec of oldSecrets) {
          try {
            const key = await deriveSyncKey(sec, id);
            plain = await syncDecrypt(payload, key);
            break;
          } catch {}
        }
        if (!plain) fail++;
        else {
          const newKey = await deriveSyncKey(newSecret, id);
          const newPayload = await syncEncrypt({ items: (plain.items || []).map(ensureItemDefaults) }, newKey);
          const put = await fetch(getSyncEndpoint(id), {
            method: "PUT",
            headers: { "Content-Type": "application/json", "X-Token": token },
            body: JSON.stringify(newPayload),
          });
          if (!put.ok) fail++;
          else {
            const proj = state.syncProjects.find(p => normalizeSyncRouteId(p?.syncId) === id);
            if (proj) { proj.secret = newSecret; proj.lastSyncedAt = Date.now(); }
            ok++;
          }
        }
      }
    } catch { fail++; }
    i++;
    try { onProgress?.(i, ids.length); } catch {}
  }
  saveSyncProjects();
  return { ok, fail };
}

function isVaultResponseOk(response) {
  return !!response?.ok && !response.headers?.get?.("X-Note");
}
