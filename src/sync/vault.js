// 密钥托管：RSA-OAEP + AES-GCM 二级加密
// 用管理员公钥加密 Sync Secret 后写入云端 vault:<syncId>
// 用管理员私钥本地解密找回

import { state, getGlobalToken, saveSyncProjects } from "../core/storage.js";
import { importRsaPublicKey, importRsaPrivateKey, rsaEncryptSecret, rsaDecryptSecret } from "../core/crypto.js";
import { deriveSyncKey, syncEncrypt, syncDecrypt } from "../core/crypto.js";
import { getSyncEndpoint } from "./sync.js";
import { ensureItemDefaults } from "../core/storage.js";

export const LS_VAULT_ENABLED = "vault.enabled";
export const LS_VAULT_PUBKEY = "vault.pubkey";

export function getVaultEnabled() { return localStorage.getItem(LS_VAULT_ENABLED) === "1"; }
export function setVaultEnabled(v) {
  if (v) localStorage.setItem(LS_VAULT_ENABLED, "1");
  else localStorage.removeItem(LS_VAULT_ENABLED);
}
export function getVaultPubkey() { return localStorage.getItem(LS_VAULT_PUBKEY) || ""; }
export function setVaultPubkey(v) {
  if (v) localStorage.setItem(LS_VAULT_PUBKEY, v);
  else localStorage.removeItem(LS_VAULT_PUBKEY);
}

export async function escrowSecrets({ syncIds, secret, pubKeyPem }) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const pubKey = await importRsaPublicKey(pubKeyPem);
  let ok = 0, fail = 0;
  for (const id of syncIds) {
    try {
      const cipher = await rsaEncryptSecret(pubKey, secret, id);
      const r = await fetch(`/api/vault/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Token": token },
        body: JSON.stringify(cipher),
      });
      if (r.ok) ok++; else fail++;
    } catch { fail++; }
  }
  return { ok, fail };
}

export async function recoverSecrets({ syncIds, privKeyPem }) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  const priv = await importRsaPrivateKey(privKeyPem);
  const recovered = [];
  for (const id of syncIds) {
    try {
      const r = await fetch(`/api/vault/${encodeURIComponent(id)}`, {
        headers: { "X-Token": token, "Cache-Control": "no-store" }
      });
      if (!r.ok) continue;
      const j = await r.json();
      const sec = await rsaDecryptSecret(priv, j);
      if (sec) recovered.push({ id, secret: sec });
    } catch {}
  }
  return recovered;
}

export async function migrateSecrets({ syncIds, oldSecrets, newSecret }) {
  const token = getGlobalToken();
  if (!token) throw new Error("需要 Admin Key");
  let ok = 0, fail = 0;
  for (const id of syncIds) {
    try {
      const res = await fetch(getSyncEndpoint(id), {
        headers: { "X-Token": token, "Cache-Control": "no-store" }
      });
      if (!res.ok) { fail++; continue; }
      const payload = await res.json();
      let plain = null;
      for (const sec of oldSecrets) {
        try {
          const key = await deriveSyncKey(sec, id);
          plain = await syncDecrypt(payload, key);
          break;
        } catch {}
      }
      if (!plain) { fail++; continue; }
      const newKey = await deriveSyncKey(newSecret, id);
      const newPayload = await syncEncrypt({ items: (plain.items || []).map(ensureItemDefaults) }, newKey);
      const put = await fetch(getSyncEndpoint(id), {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Token": token },
        body: JSON.stringify(newPayload),
      });
      if (!put.ok) { fail++; continue; }
      // update local matching project
      const proj = state.syncProjects.find(p => p.syncId === id);
      if (proj) { proj.secret = newSecret; proj.lastSyncedAt = Date.now(); }
      ok++;
    } catch { fail++; }
  }
  saveSyncProjects();
  return { ok, fail };
}
