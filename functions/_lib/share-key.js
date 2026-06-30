import { normalizeOptionalTimestamp, normalizePositiveInteger } from "./numbers.js";

export function normalizeShareKeyPayload(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  if (typeof value.k !== "string") return null;

  const k = value.k.trim();
  const protectedBundle = normalizeProtectedBundle(value.protectedBundle);
  if (!k && !protectedBundle) return null;
  if (!k && value.requiresPassword !== true) return null;

  const out = { ...value, k };
  if (typeof out.label === "string") out.label = out.label.trim();
  if (typeof out.projectName === "string") out.projectName = out.projectName.trim();
  if (typeof out.itemId === "string") out.itemId = out.itemId.trim();
  if (typeof out.issuer === "string") out.issuer = out.issuer.trim();
  if (typeof out.account === "string") out.account = out.account.trim();
  if ("createdAt" in out) out.createdAt = normalizeOptionalTimestamp(out.createdAt);
  if ("maxAccess" in out) out.maxAccess = normalizePositiveInteger(out.maxAccess) || 0;
  if (protectedBundle) out.protectedBundle = protectedBundle;
  else if ("protectedBundle" in out) out.protectedBundle = null;
  if ("requiresPassword" in out || protectedBundle) out.requiresPassword = out.requiresPassword === true || !!protectedBundle;
  return out;
}

function normalizeProtectedBundle(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const s = typeof value.s === "string" ? value.s.trim() : "";
  const iv = typeof value.iv === "string" ? value.iv.trim() : "";
  const wk = typeof value.wk === "string" ? value.wk.trim() : "";
  if (!s || !iv || !wk) return null;
  const bundle = { s, iv, wk };
  const iter = normalizePositiveInteger(value.iter);
  if (iter !== null) bundle.iter = iter;
  return bundle;
}
