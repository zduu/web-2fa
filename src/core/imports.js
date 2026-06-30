import { ensureItemDefaults } from "./storage.js";
import { normalizeOtpSecret } from "./totp.js";

export function normalizeImportedItem(raw) {
  return ensureItemDefaults({
    type: raw?.type || "totp",
    issuer: String(raw?.issuer || "").trim(),
    account: String(raw?.account || "").trim(),
    password: typeof raw?.password === "string" ? raw.password : "",
    note: typeof raw?.note === "string" ? raw.note : "",
    pinned: normalizeImportedPinned(raw?.pinned),
    secret: raw?.secret || "",
    algorithm: raw?.algorithm || "SHA1",
    digits: raw?.digits ?? 6,
    period: raw?.period ?? 30,
    counter: raw?.counter ?? 0,
    deleted: false,
    updatedAt: Date.now(),
  });
}

export function normalizeImportedPinned(value) {
  if (value === true || value === 1) return true;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "y";
  }
  return false;
}

export function importFingerprint(item) {
  const normalized = ensureItemDefaults(item);
  return [
    normalized.type || "totp",
    normalizeOtpSecret(normalized.secret),
    String(normalized.issuer || "").trim(),
    String(normalized.account || "").trim(),
    String(normalized.algorithm || "SHA1").toUpperCase(),
    normalized.digits,
    normalized.type === "hotp"
      ? `counter:${normalized.counter}`
      : `period:${normalized.period}`,
  ].join("|");
}
