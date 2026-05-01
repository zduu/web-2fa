import { ensureItemDefaults } from "./storage.js";

export function normalizeImportedItem(raw) {
  return ensureItemDefaults({
    type: raw?.type || "totp",
    issuer: String(raw?.issuer || "").trim(),
    account: String(raw?.account || "").trim(),
    password: typeof raw?.password === "string" ? raw.password : "",
    note: typeof raw?.note === "string" ? raw.note : "",
    pinned: !!raw?.pinned,
    secret: raw?.secret || "",
    algorithm: raw?.algorithm || "SHA1",
    digits: Number(raw?.digits || 6),
    period: Number(raw?.period || 30),
    counter: Number(raw?.counter || 0),
    deleted: false,
    updatedAt: Date.now(),
  });
}

export function importFingerprint(item) {
  const normalized = ensureItemDefaults(item);
  return [
    normalized.type || "totp",
    String(normalized.secret || "").replace(/\s+/g, "").toUpperCase(),
    String(normalized.issuer || "").trim(),
    String(normalized.account || "").trim(),
    String(normalized.algorithm || "SHA1").toUpperCase(),
    Number(normalized.digits || 6),
    normalized.type === "hotp"
      ? `counter:${Number(normalized.counter || 0)}`
      : `period:${Number(normalized.period || 30)}`,
  ].join("|");
}
