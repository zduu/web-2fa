const RESERVED_KV_PREFIXES = [
  "sync:",
  "syncbak:",
  "synctomb:",
  "share:",
  "sharekey:",
  "sharestat:",
  "vault:",
  "audit:",
];

export function normalizeKvSuffix(name, prefix = "") {
  const raw = String(name || "").trim();
  const suffix = prefix && raw.startsWith(prefix) ? raw.slice(prefix.length) : raw;
  return normalizeRouteId(suffix);
}

export function normalizeRouteId(value) {
  const id = String(value || "").trim();
  if (!id) return "";
  if (/[\x00-\x1F\x7F]/.test(id)) return "";
  if (RESERVED_KV_PREFIXES.some((prefix) => id.startsWith(prefix))) return "";
  return id;
}
