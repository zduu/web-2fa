const MIN_KV_TTL_SECONDS = 60;
const MAX_SHARE_ACCESS = 1_000_000;
const DEFAULT_SHARE_TTL_SECONDS = 86400;

export function parseShareOptions({ defaultTtl, ttlParam, maxParam } = {}) {
  const normalizedDefaultTtl = normalizeDefaultShareTtl(defaultTtl);
  let permanent = normalizedDefaultTtl === 0;
  let ttl = normalizedDefaultTtl;

  if (ttlParam) {
    const parsed = parseOptionalShareTtl(ttlParam);
    if (parsed === 0) {
      permanent = true;
      ttl = 0;
    } else if (parsed !== undefined) {
      permanent = false;
      ttl = parsed;
    }
  }

  return {
    permanent,
    ttl,
    maxAccess: normalizeMaxAccess(maxParam),
  };
}

function normalizeDefaultShareTtl(value) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return DEFAULT_SHARE_TTL_SECONDS;
  }
  const text = String(value).trim().toLowerCase();
  if (["perm", "permanent", "infinite", "forever", "0"].includes(text)) return 0;
  const ttl = normalizeShareTtl(text);
  return ttl > 0 ? ttl : DEFAULT_SHARE_TTL_SECONDS;
}

export function parseOptionalShareTtl(ttlParam) {
  if (!ttlParam) return undefined;
  const text = String(ttlParam).trim().toLowerCase();
  if (["perm", "permanent", "infinite", "forever", "0"].includes(text)) return 0;
  const parsed = normalizeShareTtl(text);
  return parsed > 0 ? parsed : undefined;
}

function normalizeShareTtl(value) {
  const ttl = Math.floor(Number(value));
  if (!Number.isFinite(ttl) || ttl <= 0) return 0;
  return Math.max(MIN_KV_TTL_SECONDS, ttl);
}

function normalizeMaxAccess(value) {
  const max = Math.floor(Number(value));
  if (!Number.isFinite(max) || max <= 0) return 0;
  return Math.min(MAX_SHARE_ACCESS, max);
}
