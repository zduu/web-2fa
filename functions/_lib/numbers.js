export function normalizeNonNegativeInteger(value, { fallback = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const normalizedMax = normalizeIntegerOption(max, Number.MAX_SAFE_INTEGER);
  const upper = normalizedMax >= 0 ? normalizedMax : Number.MAX_SAFE_INTEGER;
  const normalizedFallback = Math.min(
    Math.max(0, normalizeIntegerOption(fallback, 0)),
    upper
  );
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n)) return normalizedFallback;
  return Math.min(Math.max(0, n), upper);
}

export function normalizeOptionalTimestamp(value) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n <= 0 || n > Number.MAX_SAFE_INTEGER) return null;
  return n;
}

export function normalizeOptionalNonNegativeSafeInteger(value) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) return null;
  return n;
}

export function normalizePositiveInteger(value) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n <= 0) return null;
  return n;
}

export function normalizeHttpStatus(value) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n) || n < 100 || n > 599) return null;
  return n;
}

export function normalizeLimit(value, { fallback = 100, min = 1, max = 200 } = {}) {
  const normalizedMin = normalizeIntegerOption(min, 1);
  const normalizedMax = Math.max(normalizedMin, normalizeIntegerOption(max, 200));
  const normalizedFallback = clampInteger(
    normalizeIntegerOption(fallback, 100),
    normalizedMin,
    normalizedMax
  );
  if (value === undefined || value === null || String(value).trim() === "") return normalizedFallback;
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n)) return normalizedFallback;
  return clampInteger(n, normalizedMin, normalizedMax);
}

function normalizeIntegerOption(value, fallback) {
  const n = Math.trunc(Number(value));
  return Number.isFinite(n) ? n : fallback;
}

function clampInteger(value, min, max) {
  return Math.min(max, Math.max(min, value));
}
