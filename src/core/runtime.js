function readRuntimeConfig() {
  if (typeof window === "undefined") return {};
  const cfg = window.__APP_RUNTIME__;
  return cfg && typeof cfg === "object" ? cfg : {};
}

function trimTrailingSlash(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

export function getAppMode() {
  const mode = readRuntimeConfig().mode;
  if (mode === "local-app" || mode === "android-app") return mode;
  return "web";
}

export function isLocalOnlyApp() {
  return getAppMode() === "local-app";
}

export function isPackagedApp() {
  const mode = getAppMode();
  return mode === "local-app" || mode === "android-app";
}

export function getApiBaseUrl() {
  return trimTrailingSlash(readRuntimeConfig().apiBaseUrl);
}

export function getPublicBaseUrl() {
  const cfg = readRuntimeConfig();
  const configured = trimTrailingSlash(cfg.publicBaseUrl || cfg.apiBaseUrl);
  if (configured) return configured;
  if (typeof location !== "undefined" && location.origin) return trimTrailingSlash(location.origin);
  return "";
}

export function apiUrl(path) {
  const input = String(path || "");
  if (/^https?:\/\//i.test(input)) return input;
  const normalized = input.startsWith("/") ? input : `/${input}`;
  const base = getApiBaseUrl();
  return base ? `${base}${normalized}` : normalized;
}

export function canUseCloudApis() {
  if (isLocalOnlyApp()) return false;
  if (getAppMode() === "android-app") return !!getApiBaseUrl();
  return true;
}
