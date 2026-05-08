function readRuntimeConfig() {
  if (typeof window === "undefined") return {};
  const cfg = window.__APP_RUNTIME__;
  return cfg && typeof cfg === "object" ? cfg : {};
}

const LS_API_BASE_URL = "authenticator.v1.cloudApiBaseUrl";
const LS_PUBLIC_BASE_URL = "authenticator.v1.cloudPublicBaseUrl";

function trimTrailingSlash(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function readLocalOverride(key) {
  try {
    return trimTrailingSlash(localStorage.getItem(key) || "");
  } catch {
    return "";
  }
}

export function getAppMode() {
  const mode = readRuntimeConfig().mode;
  if (mode === "local-app" || mode === "android-app") return mode;
  return "web";
}

export function isAndroidApp() {
  return getAppMode() === "android-app";
}

export function isLocalOnlyApp() {
  return getAppMode() === "local-app";
}

export function isPackagedApp() {
  const mode = getAppMode();
  return mode === "local-app" || mode === "android-app";
}

export function getApiBaseUrl() {
  if (isAndroidApp()) {
    return readLocalOverride(LS_API_BASE_URL) || trimTrailingSlash(readRuntimeConfig().apiBaseUrl);
  }
  return trimTrailingSlash(readRuntimeConfig().apiBaseUrl);
}

export function getPublicBaseUrl() {
  const cfg = readRuntimeConfig();
  const configured = isAndroidApp()
    ? (readLocalOverride(LS_PUBLIC_BASE_URL) || readLocalOverride(LS_API_BASE_URL) || trimTrailingSlash(cfg.publicBaseUrl || cfg.apiBaseUrl))
    : trimTrailingSlash(cfg.publicBaseUrl || cfg.apiBaseUrl);
  if (configured) return configured;
  if (isAndroidApp()) return "";
  if (typeof location !== "undefined" && location.origin) return trimTrailingSlash(location.origin);
  return "";
}

export function getCloudBaseUrls() {
  const cfg = readRuntimeConfig();
  const apiBaseUrl = getApiBaseUrl();
  const publicBaseUrl = isAndroidApp()
    ? (readLocalOverride(LS_PUBLIC_BASE_URL) || trimTrailingSlash(cfg.publicBaseUrl))
    : getPublicBaseUrl();
  return {
    apiBaseUrl,
    publicBaseUrl,
    defaultApiBaseUrl: trimTrailingSlash(cfg.apiBaseUrl),
    defaultPublicBaseUrl: trimTrailingSlash(cfg.publicBaseUrl || cfg.apiBaseUrl),
  };
}

export function setCloudBaseUrls({ apiBaseUrl = "", publicBaseUrl = "" } = {}) {
  if (!isAndroidApp()) throw new Error("仅同步版 APK 支持在应用内设置云端地址");
  const api = normalizeHttpUrl(apiBaseUrl, "云端 API 地址");
  const pub = publicBaseUrl ? normalizeHttpUrl(publicBaseUrl, "公开站点地址") : api;
  try {
    if (api) localStorage.setItem(LS_API_BASE_URL, api);
    else localStorage.removeItem(LS_API_BASE_URL);
    if (pub && pub !== api) localStorage.setItem(LS_PUBLIC_BASE_URL, pub);
    else localStorage.removeItem(LS_PUBLIC_BASE_URL);
  } catch {}
  return { apiBaseUrl: api, publicBaseUrl: pub };
}

export function clearCloudBaseUrls() {
  try {
    localStorage.removeItem(LS_API_BASE_URL);
    localStorage.removeItem(LS_PUBLIC_BASE_URL);
  } catch {}
}

function normalizeHttpUrl(value, label) {
  const raw = trimTrailingSlash(value);
  if (!raw) return "";
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${label}格式不正确`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`${label}必须以 http:// 或 https:// 开头`);
  }
  url.hash = "";
  url.search = "";
  url.pathname = url.pathname.replace(/\/+$/, "");
  return trimTrailingSlash(url.toString());
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
