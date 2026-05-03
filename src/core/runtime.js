function readRuntimeConfig() {
  if (typeof window === "undefined") return {};
  const cfg = window.__APP_RUNTIME__;
  return cfg && typeof cfg === "object" ? cfg : {};
}

export function getAppMode() {
  const mode = readRuntimeConfig().mode;
  return mode === "local-app" ? "local-app" : "web";
}

export function isLocalOnlyApp() {
  return getAppMode() === "local-app";
}

export function canUseCloudApis() {
  return !isLocalOnlyApp();
}

