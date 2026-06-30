// UI 偏好：显示密度等
// 使用 localStorage 持久化，应用到 body 类名

export const LS_DENSITY = "authenticator.v1.density";

export function normalizeDensity(value) {
  return String(value || "").trim().toLowerCase() === "compact" ? "compact" : "comfortable";
}

export function getDensity() {
  try { return normalizeDensity(localStorage.getItem(LS_DENSITY)); }
  catch { return "comfortable"; }
}
export function setDensity(v) {
  const norm = normalizeDensity(v);
  try { localStorage.setItem(LS_DENSITY, norm); } catch {}
  return applyDensity(norm);
}
export function applyDensity(d = getDensity()) {
  const density = normalizeDensity(d);
  try { document.body.classList.toggle("compact", density === "compact"); } catch {}
  return density;
}
