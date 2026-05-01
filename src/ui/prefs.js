// UI 偏好：显示密度等
// 使用 localStorage 持久化，应用到 body 类名

export const LS_DENSITY = "authenticator.v1.density";

export function getDensity() {
  const v = localStorage.getItem(LS_DENSITY);
  return v === "compact" ? "compact" : "comfortable";
}
export function setDensity(v) {
  const norm = v === "compact" ? "compact" : "comfortable";
  localStorage.setItem(LS_DENSITY, norm);
  applyDensity();
}
export function applyDensity() {
  const d = getDensity();
  document.body.classList.toggle("compact", d === "compact");
}
