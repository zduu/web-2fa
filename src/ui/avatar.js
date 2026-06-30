// Issuer 字母头像：HSL 哈希渐变背景 + 首字母
// 完全离线，不依赖 CDN

const AVATAR_SIZE_DEFAULT = 44;
const AVATAR_SIZE_MIN = 16;
const AVATAR_SIZE_MAX = 96;

export function hashAvatarHue(value) {
  const str = String(value || "");
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) >>> 0;
  }
  return h % 360;
}

export function normalizeAvatarSize(value, fallback = AVATAR_SIZE_DEFAULT) {
  const size = Math.trunc(Number(value));
  if (!Number.isFinite(size) || size <= 0) return fallback;
  return Math.min(AVATAR_SIZE_MAX, Math.max(AVATAR_SIZE_MIN, size));
}

export function getAvatarInitial(issuer = "", account = "") {
  const text = String(issuer || account || "").trim();
  const first = Array.from(text)[0];
  return first ? first.toUpperCase() : "?";
}

export function createAvatar(issuer = "", account = "", size = 44) {
  const safeSize = normalizeAvatarSize(size);
  const text = String(issuer || account || "").trim() || "x";
  const initial = getAvatarInitial(issuer, account);
  const hue = hashAvatarHue(text);
  const div = document.createElement("div");
  div.className = "avatar";
  div.style.cssText = `
    width:${safeSize}px; height:${safeSize}px;
    background: linear-gradient(135deg, hsl(${hue}, 65%, 52%), hsl(${(hue + 40) % 360}, 70%, 42%));
    font-size: ${Math.round(safeSize * 0.42)}px;
  `;
  div.textContent = initial;
  return div;
}
