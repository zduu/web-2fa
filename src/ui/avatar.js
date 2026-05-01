// Issuer 字母头像：HSL 哈希渐变背景 + 首字母
// 完全离线，不依赖 CDN

function hashHue(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) >>> 0;
  }
  return h % 360;
}

export function createAvatar(issuer = "", account = "", size = 44) {
  const text = (issuer || account || "?").trim();
  const initial = text[0]?.toUpperCase() || "?";
  const hue = hashHue(text || "x");
  const div = document.createElement("div");
  div.className = "avatar";
  div.style.cssText = `
    width:${size}px; height:${size}px;
    background: linear-gradient(135deg, hsl(${hue}, 65%, 52%), hsl(${(hue + 40) % 360}, 70%, 42%));
    font-size: ${Math.round(size * 0.42)}px;
  `;
  div.textContent = initial;
  return div;
}
