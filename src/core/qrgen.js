// QR 生成包装：复用本地 vendored encoder，统一默认参数给分享与后续批量导出使用。

import { renderSVG } from "./qrgen-vendor.js";

export function renderQrSvg(text, options = {}) {
  const value = String(text || "");
  if (!value) throw new Error("QR 内容不能为空");
  return renderSVG(value, {
    ecc: "M",
    border: 2,
    pixelSize: 6,
    whiteColor: "#ffffff",
    blackColor: "#111827",
    boostEcc: true,
    ...options,
  });
}
