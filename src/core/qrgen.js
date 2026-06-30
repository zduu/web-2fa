// QR 生成包装：复用本地 vendored encoder，统一默认参数给分享与后续批量导出使用。

import { renderSVG } from "./qrgen-vendor.js";

const QR_DEFAULT_OPTIONS = {
  ecc: "M",
  border: 2,
  pixelSize: 6,
  whiteColor: "#ffffff",
  blackColor: "#111827",
  boostEcc: true,
};

export function renderQrSvg(text, options = {}) {
  const value = String(text || "");
  if (!value) throw new Error("QR 内容不能为空");
  return renderSVG(value, normalizeQrSvgOptions(options));
}

export function normalizeQrSvgOptions(options = {}) {
  const raw = options && typeof options === "object" ? options : {};
  return {
    ecc: normalizeQrEcc(raw.ecc),
    border: normalizeQrInteger(raw.border, QR_DEFAULT_OPTIONS.border, 0, 16),
    pixelSize: normalizeQrInteger(raw.pixelSize, QR_DEFAULT_OPTIONS.pixelSize, 1, 32),
    whiteColor: normalizeQrColor(raw.whiteColor, QR_DEFAULT_OPTIONS.whiteColor),
    blackColor: normalizeQrColor(raw.blackColor, QR_DEFAULT_OPTIONS.blackColor),
    boostEcc: typeof raw.boostEcc === "boolean" ? raw.boostEcc : QR_DEFAULT_OPTIONS.boostEcc,
  };
}

function normalizeQrEcc(value) {
  const ecc = String(value || QR_DEFAULT_OPTIONS.ecc).trim().toUpperCase();
  return ["L", "M", "Q", "H"].includes(ecc) ? ecc : QR_DEFAULT_OPTIONS.ecc;
}

function normalizeQrInteger(value, fallback, min, max) {
  const n = Math.trunc(Number(value));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function normalizeQrColor(value, fallback) {
  const color = String(value || "").trim();
  if (/^#[0-9A-Fa-f]{3}([0-9A-Fa-f]{3})?([0-9A-Fa-f]{2})?$/.test(color)) return color;
  if (/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(color)) return color;
  return fallback;
}
