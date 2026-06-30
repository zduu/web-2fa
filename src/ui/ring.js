// 圆形 SVG 进度环组件
// 用法：const ring = createRing(40); ring.update(left, period); container.appendChild(ring.el);

import { normalizeOtpPeriod } from "../core/totp.js";

const RING_SIZE_DEFAULT = 40;
const RING_SIZE_MIN = 16;
const RING_SIZE_MAX = 96;

export function createRing(size = 40) {
  const safeSize = normalizeRingSize(size);
  const stroke = 4;
  const radius = (safeSize - stroke) / 2;
  const circumference = 2 * Math.PI * radius;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "ring-svg");
  svg.setAttribute("width", safeSize);
  svg.setAttribute("height", safeSize);
  svg.setAttribute("viewBox", `0 0 ${safeSize} ${safeSize}`);

  const track = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  track.setAttribute("class", "track");
  track.setAttribute("cx", safeSize / 2);
  track.setAttribute("cy", safeSize / 2);
  track.setAttribute("r", radius);
  track.setAttribute("stroke-width", stroke);
  track.setAttribute("fill", "none");
  svg.appendChild(track);

  const progress = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  progress.setAttribute("class", "progress");
  progress.setAttribute("cx", safeSize / 2);
  progress.setAttribute("cy", safeSize / 2);
  progress.setAttribute("r", radius);
  progress.setAttribute("stroke-width", stroke);
  progress.setAttribute("fill", "none");
  progress.setAttribute("stroke-linecap", "round");
  progress.setAttribute("stroke-dasharray", String(circumference));
  progress.setAttribute("transform", `rotate(-90 ${safeSize / 2} ${safeSize / 2})`);
  progress.setAttribute("stroke", "#22c55e");
  svg.appendChild(progress);

  const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
  label.setAttribute("class", "label");
  label.setAttribute("x", safeSize / 2);
  label.setAttribute("y", safeSize / 2);
  label.setAttribute("text-anchor", "middle");
  label.setAttribute("dominant-baseline", "central");
  svg.appendChild(label);

  return {
    el: svg,
    update(left, period) {
      const total = normalizeOtpPeriod(period);
      const remaining = normalizeRingSecondsLeft(left, total);
      const ratio = remaining / total;
      progress.setAttribute("stroke-dashoffset", String(circumference * (1 - ratio)));
      let color = "#22c55e";
      if (remaining <= 5) color = "#ef4444";
      else if (remaining <= 10) color = "#f59e0b";
      progress.setAttribute("stroke", color);
      label.setAttribute("fill", color);
      label.textContent = String(remaining);
    }
  };
}

export function normalizeRingSize(value, fallback = RING_SIZE_DEFAULT) {
  const size = Math.trunc(Number(value));
  if (!Number.isFinite(size) || size <= 0) return fallback;
  return Math.min(RING_SIZE_MAX, Math.max(RING_SIZE_MIN, size));
}

export function normalizeRingSecondsLeft(value, period = 30) {
  const total = normalizeOtpPeriod(period);
  const seconds = Math.trunc(Number(value));
  if (!Number.isFinite(seconds)) return total;
  return Math.min(total, Math.max(0, seconds));
}
