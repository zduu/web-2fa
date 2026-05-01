// 圆形 SVG 进度环组件
// 用法：const ring = createRing(40); ring.update(left, period); container.appendChild(ring.el);

export function createRing(size = 40) {
  const stroke = 4;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "ring-svg");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("viewBox", `0 0 ${size} ${size}`);

  const track = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  track.setAttribute("class", "track");
  track.setAttribute("cx", size / 2);
  track.setAttribute("cy", size / 2);
  track.setAttribute("r", radius);
  track.setAttribute("stroke-width", stroke);
  track.setAttribute("fill", "none");
  svg.appendChild(track);

  const progress = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  progress.setAttribute("class", "progress");
  progress.setAttribute("cx", size / 2);
  progress.setAttribute("cy", size / 2);
  progress.setAttribute("r", radius);
  progress.setAttribute("stroke-width", stroke);
  progress.setAttribute("fill", "none");
  progress.setAttribute("stroke-linecap", "round");
  progress.setAttribute("stroke-dasharray", String(circumference));
  progress.setAttribute("transform", `rotate(-90 ${size / 2} ${size / 2})`);
  progress.setAttribute("stroke", "#22c55e");
  svg.appendChild(progress);

  const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
  label.setAttribute("class", "label");
  label.setAttribute("x", size / 2);
  label.setAttribute("y", size / 2);
  label.setAttribute("text-anchor", "middle");
  label.setAttribute("dominant-baseline", "central");
  svg.appendChild(label);

  return {
    el: svg,
    update(left, period) {
      const total = Math.max(5, Number(period) || 30);
      const ratio = Math.max(0, Math.min(1, left / total));
      progress.setAttribute("stroke-dashoffset", String(circumference * (1 - ratio)));
      let color = "#22c55e";
      if (left <= 5) color = "#ef4444";
      else if (left <= 10) color = "#f59e0b";
      progress.setAttribute("stroke", color);
      label.setAttribute("fill", color);
      label.textContent = String(left);
    }
  };
}
