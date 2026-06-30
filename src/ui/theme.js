export const LS_THEME = "authenticator.v1.theme";

const MEDIA_QUERY = "(prefers-color-scheme: dark)";
const THEME_COLOR = {
  dark: "#0a0d12",
  light: "#f4f7fb",
};

let mediaBound = false;

export function normalizeThemePreference(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized === "dark" || normalized === "light" || normalized === "auto" ? normalized : "dark";
}

export function getThemePreference() {
  let value = null;
  try { value = localStorage.getItem(LS_THEME); } catch {}
  return normalizeThemePreference(value);
}

export function resolveTheme(pref = getThemePreference()) {
  const normalized = normalizeThemePreference(pref);
  if (normalized === "dark" || normalized === "light") return normalized;
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    try { return window.matchMedia(MEDIA_QUERY).matches ? "dark" : "light"; }
    catch {}
  }
  return "dark";
}

export function applyTheme(pref = getThemePreference()) {
  const preference = normalizeThemePreference(pref);
  const resolved = resolveTheme(preference);
  const root = typeof document !== "undefined" ? document.documentElement : null;
  if (root) {
    root.dataset.theme = preference;
    root.dataset.themeResolved = resolved;
    root.style.colorScheme = resolved;
  }

  try {
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", THEME_COLOR[resolved] || THEME_COLOR.dark);
  } catch {}

  return { preference, resolved };
}

export function setThemePreference(pref) {
  const normalized = normalizeThemePreference(pref);
  try { localStorage.setItem(LS_THEME, normalized); } catch {}
  const next = applyTheme(normalized);
  dispatchThemeChanged(next);
  return next;
}

export function dispatchThemeChanged(detail) {
  const target = globalThis.window;
  if (!target || typeof target.dispatchEvent !== "function") return false;
  const EventCtor = typeof globalThis.CustomEvent === "function"
    ? globalThis.CustomEvent
    : (typeof globalThis.Event === "function" ? globalThis.Event : null);
  if (!EventCtor) return false;
  try {
    const event = EventCtor === globalThis.CustomEvent
      ? new EventCtor("theme-changed", { detail })
      : new EventCtor("theme-changed");
    target.dispatchEvent(event);
    return true;
  } catch {
    return false;
  }
}

export function initTheme() {
  const current = applyTheme();
  if (!mediaBound && typeof window !== "undefined" && typeof window.matchMedia === "function") {
    try {
      const mq = window.matchMedia(MEDIA_QUERY);
      const onChange = () => {
        if (getThemePreference() === "auto") applyTheme("auto");
      };
      if (mq && typeof mq.addEventListener === "function") {
        mq.addEventListener("change", onChange);
        mediaBound = true;
      } else if (mq && typeof mq.addListener === "function") {
        mq.addListener(onChange);
        mediaBound = true;
      }
    } catch {}
  }
  return current;
}
