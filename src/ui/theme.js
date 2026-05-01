export const LS_THEME = "authenticator.v1.theme";

const MEDIA_QUERY = "(prefers-color-scheme: dark)";
const THEME_COLOR = {
  dark: "#0a0d12",
  light: "#f4f7fb",
};

let mediaBound = false;

export function getThemePreference() {
  let value = null;
  try { value = localStorage.getItem(LS_THEME); } catch {}
  return value === "dark" || value === "light" || value === "auto" ? value : "dark";
}

export function resolveTheme(pref = getThemePreference()) {
  if (pref === "dark" || pref === "light") return pref;
  if (typeof window !== "undefined" && typeof window.matchMedia === "function") {
    return window.matchMedia(MEDIA_QUERY).matches ? "dark" : "light";
  }
  return "dark";
}

export function applyTheme(pref = getThemePreference()) {
  const root = document.documentElement;
  const resolved = resolveTheme(pref);
  root.dataset.theme = pref;
  root.dataset.themeResolved = resolved;
  root.style.colorScheme = resolved;

  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", THEME_COLOR[resolved] || THEME_COLOR.dark);

  return { preference: pref, resolved };
}

export function setThemePreference(pref) {
  const normalized = pref === "light" || pref === "auto" ? pref : "dark";
  try { localStorage.setItem(LS_THEME, normalized); } catch {}
  const next = applyTheme(normalized);
  try {
    window.dispatchEvent(new CustomEvent("theme-changed", { detail: next }));
  } catch {}
  return next;
}

export function initTheme() {
  const current = applyTheme();
  if (!mediaBound && typeof window !== "undefined" && typeof window.matchMedia === "function") {
    mediaBound = true;
    const mq = window.matchMedia(MEDIA_QUERY);
    mq.addEventListener("change", () => {
      if (getThemePreference() === "auto") applyTheme("auto");
    });
  }
  return current;
}
