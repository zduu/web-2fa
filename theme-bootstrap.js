(() => {
  try {
    const pref = localStorage.getItem("authenticator.v1.theme");
    const theme = pref === "light" || pref === "auto" ? pref : "dark";
    const resolved = theme === "auto" && window.matchMedia
      ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
      : theme;
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.themeResolved = resolved;
    document.documentElement.style.colorScheme = resolved;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", resolved === "light" ? "#f4f7fb" : "#0a0d12");
  } catch {}
})();
