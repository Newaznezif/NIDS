/* Shared appearance/theme controller.
   Resolution order: explicit user choice (persisted) -> system preference.
   The <head> inline bootstrap sets data-theme before paint to avoid a flash;
   this module keeps runtime state, persists choices and notifies listeners
   (e.g. charts) so they can re-render with theme-correct colours. */
(function () {
  const KEY = "wb-theme";
  const VALID = ["system", "light", "dark"];
  const listeners = [];

  function media() {
    return window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  }
  function systemIsLight() {
    const m = media();
    return !!(m && m.matches);
  }
  function stored() {
    try { return localStorage.getItem(KEY) || "system"; } catch (e) { return "system"; }
  }
  function resolve(mode) {
    if (mode === "light") return "light";
    if (mode === "dark") return "dark";
    return systemIsLight() ? "light" : "dark";
  }
  function paint(mode) {
    document.documentElement.setAttribute("data-theme", resolve(mode));
  }
  function current() {
    return stored();
  }
  function notify(mode) {
    listeners.forEach((fn) => { try { fn(mode, resolve(mode)); } catch (e) {} });
  }
  /* Apply a mode locally (no backend persistence). */
  function apply(mode) {
    if (VALID.indexOf(mode) === -1) mode = "system";
    try { localStorage.setItem(KEY, mode); } catch (e) {}
    paint(mode);
    notify(mode);
  }
  /* Apply + persist to the authenticated user's profile when a saver is given. */
  function set(mode, saver) {
    apply(mode);
    if (typeof saver === "function") { try { saver(mode); } catch (e) {} }
  }
  function onChange(fn) { listeners.push(fn); }

  function init() {
    paint(stored());
    const m = media();
    if (m) {
      const handler = () => { if (stored() === "system") { paint("system"); notify("system"); } };
      if (m.addEventListener) m.addEventListener("change", handler);
      else if (m.addListener) m.addListener(handler);
    }
  }

  window.NIDSTheme = { init, apply, set, current, resolve, onChange, VALID };
})();
