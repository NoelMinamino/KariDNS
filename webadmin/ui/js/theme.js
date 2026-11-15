// theme.js: the colour scheme of the page.  'auto' follows the system (prefers-color-scheme); 'light' and 'dark' are the person's choice, kept in this browser only
// (the store of the browser, like the language: never sent to the service).  The choice is the attribute data-theme of the root element, which app.css reads.

export const THEME_KEY = 'karidns-theme';
export const THEMES = ['auto', 'light', 'dark'];

// opts: { storage, apply(theme) }: apply is called at once with the saved choice and again on every change
export function createTheme({ storage, apply }) {
  let saved = null;
  try { saved = storage?.getItem(THEME_KEY) ?? null; } catch { /* storage may be refused */ }
  let theme = THEMES.includes(saved) ? saved : 'auto';
  apply(theme);
  return {
    get value() { return theme; },
    set(v) {
      if (!THEMES.includes(v)) return;
      theme = v;
      try {
        if (v === 'auto') storage?.removeItem(THEME_KEY);
        else storage?.setItem(THEME_KEY, v);
      } catch { /* the choice lasts for this page only */ }
      apply(v);
    },
  };
}
