import { useEffect, useState } from "react";

export type ThemePref = "system" | "light" | "dark";
const KEY = "cvedetector.theme";
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* storage unavailable */
  }
  return "system";
}

function apply(pref: ThemePref) {
  const dark = pref === "dark" || (pref === "system" && media().matches);
  document.documentElement.classList.toggle("dark", dark);
}

// Apply before React renders to avoid a flash of the wrong theme.
apply(read());

/** Theme preference (persisted per browser) and the resolved light/dark value. */
export function useTheme() {
  const [pref, setPref] = useState<ThemePref>(read);
  const [resolved, setResolved] = useState<"light" | "dark">(() =>
    document.documentElement.classList.contains("dark") ? "dark" : "light",
  );

  useEffect(() => {
    const update = () => {
      apply(pref);
      setResolved(document.documentElement.classList.contains("dark") ? "dark" : "light");
    };
    update();
    try {
      localStorage.setItem(KEY, pref);
    } catch {
      /* storage unavailable */
    }
    const m = media();
    m.addEventListener("change", update);
    return () => m.removeEventListener("change", update);
  }, [pref]);

  return { pref, setPref, resolved };
}
