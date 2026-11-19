// Minimal hash router: "#/images?q=nginx&cluster=prod". Hash routing needs no
// server-side fallback. The selected cluster lives in the URL and is carried
// across navigation so links stay shareable.
import { useEffect, useState } from "react";

export interface Route {
  path: string[]; // ["cve", "CVE-2024-1"]
  params: URLSearchParams;
}

function parse(): Route {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [p, q = ""] = raw.split("?", 2);
  return {
    path: p.split("/").filter(Boolean).map(decodeURIComponent),
    params: new URLSearchParams(q),
  };
}

export function useRoute(): Route {
  const [route, setRoute] = useState(parse);
  useEffect(() => {
    const on = () => setRoute(parse());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

/** The cluster selected in the current URL ("" = all clusters). */
export const currentCluster = () => parse().params.get("cluster") ?? "";

/**
 * Builds a link. The current cluster selection is kept unless `params.cluster`
 * is given (pass "" to clear it).
 */
export function href(path: string[], params?: Record<string, string | undefined>): string {
  const p = path.map(encodeURIComponent).join("/");
  const q = new URLSearchParams();
  const all = { cluster: currentCluster(), ...params };
  for (const [k, v] of Object.entries(all)) if (v) q.set(k, v);
  const qs = q.toString();
  return `#/${p}${qs ? `?${qs}` : ""}`;
}

/** Replaces query parameters of the current route without adding history entries. */
export function setParams(values: Record<string, string | undefined>) {
  const r = parse();
  for (const [k, v] of Object.entries(values)) {
    if (v) r.params.set(k, v);
    else r.params.delete(k);
  }
  const qs = r.params.toString();
  window.history.replaceState(null, "", `#/${r.path.map(encodeURIComponent).join("/")}${qs ? `?${qs}` : ""}`);
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}

export const setParam = (key: string, value: string | undefined) => setParams({ [key]: value, ...(key !== "page" ? { page: undefined } : {}) });

// Detail pages name their own cluster ("in") so opening one doesn't change the
// global cluster selection.
export const imageHref = (cluster: string, ref: string) => href(["image"], { ref, in: cluster });
export const cveHref = (id: string) => href(["cve", id]);
export const workloadHref = (w: { cluster: string; namespace: string; kind: string; name: string }) =>
  href(["workload", w.cluster, w.namespace, w.kind, w.name]);
