import { toast } from "sonner";

export function timeAgo(iso?: string): string {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export const fmtEPSS = (e?: number) => (e === undefined ? "–" : `${(e * 100).toFixed(e < 0.01 ? 2 : 1)}%`);
export const fmtCVSS = (c?: number) => (c ? c.toFixed(1) : "–");
export const shortDigest = (d: string) => d.replace(/^sha256:/, "").slice(0, 12);

export function downloadCSV(name: string, header: string[], rows: (string | number | boolean | undefined)[][]) {
  const esc = (v: string | number | boolean | undefined) => {
    const s = v === undefined ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [header, ...rows].map((r) => r.map(esc).join(",")).join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
  toast.success(`Exported ${rows.length} rows to ${name}`);
}

export async function copyText(text: string, what = "Copied to clipboard") {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(what);
  } catch {
    toast.error("Clipboard is not available in this browser context");
  }
}

export const fmtDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

/**
 * Exports every page of a server-side list (the table only holds one page).
 * `path` is the list endpoint with its filters; limit/offset are added here.
 */
export async function downloadAllCSV<T>(
  path: string,
  name: string,
  header: string[],
  row: (item: T) => (string | number | boolean | undefined)[],
) {
  const items: T[] = [];
  const sep = path.includes("?") ? "&" : "?";
  try {
    for (let offset = 0; ; offset += 500) {
      const res = await fetch(`api/v1/${path}${sep}limit=500&offset=${offset}`);
      if (!res.ok) throw new Error(res.statusText);
      const page = (await res.json()) as { items: T[]; total: number };
      items.push(...page.items);
      if (items.length >= page.total || page.items.length === 0) break;
    }
  } catch (e) {
    toast.error(`Export failed: ${(e as Error).message}`);
    return;
  }
  downloadCSV(name, header, items.map(row));
}
