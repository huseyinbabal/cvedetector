import { Boxes, CircleDashed, LayoutDashboard, Monitor, Moon, Package, Server, ShieldAlert, Sun } from "lucide-react";
import { useEffect } from "react";
import { type Image, type Page, query, useApi, type Vuln, type Workload } from "@/api";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command";
import type { ThemePref } from "@/lib/theme";
import { currentCluster, href, imageHref, setParam, workloadHref } from "@/router";
import { SeverityBadge } from "./badges";

export const NAV = [
  { path: "", label: "Overview", icon: LayoutDashboard, match: [""] },
  { path: "images", label: "Images", icon: Package, match: ["images", "image"] },
  { path: "workloads", label: "Workloads", icon: Boxes, match: ["workloads", "workload"] },
  { path: "cves", label: "Vulnerabilities", icon: ShieldAlert, match: ["cves", "cve"] },
  { path: "unknown", label: "Coverage gaps", icon: CircleDashed, match: ["unknown"] },
  { path: "clusters", label: "Clusters", icon: Server, match: ["clusters"] },
] as const;

/** ⌘K / Ctrl+K palette: jump to pages, CVEs, images and workloads. */
export function CommandPalette({ open, setOpen, setTheme }: { open: boolean; setOpen: (o: boolean) => void; setTheme: (t: ThemePref) => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen(!open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, setOpen]);

  // Only fetch while the palette is open; the top 300 of each list (by risk)
  // keeps the palette fast on large clusters. Use the list pages' search for the rest.
  const q = query({ cluster: currentCluster(), limit: 300 });
  const cves = useApi<Page<Vuln>>(open ? `cves${q}` : null);
  const images = useApi<Page<Image>>(open ? `images${q}` : null);
  const workloads = useApi<Page<Workload>>(open ? `workloads${q}` : null);

  const run = (fn: () => void) => {
    setOpen(false);
    fn();
  };
  const go = (h: string) => run(() => (window.location.hash = h));

  return (
    <CommandDialog open={open} onOpenChange={setOpen} title="Search" description="Jump to a page, vulnerability, image or workload">
      <CommandInput placeholder="Search CVEs, images, workloads…" />
      <CommandList>
        <CommandEmpty>No results.</CommandEmpty>
        <CommandGroup heading="Pages">
          {NAV.map((n) => (
            <CommandItem key={n.path} value={`page ${n.label}`} onSelect={() => go(href(n.path ? [n.path] : []))}>
              <n.icon />
              {n.label}
            </CommandItem>
          ))}
        </CommandGroup>
        {!!cves.data?.items.length && (
          <CommandGroup heading="Vulnerabilities">
            {cves.data.items.map((v) => (
              <CommandItem
                key={v.product + v.id}
                value={`${v.id} ${v.aliases?.join(" ") ?? ""} ${v.product} ${v.summary ?? ""}`}
                onSelect={() => run(() => setParam("cve", v.id))}
              >
                <ShieldAlert />
                <span className="font-mono text-[13px]">{v.id}</span>
                <span className="truncate text-muted-foreground">{v.product}</span>
                <span className="ml-auto">
                  <SeverityBadge severity={v.severity} />
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {!!images.data?.items.length && (
          <CommandGroup heading="Images">
            {images.data.items.map((i) => (
              <CommandItem key={i.cluster + i.ref} value={`image ${i.cluster} ${i.ref} ${i.productName ?? ""}`} onSelect={() => go(imageHref(i.cluster, i.ref))}>
                <Package />
                <span className="truncate font-mono text-[13px]">{i.ref}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {!!workloads.data?.items.length && (
          <CommandGroup heading="Workloads">
            {workloads.data.items.map((w) => (
              <CommandItem key={`${w.cluster}/${w.namespace}/${w.kind}/${w.name}`} value={`workload ${w.cluster} ${w.namespace} ${w.kind} ${w.name}`} onSelect={() => go(workloadHref(w))}>
                <Boxes />
                {w.name}
                <span className="text-muted-foreground">
                  {w.namespace} · {w.kind}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        <CommandSeparator />
        <CommandGroup heading="Theme">
          <CommandItem value="theme light" onSelect={() => run(() => setTheme("light"))}>
            <Sun /> Light
          </CommandItem>
          <CommandItem value="theme dark" onSelect={() => run(() => setTheme("dark"))}>
            <Moon /> Dark
          </CommandItem>
          <CommandItem value="theme system" onSelect={() => run(() => setTheme("system"))}>
            <Monitor /> System
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
