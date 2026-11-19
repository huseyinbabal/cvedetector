import { ExternalLink, Monitor, Moon, Search, ShieldCheck, Sun, TriangleAlert } from "lucide-react";
import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { type FeedState, query, type Summary, useApi } from "@/api";
import { ClusterSelect } from "@/components/app/cluster-select";
import { CommandPalette, NAV } from "@/components/app/command-palette";
import { CVEDetailView, CVETitleMeta } from "@/components/app/cve-detail";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { timeAgo } from "@/lib/format";
import { type ThemePref, useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { Clusters } from "@/pages/Clusters";
import { CVEDetailPage, CVEs } from "@/pages/CVEs";
import { ImageDetailPage, Images } from "@/pages/Images";
import { Overview } from "@/pages/Overview";
import { Unknown } from "@/pages/Unknown";
import { WorkloadDetailPage, Workloads } from "@/pages/Workloads";
import { cveHref, href, type Route, setParam, useRoute } from "@/router";
import "./index.css";

function Page({ route }: { route: Route }) {
  const cluster = route.params.get("cluster") ?? "";
  switch (route.path[0] ?? "") {
    case "":
      return <Overview cluster={cluster} />;
    case "images":
      return <Images route={route} cluster={cluster} />;
    case "image":
      return <ImageDetailPage route={route} />;
    case "workloads":
      return <Workloads route={route} cluster={cluster} />;
    case "workload":
      return <WorkloadDetailPage route={route} />;
    case "cves":
      return <CVEs route={route} cluster={cluster} />;
    case "cve":
      return <CVEDetailPage route={route} />;
    case "unknown":
      return <Unknown cluster={cluster} />;
    case "clusters":
      return <Clusters />;
  }
  return (
    <div className="py-16 text-center text-muted-foreground">
      Page not found. <a href="#/">Back to overview</a>
    </div>
  );
}

const themeIcon = { light: Sun, dark: Moon, system: Monitor };

function SideFooter() {
  const { data } = useApi<FeedState>("feed");
  if (!data) return null;
  return (
    <div className="mt-auto hidden px-2 text-xs text-muted-foreground md:block">
      Feed updated {timeAgo(data.indexGeneratedAt)}
      {data.lastError && (
        <span className="mt-1 flex items-center gap-1 text-sev-high" title={data.lastError}>
          <TriangleAlert className="size-3.5" /> refresh failing
        </span>
      )}
    </div>
  );
}

function App() {
  const route = useRoute();
  const section = route.path[0] ?? "";
  const cluster = route.params.get("cluster") ?? "";
  const { data } = useApi<Summary>(`summary${query({ cluster })}`);
  const { pref, setPref, resolved } = useTheme();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const sheetCVE = route.path[0] === "cve" ? null : route.params.get("cve");
  const ThemeIcon = themeIcon[pref];
  const isMac = navigator.platform.toLowerCase().includes("mac");

  return (
    <TooltipProvider delayDuration={300}>
      <div className="grid min-h-screen md:grid-cols-[224px_minmax(0,1fr)]">
        <aside className="flex flex-wrap items-center gap-3 border-b bg-card px-4 py-3 md:sticky md:top-0 md:h-screen md:flex-col md:flex-nowrap md:items-stretch md:gap-4 md:border-r md:border-b-0 md:px-3 md:py-5">
          <a href="#/" className="flex items-center gap-2 px-2 text-[15px] font-semibold text-foreground no-underline hover:no-underline">
            <ShieldCheck className="size-5 text-primary" />
            cvedetector
          </a>
          <nav className="flex flex-wrap gap-0.5 md:flex-col" aria-label="Main">
            {NAV.map((n) => {
              const active = (n.match as readonly string[]).includes(section);
              return (
                <a
                  key={n.path}
                  href={href(n.path ? [n.path] : [])}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-foreground no-underline transition-colors hover:bg-accent hover:no-underline",
                    active && "bg-accent font-medium md:shadow-[inset_3px_0_0_var(--primary)]",
                  )}
                >
                  <n.icon className={cn("size-4", active ? "text-primary" : "text-muted-foreground")} />
                  <span className="hidden sm:inline">{n.label}</span>
                  {n.path === "cves" && !!data?.vulns.total && (
                    <span className="ml-auto hidden text-xs text-muted-foreground tabular-nums md:inline">{data.vulns.total}</span>
                  )}
                </a>
              );
            })}
          </nav>
          <SideFooter />
        </aside>

        <div className="min-w-0">
          <div className="sticky top-0 z-10 flex items-center justify-end gap-2 border-b bg-background/85 px-4 py-2 backdrop-blur md:px-8">
            <ClusterSelect value={cluster} />
            <Button variant="outline" size="sm" className="w-full justify-start text-muted-foreground sm:w-64" onClick={() => setPaletteOpen(true)}>
              <Search />
              Search…
              <kbd className="ml-auto rounded border bg-muted px-1.5 font-mono text-[10px]">{isMac ? "⌘" : "Ctrl"} K</kbd>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon-sm" aria-label={`Theme: ${pref} (${resolved})`}>
                  <ThemeIcon />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuRadioGroup value={pref} onValueChange={(v) => setPref(v as ThemePref)}>
                  <DropdownMenuRadioItem value="light">
                    <Sun /> Light
                  </DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="dark">
                    <Moon /> Dark
                  </DropdownMenuRadioItem>
                  <DropdownMenuRadioItem value="system">
                    <Monitor /> System
                  </DropdownMenuRadioItem>
                </DropdownMenuRadioGroup>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
          <main className="mx-auto w-full max-w-[1400px] px-4 pt-6 pb-16 md:px-8">
            <Page route={route} />
          </main>
        </div>
      </div>

      <Sheet open={!!sheetCVE} onOpenChange={(o) => !o && setParam("cve", undefined)}>
        <SheetContent side="right" className="w-full gap-0 overflow-y-auto sm:max-w-2xl">
          {sheetCVE && (
            <>
              <SheetHeader className="border-b pr-12">
                <SheetTitle className="font-mono text-lg">{sheetCVE}</SheetTitle>
                <SheetDescription asChild>
                  <div className="flex flex-wrap items-center gap-2">
                    <CVETitleMeta id={sheetCVE} />
                    <a href={cveHref(sheetCVE)} className="inline-flex items-center gap-1 text-xs">
                      Open full page <ExternalLink className="size-3" />
                    </a>
                  </div>
                </SheetDescription>
              </SheetHeader>
              <div className="p-4">
                <CVEDetailView id={sheetCVE} compact />
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      <CommandPalette open={paletteOpen} setOpen={setPaletteOpen} setTheme={setPref} />
      <Toaster theme={resolved} position="bottom-right" />
    </TooltipProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
