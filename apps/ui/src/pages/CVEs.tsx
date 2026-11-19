import { createColumnHelper } from "@tanstack/react-table";
import { Download, X } from "lucide-react";
import { useState } from "react";
import { type Page, query, useApi, type Vuln } from "@/api";
import { KEVBadge, SeverityBadge } from "@/components/app/badges";
import { CVEDetailView, CVELink, CVETitleMeta } from "@/components/app/cve-detail";
import { DataTable, serverQuery, serverState } from "@/components/app/data-table";
import { FilterBar, NamespaceSelect, SearchParam, SelectParam, severityOptions, ToggleParam } from "@/components/app/filters";
import { ErrorState, PageHeader, PageSkeleton } from "@/components/app/page";
import { Button } from "@/components/ui/button";
import { downloadAllCSV, fmtCVSS, fmtEPSS, timeAgo } from "@/lib/format";
import { href, type Route, setParam } from "@/router";

const col = createColumnHelper<Vuln>();
const columns = [
  col.accessor("id", {
    header: "ID",
    cell: (c) => (
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
        <CVELink id={c.getValue()} /> {c.row.original.kev && <KEVBadge />}
      </span>
    ),
  }),
  col.accessor("severity", { header: "Severity", cell: (c) => <SeverityBadge severity={c.getValue()} /> }),
  col.accessor("cvss", { header: "CVSS", meta: { align: "right" }, cell: (c) => fmtCVSS(c.getValue()) }),
  col.accessor("epss", { header: "EPSS", meta: { align: "right" }, cell: (c) => fmtEPSS(c.getValue()) }),
  col.accessor("product", { header: "Product" }),
  col.accessor("workloads", { header: "Workloads", meta: { align: "right" } }),
  col.accessor("firstSeen", {
    header: "Open for",
    cell: (c) => <span className="whitespace-nowrap text-muted-foreground">{c.getValue() ? timeAgo(c.getValue()).replace(" ago", "") : "–"}</span>,
  }),
  col.accessor("fixable", { header: "Fix", enableSorting: false, cell: (c) => (c.getValue() ? "Yes" : <span className="text-muted-foreground">No</span>) }),
  col.accessor((v) => v.summary ?? "", {
    id: "summary",
    header: "Summary",
    enableSorting: false,
    cell: (c) => <span className="line-clamp-2 max-w-[480px] text-muted-foreground">{c.getValue()}</span>,
  }),
];

export function CVEs({ route, cluster }: { route: Route; cluster: string }) {
  const p = route.params;
  const f = {
    cluster,
    q: p.get("q") ?? "",
    minSeverity: p.get("minSeverity") ?? "",
    namespace: p.get("namespace") ?? "",
    product: p.get("product") ?? "",
    kev: p.get("kev") === "true",
    fixable: p.get("fixable") === "true",
  };
  // Empty sort = the API's triage order: known exploited, severity, CVSS, reach.
  const st = serverState(route, { sort: "" });
  const { data, error, loading } = useApi<Page<Vuln>>(`cves${query({ ...f, ...serverQuery(st) })}`);
  const [exporting, setExporting] = useState(false);

  const exportCSV = async () => {
    setExporting(true);
    await downloadAllCSV<Vuln>(
      `cves${query({ ...f, sort: st.sort, order: st.desc ? "desc" : "asc" })}`,
      "cves.csv",
      ["id", "severity", "cvss", "epss", "kev", "product", "fixable", "images", "workloads", "first_seen", "summary"],
      (v) => [v.id, v.severity, v.cvss, v.epss, !!v.kev, v.product, v.fixable, v.images, v.workloads, v.firstSeen, v.summary],
    );
    setExporting(false);
  };

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        sub="Known vulnerabilities affecting running images. Known exploited ones first."
        actions={
          <Button variant="outline" size="sm" onClick={() => void exportCSV()} disabled={!data?.total || exporting}>
            <Download /> Export CSV
          </Button>
        }
      />
      <FilterBar>
        <SearchParam name="q" value={f.q} placeholder="Search CVE id or text" />
        <SelectParam name="minSeverity" value={f.minSeverity} options={severityOptions} label="Minimum severity" />
        <NamespaceSelect value={f.namespace} />
        <ToggleParam name="kev" value={f.kev} label="Known exploited" />
        <ToggleParam name="fixable" value={f.fixable} label="Fix available" />
        {f.product && (
          <Button variant="secondary" size="sm" onClick={() => setParam("product", undefined)}>
            Product: {f.product} <X />
          </Button>
        )}
      </FilterBar>
      {loading && !data ? (
        <PageSkeleton />
      ) : error && !data ? (
        <ErrorState error={error} />
      ) : (
        <DataTable
          columns={columns}
          data={data?.items ?? []}
          server={{ state: st, total: data?.total ?? 0 }}
          getRowId={(v) => v.product + "|" + v.id}
          onRowClick={(v) => setParam("cve", v.id)}
          empty="No vulnerabilities match these filters."
        />
      )}
    </>
  );
}

export function CVEDetailPage({ route }: { route: Route }) {
  const id = route.path[1] ?? "";
  return (
    <>
      <PageHeader crumb={<a href={href(["cves"])}>Vulnerabilities</a>} title={<span className="font-mono">{id}</span>} sub={<CVETitleMeta id={id} />} />
      <CVEDetailView id={id} />
    </>
  );
}
