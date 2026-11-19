import { createColumnHelper } from "@tanstack/react-table";
import { Download, Package } from "lucide-react";
import { useState } from "react";
import { type Image, type Page, query, useApi, type Workload, type WorkloadDetail } from "@/api";
import { CountChips, countsKey, SeverityBadge, StatusBadge } from "@/components/app/badges";
import { useShowCluster } from "@/components/app/cluster-select";
import { DataTable, serverQuery, serverState } from "@/components/app/data-table";
import { FilterBar, NamespaceSelect, SearchParam, SelectParam, severityOptions } from "@/components/app/filters";
import { ErrorState, PageHeader, PageSkeleton, Section } from "@/components/app/page";
import { Button } from "@/components/ui/button";
import { downloadAllCSV } from "@/lib/format";
import { href, imageHref, type Route, workloadHref } from "@/router";

const col = createColumnHelper<Workload>();

function columns(showCluster: boolean) {
  return [
    col.accessor("name", {
      header: "Workload",
      cell: (c) => (
        <a href={workloadHref(c.row.original)} className="font-medium break-all">
          {c.getValue()}
        </a>
      ),
    }),
    ...(showCluster ? [col.accessor("cluster", { header: "Cluster" })] : []),
    col.accessor("namespace", { header: "Namespace" }),
    col.accessor("kind", { header: "Kind", cell: (c) => <span className="text-muted-foreground">{c.getValue()}</span> }),
    col.accessor("maxSeverity", {
      id: "severity",
      header: "Highest",
      cell: (c) => (c.row.original.counts.total ? <SeverityBadge severity={c.getValue()} /> : <span className="text-muted-foreground">–</span>),
    }),
    col.accessor("counts", {
      id: "vulns",
      header: "Vulnerabilities",
      cell: (c) => (c.getValue().total ? <CountChips counts={c.getValue()} /> : <span className="text-muted-foreground">–</span>),
    }),
    col.accessor((w) => w.images.length, { id: "images", header: "Images", meta: { align: "right" } }),
    col.accessor("pods", { header: "Pods", meta: { align: "right" } }),
  ];
}

export function Workloads({ route, cluster }: { route: Route; cluster: string }) {
  const p = route.params;
  const f = { cluster, q: p.get("q") ?? "", minSeverity: p.get("minSeverity") ?? "", namespace: p.get("namespace") ?? "" };
  const st = serverState(route, { sort: "vulns" });
  const { data, error, loading } = useApi<Page<Workload>>(`workloads${query({ ...f, ...serverQuery(st) })}`);
  const showCluster = useShowCluster(cluster);
  const [exporting, setExporting] = useState(false);

  const exportCSV = async () => {
    setExporting(true);
    await downloadAllCSV<Workload>(
      `workloads${query({ ...f, sort: st.sort, order: st.desc ? "desc" : "asc" })}`,
      "workloads.csv",
      ["cluster", "namespace", "kind", "name", "pods", "images", "critical", "high", "medium", "low"],
      (w) => [w.cluster, w.namespace, w.kind, w.name, w.pods, w.images.join(" "), w.counts.critical, w.counts.high, w.counts.medium, w.counts.low],
    );
    setExporting(false);
  };

  return (
    <>
      <PageHeader
        title="Workloads"
        sub="Pods grouped by their owning Deployment, StatefulSet, DaemonSet, CronJob…"
        actions={
          <Button variant="outline" size="sm" onClick={() => void exportCSV()} disabled={!data?.total || exporting}>
            <Download /> Export CSV
          </Button>
        }
      />
      <FilterBar>
        <SearchParam name="q" value={f.q} placeholder="Search workload or image" />
        <SelectParam name="minSeverity" value={f.minSeverity} options={severityOptions} label="Minimum severity" />
        <NamespaceSelect value={f.namespace} />
      </FilterBar>
      {loading && !data ? (
        <PageSkeleton />
      ) : error && !data ? (
        <ErrorState error={error} />
      ) : (
        <DataTable
          columns={columns(showCluster)}
          data={data?.items ?? []}
          server={{ state: st, total: data?.total ?? 0 }}
          getRowId={(w) => `${w.cluster}/${w.namespace}/${w.kind}/${w.name}`}
          onRowClick={(w) => (window.location.hash = workloadHref(w))}
          empty="No workloads match these filters."
        />
      )}
    </>
  );
}

const icol = createColumnHelper<Image>();
const imageColumns = [
  icol.accessor("ref", {
    header: "Image",
    cell: (c) => (
      <a href={imageHref(c.row.original.cluster, c.getValue())} className="font-mono text-[13px] break-all">
        {c.getValue()}
      </a>
    ),
  }),
  icol.accessor((i) => `${i.productName ?? ""} ${i.version ?? ""}`, {
    id: "product",
    header: "Product",
    cell: (c) =>
      c.row.original.productName ? (
        <span className="whitespace-nowrap">
          {c.row.original.productName} <span className="text-muted-foreground">{c.row.original.version}</span>
        </span>
      ) : (
        <span className="text-muted-foreground">–</span>
      ),
  }),
  icol.accessor("status", { header: "Match", cell: (c) => <StatusBadge status={c.getValue()} /> }),
  icol.accessor((i) => countsKey(i.counts), {
    id: "vulns",
    header: "Vulnerabilities",
    cell: (c) => (c.row.original.counts.total ? <CountChips counts={c.row.original.counts} /> : <span className="text-muted-foreground">none known</span>),
  }),
];

export function WorkloadDetailPage({ route }: { route: Route }) {
  const [, cluster, ns, kind, name] = route.path;
  const { data, error, loading } = useApi<WorkloadDetail>(`workloads/${[cluster, ns, kind, name].map((s) => encodeURIComponent(s ?? "")).join("/")}`);
  if (loading && !data) return <PageSkeleton />;
  if (error && !data) return <ErrorState error={error} />;
  if (!data) return null;
  const w = data.workload;
  return (
    <>
      <PageHeader
        crumb={<a href={href(["workloads"])}>Workloads</a>}
        title={w.name}
        sub={
          <>
            <span>
              {w.kind} in <a href={href(["workloads"], { namespace: w.namespace })}>{w.namespace}</a> · {w.cluster} · {w.pods} pods
            </span>
            {w.counts.total > 0 && <CountChips counts={w.counts} />}
          </>
        }
      />
      <Section title={`Images (${data.images.length})`} icon={<Package className="size-3.5" />}>
        <div className="-mx-4 -mb-4">
          <DataTable
            className="rounded-none border-x-0 border-b-0"
            columns={imageColumns}
            data={data.images}
            getRowId={(i) => i.ref}
            onRowClick={(i) => (window.location.hash = imageHref(i.cluster, i.ref))}
            initialSort={[{ id: "vulns", desc: true }]}
            paginate={false}
          />
        </div>
      </Section>
    </>
  );
}
