import { createColumnHelper } from "@tanstack/react-table";
import { CircleCheck, Download, Fingerprint, Layers, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { type Image, type ImageDetail, type ImageFinding, type Page, query, useApi } from "@/api";
import { CountChips, KEVBadge, SeverityBadge, severityRank, StatusBadge, statusDescription } from "@/components/app/badges";
import { useShowCluster } from "@/components/app/cluster-select";
import { CVELink } from "@/components/app/cve-detail";
import { DataTable, serverQuery, serverState } from "@/components/app/data-table";
import { FilterBar, NamespaceSelect, SearchParam, SelectParam, severityOptions } from "@/components/app/filters";
import { Callout, ErrorState, PageHeader, PageSkeleton, Section } from "@/components/app/page";
import { Button } from "@/components/ui/button";
import { downloadAllCSV, fmtCVSS, fmtDate, fmtEPSS, shortDigest } from "@/lib/format";
import { href, imageHref, type Route, setParam, workloadHref } from "@/router";

const col = createColumnHelper<Image>();

function columns(showCluster: boolean) {
  return [
    col.accessor("ref", {
      header: "Image",
      cell: (c) => (
        <a href={imageHref(c.row.original.cluster, c.getValue())} className="font-mono text-[13px] break-all">
          {c.getValue()}
        </a>
      ),
    }),
    ...(showCluster ? [col.accessor("cluster", { header: "Cluster" })] : []),
    col.accessor((i) => i.productName ?? "", {
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
    col.accessor("status", { header: "Match", cell: (c) => <StatusBadge status={c.getValue()} /> }),
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
    col.accessor("pods", { header: "Pods", meta: { align: "right" } }),
  ];
}

export function Images({ route, cluster }: { route: Route; cluster: string }) {
  const p = route.params;
  const f = {
    cluster,
    q: p.get("q") ?? "",
    minSeverity: p.get("minSeverity") ?? "",
    status: p.get("status") ?? "",
    namespace: p.get("namespace") ?? "",
    product: p.get("product") ?? "",
  };
  const st = serverState(route, { sort: "vulns" });
  const { data, error, loading } = useApi<Page<Image>>(`images${query({ ...f, ...serverQuery(st) })}`);
  const showCluster = useShowCluster(cluster);
  const [exporting, setExporting] = useState(false);

  const exportCSV = async () => {
    setExporting(true);
    await downloadAllCSV<Image>(
      `images${query({ ...f, sort: st.sort, order: st.desc ? "desc" : "asc" })}`,
      "images.csv",
      ["cluster", "image", "product", "version", "status", "critical", "high", "medium", "low", "pods"],
      (i) => [i.cluster, i.ref, i.product, i.version, i.status, i.counts.critical, i.counts.high, i.counts.medium, i.counts.low, i.pods],
    );
    setExporting(false);
  };

  return (
    <>
      <PageHeader
        title="Images"
        sub="Distinct image references running in the cluster"
        actions={
          <Button variant="outline" size="sm" onClick={() => void exportCSV()} disabled={!data?.total || exporting}>
            <Download /> Export CSV
          </Button>
        }
      />
      <FilterBar>
        <SearchParam name="q" value={f.q} placeholder="Search image or product" />
        <SelectParam name="minSeverity" value={f.minSeverity} options={severityOptions} label="Minimum severity" />
        <SelectParam
          name="status"
          value={f.status}
          label="Match status"
          options={[
            ["", "Any match status"],
            ["matched", "Matched"],
            ["approximate", "Approximate"],
            ["no-version", "No version"],
            ["unknown", "Not in feed"],
          ]}
        />
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
          getRowId={(i) => i.cluster + "|" + i.ref}
          onRowClick={(i) => (window.location.hash = imageHref(i.cluster, i.ref))}
          empty="No images match these filters."
        />
      )}
    </>
  );
}

const vcol = createColumnHelper<ImageFinding>();
const vulnColumns = [
  vcol.accessor("id", {
    header: "ID",
    cell: (c) => (
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
        <CVELink id={c.getValue()} /> {c.row.original.kev && <KEVBadge />}
      </span>
    ),
  }),
  vcol.accessor((v) => severityRank[v.severity] * 100 + (v.cvss ?? 0), {
    id: "severity",
    header: "Severity",
    cell: (c) => <SeverityBadge severity={c.row.original.severity} />,
  }),
  vcol.accessor((v) => v.cvss ?? 0, { id: "cvss", header: "CVSS", meta: { align: "right" }, cell: (c) => fmtCVSS(c.getValue()) }),
  vcol.accessor((v) => v.epss ?? -1, { id: "epss", header: "EPSS", meta: { align: "right" }, cell: (c) => fmtEPSS(c.row.original.epss) }),
  vcol.accessor((v) => v.fixedIn ?? "", {
    id: "fixedIn",
    header: "Fixed in",
    cell: (c) => (c.getValue() ? <span className="font-mono text-[13px]">{c.getValue()}</span> : <span className="text-muted-foreground">no fix</span>),
  }),
  vcol.accessor((v) => v.firstSeen ?? "", {
    id: "firstSeen",
    header: "Since",
    cell: (c) => <span className="whitespace-nowrap text-muted-foreground">{c.getValue() ? fmtDate(c.getValue()) : "–"}</span>,
  }),
  vcol.accessor((v) => v.summary ?? "", {
    id: "summary",
    header: "Summary",
    enableSorting: false,
    // overflow-wrap:anywhere: some NVD descriptions join words with no-break
    // spaces, and that unbreakable run set the table's minimum width.
    cell: (c) => (
      <span title={c.getValue()} className="line-clamp-2 max-w-[520px] min-w-48 text-muted-foreground [overflow-wrap:anywhere]">
        {c.getValue()}
      </span>
    ),
  }),
];

export function ImageDetailPage({ route }: { route: Route }) {
  const ref = route.params.get("ref") ?? "";
  const inCluster = route.params.get("in") ?? "";
  const { data, error, loading } = useApi<ImageDetail>(`image${query({ cluster: inCluster, ref })}`);
  if (loading && !data) return <PageSkeleton />;
  if (error && !data) return <ErrorState error={error} />;
  if (!data) return null;
  const { image: img, vulns, resolved } = data;

  return (
    <>
      <PageHeader
        crumb={<a href={href(["images"])}>Images</a>}
        title={<span className="font-mono">{img.ref}</span>}
        sub={
          <>
            <span>{img.productName ? `${img.productName} ${img.version ?? ""}` : "Unknown product"}</span>
            <span aria-hidden>·</span>
            <StatusBadge status={img.status} />
            <span aria-hidden>·</span>
            <span>
              {img.pods} pods in {img.cluster}
            </span>
          </>
        }
      />
      {img.status !== "matched" && <Callout tone="info">{statusDescription(img.status)}</Callout>}

      <div className="grid items-start gap-4 2xl:grid-cols-[minmax(0,2fr)_minmax(260px,1fr)]">
        <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4">
          <Section title={`Vulnerabilities (${vulns.length})`} icon={<ShieldAlert className="size-3.5" />}>
            {vulns.length ? (
              <div className="-mx-4 -mb-4">
                <DataTable
                  className="rounded-none border-x-0 border-b-0"
                  columns={vulnColumns}
                  data={vulns}
                  getRowId={(v) => v.id}
                  onRowClick={(v) => setParam("cve", v.id)}
                  initialSort={[{ id: "severity", desc: true }]}
                />
              </div>
            ) : (
              <p className="text-muted-foreground">
                {img.status === "matched" || img.status === "approximate"
                  ? "No known vulnerabilities for this version."
                  : "Vulnerabilities cannot be determined for this image."}
              </p>
            )}
          </Section>
          {resolved.length > 0 && (
            <Section title={`Resolved (${resolved.length})`} icon={<CircleCheck className="size-3.5" />}>
              <ul className="grid gap-1.5 text-[13px]">
                {resolved.map((v) => (
                  <li key={v.id + v.firstSeen} className="flex flex-wrap items-center gap-x-2">
                    <CVELink id={v.id} />
                    <SeverityBadge severity={v.severity} />
                    <span className="text-xs text-muted-foreground">
                      {v.firstSeen && fmtDate(v.firstSeen)} → {v.resolvedAt && fmtDate(v.resolvedAt)}
                    </span>
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>

        <div className="grid items-start gap-4 md:grid-cols-2 2xl:grid-cols-1">
          <Section title="Used by" icon={<Layers className="size-3.5" />}>
            <ul className="grid gap-1.5">
              {data.workloads.map((w) => (
                <li key={`${w.namespace}/${w.kind}/${w.name}`}>
                  <a href={workloadHref(w)}>{w.name}</a>{" "}
                  <span className="text-xs text-muted-foreground">
                    {w.namespace} · {w.kind}
                  </span>
                </li>
              ))}
            </ul>
          </Section>
          {!!img.digests?.length && (
            <Section title="Running digests" icon={<Fingerprint className="size-3.5" />}>
              <ul className="grid gap-1 font-mono text-xs">
                {img.digests.map((d) => (
                  <li key={d} title={d}>
                    {shortDigest(d)}
                  </li>
                ))}
              </ul>
              {img.digests.length > 1 && (
                <p className="mt-2 text-xs text-muted-foreground">Different digests for the same tag: some pods pulled it at different times.</p>
              )}
            </Section>
          )}
        </div>
      </div>
    </>
  );
}
