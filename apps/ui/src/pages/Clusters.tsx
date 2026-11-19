import { createColumnHelper } from "@tanstack/react-table";
import { TriangleAlert } from "lucide-react";
import { type Cluster, useApi } from "@/api";
import { CountChips, countsKey, Hint } from "@/components/app/badges";
import { DataTable } from "@/components/app/data-table";
import { ErrorState, PageHeader, PageSkeleton } from "@/components/app/page";
import { fmtDate, timeAgo } from "@/lib/format";
import { href } from "@/router";

// An agent heartbeats every RESYNC_INTERVAL (10 min by default); 30 min of
// silence means it is down or can't reach the API.
const STALE_MS = 30 * 60 * 1000;

const col = createColumnHelper<Cluster>();
const columns = [
  col.accessor("name", {
    header: "Cluster",
    cell: (c) => (
      <a href={href([], { cluster: c.getValue() })} className="font-medium">
        {c.getValue()}
      </a>
    ),
  }),
  col.accessor("lastReport", {
    header: "Last report",
    cell: (c) => {
      const stale = Date.now() - new Date(c.getValue()).getTime() > STALE_MS;
      return (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          {stale && (
            <Hint text="No report for over 30 minutes: the agent may be down or unable to reach the API. Data shown is from the last report.">
              <TriangleAlert className="size-3.5 text-sev-high" />
            </Hint>
          )}
          {timeAgo(c.getValue())}
        </span>
      );
    },
  }),
  col.accessor((c) => countsKey(c.counts), {
    id: "vulns",
    header: "Vulnerabilities",
    cell: (c) => <CountChips counts={c.row.original.counts} />,
  }),
  col.accessor("workloads", { header: "Workloads", meta: { align: "right" } }),
  col.accessor("images", { header: "Images", meta: { align: "right" } }),
  col.accessor("agentVersion", { header: "Agent", cell: (c) => <span className="font-mono text-xs">{c.getValue()}</span> }),
  col.accessor("firstSeen", { header: "Tracked since", cell: (c) => <span className="text-muted-foreground">{fmtDate(c.getValue())}</span> }),
];

export function Clusters() {
  const { data, error, loading } = useApi<Cluster[]>("clusters");
  if (loading && !data) return <PageSkeleton />;
  if (error && !data) return <ErrorState error={error} />;
  return (
    <>
      <PageHeader title="Clusters" sub="Clusters whose agent reports to this API. Select one to scope every page to it." />
      <DataTable
        columns={columns}
        data={data ?? []}
        getRowId={(c) => c.name}
        onRowClick={(c) => (window.location.hash = href([], { cluster: c.name }))}
        initialSort={[{ id: "vulns", desc: true }]}
        empty="No cluster has reported yet."
      />
      <p className="mt-3 text-xs text-muted-foreground">
        To remove a decommissioned cluster and its history: <code>curl -X DELETE -H "Authorization: Bearer $TOKEN" …/api/v1/clusters/&lt;name&gt;</code>
      </p>
    </>
  );
}
