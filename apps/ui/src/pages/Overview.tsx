import { Activity, Boxes, Database, Flame, History as HistoryIcon, Package, Server, ShieldAlert, Wrench } from "lucide-react";
import type { ReactNode } from "react";
import { type Cluster, type FeedState, type History, query, type Summary, useApi } from "@/api";
import { CountChips, SeverityBadge } from "@/components/app/badges";
import { Callout, ErrorState, PageHeader, PageSkeleton, Section } from "@/components/app/page";
import { TrendGrid } from "@/components/app/trend";
import { fmtDate, timeAgo } from "@/lib/format";
import { cn } from "@/lib/utils";
import { href, workloadHref } from "@/router";

export function Overview({ cluster }: { cluster: string }) {
  const q = query({ cluster });
  const { data, error, loading } = useApi<Summary>(`summary${q}`);
  const history = useApi<History>(`history${query({ cluster, days: 30 })}`);
  const feed = useApi<FeedState>("feed");
  const clusters = useApi<Cluster[]>("clusters");
  if (loading && !data) return <PageSkeleton />;
  if (error && !data) return <ErrorState error={error} />;
  if (!data) return null;

  if (data.clusters === 0) return <NoClusters />;

  const v = data.vulns;
  const products = Object.entries(data.vulnsByProduct).sort((a, b) => b[1] - a[1]);
  const maxProduct = products[0]?.[1] ?? 1;
  const by = data.imagesByStatus;
  const identified = (by.matched ?? 0) + (by.approximate ?? 0);
  const gaps = (by.unknown ?? 0) + (by["no-version"] ?? 0);
  const scope = cluster || (data.clusters > 1 ? `${data.clusters} clusters` : (clusters.data?.[0]?.name ?? "cluster"));

  return (
    <>
      <PageHeader
        title="Overview"
        sub={`${scope} · last report ${timeAgo(data.lastReport)} · ${data.namespaces} namespaces · ${data.workloads} workloads · ${data.images} images`}
      />

      <section aria-label="Vulnerabilities by severity" className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <Tile label="Critical" value={v.critical} tone="text-sev-critical" bar="bg-sev-critical" to={href(["cves"], { minSeverity: "critical" })} />
        <Tile label="High" value={v.high} tone="text-sev-high" bar="bg-sev-high" to={href(["cves"], { minSeverity: "high" })} />
        <Tile label="Medium" value={v.medium} tone="text-sev-medium" bar="bg-sev-medium" to={href(["cves"], { minSeverity: "medium" })} />
        <Tile label="Low" value={v.low} tone="text-sev-low" bar="bg-sev-low" to={href(["cves"], { minSeverity: "low" })} />
        <Tile label="Known exploited" hint="CISA KEV" icon={<Flame className="size-4" />} value={v.kev} tone="text-kev" bar="bg-kev" to={href(["cves"], { kev: "true" })} />
        <Tile
          label="Fixable"
          hint="a fixed version exists"
          icon={<Wrench className="size-4" />}
          value={v.fixable}
          tone="text-foreground"
          bar="bg-muted-foreground"
          to={href(["cves"], { fixable: "true" })}
        />
      </section>

      {history.data && (
        <Section
          title="Last 30 days"
          icon={<HistoryIcon className="size-3.5" />}
          className="mb-4"
          action={
            <dl className="flex gap-4 text-xs text-muted-foreground">
              <div title="Image × vulnerability pairs that started in this window">
                <dt className="inline">Findings opened </dt>
                <dd className="inline font-semibold text-foreground tabular-nums">{history.data.opened}</dd>
              </div>
              <div title="Image × vulnerability pairs that ended in this window (image upgraded or removed)">
                <dt className="inline">Resolved </dt>
                <dd className="inline font-semibold text-foreground tabular-nums">{history.data.resolved}</dd>
              </div>
              {history.data.meanDaysToFix != null && (
                <div title="Mean time from first seen to resolved, for findings resolved in this window">
                  <dt className="inline">Mean time to fix </dt>
                  <dd className="inline font-semibold text-foreground tabular-nums">{history.data.meanDaysToFix.toFixed(1)} d</dd>
                </div>
              )}
            </dl>
          }
        >
          <Trend history={history.data} />
        </Section>
      )}

      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Section title="Most affected workloads" icon={<Boxes className="size-3.5" />}>
          {data.topWorkloads?.length ? (
            <ul className="-mx-4 divide-y">
              {data.topWorkloads.map((w) => (
                <li key={`${w.cluster}/${w.namespace}/${w.kind}/${w.name}`} className="flex items-center justify-between gap-3 px-4 py-2.5">
                  <div className="min-w-0">
                    <a href={workloadHref(w)} className="font-medium break-all">
                      {w.name}
                    </a>
                    <div className="text-xs text-muted-foreground">
                      {!cluster && data.clusters > 1 && <>{w.cluster} · </>}
                      {w.namespace} · {w.kind}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <SeverityBadge severity={w.maxSeverity} className="hidden sm:inline-flex" />
                    <CountChips counts={w.counts} />
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted-foreground">No running workload is affected by a known vulnerability.</p>
          )}
        </Section>

        <div className="grid gap-4">
          <Section title="Image coverage" icon={<Package className="size-3.5" />}>
            <p className="mb-2.5 text-2xl font-semibold tabular-nums">
              {identified}
              <span className="text-sm font-normal text-muted-foreground"> / {data.images} images identified</span>
            </p>
            <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full bg-muted" role="img" aria-label="Image match status">
              {(
                [
                  ["matched", "bg-ok"],
                  ["approximate", "bg-sev-medium"],
                  ["no-version", "bg-sev-low"],
                  ["unknown", "bg-muted-foreground/50"],
                ] as const
              ).map(([s, cls]) => (by[s] ? <span key={s} className={cls} style={{ flexGrow: by[s], flexBasis: 0 }} title={`${s}: ${by[s]}`} /> : null))}
            </div>
            <ul className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <Legend cls="bg-ok">Matched {by.matched ?? 0}</Legend>
              <Legend cls="bg-sev-medium">Approximate {by.approximate ?? 0}</Legend>
              <Legend cls="bg-sev-low">No version {by["no-version"] ?? 0}</Legend>
              <Legend cls="bg-muted-foreground/50">
                <a href={href(["unknown"])}>Not in feed {by.unknown ?? 0}</a>
              </Legend>
            </ul>
            {gaps > 0 && (
              <p className="mt-3 text-xs text-muted-foreground">
                {gaps} images can't be judged from the feed. <a href={href(["unknown"])}>See coverage gaps</a>
              </p>
            )}
          </Section>

          <Section title="Vulnerabilities by product" icon={<ShieldAlert className="size-3.5" />}>
            {products.length ? (
              <ul className="grid gap-2">
                {products.slice(0, 8).map(([p, n]) => (
                  <li key={p} className="grid grid-cols-[110px_1fr_36px] items-center gap-3 text-[13px]">
                    <a href={href(["cves"], { product: p })} className="truncate">
                      {p}
                    </a>
                    <span className="h-2 overflow-hidden rounded-full bg-muted">
                      <span className="block h-full rounded-full bg-primary/80" style={{ width: `${(n / maxProduct) * 100}%` }} />
                    </span>
                    <span className="text-right text-muted-foreground tabular-nums">{n}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-muted-foreground">None.</p>
            )}
          </Section>

          {feed.data && <FeedCard feed={feed.data} />}
        </div>
      </div>
    </>
  );
}

/** Plots only the days since tracking started: earlier zeros would read as "no vulnerabilities". */
function Trend({ history }: { history: History }) {
  const since = history.trackingSince?.slice(0, 10) ?? "";
  const points = history.points.filter((p) => p.day >= since);
  if (points.length < 2) {
    return (
      <p className="text-[13px] text-muted-foreground">
        Tracking started {history.trackingSince ? fmtDate(history.trackingSince) : "today"}. The trend appears after the first full day of history.
      </p>
    );
  }
  return (
    <>
      <TrendGrid points={points} />
      {points.length < history.points.length && (
        <p className="mt-1 text-xs text-muted-foreground">Tracking since {fmtDate(history.trackingSince!)}.</p>
      )}
    </>
  );
}

function NoClusters() {
  return (
    <>
      <PageHeader title="Overview" />
      <Section title="Waiting for the first report" icon={<Server className="size-3.5" />}>
        <p className="mb-2">No cluster has reported its inventory yet.</p>
        <p className="text-[13px] text-muted-foreground">
          Install the agent in a cluster and point it at this API. With the Helm chart, the agent in the same release is configured
          automatically; for another cluster install the chart with <code>api.enabled=false</code>, <code>ui.enabled=false</code>,{" "}
          <code>postgresql.enabled=false</code>, <code>agent.apiUrl</code> and <code>agent.token</code>.
        </p>
      </Section>
    </>
  );
}

function Tile({ label, value, tone, bar, to, hint, icon }: { label: string; value: number; tone: string; bar: string; to: string; hint?: string; icon?: ReactNode }) {
  return (
    <a
      href={to}
      className="group relative flex flex-col overflow-hidden rounded-lg border bg-card px-4 pt-4 pb-3 text-foreground no-underline transition-colors hover:border-foreground/25 hover:no-underline"
    >
      <span className={cn("absolute inset-x-0 top-0 h-[3px]", value ? bar : "bg-border")} />
      <span className="flex items-center justify-between">
        <span className={cn("text-3xl leading-none font-semibold tabular-nums", value ? tone : "text-muted-foreground")}>{value}</span>
        <span className={cn(value ? tone : "text-muted-foreground", "opacity-70")}>{icon}</span>
      </span>
      <span className="mt-2 font-medium">{label}</span>
      {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
    </a>
  );
}

function Legend({ cls, children }: { cls: string; children: ReactNode }) {
  return (
    <li className="inline-flex items-center gap-1.5">
      <i className={cn("inline-block size-2 rounded-sm", cls)} />
      {children}
    </li>
  );
}

function FeedCard({ feed }: { feed: FeedState }) {
  const ageH = feed.indexGeneratedAt ? (Date.now() - new Date(feed.indexGeneratedAt).getTime()) / 3.6e6 : Infinity;
  const stale = ageH > 48;
  return (
    <Section title="CVE feed" icon={<Database className="size-3.5" />} className={cn((stale || feed.lastError) && "border-sev-high")}>
      <dl className="grid grid-cols-[90px_1fr] gap-x-3 gap-y-1 text-[13px]">
        <dt className="text-muted-foreground">Generated</dt>
        <dd>{feed.indexGeneratedAt ? timeAgo(feed.indexGeneratedAt) : "not loaded yet"}</dd>
        <dt className="text-muted-foreground">Last check</dt>
        <dd className="inline-flex items-center gap-1.5">
          <Activity className="size-3.5 text-muted-foreground" />
          {timeAgo(feed.lastAttempt)}
        </dd>
        <dt className="text-muted-foreground">Contents</dt>
        <dd>
          {feed.products} products · {feed.vulns.toLocaleString()} vulnerabilities
        </dd>
        <dt className="text-muted-foreground">Source</dt>
        <dd className="font-mono text-xs break-all">{feed.url}</dd>
      </dl>
      {stale && (
        <div className="mt-3">
          <Callout>The feed is older than 48 hours; new CVEs may be missing.</Callout>
        </div>
      )}
      {feed.lastError && (
        <div className="mt-3">
          <Callout>Last refresh failed: {feed.lastError}</Callout>
        </div>
      )}
    </Section>
  );
}
