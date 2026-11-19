// Types mirror apps/api/internal/store JSON.
import { useCallback, useEffect, useRef, useState } from "react";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | "NONE";
export type ImageStatus = "matched" | "approximate" | "no-version" | "unknown";

export interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  total: number;
  kev: number;
  fixable: number;
}

export interface Page<T> {
  items: T[];
  total: number;
}

export interface WorkloadRef {
  cluster: string;
  namespace: string;
  kind: string;
  name: string;
}

export interface Image {
  cluster: string;
  ref: string;
  repository: string;
  tag?: string;
  digests?: string[];
  product?: string;
  productName?: string;
  version?: string;
  status: ImageStatus;
  pods: number;
  workloads: number;
  counts: Counts;
  maxSeverity: Severity;
}

export interface Workload extends WorkloadRef {
  pods: number;
  images: string[];
  counts: Counts;
  maxSeverity: Severity;
}

export interface Vuln {
  id: string;
  product: string;
  aliases?: string[];
  summary?: string;
  severity: Severity;
  cvss?: number;
  cvssVector?: string;
  epss?: number;
  kev?: boolean;
  published?: string;
  references?: string[];
  fixable: boolean;
  firstSeen?: string;
  images: number;
  workloads: number;
  clusters: number;
}

export interface FeedState {
  url: string;
  indexGeneratedAt?: string;
  lastAttempt?: string;
  lastSuccess?: string;
  lastError?: string;
  revision: number;
  products: number;
  vulns: number;
}

export interface Cluster {
  name: string;
  agentVersion: string;
  firstSeen: string;
  lastReport: string;
  images: number;
  workloads: number;
  counts: Counts;
}

export interface Summary {
  clusters: number;
  vulns: Counts;
  images: number;
  imagesByStatus: Partial<Record<ImageStatus, number>>;
  workloads: number;
  vulnerableWorkloads: number;
  namespaces: number;
  topWorkloads: Workload[] | null;
  vulnsByProduct: Record<string, number>;
  lastReport?: string;
}

export type ImageFinding = Vuln & { fixedIn?: string; resolvedAt?: string };

export interface ImageDetail {
  image: Image;
  vulns: ImageFinding[];
  resolved: ImageFinding[];
  workloads: WorkloadRef[];
}

export interface WorkloadDetail {
  workload: Workload;
  images: Image[];
}

export interface AffectedImage {
  cluster: string;
  ref: string;
  version: string;
  status: ImageStatus | "";
  fixedIn?: string;
  firstSeen: string;
  resolvedAt?: string;
}

export interface CVEDetail {
  vuln: Vuln;
  images: AffectedImage[];
  resolved: AffectedImage[];
  workloads: WorkloadRef[];
}

export interface HistoryPoint {
  day: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface History {
  days: number;
  points: HistoryPoint[];
  opened: number;
  resolved: number;
  meanDaysToFix?: number;
  trackingSince?: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

// ETag cache: polling a list that didn't change costs a 304, not a re-render.
const etags = new Map<string, { etag: string; body: unknown }>();

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const url = `api/v1/${path}`;
  const cached = etags.get(url);
  const res = await fetch(url, {
    signal,
    headers: { Accept: "application/json", ...(cached ? { "If-None-Match": cached.etag } : {}) },
  });
  if (res.status === 304 && cached) return cached.body as T;
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, msg);
  }
  const body = (await res.json()) as T;
  const etag = res.headers.get("ETag");
  if (etag) etags.set(url, { etag, body });
  return body;
}

export function query(params: Record<string, string | number | boolean | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "" || v === false) continue;
    q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

const REFRESH_MS = 30_000;

/** Fetches path and refetches it every 30s while the tab is visible. */
export function useApi<T>(path: string | null) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<ApiError | Error | undefined>();
  const [loading, setLoading] = useState(true);
  const pathRef = useRef(path);
  pathRef.current = path;

  const load = useCallback(
    async (signal?: AbortSignal) => {
      if (!path) return;
      try {
        const d = await getJSON<T>(path, signal);
        if (pathRef.current === path) {
          setData(d);
          setError(undefined);
          setLoading(false);
        }
      } catch (e) {
        // An aborted request (path changed, unmount, StrictMode re-run) must not
        // end the loading state: callers would render "empty" for a moment.
        if ((e as Error).name === "AbortError") return;
        if (pathRef.current === path) {
          setError(e as Error);
          setLoading(false);
        }
      }
    },
    [path],
  );

  useEffect(() => {
    setLoading(true);
    const ctrl = new AbortController();
    void load(ctrl.signal);
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void load();
    }, REFRESH_MS);
    return () => {
      ctrl.abort();
      clearInterval(t);
    };
  }, [load]);

  return { data, error, loading };
}
