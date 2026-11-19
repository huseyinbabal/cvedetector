import { type KeyboardEvent, type PointerEvent, useId, useState } from "react";
import type { HistoryPoint } from "@/api";
import { cn } from "@/lib/utils";

// Severity colors can't be told apart as overlapping lines (red/orange/amber
// collapse under deutan CVD), so each severity gets its own small chart:
// identity comes from the title, color only accents. Each chart has its own
// y-scale; the crosshair is shared so one hover reads all four.
const SERIES = [
  { key: "critical", label: "Critical", stroke: "var(--sev-critical)" },
  { key: "high", label: "High", stroke: "var(--sev-high)" },
  { key: "medium", label: "Medium", stroke: "var(--sev-medium)" },
  { key: "low", label: "Low", stroke: "var(--sev-low)" },
] as const;

type Key = (typeof SERIES)[number]["key"];

const W = 240;
const H = 64;
const PAD = { t: 6, r: 6, b: 4, l: 6 };

const fmtDay = (d: string) => new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });

export function TrendGrid({ points }: { points: HistoryPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length < 2) return null;
  const idx = hover ?? points.length - 1;

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowLeft") setHover(Math.max(0, idx - 1));
    else if (e.key === "ArrowRight") setHover(Math.min(points.length - 1, idx + 1));
    else if (e.key === "Escape") setHover(null);
    else return;
    e.preventDefault();
  };

  return (
    <div>
      <div className="mb-2 flex items-baseline justify-between text-xs text-muted-foreground" aria-live="polite">
        <span>
          Open vulnerabilities, end of day · <b className="font-medium text-foreground">{fmtDay(points[idx].day)}</b>
          {hover === null && " (today)"}
        </span>
        <span className="hidden sm:inline">
          {fmtDay(points[0].day)} – {fmtDay(points[points.length - 1].day)}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4" onKeyDown={onKey}>
        {SERIES.map((s) => (
          <Spark key={s.key} series={s} points={points} idx={idx} hovering={hover !== null} onHover={setHover} />
        ))}
      </div>
      <details className="mt-2 text-xs text-muted-foreground">
        <summary className="cursor-pointer select-none hover:text-foreground">Show as table</summary>
        <div className="mt-2 max-h-56 overflow-auto rounded border">
          <table className="w-full text-right tabular-nums">
            <thead className="sticky top-0 bg-card">
              <tr>
                <th className="px-2 py-1 text-left font-medium">Day</th>
                {SERIES.map((s) => (
                  <th key={s.key} className="px-2 py-1 font-medium">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...points].reverse().map((p) => (
                <tr key={p.day} className="border-t">
                  <td className="px-2 py-1 text-left">{p.day}</td>
                  {SERIES.map((s) => (
                    <td key={s.key} className="px-2 py-1 text-foreground">
                      {p[s.key]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}

function Spark({
  series,
  points,
  idx,
  hovering,
  onHover,
}: {
  series: { key: Key; label: string; stroke: string };
  points: HistoryPoint[];
  idx: number;
  hovering: boolean;
  onHover: (i: number | null) => void;
}) {
  const gradId = useId();
  const values = points.map((p) => p[series.key]);
  const max = Math.max(1, ...values);
  const x = (i: number) => PAD.l + (i / (points.length - 1)) * (W - PAD.l - PAD.r);
  const y = (v: number) => PAD.t + (1 - v / max) * (H - PAD.t - PAD.b);
  const line = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  const area = `${line}L${x(values.length - 1)},${H - PAD.b}L${x(0)},${H - PAD.b}Z`;
  const now = values[idx];
  const delta = now - values[0];

  const onMove = (e: PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const rel = ((e.clientX - r.left) / r.width) * W;
    const i = Math.round(((rel - PAD.l) / (W - PAD.l - PAD.r)) * (points.length - 1));
    onHover(Math.min(points.length - 1, Math.max(0, i)));
  };

  return (
    <div className="rounded-md border bg-background/40 px-3 pt-2.5 pb-2">
      <div className="flex items-baseline justify-between">
        <span className="text-[13px] font-medium">{series.label}</span>
        <span className="text-[11px] text-muted-foreground tabular-nums" title={`Change since ${points[0].day}`}>
          {delta === 0 ? "±0" : delta > 0 ? `+${delta}` : delta}
        </span>
      </div>
      <div className="text-2xl leading-tight font-semibold tabular-nums">{now}</div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="mt-1 h-16 w-full touch-none overflow-visible outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
        preserveAspectRatio="none"
        role="img"
        tabIndex={0}
        aria-label={`${series.label}: ${now} open on ${points[idx].day}, ${delta >= 0 ? "up" : "down"} ${Math.abs(delta)} over ${points.length} days. Use arrow keys to move.`}
        onPointerMove={onMove}
        onPointerLeave={() => onHover(null)}
        onFocus={() => onHover(idx)}
      >
        <defs>
          <linearGradient id={gradId} x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor={series.stroke} stopOpacity="0.18" />
            <stop offset="1" stopColor={series.stroke} stopOpacity="0" />
          </linearGradient>
        </defs>
        <line x1={PAD.l} x2={W - PAD.r} y1={H - PAD.b} y2={H - PAD.b} stroke="var(--border)" strokeWidth="1" vectorEffect="non-scaling-stroke" />
        <path d={area} fill={`url(#${gradId})`} />
        <path d={line} fill="none" stroke={series.stroke} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        {hovering && (
          <line x1={x(idx)} x2={x(idx)} y1={PAD.t - 4} y2={H - PAD.b} stroke="var(--muted-foreground)" strokeOpacity="0.5" strokeWidth="1" vectorEffect="non-scaling-stroke" />
        )}
      </svg>
      {/* The marker sits outside the stretched SVG so it stays round. */}
      <div className="relative -mt-16 h-16 pointer-events-none" aria-hidden>
        <span
          className={cn("absolute size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-card")}
          style={{ left: `${(x(idx) / W) * 100}%`, top: `${(y(now) / H) * 100}%`, background: series.stroke }}
        />
      </div>
    </div>
  );
}
