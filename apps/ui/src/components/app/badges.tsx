import { CircleCheck, CircleDashed, CircleHelp, Flame, Tag } from "lucide-react";
import type { ComponentType, ReactNode } from "react";
import type { Counts, ImageStatus, Severity } from "@/api";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

const sevClass: Record<Severity, string> = {
  CRITICAL: "bg-sev-critical-bg text-sev-critical",
  HIGH: "bg-sev-high-bg text-sev-high",
  MEDIUM: "bg-sev-medium-bg text-sev-medium",
  LOW: "bg-sev-low-bg text-sev-low",
  UNKNOWN: "bg-sev-unknown-bg text-sev-unknown",
  NONE: "bg-sev-unknown-bg text-sev-unknown",
};

export const severityRank: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0, NONE: -1 };

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const label = severity === "NONE" ? "None" : severity[0] + severity.slice(1).toLowerCase();
  return (
    <span className={cn("inline-flex items-center rounded px-1.5 py-px text-xs font-semibold whitespace-nowrap", sevClass[severity], className)}>
      {label}
    </span>
  );
}

/** Compact C/H/M/L counts; zero counts are dimmed so the eye lands on the real ones. */
export function CountChips({ counts }: { counts: Counts }) {
  const items: [keyof Counts, string, string, string][] = [
    ["critical", "C", "Critical", sevClass.CRITICAL],
    ["high", "H", "High", sevClass.HIGH],
    ["medium", "M", "Medium", sevClass.MEDIUM],
    ["low", "L", "Low", sevClass.LOW],
  ];
  return (
    <span className="inline-flex gap-1">
      {items.map(([k, short, long, cls]) => (
        <span
          key={k}
          title={`${counts[k]} ${long}`}
          className={cn(
            "inline-flex min-w-9 gap-0.5 rounded px-1.5 py-px text-xs tabular-nums",
            counts[k] ? cls : "text-muted-foreground opacity-50",
          )}
        >
          <b className="font-semibold opacity-75">{short}</b>
          {counts[k]}
        </span>
      ))}
    </span>
  );
}

/** Sort key for counts: critical first, then high, medium, low. */
export const countsKey = (c: Counts) => c.critical * 1e9 + c.high * 1e6 + c.medium * 1e3 + c.low;

const statusInfo: Record<ImageStatus, { label: string; help: string; icon: ComponentType<{ className?: string }>; cls: string }> = {
  matched: { label: "Matched", help: "Product and full version read from the tag", icon: CircleCheck, cls: "text-ok" },
  approximate: {
    label: "Approximate",
    help: "Floating tag (e.g. 1.27): compared as the lowest patch version, so results may include already fixed CVEs",
    icon: CircleDashed,
    cls: "text-sev-medium",
  },
  "no-version": {
    label: "No version",
    help: "Product is known but the tag has no version (e.g. latest or digest only)",
    icon: Tag,
    cls: "text-sev-low",
  },
  unknown: { label: "Not in feed", help: "Repository is not mapped to any product in the feed", icon: CircleHelp, cls: "text-muted-foreground" },
};

export const statusDescription = (s: ImageStatus | "") => (s ? statusInfo[s]?.help : "") ?? "";

export function StatusBadge({ status }: { status: ImageStatus }) {
  const info = statusInfo[status];
  if (!info) return <span>{status}</span>;
  const Icon = info.icon;
  return (
    <Hint text={info.help}>
      <span className={cn("inline-flex items-center gap-1 text-xs font-medium whitespace-nowrap", info.cls)}>
        <Icon className="size-3.5" />
        {info.label}
      </span>
    </Hint>
  );
}

export function KEVBadge() {
  return (
    <Hint text="Listed in CISA Known Exploited Vulnerabilities: exploited in the wild">
      <span className="inline-flex items-center gap-0.5 rounded bg-kev px-1.5 py-px text-[11px] font-bold tracking-wide text-kev-foreground">
        <Flame className="size-3" />
        KEV
      </span>
    </Hint>
  );
}

export function Hint({ text, children }: { text: string; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex outline-none">
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-72">{text}</TooltipContent>
    </Tooltip>
  );
}
