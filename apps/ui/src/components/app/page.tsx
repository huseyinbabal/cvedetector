import { CircleAlert, Inbox } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export function PageHeader({ title, sub, actions, crumb }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; crumb?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        {crumb && <nav className="mb-1 text-[13px] text-muted-foreground">{crumb}</nav>}
        <h1 className="text-[22px] leading-tight font-semibold tracking-tight break-all">{title}</h1>
        {sub && <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-muted-foreground">{sub}</div>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}

export function PageSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading">
      <Skeleton className="mb-2 h-7 w-56" />
      <Skeleton className="mb-6 h-4 w-80" />
      <Skeleton className="mb-3 h-8 w-full max-w-xl" />
      <Skeleton className="h-72 w-full" />
    </div>
  );
}

export function ErrorState({ error }: { error: Error }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-lg border border-destructive/40 bg-card p-4 text-sm">
      <CircleAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
      <div>
        <p className="font-medium">Could not load data</p>
        <p className="text-muted-foreground">{error.message}</p>
      </div>
    </div>
  );
}

export function EmptyState({ children, icon }: { children: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center text-muted-foreground">
      {icon ?? <Inbox className="size-6 opacity-60" />}
      <div>{children}</div>
    </div>
  );
}

/** Card with an uppercase section title, used across detail pages. */
export function Section({ title, icon, children, className, action }: { title: ReactNode; icon?: ReactNode; children: ReactNode; className?: string; action?: ReactNode }) {
  return (
    <Card className={cn("gap-3 py-4 shadow-none", className)}>
      <CardHeader className="flex flex-row items-center justify-between px-4">
        <CardTitle className="flex items-center gap-2 text-xs font-semibold tracking-wider text-muted-foreground uppercase">
          {icon}
          {title}
        </CardTitle>
        {action}
      </CardHeader>
      <CardContent className="px-4">{children}</CardContent>
    </Card>
  );
}

export function Callout({ tone = "warn", children, icon }: { tone?: "warn" | "info"; children: ReactNode; icon?: ReactNode }) {
  return (
    <div
      className={cn(
        "mb-4 flex items-start gap-2.5 rounded-md border-l-[3px] px-3 py-2.5 text-sm",
        tone === "warn" ? "border-sev-high bg-sev-high-bg" : "border-sev-low bg-sev-low-bg",
      )}
    >
      {icon}
      <div className="text-foreground">{children}</div>
    </div>
  );
}
