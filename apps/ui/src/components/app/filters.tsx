import { Search } from "lucide-react";
import { useEffect, useState } from "react";
import { useApi } from "@/api";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { currentCluster, setParam } from "@/router";

// Radix Select items can't have an empty value, so "all" stands for "no filter".
const ALL = "__all__";

/** Text input bound to a route query param, debounced so typing doesn't refetch per key. */
export function SearchParam({ name, value, placeholder }: { name: string; value: string; placeholder: string }) {
  const [v, setV] = useState(value);
  useEffect(() => setV(value), [value]);
  useEffect(() => {
    if (v === value) return;
    const t = setTimeout(() => setParam(name, v.trim() || undefined), 250);
    return () => clearTimeout(t);
  }, [v, value, name]);
  return (
    <div className="relative w-full sm:w-72">
      <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
      <Input type="search" value={v} placeholder={placeholder} aria-label={placeholder} onChange={(e) => setV(e.target.value)} className="h-8 bg-card pl-8" />
    </div>
  );
}

export function SelectParam({ name, value, options, label }: { name: string; value: string; options: [string, string][]; label: string }) {
  return (
    <Select value={value || ALL} onValueChange={(v) => setParam(name, v === ALL ? undefined : v)}>
      <SelectTrigger size="sm" className="min-w-40 bg-card" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map(([v, l]) => (
          <SelectItem key={v || ALL} value={v || ALL}>
            {l}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function ToggleParam({ name, value, label }: { name: string; value: boolean; label: string }) {
  const id = `toggle-${name}`;
  return (
    <label htmlFor={id} className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-md px-2 text-sm hover:bg-accent">
      <Checkbox id={id} checked={value} onCheckedChange={(c) => setParam(name, c === true ? "true" : undefined)} />
      {label}
    </label>
  );
}

export function NamespaceSelect({ value }: { value: string }) {
  const cluster = currentCluster();
  const { data } = useApi<string[]>(`namespaces${cluster ? `?cluster=${encodeURIComponent(cluster)}` : ""}`);
  const opts: [string, string][] = [["", "All namespaces"], ...(data ?? []).map((n): [string, string] => [n, n])];
  if (value && !data?.includes(value)) opts.push([value, value]);
  return <SelectParam name="namespace" value={value} options={opts} label="Namespace" />;
}

export const severityOptions: [string, string][] = [
  ["", "Any severity"],
  ["critical", "Critical"],
  ["high", "High and above"],
  ["medium", "Medium and above"],
  ["low", "Low and above"],
];

export function FilterBar({ children }: { children: React.ReactNode }) {
  return <div className="mb-4 flex flex-wrap items-center gap-2">{children}</div>;
}
