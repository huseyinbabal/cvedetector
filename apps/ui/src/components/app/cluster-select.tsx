import { Server } from "lucide-react";
import { type Cluster, useApi } from "@/api";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { timeAgo } from "@/lib/format";
import { setParams } from "@/router";

const ALL = "__all__";

/** Global cluster filter, stored in the URL as ?cluster=. */
export function ClusterSelect({ value }: { value: string }) {
  const { data } = useApi<Cluster[]>("clusters");
  if (!data || (data.length <= 1 && !value)) return null;
  return (
    <Select
      value={value || ALL}
      onValueChange={(v) => setParams({ cluster: v === ALL ? undefined : v, page: undefined, namespace: undefined })}
    >
      <SelectTrigger size="sm" className="min-w-44 bg-card" aria-label="Cluster">
        <Server className="text-muted-foreground" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>All clusters ({data.length})</SelectItem>
        {data.map((c) => (
          <SelectItem key={c.name} value={c.name}>
            {c.name}
            <span className="text-xs text-muted-foreground">{timeAgo(c.lastReport)}</span>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** True when a cluster column is useful: several clusters and none selected. */
export function useShowCluster(selected: string) {
  const { data } = useApi<Cluster[]>("clusters");
  return !selected && (data?.length ?? 0) > 1;
}
