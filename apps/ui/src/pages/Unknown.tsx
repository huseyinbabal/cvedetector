import { CircleHelp, CirclePlus, Copy, ExternalLink, Tag } from "lucide-react";
import { type Image, type Page, query, useApi } from "@/api";
import { StatusBadge } from "@/components/app/badges";
import { EmptyState, ErrorState, PageHeader, PageSkeleton, Section } from "@/components/app/page";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { copyText } from "@/lib/format";
import { imageHref } from "@/router";

const REPO_URL = "https://github.com/huseyinbabal/cvedetector";

/** Images the feed cannot judge: unknown repositories and tags without a version. */
export function Unknown({ cluster }: { cluster: string }) {
  const unknown = useApi<Page<Image>>(`images${query({ cluster, status: "unknown", limit: 500, sort: "ref", order: "asc" })}`);
  const noVersion = useApi<Page<Image>>(`images${query({ cluster, status: "no-version", limit: 500, sort: "ref", order: "asc" })}`);
  const error = unknown.error ?? noVersion.error;
  if ((unknown.loading && !unknown.data) || (noVersion.loading && !noVersion.data)) return <PageSkeleton />;
  if (error && !unknown.data) return <ErrorState error={error} />;

  // Group by repository: that's what products.yaml maps.
  const repos = new Map<string, Image[]>();
  for (const i of unknown.data?.items ?? []) repos.set(i.repository, [...(repos.get(i.repository) ?? []), i]);
  const unversioned = noVersion.data?.items ?? [];
  const truncated = (unknown.data?.total ?? 0) > (unknown.data?.items.length ?? 0);

  return (
    <>
      <PageHeader
        title="Coverage gaps"
        sub="Images whose vulnerabilities can't be determined from the feed. Nothing is scanned, so these need a product mapping or a versioned tag."
      />
      <div className="grid gap-4">
        <Section title={`Repositories not in the feed (${repos.size})`} icon={<CircleHelp className="size-3.5" />}>
          {repos.size ? (
            <>
              <p className="mb-3 text-[13px] text-muted-foreground">
                Add a product to <code>feed/products.yaml</code> to start tracking a repository. Your own application images usually land here
                and can't be tracked this way.
                {truncated && " Showing the first 500 images."}
              </p>
              <div className="-mx-4 -mb-4 border-t">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="pl-4 text-xs text-muted-foreground">Repository</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Tags running</TableHead>
                      <TableHead className="text-right text-xs text-muted-foreground">Pods</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[...repos.entries()].map(([repo, imgs]) => (
                      <TableRow key={repo}>
                        <TableCell className="pl-4 font-mono text-[13px] break-all whitespace-normal">{repo}</TableCell>
                        <TableCell className="font-mono text-xs whitespace-normal">{[...new Set(imgs.map((i) => i.tag ?? "(digest)"))].join(", ")}</TableCell>
                        <TableCell className="text-right tabular-nums">{imgs.reduce((n, i) => n + i.pods, 0)}</TableCell>
                        <TableCell className="pr-4 text-right">
                          <Suggest repo={repo} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </>
          ) : (
            <EmptyState>Every running repository is mapped to a product.</EmptyState>
          )}
        </Section>

        <Section title={`Known product, no version in tag (${noVersion.data?.total ?? 0})`} icon={<Tag className="size-3.5" />}>
          {unversioned.length ? (
            <>
              <p className="mb-3 text-[13px] text-muted-foreground">
                Pin these to a versioned tag (for example <code>nginx:1.27.3</code> instead of <code>nginx:latest</code>) so they can be matched.
              </p>
              <ul className="grid gap-1.5">
                {unversioned.map((i) => (
                  <li key={i.cluster + i.ref} className="flex flex-wrap items-center gap-2">
                    <a className="font-mono text-[13px] break-all" href={imageHref(i.cluster, i.ref)}>
                      {i.ref}
                    </a>
                    <StatusBadge status={i.status} />
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <EmptyState>None.</EmptyState>
          )}
        </Section>
      </div>
    </>
  );
}

function Suggest({ repo }: { repo: string }) {
  const id = repo.split("/").pop()!.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const snippet = `  - id: ${id}\n    name: ${id}\n    images: [${repo}]\n    nvd:\n      cpes: [cpe:2.3:a:<vendor>:<product>]\n`;
  const issue = `${REPO_URL}/issues/new?${new URLSearchParams({
    title: `Track ${repo} in the feed`,
    body: `Please add this repository to feed/products.yaml:\n\n\`\`\`yaml\n${snippet}\`\`\``,
  })}`;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="xs">
          <CirclePlus /> Add to feed
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80">
        <p className="mb-2 text-xs text-muted-foreground">
          Entry for <code>feed/products.yaml</code>. Fill in the CPE or an OSV package.
        </p>
        <pre className="mb-3 overflow-x-auto rounded-md bg-muted p-2.5 font-mono text-xs leading-relaxed">{snippet}</pre>
        <div className="flex gap-2">
          <Button size="xs" variant="secondary" onClick={() => void copyText(snippet, "Snippet copied")}>
            <Copy /> Copy
          </Button>
          <Button size="xs" variant="secondary" asChild>
            <a href={issue} target="_blank" rel="noreferrer noopener" className="no-underline hover:no-underline">
              <ExternalLink /> Open issue
            </a>
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
