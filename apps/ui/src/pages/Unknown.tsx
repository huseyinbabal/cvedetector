import { CircleHelp, CirclePlus, Copy, ExternalLink, GitPullRequest, Tag } from "lucide-react";
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

  // Group by repository: that's what product files map.
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
                Add a product file under <code>feed/products/</code> with a pull request to start tracking a repository. Your own application images usually land here
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
                          <Suggest repo={repo} tags={[...new Set(imgs.map((i) => i.tag ?? "(digest)"))]} />
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

/** Proposes a product file. "Open pull request" opens GitHub's new-file page
 * pre-filled; for people without write access GitHub forks and opens a PR. */
function Suggest({ repo, tags }: { repo: string; tags: string[] }) {
  const id = repo.split("/").pop()!.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const sample = tags.filter((t) => t !== "(digest)").slice(0, 3);
  const testTags = (sample.length ? sample : ["<a tag you run>"]).map((t) => `  "${t}": "<version in this tag>"`).join("\n");
  const snippet = `# ${repo}
id: ${id}
name: "${id}"
images:
  - ${repo}
nvd:
  cpes:
    - cpe:2.3:a:<vendor>:<product>   # https://nvd.nist.gov/products/cpe/search
testTags:
${testTags}
`;
  const newFile = `${REPO_URL}/new/main?${new URLSearchParams({ filename: `feed/products/${id}.yaml`, value: snippet })}`;
  const issue = `${REPO_URL}/issues/new?${new URLSearchParams({ template: "product.yml", title: `Track ${repo} in the feed` })}`;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="xs">
          <CirclePlus /> Add to feed
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96">
        <p className="mb-2 text-xs text-muted-foreground">
          New file <code>feed/products/{id}.yaml</code>. Fill in the CPE (or an OSV package) and the versions, then open a pull request. A
          check queries the source and reports what would match.
        </p>
        <pre className="mb-3 max-h-56 overflow-auto rounded-md bg-muted p-2.5 font-mono text-xs leading-relaxed">{snippet}</pre>
        <div className="flex flex-wrap gap-2">
          <Button size="xs" asChild>
            <a href={newFile} target="_blank" rel="noreferrer noopener" className="text-primary-foreground no-underline hover:no-underline">
              <GitPullRequest /> Open pull request
            </a>
          </Button>
          <Button size="xs" variant="secondary" onClick={() => void copyText(snippet, "Product file copied")}>
            <Copy /> Copy
          </Button>
          <Button size="xs" variant="ghost" asChild>
            <a href={issue} target="_blank" rel="noreferrer noopener" className="no-underline hover:no-underline">
              <ExternalLink /> Request instead
            </a>
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
