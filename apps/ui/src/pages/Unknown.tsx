import { useMemo, useState } from "react";
import { ChevronDown, CircleHelp, CirclePlus, Copy, Download, ExternalLink, GitPullRequest, Tag, Upload } from "lucide-react";
import { type Image, type Page, query, useApi } from "@/api";
import { StatusBadge } from "@/components/app/badges";
import { EmptyState, ErrorState, PageHeader, PageSkeleton, Section } from "@/components/app/page";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { type Proposal, REPO_URL, UPLOAD_URL, download, editURL, issueURL, proposals, script, zip } from "@/lib/catalog";
import { copyText } from "@/lib/format";
import { imageHref } from "@/router";

interface Product {
  id: string;
}

/** Images the feed cannot judge: unknown repositories and tags without a version. */
export function Unknown({ cluster }: { cluster: string }) {
  const unknown = useApi<Page<Image>>(`images${query({ cluster, status: "unknown", limit: 500, sort: "ref", order: "asc" })}`);
  const noVersion = useApi<Page<Image>>(`images${query({ cluster, status: "no-version", limit: 500, sort: "ref", order: "asc" })}`);
  const products = useApi<Product[]>("products");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);

  // Group by repository: that's what product files map.
  const repos = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const i of unknown.data?.items ?? []) {
      const tags = m.get(i.repository) ?? [];
      const t = i.tag ?? "(digest)";
      if (!tags.includes(t)) tags.push(t);
      m.set(i.repository, tags);
    }
    return m;
  }, [unknown.data]);
  const pods = useMemo(() => {
    const m = new Map<string, number>();
    for (const i of unknown.data?.items ?? []) m.set(i.repository, (m.get(i.repository) ?? 0) + i.pods);
    return m;
  }, [unknown.data]);
  // One id per repository, unique and not already in the feed.
  const props = useMemo(
    () => new Map(proposals([...repos].map(([repo, tags]) => ({ repo, tags })), (products.data ?? []).map((p) => p.id)).map((p) => [p.repo, p])),
    [repos, products.data],
  );

  const error = unknown.error ?? noVersion.error;
  if ((unknown.loading && !unknown.data) || (noVersion.loading && !noVersion.data)) return <PageSkeleton />;
  if (error && !unknown.data) return <ErrorState error={error} />;

  const unversioned = noVersion.data?.items ?? [];
  const truncated = (unknown.data?.total ?? 0) > (unknown.data?.items.length ?? 0);
  // Selection only counts repositories still on the list (it survives reloads).
  const chosen = [...repos.keys()].filter((r) => selected.has(r));
  const all = repos.size > 0 && chosen.length === repos.size;
  const toggle = (repo: string, on: boolean) =>
    setSelected((s) => {
      const n = new Set(s);
      if (on) n.add(repo);
      else n.delete(repo);
      return n;
    });

  return (
    <>
      <PageHeader
        title="Coverage gaps"
        sub="Images whose vulnerabilities can't be determined from the feed. Nothing is scanned, so these need a product mapping or a versioned tag."
      />
      <div className="grid gap-4">
        <Section
          title={`Repositories not in the feed (${repos.size})`}
          icon={<CircleHelp className="size-3.5" />}
          action={
            repos.size > 0 && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="xs" disabled={!chosen.length}>
                    Actions{chosen.length ? ` (${chosen.length})` : ""} <ChevronDown />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => setBulkOpen(true)}>
                    <CirclePlus /> Add to feed
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => setSelected(new Set())}>Clear selection</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )
          }
        >
          {repos.size ? (
            <>
              <p className="mb-3 text-[13px] text-muted-foreground">
                Add a product file under <code>catalog/</code> on the <code>data</code> branch with a pull request to start tracking a repository. Select several to add
                them at once. Your own application images usually land here and can't be tracked this way.
                {truncated && " Showing the first 500 images."}
              </p>
              <div className="-mx-4 -mb-4 border-t">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="w-8 pl-4">
                        <Checkbox
                          aria-label="Select all repositories"
                          checked={all ? true : chosen.length ? "indeterminate" : false}
                          onCheckedChange={(v) => setSelected(v === true ? new Set(repos.keys()) : new Set())}
                        />
                      </TableHead>
                      <TableHead className="text-xs text-muted-foreground">Repository</TableHead>
                      <TableHead className="text-xs text-muted-foreground">Tags running</TableHead>
                      <TableHead className="text-right text-xs text-muted-foreground">Pods</TableHead>
                      <TableHead />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[...repos.entries()].map(([repo, tags]) => (
                      <TableRow key={repo} data-state={selected.has(repo) ? "selected" : undefined}>
                        <TableCell className="pl-4">
                          <Checkbox aria-label={`Select ${repo}`} checked={selected.has(repo)} onCheckedChange={(v) => toggle(repo, v === true)} />
                        </TableCell>
                        <TableCell className="font-mono text-[13px] break-all whitespace-normal">{repo}</TableCell>
                        <TableCell className="font-mono text-xs whitespace-normal">{tags.join(", ")}</TableCell>
                        <TableCell className="text-right tabular-nums">{pods.get(repo) ?? 0}</TableCell>
                        <TableCell className="pr-4 text-right">{props.get(repo) && <Suggest p={props.get(repo)!} />}</TableCell>
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
      <BulkAdd open={bulkOpen} onOpenChange={setBulkOpen} items={chosen.map((r) => props.get(r)!).filter(Boolean)} />
    </>
  );
}

/** Proposes one product file. "Open pull request" opens GitHub's new-file page
 * pre-filled; for people without write access GitHub forks and opens a PR. */
function Suggest({ p }: { p: Proposal }) {
  const newFile = `${REPO_URL}/new/data?${new URLSearchParams({ filename: p.file, value: p.yaml })}`;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="xs">
          <CirclePlus /> Add to feed
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96">
        <p className="mb-2 text-xs text-muted-foreground">
          New file <code>{p.file}</code> on the <code>data</code> branch. Fill in the CPE (or an OSV package) and check the versions read from the tags, then open
          a pull request. A check queries the source and reports what would match.
        </p>
        {p.existing && <ExistingHint p={p} />}
        <pre className="mb-3 max-h-56 overflow-auto rounded-md bg-muted p-2.5 font-mono text-xs leading-relaxed">{p.yaml}</pre>
        <div className="flex flex-wrap gap-2">
          <Button size="xs" asChild>
            <a href={newFile} target="_blank" rel="noreferrer noopener" className="text-primary-foreground no-underline hover:no-underline">
              <GitPullRequest /> Open pull request
            </a>
          </Button>
          <Button size="xs" variant="secondary" onClick={() => void copyText(p.yaml, "Product file copied")}>
            <Copy /> Copy
          </Button>
          <Button size="xs" variant="ghost" asChild>
            <a href={issueURL([p])} target="_blank" rel="noreferrer noopener" className="no-underline hover:no-underline">
              <ExternalLink /> Request instead
            </a>
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

/** Proposes several product files in one pull request. GitHub can't pre-fill
 * more than one file, so the files are downloaded (or written by a script). */
function BulkAdd({ open, onOpenChange, items }: { open: boolean; onOpenChange: (v: boolean) => void; items: Proposal[] }) {
  const n = items.length;
  const plural = n === 1 ? "repository" : "repositories";
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            Add {n} {plural} to the feed
          </DialogTitle>
          <DialogDescription>
            One product file each under <code>catalog/</code> on the <code>data</code> branch. Fill in the CPE (or an OSV package) in every file and check the
            versions read from the tags; the pull request check queries the sources and reports what would match.
          </DialogDescription>
        </DialogHeader>

        <ul className="max-h-48 overflow-auto rounded-md border text-[13px]">
          {items.map((p) => (
            <li key={p.repo} className="flex items-baseline justify-between gap-3 border-b px-3 py-1.5 last:border-b-0">
              <span className="font-mono break-all">{p.repo}</span>
              <span className="shrink-0 text-right text-xs text-muted-foreground">
                <code>{p.id}.yaml</code>
                {p.existing && (
                  <a className="block" href={editURL(p.existing)} target="_blank" rel="noreferrer noopener" title={`A product named ${p.existing} exists: if this is the same software, add the image to it instead`}>
                    or add to {p.existing}
                  </a>
                )}
              </span>
            </li>
          ))}
        </ul>

        <div className="grid gap-4 text-sm">
          <div className="grid gap-2">
            <div className="font-medium">In the browser</div>
            <ol className="ml-4 list-decimal text-[13px] text-muted-foreground">
              <li>Download the files and fill them in.</li>
              <li>
                Drop them on GitHub's upload page and choose <em>Create a new branch and start a pull request</em>.
              </li>
            </ol>
            <div className="flex flex-wrap gap-2">
              <Button size="xs" onClick={() => download(`catalog-${n}-products.zip`, zip(items.map((p) => ({ name: `${p.id}.yaml`, text: p.yaml }))))}>
                <Download /> Download {n} files (.zip)
              </Button>
              <Button size="xs" variant="secondary" asChild>
                <a href={UPLOAD_URL} target="_blank" rel="noreferrer noopener" className="no-underline hover:no-underline">
                  <Upload /> Open upload page
                </a>
              </Button>
            </div>
          </div>

          <div className="grid gap-2">
            <div className="font-medium">With git</div>
            <p className="text-[13px] text-muted-foreground">A script that writes the files on a new branch of a data-branch checkout.</p>
            <div>
              <Button size="xs" variant="secondary" onClick={() => void copyText(script(items), "Script copied")}>
                <Copy /> Copy script
              </Button>
            </div>
          </div>

          <div className="grid gap-2">
            <div className="font-medium">Don't know the CPEs?</div>
            <div>
              <Button size="xs" variant="ghost" asChild>
                <a href={issueURL(items)} target="_blank" rel="noreferrer noopener" className="no-underline hover:no-underline">
                  <ExternalLink /> Request all in one issue
                </a>
              </Button>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** The repository is named like a product already in the feed. */
function ExistingHint({ p }: { p: Proposal }) {
  return (
    <p className="mb-2 rounded-md border-l-[3px] border-sev-low bg-sev-low-bg px-2.5 py-1.5 text-xs">
      The feed already has a product named <code>{p.existing}</code>. If this image is the same software, add <code>{p.repo}</code> to its <code>images</code>{" "}
      instead:{" "}
      <a href={editURL(p.existing!)} target="_blank" rel="noreferrer noopener">
        edit {p.existing}.yaml
      </a>
      .
    </p>
  );
}
