// Product-file proposals for the catalog (catalog/<id>.yaml on the data branch).

export const REPO_URL = "https://github.com/huseyinbabal/cvedetector";
/** GitHub's upload page for the catalog folder: drop files, commit to a new branch, open a PR. */
export const UPLOAD_URL = `${REPO_URL}/upload/data/catalog`;

export interface Proposal {
  repo: string;
  tags: string[];
  id: string;
  file: string; // catalog/<id>.yaml
  yaml: string;
  /** A product already in the feed with this repository's name: often the
   * same software from another registry, better added to that file's images. */
  existing?: string;
}

/** Same as feed.DefaultVersionPattern (pkg/feed): what a tag yields without a versionPattern. */
const defaultVersion = /^v?(\d+(?:\.\d+){0,3})/;
export const tagVersion = (tag: string) => tag.match(defaultVersion)?.[1] ?? "";

export const editURL = (id: string) => `${REPO_URL}/edit/data/catalog/${id}.yaml`;

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "image";

/**
 * Proposals with ids that are unique among themselves and don't collide with
 * products already in the feed: GitHub's upload page overwrites a file with
 * the same name, which would replace an existing product.
 */
export function proposals(repos: { repo: string; tags: string[] }[], existingIds: Iterable<string>): Proposal[] {
  const taken = new Set(existingIds);
  const used = new Set(taken);
  return repos.map(({ repo, tags }) => {
    const parts = repo.split("/");
    const name = slug(parts[parts.length - 1]);
    const ns = parts.length > 2 && parts[parts.length - 2] !== "library" ? slug(parts[parts.length - 2]) : "";
    let id = name;
    const existing = taken.has(name) ? name : undefined;
    if (used.has(id) && ns) id = `${ns}-${name}`;
    for (let n = 2; used.has(id); n++) id = `${ns ? `${ns}-` : ""}${name}-${n}`;
    used.add(id);
    return { repo, tags, id, file: `catalog/${id}.yaml`, yaml: productYAML(repo, tags, id), existing };
  });
}

export function productYAML(repo: string, tags: string[], id: string): string {
  const sample = tags.filter((t) => t !== "(digest)").slice(0, 3);
  // Versions as the default rule reads them; if they're wrong, add a versionPattern.
  const testTags = sample.length
    ? sample.map((t) => `  "${t}": "${tagVersion(t)}"`).join("\n")
    : `  "<a tag you run>": "<version in this tag>"`;
  return `# ${repo}
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
}

/** Shell script that writes the files into a checkout of the data branch. */
export function script(ps: Proposal[]): string {
  const files = ps.map((p) => `cat > ${p.file} <<'EOF'\n${p.yaml}EOF`).join("\n\n");
  return `# Run in a checkout of the data branch, e.g.: git worktree add ../cvedetector-data data && cd ../cvedetector-data
set -e
git switch -c catalog/add-${ps.length}-products
mkdir -p catalog

${files}

# Fill in the CPEs (check the versions under testTags), then:
#   git add catalog && git commit -m "catalog: add ${ps.length} products" && git push -u origin HEAD
#   gh pr create --base data --fill
`;
}

/** Issue body listing the images, for people who don't know the CPEs. */
export function issueURL(ps: Proposal[]): string {
  const rows = ps.map((p) => `| \`${p.repo}\` | ${p.tags.filter((t) => t !== "(digest)").slice(0, 5).map((t) => `\`${t}\``).join(" ") || "(digest)"} |`);
  const head = `Please map these images to products in the feed.\n\n| Image | Tags running |\n|---|---|\n`;
  // GitHub rejects very long URLs: keep the body around 6 KB.
  let body = head;
  let i = 0;
  for (; i < rows.length && body.length + rows[i].length < 6000; i++) body += rows[i] + "\n";
  if (i < rows.length) body += `\n…and ${rows.length - i} more.\n`;
  const title = ps.length === 1 ? `Track ${ps[0].repo} in the feed` : `Track ${ps.length} images in the feed`;
  return `${REPO_URL}/issues/new?${new URLSearchParams({ title, body, labels: "feed" })}`;
}

// ---- zip (stored, no compression: a few KB of YAML)

const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(b: Uint8Array): number {
  let c = 0xffffffff;
  for (const x of b) c = crcTable[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A zip of the given files (name → text). */
export function zip(files: { name: string; text: string }[]): Blob {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const d = new Date();
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  for (const f of files) {
    const name = enc.encode(f.name);
    const data = enc.encode(f.text);
    const crc = crc32(data);
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, 0x0800, true); // UTF-8 names
    local.setUint16(10, time, true);
    local.setUint16(12, date, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, data.length, true);
    local.setUint32(22, data.length, true);
    local.setUint16(26, name.length, true);
    parts.push(new Uint8Array(local.buffer), name, data);

    const c = new DataView(new ArrayBuffer(46));
    c.setUint32(0, 0x02014b50, true);
    c.setUint16(4, 20, true);
    c.setUint16(6, 20, true);
    c.setUint16(8, 0x0800, true);
    c.setUint16(12, time, true);
    c.setUint16(14, date, true);
    c.setUint32(16, crc, true);
    c.setUint32(20, data.length, true);
    c.setUint32(24, data.length, true);
    c.setUint16(28, name.length, true);
    c.setUint32(42, offset, true);
    central.push(new Uint8Array(c.buffer), name);
    offset += 30 + name.length + data.length;
  }
  const size = central.reduce((n, b) => n + b.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, files.length, true);
  end.setUint16(10, files.length, true);
  end.setUint32(12, size, true);
  end.setUint32(16, offset, true);
  return new Blob([...parts, ...central, new Uint8Array(end.buffer)] as BlobPart[], { type: "application/zip" });
}

export function download(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
