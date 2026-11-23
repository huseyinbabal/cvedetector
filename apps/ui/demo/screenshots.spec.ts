import { test } from "@playwright/test";

/** Docs screenshots: docs/public/screenshots/<name>.png. */
const out = process.env.CVEDETECTOR_SHOTS ?? "../../docs/public/screenshots";
const shots: [name: string, hash: string, ready: string][] = [
  ["overview", "#/", "Most affected workloads"],
  ["images", "#/images", "Distinct image references"],
  ["image-detail", "#/image?in=kind-demo&ref=docker.io%2Flibrary%2Fhttpd%3A2.4.57", "Running digests"],
  ["vulnerabilities", "#/cves", "CVE-"],
  ["cve-detail", "#/cves?cve=CVE-2024-38475", "References"],
  ["workloads", "#/workloads", "Workloads"],
  ["coverage-gaps", "#/unknown", "Coverage gaps"],
  ["clusters", "#/clusters", "kind-demo"],
];

for (const [name, hash, ready] of shots) {
  test(name, async ({ page }) => {
    await page.goto(`/${hash}`);
    await page.getByText(ready).first().waitFor();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${out}/${name}.png` });
  });
}
