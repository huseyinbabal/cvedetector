import { type Page, test } from "@playwright/test";

/**
 * A guided tour for the docs. Run against an install with workloads
 * (`make demo-cluster`), then `make demo` turns the video into docs/public/demo.gif.
 */
const pause = (page: Page, ms: number) => page.waitForTimeout(ms);

test.use({ video: { mode: "on", size: { width: 1280, height: 800 } } });

test("demo", async ({ page }) => {
  await page.goto("/#/");
  await page.getByText("Most affected workloads").waitFor();
  await pause(page, 3000);

  await page.getByRole("navigation").getByRole("link", { name: "Images" }).click();
  await page.getByText("docker.io/library/httpd:2.4.57").waitFor();
  await pause(page, 1800);
  await page.getByText("docker.io/library/httpd:2.4.57").click();
  await page.getByText("Running digests").waitFor();
  await pause(page, 2000);
  await page.getByRole("link", { name: "CVE-2024-38475" }).first().click();
  await page.getByText("Known Exploited Vulnerabilities").waitFor();
  await pause(page, 3500);
  await page.keyboard.press("Escape");
  await pause(page, 600);

  await page.getByRole("navigation").getByRole("link", { name: /Vulnerabilities/ }).click();
  await page.getByPlaceholder("Search CVE id or text").waitFor();
  await pause(page, 1500);
  await page.getByPlaceholder("Search CVE id or text").pressSequentially("redis", { delay: 80 });
  await pause(page, 2500);

  await page.getByRole("navigation").getByRole("link", { name: "Workloads" }).click();
  await page.getByText("argocd-server").first().waitFor();
  await pause(page, 2200);

  await page.getByRole("navigation").getByRole("link", { name: "Coverage gaps" }).click();
  await page.getByText("Repositories not in the feed", { exact: false }).waitFor();
  await pause(page, 1500);
  for (const r of ["docker.io/hashicorp/http-echo", "docker.io/mccutchen/go-httpbin"]) {
    await page.getByRole("row").filter({ hasText: r }).getByRole("checkbox").click();
    await pause(page, 500);
  }
  await page.getByRole("button", { name: /Actions/ }).click();
  await pause(page, 700);
  await page.getByRole("menuitem", { name: /Add to feed/ }).click();
  await pause(page, 3500);
  await page.keyboard.press("Escape");
  await pause(page, 600);

  await page.keyboard.press("ControlOrMeta+k");
  await pause(page, 500);
  await page.keyboard.type("grafana", { delay: 90 });
  await pause(page, 1500);
  await page.keyboard.press("Enter");
  await pause(page, 3000);
});
