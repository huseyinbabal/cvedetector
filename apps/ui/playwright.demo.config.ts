import { defineConfig } from "@playwright/test";

/** Records the docs demo and screenshots (see `make demo`). Not a test suite. */
export default defineConfig({
  testDir: "./demo",
  timeout: 180_000,
  workers: 1,
  reporter: [["list"]],
  outputDir: "demo/out",
  use: {
    baseURL: process.env.CVEDETECTOR_DEMO_URL ?? "http://127.0.0.1:28180",
    viewport: { width: 1280, height: 800 },
    colorScheme: "dark",
  },
});
