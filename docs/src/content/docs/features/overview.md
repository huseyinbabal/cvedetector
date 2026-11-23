---
title: Overview
description: Open vulnerabilities, trends and coverage at a glance.
---

![Overview page](/cvedetector/screenshots/overview.png)

The Overview page answers "how bad is it right now?" for the selected cluster, or for all clusters.

**Severity tiles.** Distinct open CVEs by severity. A CVE that affects three images counts once. Two more tiles:

- **Known exploited:** CVEs in the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog. Fix these first.
- **Fixable:** CVEs with a fixed version, so upgrading the image helps.

**Last 30 days.** Open CVEs at the end of each day, one small chart per severity, with a shared crosshair. The header shows how many findings were opened and resolved in the window, and the mean time to resolve. History starts with the first report, so a new install shows a note until the first full day.

**Most affected workloads.** The ten workloads with the worst open CVEs.

**Image coverage.** How many running images could be matched against the feed:

| Status | Meaning |
|---|---|
| Matched | Product and full version read from the tag |
| Approximate | Floating tag such as `1.27`: compared as `1.27.0`, so it may include CVEs already fixed in later patches |
| No version | Known product, but the tag has no version (`latest`, digest only) |
| Not in feed | The repository isn't mapped to a product. See [Coverage gaps](/cvedetector/features/coverage-gaps/). |

**Vulnerabilities by product.** Open CVEs per product, to see which upgrade removes the most.

**CVE feed.** When the feed was last built and synced. A failing refresh is shown here and in the sidebar.

## Search

Press <kbd>⌘K</kbd> / <kbd>Ctrl+K</kbd> anywhere to jump to a page, a CVE, an image or a workload.
