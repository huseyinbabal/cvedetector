---
title: Images and workloads
description: Every running image and workload, with its open CVEs.
---

![Images page](/cvedetector/screenshots/images.png)

## Images

One row per distinct image reference (`docker.io/library/httpd:2.4.57`) per cluster:

- the product and version read from the tag
- the [match status](/cvedetector/reference/matching/)
- the highest severity and open CVEs by severity
- the number of pods running it

Filter by text, minimum severity, match status and namespace. Sorting, paging and filters are kept in the URL, so links can be shared. **Export CSV** exports every row that matches the filters, not just the visible page.

### Image detail

![Image detail page](/cvedetector/screenshots/image-detail.png)

- **Vulnerabilities:** each open CVE with its CVSS, EPSS, the version that fixes it and when it first appeared on this image.
- **Resolved:** CVEs that used to affect this image, and when they were resolved (the image was upgraded, or the feed changed).
- **Used by:** workloads running the image.
- **Running digests:** if pods of the same tag run different digests, some pulled the tag at a different time.

## Workloads

![Workloads page](/cvedetector/screenshots/workloads.png)

Pods grouped by their owner: Deployment, StatefulSet, DaemonSet, CronJob, Job, or `StaticPod` for pods owned by a node. Init and ephemeral containers count. Pods that finished (`Succeeded`, `Failed`) don't.

The workload page lists its images and the CVEs of each.
