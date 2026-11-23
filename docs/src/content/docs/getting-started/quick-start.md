---
title: Quick start
description: Install cvedetector with Helm and open the UI.
---

cvedetector runs in Kubernetes. One Helm release installs everything:

- the **agent**, which watches pods (read-only)
- the **API**, which matches images against the CVE feed
- the **UI**
- a bundled **PostgreSQL**

## Install

```sh
helm repo add huseyinbabal https://huseyinbabal.github.io/charts
helm install cvedetector huseyinbabal/cvedetector -n cvedetector --create-namespace
```

## Open the UI

```sh
kubectl -n cvedetector rollout status deploy/cvedetector-api
kubectl -n cvedetector port-forward svc/cvedetector-ui 8080:8080
```

Open http://localhost:8080. Within a minute:

1. The agent sends the first inventory of running images.
2. The API downloads the feed and matches the images.
3. The [Overview](/cvedetector/features/overview/) fills in.

![Overview page](/cvedetector/screenshots/overview.png)

## Try it on kind

To see it with realistic data on your laptop, run some well-known software with older tags first:

```sh
kind create cluster --name cvedetector-demo
kubectl create deployment nginx --image=nginx:1.25.3
kubectl create deployment httpd --image=httpd:2.4.57
kubectl create deployment redis --image=redis:7.2.3
kubectl create deployment grafana --image=grafana/grafana:10.2.2
```

Then install the chart as above. Images that cvedetector can't match, such as your own applications, appear under [Coverage gaps](/cvedetector/features/coverage-gaps/).

## Next steps

- [Kubernetes](/cvedetector/getting-started/kubernetes/): an external database, ingress, upgrades.
- [Multiple clusters](/cvedetector/features/multiple-clusters/): send more clusters to the same API.
- [How matching works](/cvedetector/reference/matching/): what is covered and what isn't.
