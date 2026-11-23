---
title: Kubernetes
description: Install, expose, upgrade and remove cvedetector with the Helm chart.
---

The chart lives in [huseyinbabal/charts](https://github.com/huseyinbabal/charts/tree/main/stable/cvedetector). Its `appVersion` is the tag of the `ghcr.io/huseyinbabal/cvedetector-{agent,api,ui}` images.

## What gets installed

| Component | Kind | Notes |
|---|---|---|
| agent | Deployment, 1 replica | ClusterRole with `get/list/watch` on pods, ReplicaSets and Jobs only. No internet access needed. |
| api | Deployment | Stateless. Feed sync and migrations coordinate through PostgreSQL locks, so `api.replicas` can be raised. |
| ui | Deployment | nginx serving the static app. Passes only `GET`/`HEAD` on `/api` to the API. |
| postgresql | StatefulSet | Optional. `postgres:18.6-alpine` with an 8Gi PVC. The password is generated once and kept across upgrades. |

The agent's token for the API is generated and kept in the `cvedetector-ingest` Secret.

## Install

```sh
helm repo add huseyinbabal https://huseyinbabal.github.io/charts
helm install cvedetector huseyinbabal/cvedetector -n cvedetector --create-namespace \
  --set agent.clusterName=prod-eu-1
```

`agent.clusterName` is the name shown in the UI. Use lowercase letters, digits and `-`.

## Use your own PostgreSQL

```sh
kubectl -n cvedetector create secret generic cvedetector-db --from-literal=password=<password>
helm install cvedetector huseyinbabal/cvedetector -n cvedetector --create-namespace \
  --set postgresql.enabled=false \
  --set externalDatabase.host=pg.example.com \
  --set externalDatabase.existingSecret=cvedetector-db
```

`externalDatabase.sslmode` defaults to `require`. The API creates its tables at startup. If the database isn't reachable yet, it retries for 3 minutes.

## Expose it

```sh
--set ingress.enabled=true --set ingress.host=cvedetector.example.com --set ingress.className=nginx
```

The ingress routes `/` to the UI and `/api` to the API. Agents in [other clusters](/cvedetector/features/multiple-clusters/) send their reports through it.

:::caution
The UI has no login. Anyone who can reach it can see what runs in your clusters and which CVEs affect it. Put it behind your SSO proxy or keep it internal.
:::

## Upgrade

```sh
helm repo update
helm upgrade cvedetector huseyinbabal/cvedetector -n cvedetector --reuse-values
```

The database and the generated tokens are kept.

## Uninstall

```sh
helm uninstall cvedetector -n cvedetector
kubectl -n cvedetector delete pvc -l app.kubernetes.io/instance=cvedetector   # history too
```
