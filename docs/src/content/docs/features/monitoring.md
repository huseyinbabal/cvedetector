---
title: Monitoring and alerts
description: Prometheus metrics, alerting rules and a Grafana dashboard.
---

The API and the agent serve Prometheus metrics on `/metrics`. The chart can wire them up:

```sh
--set metrics.enabled=true                                  # prometheus.io/scrape annotations
--set metrics.serviceMonitor.enabled=true                   # or a ServiceMonitor (Prometheus Operator)
--set metrics.serviceMonitor.labels.release=kube-prometheus-stack
--set metrics.prometheusRule.enabled=true                   # alerts
--set dashboard.enabled=true                                # Grafana dashboard ConfigMap
```

## Alerts

| Alert | When | Default severity |
|---|---|---|
| `CvedetectorAgentNotReporting` | A cluster sent nothing for 30 minutes | warning |
| `CvedetectorFeedStale` | The feed is older than 48 hours | warning |
| `CvedetectorFeedSyncFailing` | 3 or more failed feed syncs in 3 hours | warning |
| `CvedetectorKnownExploitedVulnerability` | A CISA KEV vulnerability affects a running image | critical |
| `CvedetectorCriticalVulnerability` | A critical vulnerability affects a running image | warning |

Thresholds and severities are under `metrics.prometheusRule`. Turn the last two off with `knownExploited: false` / `critical: false`, and append your own rules with `additionalRules`.

## Dashboard

With `dashboard.enabled=true`, the chart installs a ConfigMap labelled `grafana_dashboard: "1"`. The Grafana sidecar loads it (kube-prometheus-stack, or the Grafana chart with `sidecar.dashboards.enabled`). Set `dashboard.namespace` if the sidecar only watches Grafana's namespace. Without the sidecar, import `dashboards/cvedetector.json` from the chart.

It shows:

- open vulnerabilities, one trend per severity
- known exploited count
- a cluster and namespace breakdown
- image match coverage
- time since each cluster's last report
- report and feed sync errors

## Metrics

From the API. Every replica reports the same values, so aggregate with `max`, not `sum`.

| Metric | Labels |
|---|---|
| `cvedetector_cluster_vulnerabilities` | `cluster`, `severity`: distinct CVEs |
| `cvedetector_cluster_kev_vulnerabilities` | `cluster` |
| `cvedetector_vulnerabilities` | `cluster`, `namespace`, `severity` |
| `cvedetector_kev_vulnerabilities` | `cluster`, `namespace` |
| `cvedetector_images` | `cluster`, `status` |
| `cvedetector_cluster_last_report_timestamp_seconds` | `cluster` |
| `cvedetector_feed_age_seconds` | |
| `cvedetector_ingest_total` | `result` |
| `cvedetector_feed_sync_errors_total` | |
| `cvedetector_workload_max_severity` | `cluster`, `namespace`, `kind`, `name`, `severity`; only with `api.workloadMetrics=true` |

From the agent: `cvedetector_agent_reports_total{result}`, `cvedetector_agent_last_report_success_timestamp_seconds`, `cvedetector_agent_pods`, `cvedetector_agent_images`.
