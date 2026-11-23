#!/usr/bin/env bash
# A kind cluster with well-known software (older tags, so there is something to
# find) and cvedetector installed from a local chart: the data behind the docs
# demo and screenshots.
#
#   cluster.sh up <chart dir>    create, deploy, install (idempotent)
#   cluster.sh down              delete the cluster
#
# The kubeconfig is kept in .demo/kubeconfig: your current context is never
# changed.
set -euo pipefail
cd "$(dirname "$0")/../../.."

NAME=${DEMO_CLUSTER:-cvedetector-demo}
export KUBECONFIG=$PWD/.demo/kubeconfig
mkdir -p .demo

if [[ ${1:-} == down ]]; then
  kind delete cluster --name "$NAME" --kubeconfig "$KUBECONFIG"
  exit
fi
[[ ${1:-} == up && -n ${2:-} ]] || { echo "usage: $0 up <chart dir> | down" >&2; exit 2; }
CHART=$2
TAG=$(awk -F'"' '/^appVersion:/ {print $2}' "$CHART/Chart.yaml")

kind get clusters | grep -qx "$NAME" || kind create cluster --name "$NAME" --kubeconfig "$KUBECONFIG" --wait 120s
kubectl label node "$NAME-control-plane" ingress-ready=true --overwrite >/dev/null

# Images for the chart's appVersion, built from this checkout.
make images VERSION="$TAG"
kind load docker-image --name "$NAME" \
  "ghcr.io/huseyinbabal/cvedetector-agent:$TAG" "ghcr.io/huseyinbabal/cvedetector-api:$TAG" "ghcr.io/huseyinbabal/cvedetector-ui:$TAG"

# Well-known software from upstream manifests.
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.4/deploy/static/provider/kind/deploy.yaml >/dev/null
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.2/cert-manager.yaml >/dev/null
kubectl create ns argocd --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -n argocd --server-side -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.9.3/manifests/install.yaml >/dev/null

# deploy <namespace> <name> <image> <replicas> [-- command...]
deploy() {
  local ns=$1 name=$2 image=$3 replicas=$4
  shift 4
  kubectl create ns "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$ns" create deployment "$name" --image="$image" --replicas="$replicas" --dry-run=client -o yaml "$@" | kubectl apply -f - >/dev/null
}
deploy web nginx docker.io/library/nginx:1.25.3 3
deploy web httpd docker.io/library/httpd:2.4.57 1
deploy web caddy docker.io/library/caddy:2.7.5 1
deploy web wordpress docker.io/library/wordpress:6.4.1-apache 1
deploy shop redis docker.io/library/redis:7.2.3 1
deploy shop memcached docker.io/library/memcached:1.6.21 1
deploy shop rabbitmq docker.io/library/rabbitmq:3.12.8-management 1
deploy shop mongo docker.io/library/mongo:6.0.11 1
deploy shop postgres docker.io/library/postgres:16.1 1
deploy shop storefront ghcr.io/stefanprodan/podinfo:6.5.3 2
deploy shop httpbin docker.io/mccutchen/go-httpbin:v2.15.0 1
deploy tools busybox docker.io/library/busybox:latest 1 -- sleep infinity
deploy tools echo docker.io/hashicorp/http-echo:1.0 1 -- /http-echo -text=hello
deploy monitoring prometheus docker.io/prom/prometheus:v2.48.0 1
deploy monitoring grafana docker.io/grafana/grafana:10.2.2 1
deploy monitoring alertmanager docker.io/prom/alertmanager:v0.26.0 1
deploy security vault docker.io/hashicorp/vault:1.15.2 1
deploy security keycloak quay.io/keycloak/keycloak:22.0.5 1 -- /opt/keycloak/bin/kc.sh start-dev
kubectl -n shop set env deploy/postgres POSTGRES_PASSWORD=demo >/dev/null
kubectl -n web set env deploy/wordpress WORDPRESS_DB_HOST=127.0.0.1 >/dev/null
kubectl -n security set env deploy/keycloak KEYCLOAK_ADMIN=admin KEYCLOAK_ADMIN_PASSWORD=admin >/dev/null

# cvedetector itself.
helm upgrade --install cvedetector "$CHART" -n cvedetector --create-namespace \
  --set agent.clusterName=kind-demo \
  --set image.pullPolicy=Never \
  --set postgresql.persistence.size=1Gi \
  --wait --timeout 5m >/dev/null

echo "Ready. Open the UI with:"
echo "  KUBECONFIG=$KUBECONFIG kubectl -n cvedetector port-forward svc/cvedetector-ui 28180:8080"
