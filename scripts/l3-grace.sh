#!/usr/bin/env bash
# L3-grace: run the requirement suite against the real deployment on grace.
#
# The suite runs ON grace, not from the laptop: the microk8s API server is
# not reachable over the tailnet, and the probe pods, restart and
# NetworkPolicy tests need the node's kubeconfig. So this cross-compiles one
# test binary per requirement package, ships them over ssh, runs them there
# with REQ_TARGET=grace, and converts the output back into the same
# `go test -json` stream the kind lane produces, so reqreport reads both.
#
# No -race: the race runtime needs cgo, which cannot be cross-compiled from
# macOS here. The kind lane runs the same tests with -race.
#
# Usage: scripts/l3-grace.sh [out.json]     (env GRACE_HOST=user@host)
#        REQ_PKGS='r20_|r12_' scripts/l3-grace.sh   runs only the matching
#        requirement packages (an egrep pattern over the package basename);
#        unset = every package, the lane of record.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST=${GRACE_HOST:-geraci@grace}
OUT=${1:-l3-grace.json}
RUN_ID=${REQ_RUN_ID:-t$(printf '%x' "$(date +%s)")}
MODULE=$(go list -m)
REMOTE_DIR="work/l3-$RUN_ID"
KUBECONFIG_REMOTE=/var/snap/microk8s/current/credentials/client.config
# The in-cluster Service, not the sslip host: the gateway tests send a Host
# header naming <cluster>.<gateway domain>, and Envoy has no wildcard route for
# that yet — the Service answers by Host directly. Resolved on grace below.
BIFROST_URL_REMOTE=${BIFROST_URL:-in-cluster}
GATEWAY_DOMAIN=${REQ_GATEWAY_DOMAIN:-ray.100-89-230-107.sslip.io}

# Requirement packages only (r??_*). The generated contract negatives are
# L2-verified and deliberately send malformed bodies; against a deployment
# that predates the validation middleware they would persist junk records
# (docs/defects/2026-09-02-required-fields-unenforced.md), so they stay off
# the grace lane until grace runs an image that carries the fix.
# r17_slurm is an AST guard over the source tree, which grace does not have.
pkgs=$(go list ./test/requirements/... | grep -E '/test/requirements/r[0-9]{2}_[a-z0-9_]+$' | grep -v '/r17_slurm$')
if [ -n "${REQ_PKGS:-}" ]; then
  pkgs=$(printf '%s\n' $pkgs | grep -E "/test/requirements/(${REQ_PKGS})")
fi

rm -rf .l3 && mkdir -p .l3/bin .l3/out
for p in $pkgs; do
  name=${p##*/}
  echo "compiling $name"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o ".l3/bin/$name.test" "$p"
done

ssh -o BatchMode=yes "$HOST" "mkdir -p ~/$REMOTE_DIR"
scp -q .l3/bin/*.test "$HOST:~/$REMOTE_DIR/"

# Run every binary in one ssh session; the admin password never leaves grace.
remote_status=0
ssh -o BatchMode=yes "$HOST" bash -s -- "$REMOTE_DIR" "$RUN_ID" "$BIFROST_URL_REMOTE" "$KUBECONFIG_REMOTE" "$GATEWAY_DOMAIN" <<'REMOTE' || remote_status=$?
set -u
DIR=$1 RUN_ID=$2 URL=$3 KC=$4 GW=$5
export KUBECONFIG=$KC
if [ "$URL" = in-cluster ]; then
  URL="http://$(kubectl -n bifrost get svc bifrost -o jsonpath='{.spec.clusterIP}'):8484"
fi
PW=$(kubectl -n bifrost get secret bifrost-local-admin -o jsonpath='{.data.BIFROST_LOCAL_ADMIN_PASSWORD}' | base64 -d)
cd ~/$DIR
status=0
for t in *.test; do
  name=${t%.test}
  echo "=== $name" >&2
  REQ_TARGET=grace REQ_RUN_ID=$RUN_ID BIFROST_URL=$URL BIFROST_INSECURE_TLS=1 \
  BIFROST_ADMIN_PASSWORD=$PW REQ_CONTROL_PLANE_SELECTOR=app.kubernetes.io/name=bifrost-pack \
  REQ_NOWGET_RAY_IMAGE=${REQ_NOWGET_RAY_IMAGE:-localhost:32000/checkmaite-api:2.56.0-r1} \
  REQ_GATEWAY_DOMAIN=$GW \
    ./$t -test.v=test2json -test.timeout 40m > "$name.out" 2>&1 || status=1
  tail -3 "$name.out" >&2
done
exit $status
REMOTE

scp -q "$HOST:~/$REMOTE_DIR/*.out" .l3/out/
: > "$OUT"
for f in .l3/out/*.out; do
  name=$(basename "$f" .out)
  go tool test2json -t -p "$MODULE/test/requirements/$name" < "$f" >> "$OUT"
done
go run ./test/requirements/cmd/reqreport -in "$OUT" -lane l3-grace -out .l3/report -allow-untested
echo "results: $OUT   matrix: .l3/report/traceability.md   (remote exit $remote_status)"
exit $remote_status
