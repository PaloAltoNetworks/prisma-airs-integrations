#!/bin/bash
# The Local Mode harness, in one command (Linux x86 with Docker; run `make build` first, or use `make itest`).
#   scripts/itest.sh [main|tls|leak] [case filter]
# main: every case against Flex 1.12.12, a TLS mock AIRS and a mock upstream. tls and leak are measurements.
# The harness CA is mounted into Flex's trust store, except in the tls phase (ITEST_TRUST_CA=0/1 overrides).
set -euo pipefail
cd "$(dirname "$0")/.."
I=tests/integration
PHASE=${1:-main}
FILTER=${2:-}
FLEX_IMAGE=mulesoft/flex-gateway:1.12.12
COMPOSE="docker compose -f $I/docker-compose.yaml"
# The harness CA is trusted except in the tls phase, which measures whether Flex verifies the AIRS certificate.
TRUST=${ITEST_TRUST_CA:-$([[ $PHASE == tls ]] && echo 0 || echo 1)}
[[ $TRUST == 1 ]] && COMPOSE="$COMPOSE -f $I/docker-compose.ca.yaml"
export ITEST_COMPOSE="$COMPOSE"

mkdir -p "$I/config/custom-policies"
[[ -f $I/certs/airs.crt ]] || bash "$I/certs.sh" "$I/certs" >/dev/null
if [[ ! -f $I/config/registration.yaml ]]; then
  # The image runs as uid 65532, which cannot write into a folder the build user owns: run flexctl as that user.
  docker run --rm --user "$(id -u):$(id -g)" --entrypoint flexctl -v "$PWD/$I/config":/registration "$FLEX_IMAGE" \
    registration create --mode disconnected --output-directory=/registration itest-flex >/dev/null
  chmod 644 "$I/config/registration.yaml"
fi
REF=$(make -s show-policy-ref-name)
rm -f "$I"/config/custom-policies/*.yaml
cp target/wasm32-wasip1/release/*_implementation.yaml target/wasm32-wasip1/release/*_definition.yaml "$I/config/custom-policies/"
python3 "$I/render.py" "$REF" "$PHASE" > "$I/config/api.yaml"

cleanup() { $COMPOSE logs --no-color local-flex > "$I/flex.log" 2>&1 || true; $COMPOSE down --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
$COMPOSE down --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d >/dev/null 2>&1
ready=no
for _ in $(seq 1 60); do
  code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -H 'x-input-format: openai' localhost:8081/openai/models || true)
  [[ $code =~ ^[1-5][0-9][0-9]$ ]] && { ready=yes; break; }
  sleep 2
done
[[ $ready == yes ]] || { echo "Flex did not answer on 8081"; $COMPOSE logs --no-color local-flex 2>&1 | tail -n 30; exit 1; }
sleep 3
python3 "$I/run.py" "$PHASE" "$FILTER"
