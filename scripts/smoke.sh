#!/usr/bin/env bash
# The smoke test the CI job runs. Kept as a script so it can be run locally, which
# is the only way to know the workflow is right before pushing it.
#
#   ./scripts/smoke.sh /path/to/coldspotd
set -euo pipefail

BIN="${1:?usage: smoke.sh /path/to/coldspotd}"
STATEPORT=18082
PROXYPORT=18081
SOCKSPORT=18080

cleanup() { [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; echo "--- daemon log ---" >&2; tail -30 /tmp/coldspotd.log >&2 || true; exit 1; }

echo "==> probe ON (1s), guard should reach ok and then refuse a leak"
"$BIN" -listen 127.0.0.1:$SOCKSPORT -proxy 127.0.0.1:$PROXYPORT \
       -state 127.0.0.1:$STATEPORT -config /tmp/coldspot-smoke.json \
       -egress-probe 1 > /tmp/coldspotd.log 2>&1 &
PID=$!

for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$STATEPORT/state" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$STATEPORT/state" >/dev/null || fail "the control API never answered"
echo "    control API up"

for key in gate guard totals clients; do
  curl -sf "http://127.0.0.1:$STATEPORT/state" | grep -q "\"$key\"" || fail "/state is missing $key"
done
echo "    /state has gate, guard, totals, clients"

code=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS \
  -H 'Access-Control-Request-Method: POST' -H 'Origin: http://example.com' \
  "http://127.0.0.1:$STATEPORT/config")
[ "$code" = "204" ] || fail "OPTIONS answered $code, the panel needs 204 with CORS"
echo "    OPTIONS preflight -> 204"

curl -sf -x "http://127.0.0.1:$PROXYPORT" https://example.com -o /tmp/smoke-http.html \
  || fail "HTTP proxy leg could not fetch example.com"
grep -qi '<title>' /tmp/smoke-http.html || fail "HTTP proxy returned something, but not the page"
echo "    HTTP proxy leg carried a real request"

curl -sf --socks5-hostname "127.0.0.1:$SOCKSPORT" https://example.com -o /tmp/smoke-socks.html \
  || fail "SOCKS5 leg could not fetch example.com"
grep -qi '<title>' /tmp/smoke-socks.html || fail "SOCKS5 returned something, but not the page"
echo "    SOCKS5 leg carried a real request"

# the probe needs a moment to measure the exit address
state=""
for i in $(seq 1 20); do
  state=$(curl -sf "http://127.0.0.1:$STATEPORT/egress" | tr -d '\n')
  echo "$state" | grep -q '"state":"ok"' && break
  sleep 1
done
echo "$state" | grep -q '"state":"ok"' || fail "guard never reached ok: $state"
echo "    guard measured the exit and is ok"

# tell it the exit must be somewhere it is not; the next probe must notice
curl -sf -X POST -H 'Content-Type: application/json' \
  -d '{"expect_egress":["203.0.113.0/24"],"block_on_leak":true}' \
  "http://127.0.0.1:$STATEPORT/config" >/dev/null
leak=""
for i in $(seq 1 20); do
  leak=$(curl -sf "http://127.0.0.1:$STATEPORT/egress" | tr -d '\n')
  echo "$leak" | grep -q '"state":"leak"' && break
  sleep 1
done
echo "$leak" | grep -q '"state":"leak"' || fail "guard did not report the leak: $leak"
echo "    guard reports a leak when the exit leaves expect_egress"

if curl -sf -o /dev/null -x "http://127.0.0.1:$PROXYPORT" https://example.com; then
  fail "a client was served while the guard was in a leak state"
fi
echo "    a client is refused while the guard is leaking"

cleanup; PID=""

echo "==> probe OFF, the daemon must make no outbound of its own"
"$BIN" -listen 127.0.0.1:$SOCKSPORT -proxy 127.0.0.1:$PROXYPORT \
       -state 127.0.0.1:$STATEPORT -config /tmp/coldspot-smoke2.json \
       -egress-probe 0 > /tmp/coldspotd2.log 2>&1 &
PID=$!
for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$STATEPORT/state" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$STATEPORT/egress" | grep -q '"state":"disabled"' \
  || fail "with -egress-probe 0 the guard should report disabled"
echo "    guard reports disabled, and the daemon has no probe"

echo
echo "SMOKE PASSED"
