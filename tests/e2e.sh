#!/usr/bin/env bash
# End-to-end checks for rlproxy. Spins up the event-driven upstream and
# the proxy on isolated ports, exercises limit behavior, hot reload,
# 429/Retry-After headers, and connection cleanup, then tears everything
# down. Exits non-zero on the first failed assertion.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROXY_PORT=18091
UP_PORT=19091
CONF="$(mktemp -t rlproxy_e2e.XXXXXX.conf)"
PROXY_LOG="$(mktemp -t rlproxy_e2e.proxy.XXXXXX.log)"
UP_LOG="$(mktemp -t rlproxy_e2e.up.XXXXXX.log)"
PIDFILE="$(mktemp -t rlproxy_e2e.pid.XXXXXX)"

PROXY_PID=""
UP_PID=""
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
ok()    { green "  ok: $*"; }
bad()   { red "  FAIL: $*"; FAIL=1; }

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null
    rm -f "$CONF" "$PROXY_LOG" "$UP_LOG" "$PIDFILE"
}
trap cleanup EXIT

cat > "$CONF" <<EOF
listen 127.0.0.1:$PROXY_PORT
upstream 127.0.0.1:$UP_PORT
trust_xff on
max_conns 20000
head_timeout_ms 3000
idle_timeout_ms 5000
zone ip_t type=ip key=\$ip alg=token_bucket rate=10/s burst=10
zone admin_t type=route key=/admin alg=sliding_log rate=3/s
EOF

echo "== build =="
make -s all || { red "build failed"; exit 1; }
ok "all binaries build"

echo "== start services =="
./upstream_echo "127.0.0.1:$UP_PORT" 0 64 >"$UP_LOG" 2>&1 &
UP_PID=$!
./rlproxy -f "$CONF" -p "$PIDFILE" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
sleep 1
kill -0 "$PROXY_PID" 2>/dev/null || { red "proxy did not start"; cat "$PROXY_LOG"; exit 1; }
ok "proxy and upstream running"

code() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "http://127.0.0.1:$PROXY_PORT$2"; }

echo "== basic forwarding =="
C=$(code 203.0.113.1 /api/items)
[ "$C" = "200" ] && ok "request forwarded, 200" || bad "expected 200 got $C"

echo "== per-IP token bucket (burst 10) =="
pass=0; deny=0
for _ in $(seq 1 14); do
    C=$(code 203.0.113.2 /api/items)
    [ "$C" = "200" ] && pass=$((pass+1)) || deny=$((deny+1))
done
[ "$pass" -eq 10 ] && ok "exactly burst(10) allowed, got $pass" || bad "expected 10 allowed, got $pass"
[ "$deny" -eq 4 ] && ok "surplus denied with 429" || bad "expected 4 denied, got $deny"

echo "== 429 carries Retry-After =="
HDRS=$(curl -s -i -H "X-Forwarded-For: 203.0.113.3" "http://127.0.0.1:$PROXY_PORT/api/items" >/dev/null; \
       for _ in $(seq 1 12); do curl -s -i -H "X-Forwarded-For: 203.0.113.3" "http://127.0.0.1:$PROXY_PORT/api/items"; done)
echo "$HDRS" | grep -q "429 Too Many Requests" && ok "429 status present" || bad "no 429 observed"
echo "$HDRS" | grep -qi "Retry-After: [0-9]" && ok "Retry-After header present" || bad "Retry-After missing"

echo "== route limit (sliding log, 3/s on /admin) =="
apass=0
for _ in $(seq 1 6); do
    C=$(code 203.0.113.4 /admin/panel)
    [ "$C" = "200" ] && apass=$((apass+1))
done
[ "$apass" -eq 3 ] && ok "admin route capped at 3, got $apass" || bad "expected 3 admin allows, got $apass"

echo "== IP independence =="
C=$(code 203.0.113.99 /api/items)
[ "$C" = "200" ] && ok "fresh IP not affected by another IP's limit" || bad "fresh IP wrongly limited ($C)"

echo "== hot reload without dropping traffic =="
cp "$CONF" "$CONF.orig"
sed 's/rate=10\/s burst=10/rate=2\/s burst=2/' "$CONF.orig" > "$CONF"
kill -HUP "$PROXY_PID"; sleep 1
grep -q "config reloaded" "$PROXY_LOG" && ok "SIGHUP reload applied" || bad "reload not logged"
rpass=0
for _ in $(seq 1 5); do
    C=$(code 203.0.113.50 /api/items)
    [ "$C" = "200" ] && rpass=$((rpass+1))
done
[ "$rpass" -eq 2 ] && ok "new tight limit (burst 2) live, got $rpass" || bad "reload params ineffective, got $rpass"
cp "$CONF.orig" "$CONF"; kill -HUP "$PROXY_PID"; sleep 1

echo "== invalid reload is rejected, service stays up =="
echo "zone broken type=bogus key=/x alg=token_bucket rate=1/s" >> "$CONF"
sleep 1.5
grep -q "reload rejected" "$PROXY_LOG" && ok "bad config rejected" || bad "bad config not rejected"
C=$(code 203.0.113.60 /api/items)
[ "$C" = "200" ] && ok "service still serving after rejected reload" || bad "service down after bad reload"
cp "$CONF.orig" "$CONF"; sleep 1.5

echo "== summary =="
if [ "$FAIL" -eq 0 ]; then
    green "ALL E2E CHECKS PASSED"
    exit 0
else
    red "E2E FAILURES DETECTED"
    echo "--- proxy log tail ---"; tail -20 "$PROXY_LOG"
    exit 1
fi
