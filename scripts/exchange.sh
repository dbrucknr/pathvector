#!/usr/bin/env bash
# Simulated BGP exchange for local interop testing.
#
# Requires gobgpd and pathvectord already running:
#   just gobgp-up   (terminal 1)
#   just dev        (terminal 2)
#
# Usage: ./scripts/exchange.sh
#   or:  just exchange
set -euo pipefail

PV="cargo run --quiet -p pathvector -- --address http://127.0.0.1:50052"
GOBGP="gobgp"

log() { echo "[$(date +%T)] $*"; }

# ── Wait for BGP session to reach Established ────────────────────────────────
# The exchange requires an established session; polling avoids race conditions
# when just dev (cargo compile + startup) finishes after just exchange starts.
wait_established() {
    local timeout=60
    local elapsed=0
    log "Waiting for BGP session to reach Established (timeout: ${timeout}s)..."
    while true; do
        if $PV peer list 2>/dev/null | grep -q "Established"; then
            log "Session is Established."
            return 0
        fi
        if [ "$elapsed" -ge "$timeout" ]; then
            log "ERROR: session did not reach Established within ${timeout}s — is pathvectord running?"
            exit 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}
wait_established

# ── Phase 1: GoBGP injects a prefix table ────────────────────────────────────

log "GoBGP: announcing prefix table..."
$GOBGP global rib add 10.0.0.0/8     nexthop 10.0.0.1 origin igp
$GOBGP global rib add 172.16.0.0/12  nexthop 10.0.0.1 origin igp
$GOBGP global rib add 192.168.0.0/16 nexthop 10.0.0.1 origin egp
sleep 1

log "pathvectord Loc-RIB after GoBGP announcements:"
$PV route list

# ── Phase 2: pathvectord originates its own prefixes ─────────────────────────

log "pathvectord: originating prefixes..."
$PV route originate 203.0.113.0/24  --next-hop 10.0.0.2
$PV route originate 198.51.100.0/24 --next-hop 10.0.0.2 --med 100
sleep 1

log "GoBGP RIB after pathvectord originations:"
$GOBGP global rib

# ── Phase 3: policy change — flip peer to reject-import ──────────────────────

log "pathvectord: switching GoBGP peer to reject-import (RFC 8212 default)..."
$PV policy set-import 127.0.0.1 reject
sleep 1

log "pathvectord Loc-RIB after policy change (GoBGP routes should be gone):"
$PV route list

log "pathvectord: restoring accept-import..."
$PV policy set-import 127.0.0.1 accept
sleep 1

log "pathvectord Loc-RIB after policy restore:"
$PV route list

# ── Phase 4: withdrawals ──────────────────────────────────────────────────────

log "GoBGP: withdrawing prefixes..."
$GOBGP global rib del 10.0.0.0/8
$GOBGP global rib del 172.16.0.0/12
sleep 1

log "pathvectord: withdrawing originated prefixes..."
$PV route withdraw 203.0.113.0/24
$PV route withdraw 198.51.100.0/24
sleep 1

log "Final state — pathvectord Loc-RIB (expect only 192.168.0.0/16):"
$PV route list

log "Final state — GoBGP RIB (expect empty — pathvectord prefixes withdrawn):"
$GOBGP global rib

log "Exchange complete."
