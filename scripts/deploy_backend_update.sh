#!/bin/bash
# Deploy backend: AI settings + time zone, bulk invite resend, Base1 Watch,
# device-key retirement, live-session sign-in approval, email-verified
# access reset requests (new columns -> schema_sync --apply).
# Run from your laptop. Copy it up first so the remote shell keeps a terminal
# for sudo:
#   scp scripts/deploy_backend_update.sh cmdops@41.242.60.238:/tmp/ && ssh -t cmdops@41.242.60.238 'bash /tmp/deploy_backend_update.sh'
set -euo pipefail

SERVICE=pager_backend
DIR=$(systemctl show "$SERVICE" -p WorkingDirectory --value)
EXEC=$(systemctl show "$SERVICE" -p ExecStart --value | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
PY=$(dirname "$EXEC")/python
[ -x "$PY" ] || PY="$DIR/venv/bin/python"
ENVFILE=$(systemctl show "$SERVICE" -p EnvironmentFiles --value | awk '{print $1}')
[ -n "$ENVFILE" ] || ENVFILE="$DIR/.env"
echo "repo=$DIR python=$PY env=$ENVFILE"

cd "$DIR"
echo "== pull"
git pull --ff-only
git log --oneline -3

echo "== deps"
"$PY" -m pip install -q -r requirements.txt

echo "== schema (adds missing tables/columns, all nullable)"
set -a; [ -f "$ENVFILE" ] && . "$ENVFILE"; set +a
"$PY" schema_sync.py --apply

echo "== Base1 Watch env"
if ! sudo grep -q '^WATCH_ENVIRONMENT=' "$ENVFILE" 2>/dev/null; then
  echo 'WATCH_ENVIRONMENT=production' | sudo tee -a "$ENVFILE" >/dev/null
  echo "added WATCH_ENVIRONMENT=production"
fi

echo "== restart"
sudo systemctl restart "$SERVICE"
sleep 5
systemctl is-active "$SERVICE"
sudo journalctl -u "$SERVICE" -n 25 --no-pager | tail -25
