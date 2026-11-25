#!/bin/bash
# Deploy the backend from this checkout: pull, install deps, add missing DB
# tables/columns (schema_sync --apply), make sure Base1 Watch reports as
# production, then restart however the backend runs here (systemd, pm2, or a
# plain uvicorn process).
#
# On the server, from the repo folder:
#   git pull && bash scripts/deploy_backend_update.sh
set -euo pipefail
trap 'echo "!! stopped at line $LINENO: $BASH_COMMAND" >&2' ERR

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
echo "repo: $DIR"

PY=""
for c in "$DIR/venv/bin/python" "$DIR/.venv/bin/python" "$DIR/env/bin/python"; do
  [ -x "$c" ] && { PY="$c"; break; }
done
[ -n "$PY" ] || PY="$(command -v python3)"
echo "python: $PY"

ENVFILE="$DIR/.env"
echo "env file: $ENVFILE $([ -f "$ENVFILE" ] && echo '(found)' || echo '(missing)')"

echo "== pull"
git pull --ff-only
git log --oneline -3

echo "== deps"
"$PY" -m pip install -q -r requirements.txt

echo "== schema (adds missing tables/columns, all nullable)"
# No need to source .env: database_models.py loads it (load_dotenv), and
# values with $ in them would break a shell `source`.
"$PY" schema_sync.py --apply

echo "== Base1 Watch env"
if [ -f "$ENVFILE" ] && ! grep -q '^WATCH_ENVIRONMENT=' "$ENVFILE"; then
  printf '\nWATCH_ENVIRONMENT=production\n' >> "$ENVFILE"
  echo "added WATCH_ENVIRONMENT=production to .env"
else
  echo "WATCH_ENVIRONMENT already set (or no .env)"
fi

echo "== restart"
restarted=""
# 1) systemd: any unit whose WorkingDirectory is this repo
for unit in $(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}'); do
  wd=$(systemctl show "$unit" -p WorkingDirectory --value 2>/dev/null || true)
  if [ "$wd" = "$DIR" ]; then
    echo "systemd unit: $unit"
    sudo systemctl restart "$unit"
    sleep 4
    systemctl is-active "$unit" || true
    sudo journalctl -u "$unit" -n 20 --no-pager || true
    restarted="$unit"
    break
  fi
done
# 2) pm2: a process running from this repo
if [ -z "$restarted" ] && command -v pm2 >/dev/null 2>&1; then
  name=$(pm2 jlist 2>/dev/null | "$PY" -c '
import json, sys
d = sys.argv[1]
for p in json.load(sys.stdin):
    e = p.get("pm2_env", {})
    if e.get("pm_cwd") == d or str(e.get("pm_exec_path", "")).startswith(d + "/"):
        print(p["name"]); break
' "$DIR" || true)
  if [ -n "$name" ]; then
    echo "pm2 process: $name"
    pm2 restart "$name" --update-env
    sleep 4
    pm2 logs "$name" --lines 20 --nostream || true
    restarted="pm2:$name"
  fi
fi
if [ -z "$restarted" ]; then
  echo "!! Couldn't find how the backend is started. Running uvicorn/python processes:"
  ps -eo pid,user,args | grep -E "uvicorn|gunicorn|fastapi_mobile_backend" | grep -v grep || true
  echo "Restart it the way it is normally started, then check it answers."
  exit 1
fi

echo "== health"
PORT=$(grep -E '^PORT=' "$ENVFILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '"\r ' || true)
sleep 2
curl -fsS -m 10 http://127.0.0.1:${PORT:-8000}/health 2>/dev/null && echo || \
  echo "(no answer on 127.0.0.1:${PORT:-8000}/health; check the logs above)"
echo "done: restarted $restarted"
