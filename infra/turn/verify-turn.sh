#!/usr/bin/env bash
# Prove the TURN server actually relays, for both credential types.
#
#   ./verify-turn.sh turn.dilarion.eibstratoc.com [AUTH_SECRET]
#
# A pass means "relay allocation succeeded", which is what a call needs when both
# peers are behind symmetric NAT. Run it from a machine OTHER than the VPS.

set -euo pipefail
REALM="${1:?usage: verify-turn.sh <realm> [auth_secret]}"
SECRET="${2:-${TURN_AUTH_SECRET:-}}"

command -v turnutils_uclient >/dev/null || {
  echo "install coturn-utils first (apt-get install coturn / brew install coturn)" >&2
  exit 1
}

echo "== reachability"
for p in 3478 3479; do
  nc -z -w5 "$REALM" "$p" && echo "  tcp/$p open" || echo "  tcp/$p CLOSED"
done

echo
echo "== legacy static credential (port 3478)"
turnutils_uclient -T -u dilarion -w dilarion2026 -p 3478 -n 3 -c "$REALM" \
  && echo "  PASS" || echo "  FAIL"

if [ -n "$SECRET" ]; then
  echo
  echo "== REST ephemeral credential (port 3479)"
  EXP=$(( $(date +%s) + 3600 ))
  USER="${EXP}:verify"
  PASS=$(printf '%s' "$USER" | openssl dgst -sha1 -hmac "$SECRET" -binary | base64)
  turnutils_uclient -T -u "$USER" -w "$PASS" -p 3479 -n 3 -c "$REALM" \
    && echo "  PASS" || echo "  FAIL"
else
  echo
  echo "== REST check skipped (pass AUTH_SECRET as \$2 or TURN_AUTH_SECRET)"
fi
