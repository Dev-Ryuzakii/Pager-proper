#!/usr/bin/env bash
# Install and configure coturn for Dilarion calling.
#
# Two instances:
#   legacy (3478/5349)  static user dilarion:dilarion2026 — shipped builds
#   rest   (3479/5350)  ephemeral HMAC credentials        — new builds
#
# Usage (on the VPS, as root):
#   REALM=turndilarion.eibstratoc.com ./install-coturn.sh
#
# Optional env:
#   EXTERNAL_IP   public IP (default: autodetected)
#   AUTH_SECRET   shared secret for REST creds (default: generated)
#   SKIP_TLS=1    don't try to obtain a certificate

set -euo pipefail

REALM="${REALM:?set REALM, e.g. REALM=turndilarion.eibstratoc.com}"
# The address CLIENTS reach, which is not always the address the box egresses
# from — on a NAT'd/multi-homed host ipify returns the wrong one and coturn then
# advertises relay candidates nobody can connect to. Pass EXTERNAL_IP explicitly
# whenever the autodetected value is not the public A record's target.
EXTERNAL_IP="${EXTERNAL_IP:-$(curl -fsS --max-time 10 https://api.ipify.org)}"
# `|| true`: getent exits non-zero when the name does not resolve, and under
# `set -e` a bare assignment inherits that status and kills the script.
DNS_IP="$(getent hosts "${REALM:-}" 2>/dev/null | awk '{print $1; exit}' || true)"
if [ -n "$DNS_IP" ] && [ "$DNS_IP" != "$EXTERNAL_IP" ]; then
  echo "!! WARNING: $REALM resolves to $DNS_IP but external-ip is $EXTERNAL_IP" >&2
  echo "!! Relay candidates will be unreachable. Re-run with EXTERNAL_IP=$DNS_IP" >&2
fi
AUTH_SECRET="${AUTH_SECRET:-$(openssl rand -hex 32)}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi

echo "==> realm=$REALM external-ip=$EXTERNAL_IP"

echo "==> installing coturn"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y coturn certbot curl openssl

# The distro unit runs a single instance from /etc/turnserver.conf; we drive two
# instances from our own units instead.
systemctl disable --now coturn 2>/dev/null || true

mkdir -p /etc/coturn/certs /var/log/coturn
chown turnserver:turnserver /var/log/coturn

render() {
  sed -e "s|__REALM__|${REALM}|g" \
      -e "s|__EXTERNAL_IP__|${EXTERNAL_IP}|g" \
      -e "s|__AUTH_SECRET__|${AUTH_SECRET}|g" \
      "$1" > "$2"
  chmod 640 "$2"
  chown root:turnserver "$2"
}

render "$SRC_DIR/turnserver-legacy.conf" /etc/coturn/turnserver-legacy.conf
render "$SRC_DIR/turnserver-rest.conf"   /etc/coturn/turnserver-rest.conf

echo "==> systemd units"
for inst in legacy rest; do
  cat > "/etc/systemd/system/coturn-${inst}.service" <<UNIT
[Unit]
Description=coturn TURN server (${inst})
After=network.target

[Service]
Type=simple
User=turnserver
Group=turnserver
ExecStart=/usr/bin/turnserver -c /etc/coturn/turnserver-${inst}.conf --no-stdout-log
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
done
systemctl daemon-reload

if [ "${SKIP_TLS:-0}" != "1" ]; then
  echo "==> TLS certificate for $REALM"
  # Needs $REALM resolving to this host (grey-cloud the DNS record — a proxied
  # Cloudflare record will not work for TURN). If nginx already owns :80 we go
  # through its plugin instead of --standalone, which would fail to bind.
  CERTBOT_ARGS=(certonly --non-interactive --agree-tos
                --register-unsafely-without-email -d "$REALM")
  if ss -lnt 2>/dev/null | grep -q ':80 '; then
    if certbot plugins 2>/dev/null | grep -q nginx; then
      echo "   :80 in use by nginx — using the nginx plugin"
      CERTBOT_ARGS+=(--nginx)
    else
      echo "   :80 in use and no nginx plugin — install python3-certbot-nginx, then re-run"
      CERTBOT_ARGS+=(--standalone)
    fi
  else
    CERTBOT_ARGS+=(--standalone)
  fi
  if certbot "${CERTBOT_ARGS[@]}"; then
    install -o turnserver -g turnserver -m 644 \
      "/etc/letsencrypt/live/$REALM/fullchain.pem" /etc/coturn/certs/fullchain.pem
    install -o turnserver -g turnserver -m 640 \
      "/etc/letsencrypt/live/$REALM/privkey.pem"   /etc/coturn/certs/privkey.pem
    cat > /etc/letsencrypt/renewal-hooks/deploy/coturn.sh <<'HOOK'
#!/usr/bin/env bash
set -e
DOMAIN_DIR="$RENEWED_LINEAGE"
install -o turnserver -g turnserver -m 644 "$DOMAIN_DIR/fullchain.pem" /etc/coturn/certs/fullchain.pem
install -o turnserver -g turnserver -m 640 "$DOMAIN_DIR/privkey.pem"   /etc/coturn/certs/privkey.pem
systemctl restart coturn-legacy coturn-rest
HOOK
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/coturn.sh
  else
    echo "!! certbot failed — starting without TLS listeners (3478/3479 still work)"
  fi
fi

echo "==> firewall"
if command -v ufw >/dev/null; then
  ufw allow 3478/udp; ufw allow 3478/tcp
  ufw allow 3479/udp; ufw allow 3479/tcp
  ufw allow 5349/tcp; ufw allow 5350/tcp
  ufw allow 49160:49500/udp
fi

echo "==> starting"
systemctl enable --now coturn-legacy coturn-rest
sleep 2
systemctl --no-pager --lines=5 status coturn-legacy coturn-rest || true

cat <<EOF

==================================================================
coturn is up.

  legacy  turn:${REALM}:3478   user dilarion / dilarion2026
  rest    turn:${REALM}:3479   ephemeral HMAC credentials

Put this in the backend environment (never in a client build):

  TURN_REALM=${REALM}
  TURN_AUTH_SECRET=${AUTH_SECRET}

Then verify with ./verify-turn.sh ${REALM}
==================================================================
EOF
