# TURN / WebRTC relay setup

Calls use WebRTC. When both peers sit behind symmetric NAT (most mobile carriers),
STUN alone cannot make a path and the call connects but carries no audio. A TURN
relay fixes that, so this box is a hard dependency for reliable calling.

## Layout

Two coturn instances run side by side, because coturn ignores static `user=`
entries once `use-auth-secret` is on:

| Instance | Ports            | Auth                        | Used by |
|----------|------------------|-----------------------------|---------|
| legacy   | 3478, 5349 (TLS) | static `dilarion:dilarion2026` | already-released Android/desktop builds |
| rest     | 3479, 5350 (TLS) | ephemeral HMAC (TURN REST)  | new builds via `GET /webrtc/ice-servers` |

Relay port ranges are disjoint: legacy `49160-49300`, rest `49301-49500`.

Retire the legacy instance once released builds with the old hardcoded credential
are out of circulation — that password is extractable from any APK, so anyone can
spend your bandwidth through it. `user-quota` / `total-quota` in the config caps
the damage until then.

## Install

On the VPS, as root:

```bash
REALM=turn.dilarion.eibstratoc.com ./install-coturn.sh
```

It prints a generated `TURN_AUTH_SECRET`. Put it in the backend environment:

```
TURN_REALM=turn.dilarion.eibstratoc.com
TURN_AUTH_SECRET=<printed secret>
TURN_REST_PORT=3479
TURN_REST_TLS_PORT=5350
```

Restart the API. `GET /webrtc/ice-servers` then returns TURN entries; without the
secret it logs a warning and serves STUN only, and clients quietly fall back to
their built-in list.

## DNS

`turn.dilarion.eibstratoc.com` must be an **A record straight to the VPS IP with
Cloudflare proxying OFF** (grey cloud). A proxied record breaks both UDP relay and
the certificate issuance below.

## Verify

From a machine that is *not* the VPS:

```bash
./verify-turn.sh turn.dilarion.eibstratoc.com "$TURN_AUTH_SECRET"
```

Both sections must print `PASS` — that means a relay allocation succeeded, which
is the thing a call actually needs.

Browser-side cross-check: https://icetest.info or webrtc.github.io/samples/src/content/peerconnection/trickle-ice/ —
enter the TURN URL and credentials, and confirm at least one candidate of type
`relay` appears. `srflx` only means STUN works and TURN does not.

## Live checks

```bash
systemctl status coturn-legacy coturn-rest
tail -f /var/log/coturn/turnserver-rest.log      # allocations appear here
ss -lunp | grep turnserver                       # UDP listeners
```

Common failures:

- **`401` loops in the log** — client clock skew or a wrong/rotated
  `TURN_AUTH_SECRET`. REST usernames carry an expiry timestamp.
- **Allocation succeeds, no audio** — the relay UDP range is blocked upstream.
  Open `49160-49500/udp` in the provider's firewall too, not just `ufw`.
- **TLS listener dead** — certs missing at `/etc/coturn/certs/`. The plain 3478 /
  3479 listeners still work; `turns:` does not.

## Firewall

```
3478/udp 3478/tcp      legacy
3479/udp 3479/tcp      rest
5349/tcp 5350/tcp      TLS
49160-49500/udp        relay range
```
