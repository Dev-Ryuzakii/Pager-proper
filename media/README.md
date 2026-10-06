# Dilarion media stack (prod) — LiveKit + coturn

Calls and meetings need an SFU (LiveKit) and a TURN relay (coturn). This brings
both up on the prod host and wires them to the backend via `.env`.

## 1. Generate LiveKit key/secret

```bash
docker run --rm livekit/livekit-server generate-keys
```
Put the pair in `livekit.yaml` under `keys:` AND in the backend `.env` as
`LIVEKIT_API_KEY` / `LIVEKIT_API_SECRET` (they must match).

## 2. Fill the configs

- `livekit.yaml`: set your key/secret. `use_external_ip: true` is already on.
- `turnserver.conf`: set `external-ip` to the host's public IP, pick a strong
  `user=dilarion:<password>`.

## 3. Start

```bash
cd media && docker compose up -d
docker compose logs -f livekit   # confirm "starting LiveKit server"
```

Open the firewall:

```bash
ufw allow 7880/tcp; ufw allow 7881/tcp; ufw allow 50000:60000/udp   # LiveKit
ufw allow 3478/tcp; ufw allow 3478/udp; ufw allow 5349/tcp; ufw allow 49160:49200/udp  # coturn
```

## 4. Expose LiveKit over wss (nginx)

Clients connect to `wss://apidilarion.eibstratoc.com` for LiveKit. Add to the
apidilarion server block:

```nginx
location /rtc {
    proxy_pass http://127.0.0.1:7880;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
}
```
(LiveKit's signalling path is `/rtc`; the client builds it from `LIVEKIT_URL`.)
Reload nginx: `nginx -t && systemctl reload nginx`.

## 5. Backend `.env` (apidilarion)

```
LIVEKIT_URL=wss://apidilarion.eibstratoc.com
LIVEKIT_API_KEY=<same as livekit.yaml>
LIVEKIT_API_SECRET=<same as livekit.yaml>

TURN_HOST=<host public IP or turndilarion.eibstratoc.com>
TURN_PORT=3478
TURN_REALM=turndilarion.eibstratoc.com
TURN_STATIC_USERNAME=dilarion
TURN_STATIC_CREDENTIAL=<the turnserver.conf password>
TURN_STATIC_TLS_PORT=5349
```
Then restart the backend: `pm2 restart pager-backend`.

## 6. Verify

- `wscat -c wss://apidilarion.eibstratoc.com/rtc` connects (not 502).
- Start a meeting from a prod client — video/audio should flow.
- If 1:1 calls connect only on the same network, check coturn `external-ip`
  and the UDP port range are open.

## Shortcut

If you just want calls working now, point the prod `.env` at the EXISTING test
LiveKit/TURN (copy `LIVEKIT_*` and `TURN_*` from the test `.env`) and restart —
no stack to deploy, but prod media then runs through the test servers.
