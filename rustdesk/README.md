# Dilarion Remote Control — self-hosted RustDesk

Replaces the custom enigo input injection with RustDesk's mature protocol
(multi-monitor, clipboard, file transfer, NAT traversal), while keeping the
meeting's audio/video on LiveKit. All control traffic stays on your own relay.

## 1. Deploy the relay (one VPS)

```bash
cd rustdesk
cp .env.example .env            # set RUSTDESK_RELAY_HOST to a public host/IP
docker compose up -d
```

Open the firewall:

```bash
ufw allow 21115/tcp; ufw allow 21116/tcp; ufw allow 21116/udp
ufw allow 21117/tcp; ufw allow 21118/tcp; ufw allow 21119/tcp
```

Grab the server public key (clients are pinned to it so only your relay is trusted):

```bash
cat data/id_ed25519.pub
```

A DNS record like `rustdesk.eibstratoc.com → <vps-ip>` is recommended so the
host can change without rebuilding clients.

Ports: 21115 (hbbs NAT type test), 21116 (hbbs TCP + UDP registration),
21117 (hbbr relay), 21118/21119 (web clients, optional).

## 2. Pin every Dilarion desktop to this relay

The RustDesk client reads a config. Ship it preset so users never type a server:

- Rendezvous/ID server: `RUSTDESK_RELAY_HOST`
- Relay server: `RUSTDESK_RELAY_HOST`
- Key: the `id_ed25519.pub` contents from step 1

Either bundle a `RustDesk2.toml` with these values, or launch the client with:

```bash
rustdesk --config "<base64 of host,key>"     # RustDesk exports/imports config as base64
```

(Build the config string once with `rustdesk --get-config`, edit host+key, re-encode.)

## 3. In-meeting flow (external-launch integration)

Reuses the existing control request/consent UI and WebSocket signaling. Only the
transport changes: instead of `inject_remote_input`, a RustDesk session is opened.

1. **Host** clicks "Request control" on a participant tile (existing UI).
2. Backend sends the consent prompt over WS (existing `remote_control_requested`).
   Target accepts (existing `remote_control_response`).
3. **Target** (Tauri, on accept):
   - `rustdesk --get-id`            → its RustDesk ID
   - generate a random one-time password
   - `rustdesk --password <otp>`    → set it (clear again on control end)
   - report `{ rustdesk_id, otp }` to the backend.
4. **Backend** relays `{ rustdesk_id, otp }` to the host over WS
   (new message type, e.g. `remote_control_rustdesk_session`).
5. **Host** (Tauri): `rustdesk --connect <rustdesk_id>` and supply `<otp>`
   (via preset config or the connect dialog). RustDesk opens the remote desktop
   in its own window; the Dilarion meeting keeps running on LiveKit.
6. **End control** (existing `remote_control_ended`): target runs
   `rustdesk --password ""` (or a fresh random one) to invalidate the OTP.

Security: consent-gated (unchanged), OTP is single-use and short-lived, brokered
only by your backend, and the client is pinned to your relay + key. Scope to
org-owned devices as today.

## 4. Backend changes (sketch)

The `ws_manager` already carries `remote_control_*` events between host and
target. Add one message type carrying the brokered session:

- Target → server: `{"type":"remote_control_rustdesk_offer","data":{"to":<host_id>,"rustdesk_id":"...","otp":"..."}}`
- Server → host:   `{"type":"remote_control_rustdesk_session","data":{"from":<target>,"rustdesk_id":"...","otp":"..."}}`

No DB needed — it is ephemeral signaling, exactly like the SDP/ICE relays.

## 5. Desktop changes (sketch)

Replace the `inject_remote_input` path in `GalleryView.tsx` for the control
action with:

- a Rust command `rustdesk_prepare()` → runs `--get-id`, sets a random password,
  returns `{ id, otp }` (controlled side);
- a Rust command `rustdesk_connect(id, otp)` → launches `rustdesk --connect`
  (controller side);
- a Rust command `rustdesk_reset_password()` on control end.

Ship the RustDesk binary with the app (Tauri `externalBin`) or require it
installed. Keep the existing enigo path as a fallback for environments without
RustDesk.

## License note

RustDesk is **AGPL-3.0**. **Launching the unmodified RustDesk binary** (this
external-launch design) keeps Dilarion's own source separate. **Embedding
`librustdesk`** into the app would likely bring Dilarion under AGPL obligations —
avoid unless you intend to comply. If AGPL is unacceptable, use a commercial SDK
(e.g. Cobrowse.io) instead.
