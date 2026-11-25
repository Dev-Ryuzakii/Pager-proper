#!/bin/bash
# READ-ONLY. Why can't a user read their OWN sent messages?
# Shows the user's device keys and, for their last sent DMs, which device
# entries each message was encrypted for. Changes nothing.
# On the server, from the repo folder:
#   bash scripts/diagnose_sender_decrypt.sh dombo
set -euo pipefail
trap 'echo "!! stopped at line $LINENO: $BASH_COMMAND" >&2' ERR
WHO="${1:?pass a username, email or part of a name}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
PY=""
for c in "$DIR/venv/bin/python" "$DIR/.venv/bin/python" "$DIR/env/bin/python"; do
  [ -x "$c" ] && { PY="$c"; break; }
done
[ -n "$PY" ] || PY="$(command -v python3)"
# database_models.py loads .env itself (load_dotenv).

WHO="$WHO" "$PY" - <<'PY'
import os, json, hashlib
from sqlalchemy import or_, func
from database_models import SessionLocal, User, LinkedDevice, Message

who = os.environ["WHO"].strip().lower()
db = SessionLocal()
u = db.query(User).filter(or_(func.lower(User.username) == who, func.lower(User.email) == who,
                              func.lower(User.username).like(f"%{who}%"),
                              func.lower(User.full_name).like(f"%{who}%"))).first()
if not u:
    raise SystemExit(f"No user matching {who!r}")
print(f"user: @{u.username} ({u.full_name}) id={u.id}")
fp = lambda k: hashlib.sha256((k or "").encode()).hexdigest()[:10]

devs = db.query(LinkedDevice).filter(LinkedDevice.user_id == u.id).order_by(LinkedDevice.id).all()
mine = {}
print("\ndevices (newest last):")
for d in devs:
    state = "REVOKED " + str(d.revoked_at) if d.revoked_at else "active"
    mine[d.device_uuid] = d
    print(f"  {d.device_uuid[:8]}  {d.platform:8} {str(d.device_name or '')[:22]:22} key={fp(d.public_key)} "
          f"created={d.created_at} last_seen={d.last_seen} {state}")
print(f"  users.public_key key={fp(u.public_key)}")

active = [d for d in devs if not d.revoked_at]
phones = [d for d in active if d.platform in ("android", "ios")]
print("\nlast 15 messages he SENT (which of his devices each was encrypted for):")
for m in db.query(Message).filter(Message.sender_id == u.id).order_by(Message.id.desc()).limit(15):
    try:
        keys = list(json.loads(m.encrypted_key).keys()) if (m.encrypted_key or "").startswith("{") else ["<single key>"]
    except Exception:
        keys = ["<unreadable>"]
    own = [k for k in keys if k in mine]
    own_txt = ", ".join(f"{k[:8]}({mine[k].platform}{', revoked' if mine[k].revoked_at else ''})" for k in own) or "NONE"
    phone_ok = any(k in {p.device_uuid for p in phones} for k in keys)
    print(f"  #{m.id} {m.timestamp} to={'group '+str(m.group_id) if m.group_id else m.recipient_id} "
          f"entries={len(keys)} his={own_txt} current_phone={'yes' if phone_ok else 'NO'}")
print("\ncurrent_phone=NO means the message was never encrypted for the phone key he has now,"
      "\nso that phone can't open it (the recipient still can).")
PY
