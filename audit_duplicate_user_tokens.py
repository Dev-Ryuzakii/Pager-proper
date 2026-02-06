#!/usr/bin/env python3
"""
Audit duplicate user auth tokens.

Why: If the same auth token is assigned to multiple users, one token can be used
to access multiple accounts (depending on the auth flow). This script detects
duplicates so you can rotate them safely.

Checks:
- `user_keys_secure.json` (TLS server user store)

Usage:
  python audit_duplicate_user_tokens.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def main() -> int:
    path = Path("user_keys_secure.json")
    if not path.exists():
        print("No user_keys_secure.json found. Nothing to audit.")
        return 0

    data = json.loads(path.read_text(encoding="utf-8"))
    users = data.get("users", {})
    if not isinstance(users, dict):
        print("Unexpected format: expected top-level key 'users' to be a dict.")
        return 2

    token_to_users: dict[str, list[str]] = defaultdict(list)
    for username, udata in users.items():
        if not isinstance(udata, dict):
            continue
        token = udata.get("token")
        if isinstance(token, str) and token:
            token_to_users[token].append(username)

    duplicates = {t: us for t, us in token_to_users.items() if len(us) > 1}
    if not duplicates:
        print("✅ No duplicate tokens found.")
        return 0

    print("❌ Duplicate tokens found (token -> usernames):")
    for token, usernames in sorted(duplicates.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"- {token!r} -> {', '.join(sorted(usernames))}")

    print("\nRecommended next step: rotate tokens so each user has a unique value.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

