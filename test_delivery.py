#!/usr/bin/env python3
"""Standalone email + SMS delivery diagnostic.

Run this ON THE VPS, from the app directory, with the same environment the
server uses:

    cd /opt/pager-proper          # or wherever the app lives
    source venv/bin/activate
    set -a; . ./.env; set +a      # load the same .env the server reads
    python3 test_delivery.py faladerasaq22@gmail.com 07040746576

It mirrors the real _send_email_message / _send_sms logic but has no app or
DB import side effects, prints which env vars are actually visible (values
masked), and shows the exact failure instead of silently returning False.
"""
import os
import re
import sys
import ssl
import smtplib
import json
import urllib.request
import urllib.error
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr

# Load .env exactly like the running server does (database_models /
# database_config both call load_dotenv() at import), so this test sees the
# same config the server sees — no need to `set -a; . ./.env` first.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # noqa: BLE001
    pass

DEFAULT_EMAIL = "faladerasaq22@gmail.com"
DEFAULT_PHONE = "07040746576"


def mask(value):
    if not value:
        return "(not set)"
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}…{value[-3:]} (len {len(value)})"


def show_env():
    print("=" * 64)
    print("ENVIRONMENT (values masked)")
    print("=" * 64)
    names = [
        "RESEND_API_KEY", "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME",
        "SMTP_PASSWORD", "SMTP_FROM", "RESEND_FROM_EMAIL", "SMTP_FROM_NAME",
        "SMTP_SSL", "SMTP_STARTTLS", "SMTP_REPLY_TO", "SUPPORT_EMAIL",
        "SENDCHAMP_API_KEY", "SENDCHAMP_BASE_URL", "SENDCHAMP_SENDER_NAME",
        "SENDCHAMP_ROUTE", "SENDCHAMP_DEFAULT_COUNTRY_CODE",
        "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER",
    ]
    for name in names:
        print(f"  {name:<32} {mask(os.getenv(name))}")
    print()


def _email_providers():
    """Same order the server uses: configured SMTP first, Resend fallback."""
    providers = []
    smtp_host = os.getenv("SMTP_HOST")
    smtp_from = os.getenv("SMTP_FROM")
    if smtp_host and os.getenv("SMTP_USERNAME") and os.getenv("SMTP_PASSWORD") and smtp_from:
        port = int(os.getenv("SMTP_PORT", "465" if smtp_host == "smtp.resend.com" else "587"))
        use_ssl = os.getenv("SMTP_SSL", "1" if port in (465, 2465) else "0") == "1"
        use_starttls = (os.getenv("SMTP_STARTTLS", "0" if use_ssl else "1") == "1") and not use_ssl
        providers.append(("smtp", smtp_host, port, os.getenv("SMTP_USERNAME"),
                          os.getenv("SMTP_PASSWORD"), use_ssl, use_starttls, smtp_from))
    resend_key = os.getenv("RESEND_API_KEY")
    resend_from = os.getenv("RESEND_FROM_EMAIL") or smtp_from
    if resend_key and resend_from and smtp_host != "smtp.resend.com":
        providers.append(("resend", "smtp.resend.com", 465, "resend",
                          resend_key, True, False, resend_from))
    return providers


def test_email(to_email):
    print("=" * 64)
    print(f"EMAIL  ->  {to_email}")
    print("=" * 64)
    providers = _email_providers()
    if not providers:
        print("  RESULT: NOT SENT — no SMTP/Resend provider configured.")
        print()
        return

    for name, host, port, user, password, use_ssl, use_starttls, from_email in providers:
        print(f"  [{name}] host={host} port={port} ssl={use_ssl} starttls={use_starttls} from={from_email}")
        sender_name, sender_addr = parseaddr(from_email)
        if not sender_name:
            sender_name = os.getenv("SMTP_FROM_NAME", "Dilarion")
        sender_domain = sender_addr.split("@", 1)[-1] if "@" in sender_addr else None
        msg = EmailMessage()
        msg["Subject"] = "Dilarion delivery test"
        msg["From"] = formataddr((sender_name, sender_addr))
        msg["To"] = to_email
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = make_msgid(domain=sender_domain)
        msg.set_content("This is a Dilarion email delivery test. If you received it, email works.")
        try:
            smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
            kwargs = {"timeout": 20}
            if use_ssl:
                kwargs["context"] = ssl.create_default_context()
            with smtp_class(host, port, **kwargs) as server:
                if use_starttls:
                    server.starttls(context=ssl.create_default_context())
                server.login(user, password)
                server.send_message(msg)
            print(f"  RESULT: SENT OK via {name} — check the inbox (and spam).")
            print()
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  [{name}] failed: {type(exc).__name__}: {exc} — trying next")
    print("  RESULT: FAILED — every provider failed.")
    print()


def sms_number(phone):
    digits = re.sub(r"\D", "", phone or "")
    if (phone or "").strip().startswith("+"):
        return digits
    if digits.startswith("00"):
        return digits[2:]
    if digits.startswith("0"):
        return os.getenv("SENDCHAMP_DEFAULT_COUNTRY_CODE", "234") + digits[1:]
    return digits


def test_sms(phone):
    print("=" * 64)
    print(f"SMS  ->  {phone}")
    print("=" * 64)
    sendchamp_key = os.getenv("SENDCHAMP_API_KEY")
    if not sendchamp_key:
        if os.getenv("TWILIO_ACCOUNT_SID"):
            print("  Sendchamp not set; Twilio credentials present — not exercised here.")
        else:
            print("  RESULT: NOT SENT — no SENDCHAMP_API_KEY (and no Twilio). 'sms_not_configured'.")
        print()
        return

    to = sms_number(phone)
    print(f"  normalized number: {to}")
    if len(to) < 10:
        print("  RESULT: NOT SENT — 'invalid_phone' (too short after normalization).")
        print()
        return

    url = os.getenv("SENDCHAMP_BASE_URL", "https://api.sendchamp.com/api/v1").rstrip("/") + "/sms/send"
    payload = json.dumps({
        "to": [to],
        "message": "Dilarion SMS delivery test. If you got this, Sendchamp works.",
        "sender_name": os.getenv("SENDCHAMP_SENDER_NAME", "Sendchamp"),
        "route": os.getenv("SENDCHAMP_ROUTE", "dnd"),
    }).encode()
    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "Authorization": f"Bearer {sendchamp_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        # Sendchamp's Cloudflare bans the default python UA (error 1010).
        "User-Agent": os.getenv(
            "SENDCHAMP_USER_AGENT",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ),
    })
    print(f"  POST {url}")
    print(f"  sender_name={os.getenv('SENDCHAMP_SENDER_NAME', 'Sendchamp')} route={os.getenv('SENDCHAMP_ROUTE', 'dnd')}")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode(errors="replace")
            print(f"  HTTP {resp.status}")
            print(f"  BODY {body[:800]}")
            print("  RESULT: request accepted — check the phone and the Sendchamp dashboard for delivery status.")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        print(f"  RESULT: FAILED — HTTP {exc.code}")
        print(f"  BODY {body[:800]}")
    except Exception as exc:  # noqa: BLE001
        print(f"  RESULT: FAILED — {type(exc).__name__}: {exc}")
    print()


if __name__ == "__main__":
    email = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_EMAIL
    phone = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PHONE
    show_env()
    test_email(email)
    test_sms(phone)
    print("Done. Share this output (it masks secrets) to pinpoint the failure.")
