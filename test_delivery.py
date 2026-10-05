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


def test_email(to_email):
    print("=" * 64)
    print(f"EMAIL  ->  {to_email}")
    print("=" * 64)
    resend_key = os.getenv("RESEND_API_KEY")
    smtp_host = os.getenv("SMTP_HOST") or ("smtp.resend.com" if resend_key else None)
    smtp_user = os.getenv("SMTP_USERNAME") or ("resend" if resend_key else None)
    smtp_password = os.getenv("SMTP_PASSWORD") or resend_key
    from_email = os.getenv("SMTP_FROM") or os.getenv("RESEND_FROM_EMAIL")

    missing = [n for n, v in [
        ("SMTP_HOST/RESEND_API_KEY", smtp_host),
        ("SMTP_USERNAME/RESEND_API_KEY", smtp_user),
        ("SMTP_PASSWORD/RESEND_API_KEY", smtp_password),
        ("SMTP_FROM/RESEND_FROM_EMAIL", from_email),
    ] if not v]
    if missing:
        print("  RESULT: NOT SENT — configuration incomplete.")
        print("  Missing:", ", ".join(missing))
        print("  (This is exactly why the server logs 'configuration is incomplete'.)")
        print()
        return

    port = int(os.getenv("SMTP_PORT", "465" if smtp_host == "smtp.resend.com" else "587"))
    use_ssl = os.getenv("SMTP_SSL", "1" if port in (465, 2465) else "0") == "1"
    use_starttls = os.getenv("SMTP_STARTTLS", "0" if use_ssl else "1") == "1"
    print(f"  host={smtp_host} port={port} ssl={use_ssl} starttls={use_starttls} user={smtp_user}")
    print(f"  from={from_email}")

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
    msg.set_content("This is a Dilarion email delivery test. If you received it, SMTP works.")

    try:
        smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        kwargs = {"timeout": 20}
        if use_ssl:
            kwargs["context"] = ssl.create_default_context()
        with smtp_class(smtp_host, port, **kwargs) as server:
            server.set_debuglevel(1)
            if use_starttls:
                server.starttls(context=ssl.create_default_context())
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        print("  RESULT: SENT OK — check the inbox (and spam).")
    except Exception as exc:  # noqa: BLE001
        print(f"  RESULT: FAILED — {type(exc).__name__}: {exc}")
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
