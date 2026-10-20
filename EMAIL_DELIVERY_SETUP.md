# Email delivery with two Resend accounts

Set these values in the environment read by `pager_backend` (commonly
`~/Pager-proper/.env`). Use keys from **different Resend accounts**. Two keys
from one account share the same account quota and will not double capacity.
Each sender address must be authorized in its corresponding account.

If Resend is configured directly, use:

```dotenv
RESEND_API_KEY=re_FIRST_ACCOUNT_KEY
RESEND_FROM_EMAIL=notifications@first-verified-domain.example
RESEND_API_KEY_2=re_SECOND_ACCOUNT_KEY
RESEND_FROM_EMAIL_2=notifications@second-verified-domain.example
```

If the first account is already configured as SMTP with
`SMTP_HOST=smtp.resend.com` and `SMTP_PASSWORD` containing its key, keep that
configuration and add only `RESEND_API_KEY_2` and `RESEND_FROM_EMAIL_2`.
Do not remove a separate non-Resend SMTP provider unless you intend to stop
using it: a configured SMTP provider remains first in the delivery order.

The backend alternates the two Resend accounts for email requests and tries
the other account if the first attempt fails. It creates one admin-visible log
record per requested email, with `pending`, `sent`, or `failed` status, and
does not expose credentials or provider names on that page. `sent` records
SMTP acceptance; it is not proof of inbox delivery. Resend applies its own
daily and monthly account limits. This rotation does not guarantee 200 sends
if either account has already used quota elsewhere, its sender is unverified,
or the provider declines an email.

After editing the environment, restart the backend and check that both
providers are recognized without printing secrets:

```bash
sudo systemctl restart pager_backend
cd ~/Pager-proper
venv/bin/python - <<'PY'
from fastapi_mobile_backend_postgresql import _email_providers
print([(name, host, from_email) for name, host, _, _, _, _, _, from_email in _email_providers()])
PY
```

The output should include two `resend` entries with the intended sender
addresses. If the second one is missing, check that both `_2` variables are
visible to the service and that the second key is not identical to the first.
Use the superadmin delivery test and the Email Logs page to verify an actual
send and inspect any failure reason.
