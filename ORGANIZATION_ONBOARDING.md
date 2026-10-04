# Organization provisioning and onboarding

Dilarion now provisions regular users through an organization request. Public
self-registration is disabled.

## Flow

1. An organization submits `POST /organization-requests` with its contact and
   the username/password it wants for its read-only organization portal. The
   password is bcrypt-hashed immediately and is never returned by an API.
2. An authenticated platform admin reviews pending requests with
   `GET /admin/organization-requests` and approves one with
   `POST /admin/organization-requests/{id}/approve`.
3. Approval creates the organization and its read-only portal account. The
   organization can sign in at `POST /organization/auth/login` and use only
   `GET /organization/me` and `GET /organization/users`; it has no staff
   management permissions.
4. A platform admin/operator creates an organization directly when needed with
   `POST /admin/organizations`, then adds staff only after the organization
   exists with `POST /admin/organizations/{id}/users`. Every staff entry needs
   `email`, `full_name`, `phone_number`, and `department`. Email and SMS
   invitations are queued for those staff members.
5. A staff user follows the one-time link and calls `POST /auth/activate` with the
   invitation code and a private token they chose. Only a bcrypt hash is stored.
6. The returned session is limited to `POST /auth/onboarding/profile` until the
   user provides their job title, address, emergency contact, and a fresh camera
   capture. The capture must include a recent `captured_at` timestamp and
   `camera_attestation=true`; ordinary profile upload is unavailable before this
   step is complete.

Organization portal accounts are deliberately blocked from the regular/mobile
API. After staff onboarding, directory results, direct messaging, calls, media, public
keys, profile photos, groups, invite links, typing events, and conversation
lists enforce the user's organization boundary.

## Notification configuration

Email uses SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_STARTTLS`, `SMTP_USERNAME`,
`SMTP_PASSWORD`, `SMTP_FROM`). SMS uses Twilio
(`TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`). Set
`DILARION_APP_URL` to the mobile app's activation deep-link or HTTPS URL.

Delivery timestamps and provider-neutral errors are stored per user. Provider
secrets and invitation values are never stored in those status fields.

## Deployment

Run the schema migration before starting the updated API:

```bash
python migrate_organization_tenancy.py
```

Existing accounts are kept as legacy/unassigned accounts. New regular accounts
must be attached to an organization.
