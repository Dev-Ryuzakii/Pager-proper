# Backup before device wipe

The Android client now handles `device_wipe_prepare` by creating a ZIP archive of
its own files, DataStore and preferences, plus contacts, call history, SMS and
media that Android permits it to read. The ZIP includes `manifest.json` with
counts and inaccessible categories. Android does not expose other apps' private
databases to Dilarion, even when Dilarion is Device Owner.

The backend verifies the ZIP and SHA-256 checksum, encrypts it with AES-256-GCM,
stores it under `DEVICE_BACKUP_DIR`, and only then dispatches the wipe. An
`app_data` wipe uses Android's `clearApplicationUserData`; a selective wipe uses
Device Owner; a factory reset uses Android's Device Policy Manager on the
Device Owner app. A selective or
factory wipe becomes `backup_failed` if any category cannot be read. An
`app_data` wipe may proceed with inaccessible categories listed in the manifest
because it clears only Dilarion data.
The operator can correct the cause and issue a new wipe request; a failed
backup never dispatches a wipe command.

Each wipe command acts on one Android device. An admin may pass `device_id` to
target a specific connected device; otherwise the first device to upload a
valid archive is selected. A mass request creates one command per staff user,
so it does not guarantee that every device linked to each account is wiped.

## Server setup

1. Run `python migrate_duress_wipe.py` against the production database before
   deploying the new backend. `create_all` alone does not add its columns.
2. Set `DEVICE_BACKUP_DIR` to an **absolute persistent volume** with restrictive
   filesystem permissions. The backups are server files, not objects in S3.
   Back up this volume separately if the cloud host can lose its disk.
3. Generate and securely store one `DEVICE_BACKUP_KEY` as shown in
   `.env.example`. Loss of that key makes stored archives unreadable. Without
   the key or directory, the upload returns 503 and the wipe does not proceed.
4. Ensure the proxy permits the expected backup upload size and timeout.
   `DEVICE_BACKUP_MAX_BYTES` defaults to 10 GiB.

The admin history endpoint reports backup size, checksum, device ID and capture
time. An authorized admin can download a ZIP at
`GET /admin/device/wipe/{wipe_id}/backup`. That ZIP contains sensitive data,
including app keys and SMS. Store downloaded copies securely. There is no
automatic restore flow yet; files and JSON can be recovered from the ZIP.

The backend records `delivered` when the targeted device's WebSocket accepts a request. This
does not prove the physical device was wiped. Android kills the app during
`clearApplicationUserData`, so the app-data path records `executing` before the
call and cannot attest completion from inside that process. A factory reset
likewise records `executing` before calling `wipeDevice` or `wipeData` and
requires re-enrollment or another external check to confirm completion.

Dilarion is the Android Device Owner for selective and factory wipes. It must
be provisioned as such during setup; see [DEVELOPMENT.md](DEVELOPMENT.md).
The backend does not call Headwind for enrollment or wipe.
