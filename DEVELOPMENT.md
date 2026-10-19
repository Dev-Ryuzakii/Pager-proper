# Dilarion Android device management

Dilarion is the Android Device Policy Controller (DPC) for fully managed phones.
Headwind is not in the enrollment or wipe path. The backend records the state
reported by the Android app and delivers commands; Android's DevicePolicyManager
grants and enforces Device Owner privileges on the phone.

## Provision a phone

Device Owner cannot be requested by a normally installed app after setup. Use a
new or factory-reset, organization-owned phone. Build and sign the production
APK, host that exact APK at a stable HTTPS URL, and create an Android setup QR
payload with `python3 scripts/managed_device_qr.py <signed-apk> <https-url> --png setup.png`
in the Kotlin app repository (install `qrcode[pil]` for PNG output). At the initial
Android welcome screen, tap six times, connect to the network, and scan it.
Android downloads the APK, verifies its SHA-256, and provisions Dilarion as
Device Owner. The app handles `GET_PROVISIONING_MODE` and
`ADMIN_POLICY_COMPLIANCE` on Android 12 and newer.

For a development-only phone with no accounts or existing owner, install the
APK and run:

```sh
adb shell dpm set-device-owner com.dilarion.app/.device.DilarionDeviceAdminReceiver
```

After setup, sign in to Dilarion. Its monitoring service registers the Android
device ID, model, app version, and `isDeviceOwnerApp()` result using
`POST /api/v1/mdm/devices`. The admin can inspect these reports with
`GET /admin/mdm/devices`. This is a report from the authenticated app, not
hardware attestation. The app checks Device Owner again locally before a
selective wipe or factory reset.

Run `python migrate_managed_android_devices.py` before deploying the new API.
The old `mdm_device_profiles` table is retained only for historical rows.
The old Headwind connector is no longer called by the backend.

## Wipe

See [DEVICE_WIPE_BACKUP.md](DEVICE_WIPE_BACKUP.md). Admin wipe requests target
one Android device. The phone backs up accessible data, the server verifies and
encrypts the archive, and only then sends the wipe. Factory reset uses Android
`DevicePolicyManager` from Dilarion itself. A missing backup, failed Device
Owner check, or Android permission problem stops the requested wipe and reports
the failure.

Physical-device provisioning and wipe behavior must be verified on a test
phone before operational use. A factory reset requires re-provisioning the
phone; the backend cannot confirm completion after Android terminates the app.
