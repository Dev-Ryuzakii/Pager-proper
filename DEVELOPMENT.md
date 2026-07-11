# Project Eagle One - Device Security & Management

## 1. Overview
Project Eagle One requires a dual-layered security approach:
 * **Layer 1 (MAM):** Application-level security (E2EE) for secure messaging and mission data.
 * **Layer 2 (MDM):** Device-level management (Headwind MDM) for remote sanitization, forensic extraction, and system-level security.

## 2. The "Unified Agent" Concept
Installing the E2EE app acts as the enrollment. The E2EE app functions as a System-Level Agent communicating with the Headwind MDM server behind the scenes.
 * **Logic:** When the E2EE app is installed, it requests Device Owner permissions via the Android Enterprise framework.
 * **Enrollment:** Once granted, the app automatically configures the Headwind MDM settings in the background. The soldier never has to manually configure the MDM—the E2EE app does it for them.

## 3. Implementation Roadmap
### Phase 1: Prototype (Manual Enrollment)
 * **Infrastructure:** Spin up a private instance of Headwind MDM on your sovereign server.
 * **Manual Setup:** For initial testing, perform a factory reset on test devices and use `afw#setup` to manually enroll them into your Headwind instance.
 * **Goal:** Verify that you can trigger a Wipe command from the Headwind dashboard and see the device respond instantly.

### Phase 2: Integration (Automated Enrollment)
 * **Agent Development:** Update your E2EE app to include a `DeviceAdminReceiver` class.
 * **Permission Request:** Add logic to the app that requests `BIND_DEVICE_ADMIN` and Device Owner status upon first launch.
 * **API Bridge:** Your app will contain a built-in "Headwind Connector" that passes the device's unique credentials to your MDM server automatically upon first successful login.

### Phase 3: Operational Workflow (The "Kill Switch")
 * **Trigger:** If the E2EE platform detects a security breach (e.g., geofence violation), the server sends a command to your app.
 * **Extraction:** Your app executes a background routine to encrypt and upload media/logs to your sovereign server.
 * **Sanitization:**
   * **Option A (App Wipe):** Your app clears its local SQLCipher database.
   * **Option B (Full Wipe):** Your app calls the Headwind API to trigger a full system factory reset.

## 4. Developer Toolkit
 * **Headwind MDM (Open Source):** Use this for your server-side C2 and device management.
 * **Android Enterprise APIs:** Use Google’s Management APIs to manage the device lifecycle.
 * **SQLCipher:** Use this for the local, encrypted storage of mission data within your E2EE app.
 * **Retrofit/OkHttp:** Use these in your Android app to handle the E2EE communication and the API calls to your MDM server.

---
*Note: Building the app as a Device Policy Controller (DPC) makes the E2EE app the "boss" of the device, binding the device to the Headwind MDM server without the soldier needing to touch any Android settings.*
