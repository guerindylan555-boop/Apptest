# Feature Specification: APK Upload & Install + Frida & Tooling (Local-Only)

**Feature Branch**: `002-apk-upload-install`
**Created**: 2025-10-09
**Status**: Draft
**Input**: User description: "Extend the local web app so a tester can: Upload an APK, validate it, and install/launch it on the single rooted emulator. Enable Frida instrumentation (start/stop frida-server on the emulator; show connection status). Capture traffic with a local mitmproxy and (optional) help install a system-trusted CA inside the emulator to handle apps with stricter trust settings. (Optional, toggle) Run a local static scan of the uploaded APK via MobSF and show a summary. Everything remains strictly localhost."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Upload, Verify, Install, and Launch APK (Priority: P1)

A security tester uploads an APK file, views its metadata and signing information, installs it on the emulator, and launches it to begin testing.

**Why this priority**: Without the ability to get an app running on the emulator, no security testing can occur. This is the foundational workflow.

**Independent Test**: Upload any valid APK, verify metadata is displayed (package name, version, SHA-256, signer info), click Install, then Launch, and confirm the app appears on the emulator screen.

**Acceptance Scenarios**:

1. **Given** the tester has a valid APK file, **When** they upload it via the UI, **Then** the system computes and displays SHA-256 hash, package name, version, and signing certificate info (issuer + cert SHA-256) within 3 seconds.
2. **Given** an APK is uploaded and verified, **When** the tester clicks Install, **Then** the APK is installed on the emulator with signature verification, and any installation errors (signature mismatch, insufficient storage, etc.) are displayed with the exact package manager error text.
3. **Given** an APK is successfully installed, **When** the tester clicks Launch, **Then** the app's main activity is auto-resolved and launched, becoming visible in the emulator stream within 20 seconds.
4. **Given** an APK is uploaded, **When** it is stored, **Then** a new project folder is created keyed by APK name and hash, and all artifacts (APK file, metadata JSON, logs) are organized under this project following 30-day retention rules.

---

### User Story 2 - Enable and Monitor Frida Instrumentation (Priority: P2)

A security tester enables Frida on the emulator to prepare for dynamic instrumentation, verifies version/arch compatibility, and sees clear connection status.

**Why this priority**: Frida instrumentation is a core capability for dynamic analysis, but it depends on having an app already installed and requires proper setup before use.

**Independent Test**: With the emulator running, click "Start Frida", verify the UI shows Running status with version/arch match indicators, confirm Frida server is listening on the expected port, then click "Stop Frida" and confirm clean teardown.

**Acceptance Scenarios**:

1. **Given** the emulator is running and rooted, **When** the tester clicks Start Frida, **Then** the system verifies root access, determines device architecture (x86_64), downloads/pushes the correct frida-server binary for the device arch and Frida version, starts the server process, and verifies it is listening on the expected port—all within 3 seconds.
2. **Given** Frida server is starting, **When** the operation completes successfully, **Then** the UI displays Running status, shows device architecture, displays frida-server version, displays host Frida client version, and shows a match/mismatch indicator.
3. **Given** Frida server is running, **When** the tester clicks Stop Frida, **Then** the server process is terminated cleanly, the UI updates to Stopped status, and the operation completes within 3 seconds.
4. **Given** a version/arch mismatch is detected during Frida start, **When** the error occurs, **Then** the UI displays Error status, shows the specific mismatch details (e.g., "Host client v16.1.0 vs Server v15.2.0"), and prompts the tester to fetch the correct server build with a specific link or command.

---

### User Story 3 - Capture and Analyze Network Traffic (Priority: P3)

A security tester enables traffic capture with mitmproxy, installs the proxy CA certificate system-wide on the emulator (when possible), and views HTTP(S) flows in the UI.

**Why this priority**: Traffic analysis is essential for security testing but depends on the app being installed and running, and requires CA setup which can be complex on modern Android.

**Independent Test**: Click "Start Traffic Capture", follow the guided CA install flow, launch an app that makes HTTPS requests, and confirm that flows appear in the UI with decrypted HTTPS traffic visible.

**Acceptance Scenarios**:

1. **Given** the emulator is running, **When** the tester clicks Start Traffic Capture, **Then** mitmproxy starts locally bound to 127.0.0.1, the emulator's network traffic is routed through it (via proxy config or iptables), and the UI updates to Running status within 2 seconds (excluding CA steps).
2. **Given** Traffic Capture is starting, **When** the tester clicks "Install Proxy CA (emulator)", **Then** the UI opens a guided helper that explains Android 14+ APEX trust store behavior, recommends the Magisk module approach for system CA installation on supported emulator setups, provides step-by-step instructions, and shows success/failure status after attempting installation.
3. **Given** Traffic Capture is running and CA is installed, **When** the app makes network requests, **Then** HTTP(S) flows are logged by mitmproxy and displayed in the UI with request/response details, timestamps, and status codes.
4. **Given** system CA installation fails on Android 14+, **When** the error is detected, **Then** the UI explains APEX constraints, indicates CA is installed as user-trusted only, and suggests using Frida-based pinning bypass scripts as an alternative for apps with strict trust requirements.
5. **Given** Traffic Capture is running, **When** the tester clicks Stop Traffic Capture, **Then** mitmproxy is stopped cleanly, traffic routing is restored to normal, and the UI updates to Stopped status.

---

### User Story 4 - Run Static Security Scan (Priority: P4) [OPTIONAL]

A security tester optionally runs a local MobSF static scan on an uploaded APK and views a summary of findings.

**Why this priority**: Static analysis provides valuable insights but is not required for the core workflow and can be run later or skipped entirely.

**Independent Test**: Upload an APK, enable the "Run MobSF" toggle or click a "Scan" button, wait for the scan to complete, and verify a summary is displayed with a link to the full local report.

**Acceptance Scenarios**:

1. **Given** an APK is uploaded and the MobSF feature is enabled, **When** the tester triggers a static scan, **Then** MobSF runs locally (Docker container or local install) in local-only mode (no external network calls), scans the APK, and generates a report.
2. **Given** a MobSF scan is in progress, **When** the scan completes, **Then** the UI displays a compact summary showing permissions requested, known trackers detected, potentially vulnerable libraries, and a link to the full local HTML report.
3. **Given** MobSF is not installed or fails to start, **When** the scan is triggered, **Then** the UI displays an error with clear instructions on how to install or troubleshoot MobSF locally.

---

### Edge Cases

- **APK upload with corrupted file**: If the uploaded file is not a valid APK (corrupted, wrong format, incomplete), the system detects this during verification and displays "Invalid APK file" with the specific error (e.g., "ZIP signature missing").
- **APK install signature verification failure**: If the APK signature cannot be verified or is invalid, ADB install fails and the exact package manager error is shown (e.g., "INSTALL_PARSE_FAILED_NO_CERTIFICATES").
- **Frida server version mismatch**: If the host Frida client version does not match the server version, the UI displays a warning and provides a link to download the matching server binary.
- **Frida start on non-rooted emulator**: If root access cannot be confirmed, Frida start fails immediately with "Emulator must be rooted" error.
- **CA install on Android 14+**: The guided helper installs the CA as user-trusted and immediately provides clear guidance on using Frida-based certificate pinning bypass scripts for apps with strict trust requirements, as this is the preferred approach over attempting complex Magisk-based system CA installation.
- **mitmproxy fails to start**: If port 8080 (or configured proxy port) is already in use, mitmproxy fails to start and the UI shows "Proxy port in use" with the port number.
- **App with Network Security Config pinning**: If the app uses certificate pinning or restrictive Network Security Configuration, the UI clarifies this limitation in the Traffic Capture panel and links to guidance on using Frida-based pinning bypass scripts (informational only, no code provided).
- **MobSF scan timeout**: If a MobSF scan takes longer than expected (>5 minutes for a typical APK), the UI displays a progress indicator and allows the tester to cancel and retry.
- **Multiple APKs for the same package**: If a tester uploads a new version of an already-uploaded APK (same package name but different version/hash), a new project folder is created with the new hash, and both versions are retained independently per the 30-day retention policy.

## Requirements *(mandatory)*

### Functional Requirements

#### APK Upload, Verification, and Project Management

- **FR-001**: The UI MUST provide an APK upload control that accepts .apk files up to 500 MB in size.
- **FR-002**: Upon upload, the system MUST compute the SHA-256 hash of the APK file within 3 seconds for typical APKs (<100 MB).
- **FR-003**: The system MUST extract and display package metadata: package name, version code, version name, minimum SDK version, and target SDK version.
- **FR-004**: The system MUST extract and display APK signing information: signing certificate issuer (DN), and SHA-256 hash of the signing certificate.
- **FR-005**: Each uploaded APK MUST create a new project folder named with a combination of package name and APK SHA-256 hash (e.g., `com.example.app_a1b2c3d4`).
- **FR-006**: All artifacts related to an APK (the APK file itself, metadata JSON, installation logs, Frida logs, traffic captures, scan reports) MUST be stored in the project folder.
- **FR-007**: Project folders MUST follow the 30-day retention policy defined in the constitution, with support for "pinning" a project to exempt it from automatic deletion.
- **FR-008**: APK files MUST be deduplicated by SHA-256 hash; if the same APK is uploaded twice, the system MUST reference the existing file rather than storing a duplicate.

#### APK Installation and Launch

- **FR-009**: The UI MUST provide Install and Launch buttons that are enabled/disabled based on current APK and app state.
- **FR-010**: Clicking Install MUST invoke `adb install` with signature verification enabled, and the system MUST surface any installation errors with the exact text from the package manager (e.g., `INSTALL_FAILED_INSUFFICIENT_STORAGE`, `INSTALL_PARSE_FAILED_NO_CERTIFICATES`).
- **FR-011**: Clicking Launch MUST auto-resolve the app's main (launcher) activity using `adb shell pm dump <package>` or equivalent, and launch it via `adb shell am start`.
- **FR-012**: If an app is already installed and the tester attempts to install a different version, the system MUST handle this as an update (or prompt for uninstall first if signatures mismatch).
- **FR-013**: The UI MUST provide an Uninstall button that invokes `adb uninstall <package>` and updates the UI state accordingly.
- **FR-014**: All APK install, launch, and uninstall operations MUST log detailed output to the project's logs directory with timestamps.

#### Frida Control and Version Management

- **FR-015**: The UI MUST provide a Frida panel with Start/Stop toggle controls.
- **FR-016**: Before starting Frida, the system MUST verify that the emulator is rooted by attempting `adb shell su -c id`; if this fails, Frida start MUST fail with "Emulator must be rooted" error.
- **FR-017**: The system MUST detect the device architecture (e.g., x86_64) via `adb shell getprop ro.product.cpu.abi`.
- **FR-018**: The system MUST determine the appropriate frida-server version to match the host Frida client version (e.g., if the host has frida-tools 16.1.0, use frida-server 16.1.0).
- **FR-019**: If the correct frida-server binary is not already cached locally, the system MUST download it from the official Frida GitHub releases for the detected architecture and version.
- **FR-020**: The system MUST push the frida-server binary to the emulator (e.g., `/data/local/tmp/frida-server`), set executable permissions via `adb shell chmod 755`, and start it via `adb shell su -c /data/local/tmp/frida-server &`.
- **FR-021**: After starting frida-server, the system MUST verify it is running by checking for the process (`adb shell ps | grep frida-server`) and confirming it is listening on the expected port (default 27042).
- **FR-022**: The Frida panel MUST display current status (Stopped/Starting/Running/Stopping/Error), device architecture, frida-server version, host Frida client version, and a visual indicator of whether versions match. The UI MUST NOT include hints about objection or other third-party Frida tools.
- **FR-023**: If host and server versions do not match, the UI MUST display a warning and provide a link or command to download the correct server binary.
- **FR-024**: Clicking Stop Frida MUST terminate the frida-server process via `adb shell su -c pkill frida-server`, verify termination, and update the UI to Stopped status within 3 seconds.
- **FR-025**: All Frida operations (start, stop, version checks, errors) MUST be logged to the project's logs directory.

#### Traffic Capture with mitmproxy and CA Installation

- **FR-026**: The UI MUST provide a Traffic Capture panel with Start/Stop toggle controls.
- **FR-027**: Clicking Start Traffic Capture MUST start a local mitmproxy instance bound to 127.0.0.1 on a configurable port (default 8080).
- **FR-028**: The system MUST configure the emulator to route traffic through the mitmproxy by setting the emulator's HTTP proxy (`adb shell settings put global http_proxy 127.0.0.1:8080`) or via iptables rules.
- **FR-029**: mitmproxy MUST be configured to log all HTTP(S) flows and store them in the project's artifacts directory.
- **FR-030**: The UI MUST display a summary of recent flows (method, URL, status code, timestamp) with the ability to view full request/response details.
- **FR-031**: The Traffic Capture panel MUST include a link "Install Proxy CA (emulator)" that opens a guided helper UI.
- **FR-032**: The CA install helper MUST detect the Android version on the emulator and provide version-specific guidance.
- **FR-033**: For Android 14+, the helper MUST explain the APEX trust store behavior, install the CA as user-trusted, and immediately suggest Frida-based certificate pinning bypass scripts as the primary approach for apps with strict trust requirements.
- **FR-034**: The CA install helper MUST install the mitmproxy CA certificate as user-trusted, report success or failure, and display the CA trust mode (User-Trusted).
- **FR-035**: The UI MUST provide clear guidance and links to Frida-based certificate pinning bypass techniques, as this is the preferred approach for handling apps with strict trust requirements on Android 14+ (informational only, no code implementation in v1).
- **FR-036**: The Traffic Capture panel MUST display current status (Stopped/Starting/Running/Stopping/Error), proxy port, CA trust status (Not Installed/User-Trusted/System-Trusted), and the number of captured flows.
- **FR-037**: Clicking Stop Traffic Capture MUST stop mitmproxy, restore the emulator's proxy settings to default, and update the UI to Stopped status within 2 seconds.
- **FR-038**: The UI SHOULD clarify that apps using certificate pinning or restrictive Network Security Configuration may not trust the proxy CA, and provide links to guidance on Frida-based pinning bypass (no code implementation required in v1).

#### Static Scan with MobSF (Optional)

- **FR-039**: The UI MUST provide a Static Scan panel with a "Run MobSF" button that is strictly opt-in (does not trigger automatically after upload).
- **FR-040**: When the tester clicks Run MobSF, the system MUST trigger a local-only static scan of the uploaded APK using a locally-installed MobSF instance (Docker container or native install).
- **FR-041**: The system MUST ensure MobSF runs in local-only mode with no external network access and no telemetry.
- **FR-042**: The UI MUST display scan progress and show a summary of findings when complete, including: requested permissions, detected trackers, known vulnerable libraries, and security score.
- **FR-043**: The UI MUST provide a link to the full local MobSF HTML report stored in the project artifacts.
- **FR-044**: If MobSF is not installed or fails to start, the UI MUST display a clear error message with installation/troubleshooting instructions.

#### Health and Status Monitoring

- **FR-045**: The UI MUST display a unified status panel showing: Emulator state (Running/Stopped/Error), APK installed (Yes/No with package name), App running (Yes/No with activity name), Frida status (with version info), Traffic Capture status (with CA trust mode), and last errors (timestamped).
- **FR-046**: The status panel MUST update in real-time or near-real-time (within 2 seconds of state changes) via polling or event-driven updates.
- **FR-047**: The UI MUST provide a link to "View local logs" that opens the project's log directory or a log viewer showing recent entries.

#### Events and Logging

- **FR-048**: The UI MUST provide an Events/Logs drawer or panel showing a human-readable timeline of operations: APK uploaded, verified, installed, launched, Frida started/stopped, Traffic Capture started/stopped, CA install attempts, scan started/completed, and all errors.
- **FR-049**: Each log entry MUST include a timestamp, operation type, status (success/failure), and relevant details.
- **FR-050**: Logs MUST be persisted to the project artifacts directory and follow the 30-day retention policy.

#### Security and Privacy

- **FR-051**: All endpoints and services (backend API, mitmproxy, MobSF) MUST bind to 127.0.0.1 only and MUST NOT be accessible from external networks.
- **FR-052**: The system MUST NOT send any telemetry, analytics, or data to third-party services.
- **FR-053**: The UI MUST display a reminder that testing must be authorized by the app owner, and that using these tools on apps without permission may violate laws or terms of service.
- **FR-054**: If credentials or sensitive data must be included in test scripts or configuration, they MUST be stored in the project's private directory and redacted from logs.

### Key Entities *(include if feature involves data)*

- **APK Project**: Represents an uploaded APK with metadata (package name, version, SHA-256 hash, signing info) and a directory for all related artifacts.
- **Frida Session**: Represents the state of Frida instrumentation (Stopped/Running/Error) with version information, process ID, and port.
- **Traffic Capture Session**: Represents the state of mitmproxy (Stopped/Running/Error) with port, CA trust status, and captured flow references.
- **MobSF Scan Result**: Represents the results of a static scan (permissions, trackers, vulnerabilities, score) with a link to the full report.
- **Event Log Entry**: Represents a single logged operation with timestamp, type, status, and details.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Testers can upload an APK and view complete metadata (SHA-256, package info, signing info) within 3 seconds for 95% of APKs under 100 MB.
- **SC-002**: Testers can complete the workflow Upload → Install → Launch for a typical APK within 25 seconds from upload start to app visible on emulator screen.
- **SC-003**: Frida instrumentation can be started from Stopped to Running (with version/arch verification) in under 3 seconds for 95% of attempts on a properly configured emulator.
- **SC-004**: Traffic Capture can be started and begin logging flows within 2 seconds (excluding CA installation time) for 95% of attempts.
- **SC-005**: The guided CA install helper successfully installs a user-trusted CA on 95% of emulator configurations and provides clear Frida-based pinning bypass guidance for apps with strict trust requirements on Android 14+.
- **SC-006**: MobSF static scans (when enabled) complete within 5 minutes for 90% of APKs under 50 MB and display a summary with at least permissions, trackers, and vulnerability count.
- **SC-007**: All errors (APK install failures, Frida version mismatches, proxy CA failures, MobSF errors) provide actionable messages and links to logs or troubleshooting steps within 2 seconds of detection.
- **SC-008**: The status panel reflects accurate system state (emulator, app, Frida, proxy) within 2 seconds of any state change for 99% of operations.

## Clarifications

### Session 2025-10-09

- Q: Should MobSF scanning happen automatically after every APK upload, or should it require explicit user action? → A: Strictly opt-in (manual trigger)
- Q: When the emulator runs Android 14+ and system CA installation is challenging due to APEX constraints, should the platform default to attempting Magisk-based CA installation, or should it skip CA installation and direct users to Frida-based pinning bypass techniques? → A: Prefer Frida pinning bypass by default
- Q: Should the UI include informational hints or links explaining how to use objection once Frida is running? → A: No, keep UI minimal

## Assumptions

- The emulator is already running and managed by the platform; this feature does not control emulator start/stop (that is a separate existing feature).
- The emulator is rooted and configured with Magisk or equivalent root solution, which is a requirement from the constitution.
- ADB is available on the host and accessible via localhost (127.0.0.1:5555 or similar).
- The host has sufficient resources to run mitmproxy and optionally MobSF (Docker) without degrading emulator performance.
- Frida client tools (frida, frida-tools) are installed on the host and accessible in the PATH or via known installation paths.
- Network connectivity is available for downloading frida-server binaries from GitHub releases (one-time per version/arch combination, then cached).
- For Android 14+ CA installation, the platform installs CAs as user-trusted and relies on Frida-based certificate pinning bypass techniques for apps with strict trust requirements, avoiding the complexity of Magisk-based system CA installation.
- MobSF (if used) is assumed to be locally installed (Docker preferred) and accessible via a localhost API endpoint; the platform does not install MobSF itself.
- Testers are authorized to test the APKs they upload; the platform does not enforce authorization but displays a legal/ethical use reminder.

## Dependencies

- **Emulator Lifecycle Management**: This feature depends on the existing emulator start/stop feature (001-web-ui-read) to ensure the emulator is running before APK operations can proceed.
- **ADB Tooling**: Requires Android Debug Bridge (adb) installed on the host and accessible to the backend.
- **Frida Client**: Requires frida and frida-tools installed on the host.
- **frida-server Binaries**: Requires network access to download architecture/version-specific frida-server binaries from GitHub releases (or a local mirror).
- **mitmproxy**: Requires mitmproxy installed on the host and accessible via command-line or API.
- **MobSF (Optional)**: Requires MobSF installed locally (Docker or native) with local-only API access enabled.
- **Root Access on Emulator**: Requires the emulator to be rooted (su command available) per the constitution.
- **Frida-based Pinning Bypass Techniques**: Testers should be familiar with or willing to learn Frida-based certificate pinning bypass techniques for testing apps with strict trust requirements on Android 14+.

## Risks & Mitigations

- **Risk**: Frida version mismatches between host client and device server cause instrumentation failures.
  **Mitigation**: Implement version detection and compatibility checks before starting Frida; provide clear error messages and links to download matching binaries.

- **Risk**: Apps with certificate pinning or strict Network Security Configuration prevent HTTPS interception even with user-trusted CA installed.
  **Mitigation**: Install CA as user-trusted and provide clear, prominent guidance on Frida-based certificate pinning bypass techniques. Set expectations that testers may need to manually apply Frida scripts for strict apps. Avoid complexity of Magisk-based system CA installation.

- **Risk**: Large APKs (>200 MB) slow down upload and verification, causing timeouts or UI freezes.
  **Mitigation**: Implement chunked uploads with progress indicators; run SHA-256 computation asynchronously; set reasonable upload size limits (500 MB) and display estimated processing time.

- **Risk**: mitmproxy port conflicts (8080 already in use by another service) prevent Traffic Capture from starting.
  **Mitigation**: Make the proxy port configurable; detect port conflicts on startup and display clear error with the conflicting port number; suggest alternative ports.

- **Risk**: MobSF scans take longer than expected (>5 minutes) for complex APKs, causing user frustration.
  **Mitigation**: Display progress indicators and scan stage information; allow scan cancellation; log detailed MobSF output for troubleshooting.

- **Risk**: Network Security Configuration or certificate pinning in apps prevents traffic interception even with CA installed.
  **Mitigation**: Clearly document this limitation in the UI; provide informational links to Frida-based pinning bypass techniques; do not implement bypass in v1 (out of scope per constitution).

- **Risk**: Insufficient disk space for storing APKs, scan reports, and traffic captures.
  **Mitigation**: Monitor disk usage; enforce 30-day retention policy with automatic cleanup; allow pinning for important projects; display disk usage warnings in the UI.
