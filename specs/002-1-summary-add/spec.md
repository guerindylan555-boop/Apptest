# Feature Specification: Apps Library & Instrumentation Hub

**Feature Branch**: `002-1-summary-add`  
**Created**: 2025-10-12  
**Status**: Draft  
**Input**: User description: "Add a local-only “Apps” section to the web UI where the user can upload APKs, install & launch them on the rooted emulator, optionally start Frida, and access logcat/proxy tools with 30-day local retention."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Upload & Catalogue APK (Priority: P1)

A tester adds a new APK to the local library, reviews extracted metadata, and confirms it is retained for future use without affecting existing entries.

**Why this priority**: Without reliable intake and cataloguing, no downstream install, launch, or tooling actions are possible.

**Independent Test**: Drop a unique APK file into the Apps section and verify it appears in the library with all mandatory metadata populated and deduplicated if re-uploaded.

**Acceptance Scenarios**:

1. **Given** the tester is on the Apps page with the emulator available, **When** they upload a valid APK via drag-and-drop, **Then** the APK appears in the list with package name, version, SDK targets, launchable activity if detected, signer digest, file size, and upload time.
2. **Given** the library already contains the same APK hash, **When** the tester attempts to upload it again, **Then** the system surfaces the existing entry instead of duplicating storage while updating the “last used” timestamp.

---

### User Story 2 - Install & Launch From Library (Priority: P1)

A tester selects any stored APK and installs it on the rooted emulator, optionally forcing a downgrade and auto-granting runtime permissions, then launches the correct activity and sees status feedback.

**Why this priority**: Installing and launching apps is the core job the tester needs to accomplish after curating the library.

**Independent Test**: Choose an APK, trigger “Install & Launch,” and observe install status, launch status, and runtime permission handling without touching other tools.

**Acceptance Scenarios**:

1. **Given** an APK entry is selected, **When** the tester clicks “Install & Launch,” **Then** the system performs a reinstall to the emulator (respecting the downgrade toggle) and reports success or descriptive failure.
2. **Given** the install succeeds and the APK has a resolvable launchable activity, **When** the launch step runs, **Then** the target app is opened on the emulator and the UI reflects a “Launched” status; if no activity is resolvable, the system uses the documented MAIN/LAUNCHER fallback chain and records which path was used.

---

### User Story 3 - Instrument App With Frida (Priority: P2)

A tester activates Frida on the device, attaches to the running app, loads a chosen script, and monitors output to confirm instrumentation is active.

**Why this priority**: Frida integration is essential for dynamic analysis but can be delivered after install/launch flows exist.

**Independent Test**: Toggle Frida on, pick the launched package, inject a script from disk, and verify attach success and console output without engaging logcat or proxy tools.

**Acceptance Scenarios**:

1. **Given** the emulator is running and Frida is off, **When** the tester toggles Frida on, **Then** the system starts the matching frida-server, surfaces its status, and exposes available processes by package.
2. **Given** Frida is running and the target app is launched, **When** the tester selects the package and loads a script, **Then** the UI confirms attachment, runs the script, and displays recent stdout/stderr from Frida.

---

### User Story 4 - Observe Logs & Network (Priority: P2)

A tester reviews live logcat output scoped to the selected app and optionally routes traffic through a local proxy for capture.

**Why this priority**: Log and proxy controls support investigation but depend on app execution, so they follow installation capabilities.

**Independent Test**: Start logcat tail for the app, download a capture, toggle proxy on, and verify instructions for mitm certificate handling display.

**Acceptance Scenarios**:

1. **Given** an APK is selected, **When** the tester starts logcat with package filters, **Then** the viewer streams matching logs, allows pausing, and the tester can download the buffered capture.
2. **Given** the proxy toggle is off, **When** the tester enables it, **Then** the emulator is pointed to the local proxy endpoint, the UI shows active status, and guidance to trust the certificate is available without external calls.

---

### Edge Cases

- Uploading an APK while the daily retention sweep runs must preserve pinned items and avoid race conditions that delete fresh uploads.
- Installing an APK that requires a higher SDK than the emulator must fail gracefully with a clear warning, leaving the prior app state unchanged.
- Launch attempts for packages lacking launchable activities must record the fallback path used and stop after Monkey without entering an error loop.
- Frida server start failures (e.g., ABI mismatch, occupied port) must surface actionable error text and stop retries until the tester intervenes.
- Proxy toggle must revert emulator settings if the proxy is disabled or crashes to avoid orphaning test traffic.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST accept APK uploads via drag-and-drop and file picker, validate file type, compute SHA-256, and store files under a deduplicated path structure.
- **FR-002**: The system MUST extract and display metadata (package name, version code/name, min and target SDK, launchable activity if available, signer digest, file size, upload timestamp, last used timestamp, pin flag) using local tooling with fallbacks when aapt2 data is incomplete.
- **FR-003**: The system MUST maintain a searchable, sortable library view with row-level actions: Install & Launch, Rename display name, Pin/Unpin, Delete, and metadata preview.
- **FR-004**: The system MUST enforce a 30-day retention policy that removes unpinned APKs, metadata, and associated log captures during a scheduled sweep while respecting pinned items.
- **FR-005**: The system MUST install the selected APK on the single rooted emulator via a reinstall flow, honoring a user-provided toggle to allow version downgrades.
- **FR-006**: The system MUST launch the installed app, preferring explicit package/activity pairs; if unavailable, it MUST attempt MAIN/LAUNCHER resolution via package manager and finally a Monkey fallback, reporting which path succeeded or failed.
- **FR-007**: The system MUST optionally auto-grant runtime permissions post-install when the tester enables the toggle, reporting which permissions were granted or skipped.
- **FR-008**: The system MUST provide Frida controls to start/stop the device server, list running processes by package, attach to the chosen package, load a tester-supplied script, and show attachment plus script execution status with recent output.
- **FR-009**: The system MUST expose a logcat viewer scoped by package/tag filters with start, pause, resume, clear, and download actions, retaining captures alongside their originating APK entry.
- **FR-010**: The system MUST offer a proxy toggle that reconfigures the emulator to use a local host proxy endpoint, indicate active status, and provide instructions for installing the interception certificate; disabling the toggle MUST restore default emulator networking.
- **FR-011**: The system MUST log and display user-facing statuses for all major actions (upload, metadata extraction, install, launch, Frida operations, logcat, proxy) including success, failure reason, and timestamps.
- **FR-012**: The system MUST keep all services, file paths, and endpoints bound to 127.0.0.1, ensuring no remote exposure or outbound telemetry.

### Assumptions & Decisions

- Testers operate a single rooted emulator locally; multi-device orchestration is out of scope.
- Required tooling (ADB, aapt2, frida-server, mitmproxy) is pre-installed on the host and reachable by the application.
- APK metadata extraction failures default to displaying available fields with user-facing warnings instead of blocking ingestion.
- Retention sweeps run during low-activity periods (e.g., nightly) to minimize conflicts with uploads.

### Key Entities

- **APK Entry**: Represents a stored APK, tracking file path, SHA-256, metadata fields, pin flag, upload time, last used time, retention status, and associated resources (log captures, Frida scripts history).
- **Install Session**: Captures each install/launch attempt including selected APK, options (downgrade, auto-grant), resolution path, outcome, and timestamps for audit history.
- **Frida Session**: Records server state, attached package, script used, output log pointer, and last updated time to display current instrumentation context.
- **Log Capture**: Metadata about recorded logcat sessions including APK reference, filters applied, start/end times, storage location, and download status.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Testers can ingest and catalogue a new APK (including metadata extraction and dedupe) in under 30 seconds for files ≤200 MB, measured from upload start to library availability.
- **SC-002**: At least 95% of successful installs transition from “Install” click to “Launch confirmed” in ≤10 seconds when the emulator is already running.
- **SC-003**: 100% of Frida attach attempts provide clear success/failure feedback within 5 seconds of the tester submitting a script load request.
- **SC-004**: Logcat viewer sustains live filtering for a single app without exceeding 10% CPU utilization on reference hardware while capturing at least 5 minutes of logs.
- **SC-005**: Retention sweeps remove ≥99% of unpinned APKs and associated artifacts once they exceed 30 days while leaving all pinned entries untouched.
- **SC-006**: Usability research (or internal QA surveys) confirms 90% of testers can complete the full flow (upload → install → launch → Frida attach → log capture) without consulting engineering support.
