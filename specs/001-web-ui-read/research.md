# Phase 0 Research — Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

## Decision: Use Node.js 20 + Express for the local backend orchestrator
- **Rationale**: Node.js already required for ws-scrcpy, allowing a single runtime for API and streaming supervision. Express provides lightweight routing, integrates with child_process utilities for emulator control, and keeps the stack consistent with the frontend tooling.
- **Alternatives considered**:
  - *Python (FastAPI)* — strong async support but introduces an extra runtime and packaging overhead alongside Node.
  - *Go microservice* — excellent concurrency but unnecessary compilation/toolchain complexity for a single user workflow.

## Decision: Manage emulator lifecycle via Android CLI (sdkmanager → avdmanager → emulator) with deterministic flags
- **Rationale**: Headless flags `-no-window -no-boot-anim -no-snapshot-load` deliver faster, consistent startup in local pipelines and align with constitution resource targets. Leveraging official CLI ensures compatibility with rooted system images and simplifies scripted setup.
- **Alternatives considered**:
  - *GUI-driven emulator launch* — violates headless requirement and complicates automation.
  - *Third-party emulator wrappers* — risk of hidden telemetry or network exposure; out of scope for v1.

## Decision: Gate readiness with `adb wait-for-device` plus `adb shell getprop sys.boot_completed`
- **Rationale**: `wait-for-device` alone fires before the launcher is ready; checking `sys.boot_completed` is the de facto pattern in CI to guarantee the home screen is responsive before enabling streaming. Ensures compliance with stable replay discipline.
- **Alternatives considered**:
  - *Fixed sleep duration* — brittle across host performance profiles and conflicts with constitution timing principles.
  - *Polling `getprop dev.bootcomplete` only* — some images report it earlier; combining both is more reliable.

## Decision: Integrate ws-scrcpy in read-only mode with single-use stream tokens
- **Rationale**: ws-scrcpy supplies an in-browser scrcpy client, allows disabling control channel messages to prevent input injection, and runs entirely on localhost. Tokens (random UUID mapped to emulator serial) guard against stale connections even on a single user box.
- **Alternatives considered**:
  - *Native scrcpy desktop app with window capture* — requires additional UI bridging and cannot embed into the SPA.
  - *WebRTC streamer* — higher integration effort and requires extra signaling; ws-scrcpy already optimized for scrcpy workloads.

## Decision: Prefer console kill → `adb emu kill` → process group kill for shutdown ladder
- **Rationale**: Console kill is the supported clean shutdown path; `adb emu kill` covers scenarios where console authentication fails, and process group termination ensures no orphaned emulator remains. UI surfaces Force Stop when ladder escalates, matching clarified requirements.
- **Alternatives considered**:
  - *Only use process kill* — fastest but risks data corruption and noisy logs.
  - *Rely solely on adb emu kill* — known to hang when console auth tokens rotate; insufficient as the only strategy.

## Decision: Expose backend health with enriched diagnostics payload
- **Rationale**: Including AVD name, PID, boot duration, and last error in `/health` supports UI messaging and local troubleshooting without external tooling. Aligns with observability requirements and keeps data local.
- **Alternatives considered**:
  - *Minimal `state` string only* — simpler but forces testers to inspect logs manually for recovery steps.
  - *Full log streaming endpoint* — overkill for v1 and risks leaking large payloads into the UI.
