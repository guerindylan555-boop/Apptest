# Implementation Plan: Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

**Branch**: `001-web-ui-read` | **Date**: 2025-10-08 | **Spec**: [/specs/001-web-ui-read/spec.md](/specs/001-web-ui-read/spec.md)
**Input**: Feature specification from `/specs/001-web-ui-read/spec.md`

## Summary

Deliver a localhost-only experience that lets a solo tester start and stop a single rooted Android 14 emulator, observe its screen through a read-only ws-scrcpy stream, and monitor lifecycle state. The solution pairs a minimal Express-based backend orchestrating Android SDK tooling (emulator, adb, console kill) with a Vite/React single-page UI that consumes local HTTP endpoints and embeds the ws-scrcpy player (defaulting to WebCodecs) inside an iframe with input disabled. Research confirms the use of deterministic headless emulator flags, robust boot/readiness gating, and safe shutdown fallbacks aligned with v1 constitutional constraints. A convenience launcher script (`scripts/run-everything.sh`) handles process orchestration and cleanup during local development.

## Technical Context

**Language/Version**: Node.js 20 LTS with TypeScript 5.x for backend and frontend tooling  
**Primary Dependencies**: Express 4 (backend API), ws-scrcpy (streamer service + browser client), axios/fetch for HTTP polling, Zustand (lightweight state store), Android SDK CLI tools (sdkmanager, avdmanager, emulator, adb), pm2/nodemon for local orchestration scripts  
**Storage**: N/A (in-memory state plus filesystem logs only)  
**Testing**: Vitest + Supertest for backend integration, Playwright component tests for the SPA (read-only checks)  
**Target Platform**: Ubuntu 25.04 host (desktop) with single user  
**Project Type**: Local web + CLI tooling (backend + frontend)  
**Performance Goals**: Stream latency ≤500 ms; emulator boot-to-stream ≤45 s; health polling ≤1 s drift from backend state  
**Constraints**: Services must bind to `127.0.0.1`; exactly one emulator instance; memory footprint <6 GB incremental; no external network access during runtime  
**Scale/Scope**: Single user, single emulator session, one browser client at a time

## Constitution Check

- ✅ Local-Only Networking: backend, streamer, and UI all listen on `127.0.0.1` and refuse external binds.
- ✅ Single Device Focus: plan enforces one named AVD and mutex guard around start/stop operations.
- ✅ Rooted Emulator Access: AVD profile uses rooted Android 14 (API 34) image; adb restricted to localhost.
- ✅ Stable Replay Discipline: readiness gating via `adb wait-for-device` + `getprop sys.boot_completed`; stop flow captures logs and exposes force-stop per spec.
- ✅ Project Isolation: Artifacts/logs scoped under `var/projects/<apk-hash>` (future reuse) and not shared.
- ✅ Data Lifecycle Stewardship: Logs retained locally with existing cleanup tooling; no cross-project leakage.
- ✅ No AI in Runtime / Zero External Security Tooling: Implementation avoids AI assistants and excludes Frida/MobSF integrations.

Post-design review confirms all gates remain satisfied; no exceptions required.

## Project Structure

### Documentation (this feature)

```
specs/001-web-ui-read/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
└── tasks.md  # created by /speckit.tasks
```

### Source Code (repository root)

```
backend/
├── src/
│   ├── api/          # Express route handlers (health, start, stop, stream ticket)
│   ├── services/     # Emulator + streamer orchestrators (adb/emulator wrappers)
│   ├── state/        # In-memory state machine + logging utilities
│   └── cli/          # Setup scripts (AVD creation, diagnostics)
└── tests/
    ├── integration/  # API + process orchestration tests via Supertest + mocked CLI
    └── unit/         # State machine, timers, token utilities

frontend/
├── src/
│   ├── components/   # StreamViewer, StateBadge, ControlButton, DiagnosticsDrawer
│   ├── hooks/        # useHealthPoller, other polling utilities
│   ├── services/     # REST clients (fetch wrappers)
│   └── styles/
└── tests/
    ├── component/    # Vitest + Testing Library for UI states
    └── e2e/          # Playwright happy-path smoke (start/stop w/ mocked backend)

scripts/
├── setup-avd.sh      # Idempotent Android SDK/AVD provisioning
├── run-local.sh      # Legacy per-service launcher (kept for granular debugging)
└── run-everything.sh # Primary orchestration script that cleans stale processes and starts ws-scrcpy + backend + frontend
```

**Structure Decision**: Adopt a two-project layout (`backend/`, `frontend/`) to separate Express orchestration logic from the SPA. Supporting scripts live under `scripts/` for repeatable setup and dev workflows.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| *(none)* | | |
