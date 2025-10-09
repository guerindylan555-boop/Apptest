# Implementation Plan: APK Upload & Install + Frida & Tooling

**Branch**: `002-apk-upload-install` | **Date**: 2025-10-09 | **Spec**: [spec.md](./spec.md)

## Summary

Extend the existing web UI (from feature 001) to support APK upload/install/launch workflows, Frida instrumentation control, mitmproxy traffic capture with user-trusted CA installation, and optional MobSF static scanning—all strictly opt-in and localhost-only per constitution v1.1.0.

## Technical Context

**Language/Version**: TypeScript 5.x (frontend), Node.js 20.x (backend)
**Primary Dependencies**: React 18, Express, AndroidSDK CLI tools, mitmproxy, frida-tools
**Storage**: Filesystem (project folders per APK hash), no database required
**Testing**: Jest + React Testing Library (frontend), Jest (backend)
**Target Platform**: Ubuntu 25.04, localhost-only web application
**Project Type**: Web (existing backend/ + frontend/ structure from 001)
**Performance Goals**: <3s APK metadata extraction, <2s service start/stop
**Constraints**: Localhost-only (127.0.0.1), single emulator, 30-day retention
**Scale/Scope**: Single user, ~50-100 APKs per project lifecycle

## Constitution Check

✅ **I. Local-Only Networking** - All endpoints bind to 127.0.0.1
✅ **II. Rooted Emulator (Single Device)** - Frida/ADB require root; single device maintained
✅ **III. Element-Aware Automation** - Not applicable (no recording/replay in this feature)
✅ **IV. Stable Replay** - Not applicable
✅ **V. Project Separation** - Each APK gets isolated project folder by hash
✅ **VI. Data Lifecycle** - 30-day retention with pinning support required
✅ **VII. No AI in v1** - No LLM features
✅ **VIII. External Security Tooling (Opt-In)** - Frida, MobSF, mitmproxy all strictly opt-in with clear UI controls

**Gates PASSED** - No violations. Proceed to Phase 0.

## Project Structure

### Documentation (this feature)

```
specs/002-apk-upload-install/
├── spec.md
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── backend-api.yaml # Phase 1 output
└── checklists/
    └── requirements.md
```

### Source Code (extends existing 001 structure)

```
backend/
├── src/
│   ├── api/routes/
│   │   ├── apkUpload.ts         # NEW: APK upload/verification
│   │   ├── apkInstall.ts        # NEW: Install/launch/uninstall
│   │   ├── fridaControl.ts      # NEW: Start/stop Frida server
│   │   ├── trafficCapture.ts    # NEW: mitmproxy control
│   │   ├── caInstall.ts         # NEW: Proxy CA installation helper
│   │   └── mobsfScan.ts         # NEW: Optional static scan
│   ├── services/
│   │   ├── apkManager.ts        # NEW: APK parsing, project creation
│   │   ├── fridaService.ts      # NEW: Frida version/arch matching
│   │   ├── mitmproxyService.ts  # NEW: Proxy lifecycle
│   │   └── mobsfService.ts      # NEW: MobSF Docker orchestration
│   ├── state/
│   │   └── projectStore.ts      # NEW: In-memory project state
│   └── types/
│       └── apk.ts               # NEW: APK metadata types
└── tests/
    └── services/                # NEW: Service unit tests

frontend/
├── src/
│   ├── components/
│   │   ├── ApkUploader.tsx      # NEW: File upload + metadata display
│   │   ├── ApkControls.tsx      # NEW: Install/Launch/Uninstall buttons
│   │   ├── FridaPanel.tsx       # NEW: Frida start/stop + status
│   │   ├── TrafficCapturePanel.tsx # NEW: Proxy control + CA helper
│   │   ├── MobSFPanel.tsx       # NEW: Optional scan trigger + results
│   │   └── StatusPanel.tsx      # NEW: Unified system status
│   ├── hooks/
│   │   └── useProjectState.ts   # NEW: Project/tool state management
│   └── services/
│       └── apkClient.ts         # NEW: APK API client
└── tests/
    └── components/              # NEW: Component tests
```

**Structure Decision**: Web application (Option 2). Extends existing backend/frontend from feature 001. APK-related routes and services are net-new; emulator lifecycle (from 001) is a dependency.

## Complexity Tracking

*No constitution violations - this section intentionally left empty.*
