# Implementation Plan: Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

**Branch**: `001-web-ui-read` | **Date**: 2025-10-08 | **Spec**: `specs/001-web-ui-read/spec.md`
**Input**: Feature specification from `specs/001-web-ui-read/spec.md`

## Summary

Deliver a localhost-only SPA that can boot and stop the rooted Android emulator while rendering a low-latency, read-only video stream with actionable error handling; current black-screen behaviour shows the stream transport between scrcpy and the browser must be redesigned for compatibility.

## Technical Context

**Language/Version**: Node.js 20 LTS + TypeScript 5.x (backend + tooling), React 18 + Vite 5 (frontend)  
**Primary Dependencies**: Express 5, ws-scrcpy toolchain (wrapper + scrcpyws-client), Zustand, Media Source Extensions API  
**Storage**: N/A (runtime state held in memory)  
**Testing**: Backend Jest unit coverage for lifecycle/ticket logic + documented manual stream validation  
**Target Platform**: Localhost web UI in Chromium-based browsers on developer workstations  
**Project Type**: Web application with discrete `backend/` and `frontend/` packages  
**Performance Goals**: Stream latency ≤500 ms perceived, boot-to-stream ≤45 s, 1 Hz health polling  
**Constraints**: Localhost-only networking, read-only stream, resilient error messaging for lifecycle faults  
**Scale/Scope**: Single tester session, single emulator instance, single stream consumer

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Constitution skeleton lacks actionable principles; mark gating as NEEDS CLARIFICATION and proceed while awaiting governance updates (no conflicting mandates identified). Post-design review confirms planned changes stay within localhost-only scope and avoid introducing new persistence layers.

## Project Structure

### Documentation (this feature)

```
specs/001-web-ui-read/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
└── contracts/
```

### Source Code (repository root)

```
backend/
├── src/
│   ├── api/
│   ├── services/
│   ├── state/
│   └── types/
├── dist/
├── package.json
└── tsconfig.json

frontend/
├── src/
│   ├── components/
│   ├── hooks/
│   ├── services/
│   ├── state/
│   └── styles/
├── index.html
├── package.json
└── vite.config.ts

specs/001-web-ui-read/
├── plan.md
└── spec.md

var/log/autoapp/
└── backend.log
```

**Structure Decision**: Retain the existing `backend/` (Express + emulator orchestration) and `frontend/` (React SPA) projects; extend `specs/001-web-ui-read/` with the required planning artefacts to guide the streaming fix.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|--------------------------------------|
