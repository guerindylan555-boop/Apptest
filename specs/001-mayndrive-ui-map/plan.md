# Implementation Plan: MaynDrive State-Aware UI Mapping

**Branch**: `001-mayndrive-ui-map` | **Date**: 2025-10-25 | **Spec**: [spec.md](./spec.md)  
**Input**: Feature specification from `/specs/001-mayndrive-ui-map/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

Build a MaynDrive-specific manual discovery toolkit that captures emulator screens, produces a deterministic UI graph (nodes, edges, artifacts), and executes declarative flows (login, unlock, lock) with state-aware routing plus recovery. Implementation will extend the existing Node.js 20 TypeScript backend, React/Vite frontend, and filesystem-based artifact store so operators can capture signatures, LLMs can reason over lightweight JSON/YAML outputs, and runners can pathfind plus re-detect screens after every action.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: TypeScript 5.x on Node.js 20 (backend tooling + frontend Vite React 18).  
**Primary Dependencies**: Express 4 API, Zustand store, axios/fetch polling, Dockploy-managed Docker Compose stack, Android emulator via WebRTC/ADB/Frida hooks.  
**Storage**: Local filesystem under `var/` with JSON indexes + artifact bundles (screenshots, XML dumps); no new database introduced.  
**Testing**: `npm test` (Jest/ts-jest) plus `npm run lint` per repo standards for backend/frontend packages.  
**Target Platform**: Containerized services (backend, frontend, emulator bridge) orchestrated via Docker Compose in Dockploy, accessible through Traefik ingress.  
**Project Type**: Web control plane (backend + frontend) with Android automation helpers and CLI tooling.  
**Performance Goals**: Capture action turns <30s, detector classification <2s per dump, flow execution with ≤1 manual intervention in 95% runs (per success criteria).  
**Constraints**: Must honor Constitution §2 (containers only, pinned Node 20 images), §4 (native WebRTC bridge, no ws-scrcpy), §7 (centralized artifact volume), §9 (TS strict, CI-blocking lint), and §12 (document any new env vars).  
**Scale/Scope**: Focused on a single target app (MaynDrive) with ~20-40 screens initially, three baseline flows, and extensibility for future apps post-validation.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Compliance Notes |
|-----------|------------------|
| §1 Identity & Workflow | Working on spec-derived branch `001-mayndrive-ui-map`; plan will reference spec.md/plan.md/tasks.md ensuring full SDD traceability. |
| §2 Runtimes & Packaging | Feature reuses existing Docker Compose services (backend `node:20-slim`, frontend `node:20-slim` builder + `nginx:alpine` runtime) and will introduce no bare-metal daemons. |
| §3 Dockploy & Ingress | No new public ingress; any new endpoints remain behind Traefik-managed backend routes. |
| §4 Streaming Path | Plan explicitly extends the native WebRTC bridge (Envoy + emulator) and will not resurrect legacy `ws-scrcpy` tooling. |
| §7 Captures & Artifacts | Screen artifacts stored within the shared volume (`var/`) with retention metadata to satisfy single-volume mandate. |
| §9 Tooling & Quality | All TypeScript deliverables must compile under strict mode and pass lint/tests before merge. |
| §12 Config Surface | Any new env/config options (e.g., detector thresholds) must be added to `CONFIG.md` and Docker compose definitions. |

**Gate Result**: PASS – all applicable constitutional requirements acknowledged with implementation hooks planned.

**Post-Design Check (Phase 1)**: PASS – research outcomes, data model, contracts, quickstart, and agent-context updates add no new services or ingress and keep artifacts inside the mandated `var/` volume, so §§2, 4, 7, 9, 12 remain satisfied.

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
backend/
├── src/
│   ├── api/                  # Express routes + controllers
│   ├── services/             # Device control, capture utilities
│   ├── state/                # Zustand-compatible stores
│   ├── config/               # Dockploy + WebRTC config surfaces
│   └── utils/
└── tests/
    ├── integration/
    └── unit/

frontend/
├── src/
│   ├── components/           # Capture panels, flow builder UI
│   ├── pages/
│   ├── stores/               # Zustand slices for UI graph
│   └── services/             # API clients (axios/fetch)
└── tests/

var/
├── captures/                 # Screenshots, XML dumps (existing)
├── graphs/                   # JSON UI graph snapshots (to be extended)
└── flows/                    # YAML/JSON flows + README artifacts

scripts/                      # CLI automation helpers (ADB, capture)
.specify/                     # Specs/plan/tasks automation tooling
```

**Structure Decision**: Continue using the existing backend/frontend split with shared `var/` storage. New UI graph stores, flow definitions, and README content will live under `var/` (for artifacts) and `specs/001-mayndrive-ui-map` (for governance). Backend services expose REST/WS endpoints consumed by the React frontend, and CLI scripts under `scripts/` orchestrate emulator/ADB helpers.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|

No constitutional violations currently require tracking.
