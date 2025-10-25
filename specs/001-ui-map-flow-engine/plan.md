# Implementation Plan: AutoApp UI Map & Intelligent Flow Engine

**Branch**: `001-ui-map-flow-engine` | **Date**: 2025-10-25 | **Spec**: `/specs/001-ui-map-flow-engine/spec.md`
**Input**: Feature specification from `/specs/001-ui-map-flow-engine/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

Implement an end-to-end system that captures Android UI states from the emulator stream, persists a deduplicated UI Transition Graph (UTG) in JSON, enables flow authoring against those states, and replays flows with state recovery. Delivery spans the Express backend (ADB/UIAutomator2 orchestration + graph persistence), the React/Vite dashboard (discovery/flow UI + telemetry), and supporting automation scripts/CLI tooling, all within the existing containerized stack.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: Node.js 20 + TypeScript 5.x (backend/tooling), React 18 + Vite (frontend), UIAutomator2 scripts on Android API ≥26  
**Primary Dependencies**: Express 4 API, Zustand state store, android-emulator-webrtc bridge, UIAutomator2/ADB pipelines, JSON artifact storage under `var/autoapp`  
**Storage**: Version-controlled JSON artifacts (graphs, flows, sessions) plus screenshots/logs under `var/autoapp/{graphs,flows,logs,screenshots}`  
**Testing**: ESLint/Prettier gates + emulator-driven integration scenarios for graph capture/flow replay + remote access validation via Dockploy. Integration tests run within containers but validate full remote workflow through Traefik proxy.  
**Target Platform**: Containerized services (backend Node API, frontend static bundle, Android emulator + Envoy + Traefik as ingress)  
**Project Type**: Multi-service web + automation stack (frontend dashboard, backend orchestration service, CLI automation scripts)  
**Performance Goals**: ≥95% dedup accuracy, flow validation <2s for ≤50 states/100 transitions, replay localization <1s, WebRTC ≥720p@15fps, recovery success ≥80% (per spec SC-001..SC-006 & NFR-006)  
**Constraints**: Graph size capped at 500 states/2000 transitions, containers only with pinned images (Constitution §2), Traefik-only ingress (§3), WebRTC env vars + 1500ms timeout (§4), JSON compatibility across versions (NFR-004), config via env vars (§12)  
**Scale/Scope**: Single MaynDrive target app with up to 500 discovered states, dozens of flows (login/unlock/lock) shared among researchers

**Remote Access Model**: All services accessible through Dockploy domain
- Frontend: https://your-domain.com (Traefik :5173)
- Backend APIs: https://your-domain.com/api/* (Traefik :3001)
- WebRTC: https://your-domain.com:9000 (Traefik proxy to emulator)
- No localhost-only services; all properly exposed for remote automation

**MaynDrive Configuration**:
- `MAYNDRIVE_PACKAGE`: com.mayndrive.app (default)
- `MAYNDRIDE_MAIN_ACTIVITY`: com.mayndrive.app.MainActivity (default)
- `MAYNDRIDE_LAUNCH_TIMEOUT`: 10000ms (default)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

1. **Containers only (Const. §2)** – All new services/scripts run inside the existing docker-compose stack; no host binaries introduced.  
2. **Traefik ingress (Const. §3)** – Frontend remains proxied via Traefik on :5173; backend/Envoy stay internal. New endpoints expose only through internal network.  
3. **WebRTC env contract (Const. §4)** – Replay/capture features will read `EMULATOR_WEBRTC_PUBLIC_URL`, `EMULATOR_WEBRTC_ICE_SERVERS`, `EMULATOR_GRPC_ENDPOINT` and respect the 1500 ms timeout for health.  
4. **Logging & health (§10)** – Backend additions emit structured JSON logs (`service,event,severity,trace_id`) and honor `/healthz` performance budget <500 ms.  
5. **Configuration via env (§12)** – Feature-specific limits (graph path, dedup thresholds, replay retries) exposed through env vars and documented in CONFIG.md.

Status: ✅ Gates satisfied; will re-validate after Phase 1 artifacts to ensure no new violations.

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
<!--
  ACTION REQUIRED: Replace the placeholder tree below with the concrete layout
  for this feature. Delete unused options and expand the chosen structure with
  real paths (e.g., apps/admin, packages/something). The delivered plan must
  not include Option labels.
-->

```text
backend/
├── src/
│   ├── api/
│   ├── controllers/
│   ├── routes/
│   ├── services/
│   ├── state/
│   └── utils/
├── config/
├── scripts/
└── tests/              # planned API + automation harness

frontend/
├── src/
│   ├── components/
│   ├── pages/
│   ├── hooks/
│   ├── services/
│   ├── state/
│   └── styles/
└── tests/              # Vite/TS test harness TBD

automation/
├── mayndrive_*.js
├── incremental_discovery/
└── step_discovery/

var/autoapp/
├── graphs/
├── flows/
├── logs/
└── screenshots/

docker-compose.yml      # Traefik, backend, frontend, emulator, envoy
```

**Structure Decision**: Multi-service repo with Express backend, React/Vite frontend, auxiliary automation scripts, and a shared `var/autoapp` volume for JSON/log artifacts. Tests will be split between backend automation harnesses and forthcoming frontend component/integration suites aligned with constitution lint/build gates.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| _None_ | All planned work fits within existing containerized backend/frontend stack and constitution rules | N/A |
