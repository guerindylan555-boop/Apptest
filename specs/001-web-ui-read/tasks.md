# Tasks: Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

**Input**: Design documents from `/specs/001-web-ui-read/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Automated tests are optional for this feature; include them when they directly support acceptance criteria.

**Organization**: Tasks are grouped by user story to enable independent implementation and validation.

## Format: `[ID] [P?] [Story] Description`
- **[P]**: Task can run in parallel (different files, no ordering dependency)
- **[Story]**: User story label (US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish repository structure, tooling, and base scripts required for all stories.

- [X] T001 Create project directories per plan (`backend/src`, `frontend/src`, `scripts`, `var/log/autoapp`) and add `.gitkeep` placeholders.
- [X] T002 Initialize backend Node.js workspace with TypeScript support (`backend/package.json`, `backend/tsconfig.json`, `backend/src/index.ts`).
- [X] T003 [P] Scaffold frontend Vite React TypeScript app (`frontend/package.json`, `frontend/tsconfig.json`, `frontend/src/main.tsx`).
- [X] T004 [P] Author `scripts/setup-avd.sh` to install SDK components and create the rooted `autoapp-local` AVD.
- [X] T005 [P] Configure shared lint/format tooling (`package.json` scripts, `.eslintrc.cjs`, `.prettierrc`) scoped to backend and frontend.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core services and shared state that all user stories rely on.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

- [X] T006 Define shared lifecycle & health types (`backend/src/types/session.ts`, `backend/src/types/health.ts`).
- [X] T007 Implement structured file logger writing to `var/log/autoapp/backend.log` (`backend/src/services/logger.ts`).
- [X] T008 Build Android CLI wrapper utilities for emulator and adb commands (`backend/src/services/androidCli.ts`).
- [X] T009 Create singleton session store with token generation and state transitions (`backend/src/state/sessionStore.ts`).
- [X] T010 Stand up Express server skeleton bound to `127.0.0.1:8080` with empty routers (`backend/src/api/server.ts`, `backend/src/api/routes/index.ts`).
- [X] T011 Establish frontend app shell + global state store (`frontend/src/state/useAppStore.ts`, `frontend/src/App.tsx`) rendering placeholder layout.
- [X] T012 [P] Add shared styles and stream placeholder assets (`frontend/src/styles/base.css`, `frontend/src/components/StreamPlaceholder.tsx`).

**Checkpoint**: Foundation ready — safe to begin user story implementation.

---

## Phase 3: User Story 1 – Start emulator and view live stream (Priority: P1) 🎯 MVP

**Goal**: Tester can start the emulator from the page and view a responsive read-only stream within 45 seconds.

**Independent Test**: From a clean boot, run `scripts/run-local.sh`, load the UI, click Start Emulator, and observe the stream with the badge progressing Stopped → Booting → Running.

### Implementation

- [X] T013 [US1] Implement `startEmulator` flow with readiness gating and state updates (`backend/src/services/emulatorLifecycle.ts`).
- [X] T014 [US1] Implement ws-scrcpy streamer supervisor issuing single-use tokens (`backend/src/services/streamerService.ts`).
- [X] T015 [US1] Wire POST `/emulator/start` route to orchestrator and guard against concurrent boots (`backend/src/api/routes/emulatorStart.ts`).
- [X] T016 [US1] Provide GET `/stream/url` endpoint returning token + URL when running (`backend/src/api/routes/streamUrl.ts`).
- [X] T017 [US1] Implement GET `/health` to expose session diagnostics (`backend/src/api/routes/health.ts`).
- [X] T018 [US1] Finalize backend bootstrap exporting Express app and start script (`backend/src/index.ts`, `backend/package.json` scripts).
- [X] T019 [US1] Create frontend HTTP client helpers (`frontend/src/services/backendClient.ts`).
- [X] T020 [US1] Build `useHealthPoller` hook with 1s polling and auto stream fetch (`frontend/src/hooks/useHealthPoller.ts`).
- [X] T021 [P] [US1] Implement `StateBadge` component with color variants (`frontend/src/components/StateBadge.tsx`).
- [X] T022 [P] [US1] Implement primary `ControlButton` component handling disabled/loading states (`frontend/src/components/ControlButton.tsx`).
- [X] T023 [P] [US1] Implement `StreamViewer` rendering `<video>` element with pointer disabled (`frontend/src/components/StreamViewer.tsx`, `frontend/src/styles/stream.css`).
- [X] T024 [US1] Integrate components in `App.tsx` to trigger start flow, bind state, and attach stream.
- [X] T025 [US1] Create `scripts/run-local.sh` to launch backend, streamer, and frontend on localhost.

**Checkpoint**: User Story 1 delivers MVP — start flow and read-only stream verified.

---

## Phase 4: User Story 2 – Stop emulator safely from the UI (Priority: P2)

**Goal**: Tester can stop the running emulator from the page, see Stopping → Stopped, and the stream shuts down cleanly.

**Independent Test**: With emulator streaming, press Stop Emulator; confirm state badge transitions to Stopping then Stopped and the stream placeholder returns.

### Implementation

- [X] T026 [US2] Extend lifecycle service with stop ladder (console kill → `adb emu kill` → process kill) and state transitions (`backend/src/services/emulatorLifecycle.ts`).
- [X] T027 [US2] Add streamer teardown handling (`backend/src/services/streamerService.ts`).
- [X] T028 [US2] Implement POST `/emulator/stop` route enforcing mutual exclusion and success responses (`backend/src/api/routes/emulatorStop.ts`).
- [X] T029 [US2] Enhance session store with Stopping state handling and stream cleanup hooks (`backend/src/state/sessionStore.ts`).
- [X] T030 [US2] Update frontend client with stop request helper (`frontend/src/services/backendClient.ts`).
- [X] T031 [US2] Update `ControlButton` to toggle Start/Stop labels and show spinner during transitions (`frontend/src/components/ControlButton.tsx`).
- [X] T032 [US2] Update app logic to disable inputs while stopping and reset stream when stopped (`frontend/src/App.tsx`).
- [X] T033 [US2] Ensure `StreamViewer` clears media element on stop (`frontend/src/components/StreamViewer.tsx`).

**Checkpoint**: User Stories 1 & 2 run end-to-end — start/stop cycles succeed.

---

## Phase 5: User Story 3 – Understand failures and access logs (Priority: P3)

**Goal**: Tester receives actionable error feedback, can trigger Force Stop, and sees diagnostics/log links during failures.

**Independent Test**: Simulate boot timeout or kill the health endpoint; UI switches to Error, surfaces logs link and Force Stop option; health badge reflects recovery once resolved.

### Implementation

- [X] T034 [US3] Add timeout and error instrumentation to lifecycle service (boot/stop timeouts, health unreachable) (`backend/src/services/emulatorLifecycle.ts`).
- [X] T035 [US3] Persist `lastError` and Force Stop flags within session store (`backend/src/state/sessionStore.ts`).
- [X] T036 [US3] Enrich `/health` response with diagnostics (pid, bootElapsedMs, lastError) (`backend/src/api/routes/health.ts`).
- [X] T037 [US3] Extend `/emulator/stop` route to accept Force Stop and propagate results (`backend/src/api/routes/emulatorStop.ts`).
- [X] T038 [US3] Introduce reusable `ErrorBanner` + logs link component (`frontend/src/components/ErrorBanner.tsx`).
- [X] T039 [US3] Integrate error banner, logs link, and Force Stop control into `App.tsx` (`frontend/src/App.tsx`).
- [X] T040 [US3] Enhance `useHealthPoller` to handle health endpoint loss, stream attach timeout, and error resets (`frontend/src/hooks/useHealthPoller.ts`).
- [X] T041 [P] [US3] Implement optional diagnostics drawer showing PID, uptime, last error (`frontend/src/components/DiagnosticsDrawer.tsx`).

**Checkpoint**: All user stories complete — failures are observable with recovery tools.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Repo hardening, documentation updates, and local-only validation.

- [X] T042 Update Quickstart instructions with final commands and ports (`specs/001-web-ui-read/quickstart.md`).
- [X] T043 Document troubleshooting scenarios and log locations (`docs/troubleshooting.md`).
- [X] T044 Add npm scripts for lifecycle tasks (`backend/package.json`, `frontend/package.json`) aligning with `scripts/run-local.sh`.
- [X] T045 Create `scripts/validate-local-only.sh` to assert listeners are bound to 127.0.0.1 only using `ss`/`netstat`.

---

## Dependencies & Execution Order

- **Phase 1 → Phase 2**: Setup must finish before foundational work.
- **Phase 2 → User Stories**: All foundational tasks (T006–T012) are prerequisites for US1–US3.
- **User Story Order**: Implement in priority order (US1 → US2 → US3) for MVP-first delivery. Stories can run in parallel post-foundation if staffing allows, but ensure shared files (e.g., `emulatorLifecycle.ts`, `App.tsx`) are coordinated.
- **Polish Phase**: Execute after desired user stories are complete.

## Parallel Opportunities

- Phase 1 tasks T003, T004, T005 can run alongside backend initialization once T001 is done.
- In Phase 3, component work (T021, T022, T023) can proceed in parallel while service logic (T013–T017) is implemented.
- In Phase 5, diagnostics UI (T041) can progress concurrently with backend error instrumentation (T034–T037).

*Example (User Story 1 parallel work):*
```
# Backend engineer
T013 → T014 → T015

# Frontend engineer (in parallel)
T021 + T022 + T023  (distinct files)
```

## Implementation Strategy

1. **MVP (US1)**: Complete Phases 1–3 to deliver start + stream functionality. Demo once T025 passes manual test.
2. **Incremental Expansion**: Layer User Story 2 to introduce safe shutdown without breaking US1. Validate cycle tests.
3. **Resilience & Observability**: Implement User Story 3 for error handling, then finish polish tasks to document and verify localhost boundaries.
4. **Continuous Validation**: After each phase checkpoint, run `scripts/run-local.sh`, verify acceptance criteria, and commit.

## Notes

- Keep backend services bound to `127.0.0.1` per constitution.
- Regenerate ws-scrcpy tokens on each run and redact them in logs.
- Force Stop actions must log escalations for postmortem analysis.
- Ensure scripts clean up emulator processes to prevent orphaned instances.
