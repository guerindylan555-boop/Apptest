# Tasks: Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

**Input**: Design documents from `/specs/001-web-ui-read/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Backend Jest unit coverage is required for lifecycle and stream logic per plan.md. Frontend relies on manual validation via quickstart checklist.

**Organization**: Tasks are grouped by user story to enable independent delivery and validation. IDs are unique and strictly ordered for execution.

## Format: `[ID] [P?] [Story] Description`
- **[P]**: Task can run in parallel with others in its phase (touches different files/no dependency)
- **[Story]**: `Setup`, `Foundation`, or user story label (`US1`, `US2`, `US3`, …)
- Include concrete file paths so each task is immediately actionable

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish shared tooling and environment required by all stories

- [ ] T001 [Setup] Add Jest + ts-jest tooling in `backend/package.json`, regenerate `backend/package-lock.json`, create `backend/jest.config.ts`, and extend `backend/tsconfig.json` so backend services can be unit-tested.
- [ ] T002 [P] [Setup] Create `backend/.env.example` and `frontend/.env.example` documenting `STREAM_HOST`, `STREAM_PORT`, `STREAM_TIMEOUT_MS`, then update `scripts/run-local.sh` to export sane defaults before launching backend/frontend.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core state + configuration updates that all stories depend on

**⚠️ CRITICAL**: Complete these tasks before starting any user story work

- [ ] T003 [Foundation] Extend lifecycle metadata in `backend/src/types/session.ts` and `backend/src/state/sessionStore.ts` to track stream bridge URL, ticket expiry, and normalized error codes shared across stories.
- [ ] T004 [P] [Foundation] Introduce `backend/src/config/stream.ts` for host/port/timeouts, refactor `backend/src/services/streamerService.ts` to use it, and delete the legacy `backend/src/ws-scrcpy-wrapper.js` plus stray `backend/-` stub.

**Checkpoint**: Backend state models + config ready for story implementations

---

## Phase 3: User Story 1 - Start emulator and view live stream (Priority: P1) 🎯 MVP

**Goal**: Tester can start the emulator from the UI and see the Android screen streaming with ≤500 ms perceived latency.

**Independent Test**: Launch frontend, trigger "Start Emulator", confirm badge transitions Stopped → Booting… → Running, and ensure the canvas renders the live feed within 45 s.

### Tests for User Story 1 (write first)

- [ ] T005 [US1] Create `backend/src/services/__tests__/streamerService.spec.ts` covering `issueStreamTicket` happy path and failure when session.state ≠ 'Running'.

### Implementation for User Story 1

- [ ] T006 [US1] Add `ws-scrcpy` CLI dependency + `npm run streamer:bridge` script in `backend/package.json`, update `backend/package-lock.json`, and document usage in script comments.
- [ ] T007 [US1] Implement a new `backend/src/services/wsScrcpyBridge.ts` helper that spawns the ws-scrcpy binary via config, watches process output, and exposes a promise-based start hook.
- [ ] T008 [US1] Refactor `backend/src/services/streamerService.ts` to call the new bridge, generate signed tickets with expiry, and update `stopStreamer` to gracefully close the bridge.
- [ ] T009 [US1] Update `backend/src/api/routes/streamUrl.ts` (and `backend/src/api/server.ts` if needed for headers) to return `{ url, token, expiresAt }` per contracts/backend.yaml.
- [ ] T010 [P] [US1] Add `@yume-chan/scrcpy-ws-client` (or equivalent) to `frontend/package.json` / `frontend/package-lock.json` and create `frontend/src/services/streamClient.ts` that opens the ws-scrcpy websocket and renders frames onto a supplied `<canvas>` element.
- [ ] T011 [US1] Replace `frontend/src/components/StreamViewer.tsx` with a canvas-based renderer using `streamClient`, update `frontend/src/styles/stream.css` for the canvas, and ensure teardown when state ≠ Running.
- [ ] T012 [US1] Enhance `frontend/src/hooks/useHealthPoller.ts`, `frontend/src/services/backendClient.ts`, `frontend/src/state/useAppStore.ts`, and `frontend/src/App.tsx` to request stream tickets, manage expiry retries, and clear `streamUrl` when transitions leave Running.

**Checkpoint**: Emulator starts from UI, stream renders, quickstart Step 5 passes without manual workarounds.

---

## Phase 4: User Story 2 - Stop emulator safely from the UI (Priority: P2)

**Goal**: Tester stops the running emulator via the UI and sees stream teardown with state badge returning to Stopped.

**Independent Test**: With stream active, press "Stop Emulator"; verify button disables, badge shows Stopping… then Stopped, and stream pane reverts to placeholder.

### Tests for User Story 2 (write first)

- [ ] T013 [US2] Add `backend/src/services/__tests__/emulatorLifecycle.spec.ts` to assert `stopEmulator(false)` clears stream tokens, and `stopEmulator(true)` invokes `sessionStore.requireForceStop` on failure.

### Implementation for User Story 2

- [ ] T014 [US2] Update `backend/src/services/emulatorLifecycle.ts` and `backend/src/state/sessionStore.ts` so stop transitions reset stream metadata, trigger `handleEmulatorStopped`, and surface force-stop hints.
- [ ] T015 [US2] Refine `backend/src/api/routes/emulatorStop.ts` responses to align with contracts (202 + message vs 409/force), ensuring logger context includes `force` flag.
- [ ] T016 [US2] Adjust `frontend/src/App.tsx` and `frontend/src/components/ControlButton.tsx` to disable controls during Stopping, auto-clear stream canvas on Stopped, and show contextual button label.

**Checkpoint**: Start/stop cycle is reliable with deterministic UI transitions.

---

## Phase 5: User Story 3 - Understand failures and access logs (Priority: P3)

**Goal**: Tester receives actionable messaging and a logs link whenever start/stop/stream attach fails, with optional Force Stop action.

**Independent Test**: Simulate start timeout or stream attach failure; confirm Error badge with human-readable message, "View local logs" link, and Force Stop/Retry controls per scenario.

### Tests for User Story 3 (write first)

- [ ] T017 [US3] Create `backend/src/state/__tests__/sessionStore.spec.ts` validating `recordError`, `markHealthUnreachable`, and `requireForceStop` populate `lastError` and `forceStopRequired` as expected.

### Implementation for User Story 3

- [ ] T018 [US3] Extend `backend/src/state/sessionStore.ts`, `backend/src/api/routes/health.ts`, and `backend/src/services/emulatorLifecycle.ts` to emit descriptive error codes/messages/hints and persist `forceStopRequired` until cleared.
- [ ] T019 [US3] Update `frontend/src/components/ErrorBanner.tsx`, `frontend/src/App.tsx`, and `frontend/src/hooks/useHealthPoller.ts` to render error hints, wire Force Stop/Retry actions, and display the `var/log/autoapp/backend.log` link.

**Checkpoint**: Error flows guide the tester without page refreshes, satisfying FR-008 to FR-010.

---

## Phase 6: Polish & Cross-Cutting

**Purpose**: Documentation, verification, and clean-up spanning multiple stories

- [x] T020 [P] [Polish] Refresh `specs/001-web-ui-read/quickstart.md` and `docs/` (if applicable) with canvas streaming notes, Force Stop guidance, and Jest usage instructions.
- [x] T021 [Polish] Execute `npm run lint && npm run test` in both `backend/` and `frontend/`, capture results in `docs/verification.md` (create if absent), and note any manual quickstart deviations.

---

## Dependencies & Execution Order

- **Phase 1 → Phase 2**: Complete T001–T004 before any user story tasks begin.
- **User Story Phases**: US1 (T005–T012) must finish before US2 (T013–T016); US3 (T017–T019) depends on both prior stories to ensure consistent state handling.
- **Polish**: T020–T021 run after all targeted user stories are complete.

### Task Dependencies Within Stories

- US1: T005 → T006 → T007 → T008 precede frontend tasks; T009 [P] can start once T006 is done; T010 depends on T009; T011 depends on T010.
- US2: T013 precedes backend updates (T014, T015); frontend adjustments (T016) follow backend stop semantics.
- US3: T017 informs backend updates (T018) which must complete before UI wiring (T019).

### Parallel Opportunities

- Setup: T002 can run alongside T001 after dependency installation completes.
- Foundation: T004 [P] can proceed while T003 is under review since it introduces separate config plumbing.
- US1 Frontend: T009 [P] (frontend service + dependency install) can progress while backend refactors (T007/T008) are underway.
- Polish: T020 [P] documentation updates can occur while verification task T021 is prepared.

---

## Parallel Example: User Story 1

```bash
# In parallel, once backend deps are updating (T006) and contracts settled:
npm --prefix frontend install @yume-chan/scrcpy-ws-client  # (T009)
# Meanwhile in backend:
npm --prefix backend run test -- stream  # Executes new Jest spec from T005 after implementation
```

---

## Implementation Strategy

1. Land Phase 1–2 foundations to stabilize state + tooling.
2. Deliver User Story 1 as the MVP (stream working end-to-end) before touching stop/error flows.
3. Layer User Story 2 stop controls, then User Story 3 error surfaces.
4. Finish with documentation and lint/test verification to lock regression safety.
