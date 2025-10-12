# Tasks: Apps Library & Instrumentation Hub

**Input**: Design documents from `/specs/002-1-summary-add/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Automated tests were not explicitly requested in the spec; focus is on delivering functional increments with manual verification via the emulator.

**Organization**: Tasks are grouped by user story so each story can be implemented and validated independently.

## Format: `[ID] [P?] [Story] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Story label – `Setup`, `Foundation`, `US1`, `US2`, `US3`, `US4`, or `Polish`
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish directories and configuration scaffolding used by all stories

- [X] T001 [Setup] Create `var/autoapp/apps/{library,logs,scripts}` directories with `.gitkeep` placeholders
- [X] T002 [Setup] Add apps data path constants in `backend/src/config/appPaths.ts` and export via existing config index

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core scaffolding that MUST be complete before any user story

- [X] T003 [Foundation] Define shared domain types in `backend/src/types/apps.ts` (APK entry, install session, log capture, frida state)
- [X] T004 [Foundation] Mount `/apps` router in `backend/src/api/routes/index.ts` with placeholder handler module
- [X] T005 [Foundation] Scaffold Apps page route and nav entry in `frontend/src/pages/AppsPage.tsx` and `frontend/src/components/NavSidebar.tsx`
- [X] T006 [Foundation] Introduce feature flag config for Frida tools in `backend/src/config/featureFlags.ts` and expose toggle via `frontend/src/state/featureFlagsStore.ts`

**Checkpoint**: Foundation ready – Apps routes and page skeleton exist; feature flags guard optional tooling

---

## Phase 3: User Story 1 – Upload & Catalogue APK (Priority: P1) 🎯 MVP

**Goal**: Let testers upload APKs, extract metadata, dedupe by hash, list entries with search/sort, and schedule 30-day retention sweeps.

**Independent Test**: Upload a fresh APK through the Apps page; verify metadata and actions render, dedupe prevents duplicate storage, and retention sweep respects pinned flag.

### Implementation

- [X] T007 [US1] Implement filesystem repository for APK storage/index in `backend/src/services/apps/appsRepository.ts`
- [X] T008 [P] [US1] Implement metadata extraction service using `aapt2` in `backend/src/services/apps/apkMetadataService.ts`
- [X] T009 [US1] Implement POST `/apps` upload handler with dedupe in `backend/src/api/routes/apps/upload.ts`
- [X] T010 [US1] Implement GET `/apps` listing route with search/sort parameters in `backend/src/api/routes/apps/list.ts`
- [X] T011 [US1] Add retention scheduler (30-day sweep with pin respect) in `backend/src/services/apps/retentionScheduler.ts` and hook via app bootstrap
- [ ] T012 [US1] Persist metadata index and session logs via `backend/src/state/appsStore.ts` updates
- [X] T013 [P] [US1] Create Zustand slice for apps library state in `frontend/src/state/appsLibraryStore.ts`
- [X] T014 [P] [US1] Build upload/dropzone component with drag-and-drop in `frontend/src/components/apps/ApkUploader.tsx`
- [X] T015 [US1] Build searchable/sortable APK list view in `frontend/src/components/apps/ApkList.tsx`
- [X] T016 [US1] Build APK details panel showing metadata and actions in `frontend/src/components/apps/ApkDetailsPanel.tsx`
- [X] T017 [US1] Wire Apps page integration in `frontend/src/pages/AppsPage.tsx` (list, details, upload, pin/unpin actions)
- [ ] T018 [US1] Implement upload/status event logging appender in `backend/src/state/appsStore.ts` and API to fetch recent activity for the library
- [ ] T019 [US1] Build activity/status feed component showing upload/dedupe/retention events in `frontend/src/components/apps/ActivityFeed.tsx`

**Checkpoint**: Upload, metadata extraction, library management, and retention scheduling functional end-to-end

---

## Phase 4: User Story 2 – Install & Launch From Library (Priority: P1)

**Goal**: Allow testers to install a selected APK onto the rooted emulator, optionally downgrade and auto-grant permissions, and launch the app with fallback strategies.

**Independent Test**: From an existing library entry, run “Install & Launch”; confirm reinstall options honoured, launch occurs (with fallback path logged), and UI reflects status.

### Implementation

- [X] T020 [US2] Implement install orchestrator (adb install with downgrade toggle & auto-grant) in `backend/src/services/apps/installService.ts`
- [X] T021 [US2] Implement launch service with activity resolution & Monkey fallback in `backend/src/services/apps/launchService.ts`
- [X] T022 [US2] Add POST `/apps/{id}/install-launch` route handling install + launch in `backend/src/api/routes/apps/installLaunch.ts`
- [X] T023 [US2] Extend apps store to record install/launch sessions and statuses in `backend/src/state/appsStore.ts`
- [X] T024 [P] [US2] Create frontend hook for install/launch actions in `frontend/src/hooks/useInstallLaunch.ts`
- [X] T025 [US2] Extend `ApkDetailsPanel` to expose install controls, toggles, and status feedback
- [X] T026 [US2] Add status banner/toast component for install/launch outcomes (integrated into ApkDetailsPanel)
- [X] T027 [US2] Append install/launch status entries (including fallback path) to activity log in `backend/src/state/appsStore.ts`
- [X] T028 [US2] Surface install/launch history entries in Apps activity feed with timestamps and results

**Checkpoint**: Install & Launch workflow operates independently with clear UI feedback

---

## Phase 5: User Story 3 – Instrument App With Frida (Priority: P2)

**Goal**: Provide optional Frida controls (feature-flagged) to start/stop frida-server, attach to running app, load script, and surface console output.

**Independent Test**: Enable Frida via feature flag, start the server, attach to a launched app with a local script, and confirm output lines update.

### Implementation

- [ ] T029 [US3] Implement Frida controller (start/stop server, process list, attach & script execution) in `backend/src/services/apps/fridaController.ts`
- [ ] T030 [US3] Add `/frida/server` and `/frida/attach` routes in `backend/src/api/routes/apps/frida.ts` gated by feature flag
- [ ] T031 [US3] Extend apps store to track Frida session state/output in `backend/src/state/appsStore.ts`
- [ ] T032 [P] [US3] Build Frida control panel component in `frontend/src/components/apps/FridaPanel.tsx`
- [ ] T033 [US3] Implement frontend hook for Frida controls with feature-flag guard in `frontend/src/hooks/useFridaControls.ts`
- [ ] T034 [US3] Log Frida server/attach outcomes with last output snippet in `backend/src/state/appsStore.ts` and expose via activity feed
- [ ] T035 [US3] Show Frida status entries (start/stop/attach) in activity feed with clear success/failure messaging

**Checkpoint**: Frida tooling available (when enabled) with clear status and output handling

---

## Phase 6: User Story 4 – Observe Logs & Network (Priority: P2)

**Goal**: Stream logcat scoped to the selected app, allow capture download, and toggle emulator proxy through mitmproxy guidance.

**Independent Test**: Start logcat filtered by package, pause/resume, download capture, enable proxy and confirm emulator traffic routes through local proxy.

### Implementation

- [ ] T036 [US4] Implement logcat capture manager (start/pause/resume/stop, file persistence) in `backend/src/services/apps/logcatService.ts`
- [ ] T037 [US4] Add logcat session endpoints in `backend/src/api/routes/apps/logcat.ts`
- [ ] T038 [US4] Implement proxy toggle service (adb shell settings) in `backend/src/services/apps/proxyService.ts`
- [ ] T039 [P] [US4] Build log viewer panel with controls in `frontend/src/components/apps/LogcatPanel.tsx`
- [ ] T040 [US4] Build proxy toggle UI with CA guidance link in `frontend/src/components/apps/ProxyToggle.tsx`
- [ ] T041 [US4] Add device tools hook wiring logcat/proxy state in `frontend/src/hooks/useDeviceTools.ts`
- [ ] T042 [US4] Record logcat/proxy start-stop events (with file links) in `backend/src/state/appsStore.ts`
- [ ] T043 [US4] Display logcat/proxy status updates in activity feed, linking to captured artifacts when available

**Checkpoint**: Logcat viewer and proxy tools function independently alongside prior stories

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Final docs, validation, and quality passes across all stories

- [ ] T044 [Polish] Update `docs/quickstart.md` and `docs/troubleshooting.md` with Apps workflow, Frida flag note, and proxy instructions
- [ ] T045 [Polish] Run full quickstart walkthrough (upload → install → launch → Frida → logcat/proxy) and record metrics against success criteria in `var/log/autoapp/apps-smoke.log`

---

## Dependencies & Execution Order

### Phase Dependencies
- **Setup (Phase 1)** → required before Foundational
- **Foundational (Phase 2)** → required before any user story work
- **User Stories (Phases 3–6)** → can begin after Foundational; US1 (P1) should ship first as MVP; US2 depends on install metadata from US1; US3 & US4 depend on US2’s installed app context
- **Polish (Phase 7)** → final phase after desired user stories complete

### Story Dependencies
- **US1** → no story prerequisites once Foundation done
- **US2** → depends on US1 to supply library entries and metadata
- **US3** → depends on US2 (needs running app); also feature flag must be enabled post-governance
- **US4** → depends on US2 (needs running app); log captures reference APK entries from US1

### Parallel Opportunities
- Setup tasks operate on separate paths and can be parallelized as marked
- In US1, metadata service (T008) and frontend slice/uploader (T013–T014) can run in parallel
- In US2, backend services (T018–T019) and frontend hook (T022) are parallelizable
- Similar parallelization applies to component vs. service work in US3 and US4

---

## Parallel Example: User Story 1

```
# Parallel backend tasks
T007 Implement filesystem repository
T008 Implement metadata extraction service

# Parallel frontend tasks
T013 Create apps library slice
T014 Build upload dropzone component
```

---

## Implementation Strategy

### MVP First (Deliver US1)
1. Complete Setup and Foundational phases
2. Implement Phase 3 (US1) and validate upload/catalogue flow
3. Deliver MVP to stakeholders before proceeding

### Incremental Delivery
1. After MVP, implement US2 for install/launch
2. Layer optional tooling (US3 Frida, US4 Logs/Proxy) based on governance approval and tester priority
3. Use Polish phase to finalize docs and smoke validation

### Team Parallelization
1. Shared team handles phases 1–2 together
2. Assign separate contributors to US1, US2, US3/US4 once foundation complete, respecting dependencies
3. Coordinate via checkpoints to keep stories independently testable
