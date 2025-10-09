# Tasks: APK Upload & Install + Frida & Tooling

**Input**: Design documents from `/home/ubuntu/project/Apptest/specs/002-apk-upload-install/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/backend-api.yaml

**Tests**: Tests are NOT requested in the specification. No test tasks are included.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, US4)
- Include exact file paths in descriptions

## Path Conventions
- **Web app**: `backend/src/`, `frontend/src/`
- Extends existing structure from feature 001-web-ui-read

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [ ] T001 [P] Install backend dependencies (apk-parser, frida-tools) in backend/package.json
- [ ] T002 [P] Install frontend dependencies (file upload libraries if needed) in frontend/package.json
- [ ] T003 [P] Create project storage directory structure ~/apptest-projects with .gitignore entry
- [ ] T004 [P] Add environment variable APPTEST_PROJECTS_DIR to backend/.env.example

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [ ] T005 [P] Create APKProject TypeScript types in backend/src/types/apk.ts (based on data-model.md)
- [ ] T006 [P] Create FridaSession TypeScript types in backend/src/types/apk.ts
- [ ] T007 [P] Create TrafficCaptureSession TypeScript types in backend/src/types/apk.ts
- [ ] T008 [P] Create MobSFScanResult TypeScript types in backend/src/types/apk.ts
- [ ] T009 [P] Create EventLogEntry TypeScript types in backend/src/types/apk.ts
- [ ] T010 Create projectStore in-memory state manager in backend/src/state/projectStore.ts
- [ ] T011 [P] Create apkManager service skeleton in backend/src/services/apkManager.ts (filesystem utilities)
- [ ] T012 [P] Create fridaService skeleton in backend/src/services/fridaService.ts
- [ ] T013 [P] Create mitmproxyService skeleton in backend/src/services/mitmproxyService.ts
- [ ] T014 [P] Create mobsfService skeleton in backend/src/services/mobsfService.ts
- [ ] T015 [P] Create apkClient API client in frontend/src/services/apkClient.ts
- [ ] T016 [P] Create useProjectState hook skeleton in frontend/src/hooks/useProjectState.ts
- [ ] T017 Add project state to useAppStore in frontend/src/state/useAppStore.ts (currentProject, fridaSession, trafficSession)

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Upload, Verify, Install, and Launch APK (Priority: P1) 🎯 MVP

**Goal**: Enable testers to upload an APK, view metadata, install it on the emulator, and launch the app

**Independent Test**: Upload any valid APK, verify metadata is displayed (package name, version, SHA-256, signer info), click Install, then Launch, and confirm the app appears on the emulator screen.

### Implementation for User Story 1

- [ ] T018 [P] [US1] Implement APK upload parsing (apk-parser) in backend/src/services/apkManager.ts::parseApk()
- [ ] T019 [P] [US1] Implement SHA-256 hash computation in backend/src/services/apkManager.ts::computeHash()
- [ ] T020 [P] [US1] Implement signing certificate extraction in backend/src/services/apkManager.ts::extractSigningInfo()
- [ ] T021 [US1] Implement project folder creation in backend/src/services/apkManager.ts::createProject() (depends on T018, T019, T020)
- [ ] T022 [US1] Implement metadata.json persistence in backend/src/services/apkManager.ts::saveMetadata()
- [ ] T023 [US1] Implement APK deduplication by SHA-256 in backend/src/services/apkManager.ts::deduplicateApk()
- [ ] T024 [US1] Implement POST /api/apk/upload route in backend/src/api/routes/apkUpload.ts (depends on T021, T022, T023)
- [ ] T025 [P] [US1] Implement APK install via adb in backend/src/services/apkManager.ts::installApk()
- [ ] T026 [P] [US1] Implement main activity resolution in backend/src/services/apkManager.ts::resolveMainActivity()
- [ ] T027 [P] [US1] Implement app launch via adb in backend/src/services/apkManager.ts::launchApp()
- [ ] T028 [US1] Implement POST /api/apk/:projectId/install route in backend/src/api/routes/apkInstall.ts (depends on T025)
- [ ] T029 [US1] Implement POST /api/apk/:projectId/launch route in backend/src/api/routes/apkInstall.ts (depends on T026, T027)
- [ ] T030 [US1] Implement DELETE /api/apk/:projectId/uninstall route in backend/src/api/routes/apkInstall.ts
- [ ] T031 [P] [US1] Implement detailed operation logging to project logs directory in backend/src/services/apkManager.ts::logOperation()
- [ ] T032 [P] [US1] Implement EventLogEntry appending in backend/src/services/apkManager.ts::logEvent()
- [ ] T033 [US1] Add route registrations for apkUpload and apkInstall in backend/src/index.ts (depends on T024, T028, T029, T030)
- [ ] T034 [P] [US1] Create ApkUploader component in frontend/src/components/ApkUploader.tsx (file upload UI, metadata display)
- [ ] T035 [P] [US1] Create ApkControls component in frontend/src/components/ApkControls.tsx (Install/Launch/Uninstall buttons)
- [ ] T036 [US1] Implement upload handler in frontend/src/services/apkClient.ts::uploadApk()
- [ ] T037 [US1] Implement install/launch/uninstall handlers in frontend/src/services/apkClient.ts
- [ ] T038 [US1] Integrate ApkUploader and ApkControls into frontend/src/hooks/useProjectState.ts
- [ ] T039 [US1] Add APK workflow UI to main app view (integrate components from T034, T035)
- [ ] T040 [US1] Add error handling and display for APK upload/install failures in frontend/src/components/ErrorBanner.tsx
- [ ] T041 [US1] Implement 30-day retention policy logic in backend/src/services/apkManager.ts::cleanupOldProjects()
- [ ] T042 [US1] Add pinning support (.pinned file marker) in backend/src/services/apkManager.ts::pinProject()

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Enable and Monitor Frida Instrumentation (Priority: P2)

**Goal**: Enable testers to start/stop Frida on the emulator, verify version/arch compatibility, and see clear connection status

**Independent Test**: With the emulator running, click "Start Frida", verify the UI shows Running status with version/arch match indicators, confirm Frida server is listening on the expected port, then click "Stop Frida" and confirm clean teardown.

### Implementation for User Story 2

- [ ] T043 [P] [US2] Implement root access verification in backend/src/services/fridaService.ts::verifyRootAccess()
- [ ] T044 [P] [US2] Implement device architecture detection in backend/src/services/fridaService.ts::detectDeviceArch()
- [ ] T045 [P] [US2] Implement host Frida version detection in backend/src/services/fridaService.ts::getHostFridaVersion()
- [ ] T046 [US2] Implement frida-server binary download from GitHub releases in backend/src/services/fridaService.ts::downloadFridaServer() (depends on T044, T045)
- [ ] T047 [US2] Implement frida-server binary caching in ~/.cache/apptest/frida-server/ in backend/src/services/fridaService.ts::cacheFridaServer()
- [ ] T048 [US2] Implement SHA-256 verification of downloaded frida-server in backend/src/services/fridaService.ts::verifyBinary()
- [ ] T049 [US2] Implement frida-server push to emulator in backend/src/services/fridaService.ts::pushFridaServer()
- [ ] T050 [US2] Implement frida-server startup via adb in backend/src/services/fridaService.ts::startFridaServer() (depends on T049)
- [ ] T051 [US2] Implement frida-server process verification in backend/src/services/fridaService.ts::verifyFridaRunning()
- [ ] T052 [US2] Implement frida-server port listening check in backend/src/services/fridaService.ts::checkFridaPort()
- [ ] T053 [US2] Implement frida-server termination in backend/src/services/fridaService.ts::stopFridaServer()
- [ ] T054 [US2] Implement version match validation in backend/src/services/fridaService.ts::validateVersionMatch()
- [ ] T055 [US2] Implement FridaSession state transitions in backend/src/state/projectStore.ts::updateFridaSession()
- [ ] T056 [US2] Implement POST /api/frida/start route in backend/src/api/routes/fridaControl.ts (depends on T043-T052, T054)
- [ ] T057 [US2] Implement POST /api/frida/stop route in backend/src/api/routes/fridaControl.ts (depends on T053)
- [ ] T058 [US2] Add route registrations for fridaControl in backend/src/index.ts (depends on T056, T057)
- [ ] T059 [US2] Implement Frida operation logging in backend/src/services/fridaService.ts::logFridaOperation()
- [ ] T060 [P] [US2] Create FridaPanel component in frontend/src/components/FridaPanel.tsx (Start/Stop controls, status display, version info)
- [ ] T061 [US2] Implement Frida start/stop handlers in frontend/src/services/apkClient.ts::startFrida(), stopFrida()
- [ ] T062 [US2] Integrate FridaPanel into frontend/src/hooks/useProjectState.ts
- [ ] T063 [US2] Add Frida UI to main app view (integrate FridaPanel from T060)
- [ ] T064 [US2] Add error display for Frida version mismatch with download link in frontend/src/components/FridaPanel.tsx

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Capture and Analyze Network Traffic (Priority: P3)

**Goal**: Enable testers to capture traffic with mitmproxy, install proxy CA certificate, and view HTTP(S) flows

**Independent Test**: Click "Start Traffic Capture", follow the guided CA install flow, launch an app that makes HTTPS requests, and confirm that flows appear in the UI with decrypted HTTPS traffic visible.

### Implementation for User Story 3

- [ ] T065 [P] [US3] Implement mitmproxy process start in backend/src/services/mitmproxyService.ts::startMitmproxy()
- [ ] T066 [P] [US3] Implement port conflict detection in backend/src/services/mitmproxyService.ts::checkPortAvailable()
- [ ] T067 [P] [US3] Implement emulator proxy configuration via adb in backend/src/services/mitmproxyService.ts::configureEmulatorProxy()
- [ ] T068 [US3] Implement mitmproxy flow logging configuration in backend/src/services/mitmproxyService.ts::configureFlowLogging() (depends on T065)
- [ ] T069 [US3] Implement mitmproxy process termination in backend/src/services/mitmproxyService.ts::stopMitmproxy()
- [ ] T070 [US3] Implement emulator proxy reset in backend/src/services/mitmproxyService.ts::resetEmulatorProxy()
- [ ] T071 [US3] Implement POST /api/traffic/start route in backend/src/api/routes/trafficCapture.ts (depends on T065-T068)
- [ ] T072 [US3] Implement POST /api/traffic/stop route in backend/src/api/routes/trafficCapture.ts (depends on T069, T070)
- [ ] T073 [P] [US3] Implement Android version detection in backend/src/services/mitmproxyService.ts::detectAndroidVersion()
- [ ] T074 [P] [US3] Implement mitmproxy CA extraction in backend/src/services/mitmproxyService.ts::extractMitmCA()
- [ ] T075 [US3] Implement CA push to emulator in backend/src/services/mitmproxyService.ts::pushCAToEmulator() (depends on T074)
- [ ] T076 [US3] Implement user-trusted CA install instructions in backend/src/services/mitmproxyService.ts::generateCAInstallInstructions() (depends on T073)
- [ ] T077 [US3] Implement CA trust status verification in backend/src/services/mitmproxyService.ts::verifyCAInstalled()
- [ ] T078 [US3] Implement POST /api/traffic/ca-install route in backend/src/api/routes/caInstall.ts (depends on T075, T076, T077)
- [ ] T079 [US3] Implement flow summary parsing from mitmproxy logs in backend/src/services/mitmproxyService.ts::parseFlows()
- [ ] T080 [US3] Implement flow detail retrieval in backend/src/services/mitmproxyService.ts::getFlowDetails()
- [ ] T081 [US3] Add route registrations for trafficCapture and caInstall in backend/src/index.ts (depends on T071, T072, T078)
- [ ] T082 [US3] Implement TrafficCaptureSession state transitions in backend/src/state/projectStore.ts::updateTrafficSession()
- [ ] T083 [US3] Implement traffic capture operation logging in backend/src/services/mitmproxyService.ts::logTrafficOperation()
- [ ] T084 [P] [US3] Create TrafficCapturePanel component in frontend/src/components/TrafficCapturePanel.tsx (Start/Stop controls, flow summary, CA install button)
- [ ] T085 [P] [US3] Create CA install guided helper modal in frontend/src/components/TrafficCapturePanel.tsx (version-specific instructions, Frida bypass guidance)
- [ ] T086 [US3] Implement traffic start/stop handlers in frontend/src/services/apkClient.ts::startTraffic(), stopTraffic()
- [ ] T087 [US3] Implement CA install handler in frontend/src/services/apkClient.ts::installCA()
- [ ] T088 [US3] Integrate TrafficCapturePanel into frontend/src/hooks/useProjectState.ts
- [ ] T089 [US3] Add Traffic Capture UI to main app view (integrate TrafficCapturePanel from T084)
- [ ] T090 [US3] Add informational links for Frida-based certificate pinning bypass in frontend/src/components/TrafficCapturePanel.tsx (static informational text only, no code)
- [ ] T091 [US3] Add flow detail viewer to TrafficCapturePanel (request/response display)

**Checkpoint**: At this point, User Stories 1, 2, AND 3 should all work independently

---

## Phase 6: User Story 4 - Run Static Security Scan (Priority: P4) [OPTIONAL]

**Goal**: Enable testers to optionally run MobSF static scan and view summary of findings

**Independent Test**: Upload an APK, enable the "Run MobSF" toggle or click a "Scan" button, wait for the scan to complete, and verify a summary is displayed with a link to the full local report.

### Implementation for User Story 4

- [ ] T092 [P] [US4] Implement Docker availability check in backend/src/services/mobsfService.ts::checkDockerAvailable()
- [ ] T093 [P] [US4] Implement MobSF container start in backend/src/services/mobsfService.ts::startMobsfContainer()
- [ ] T094 [P] [US4] Implement MobSF health check in backend/src/services/mobsfService.ts::checkMobsfHealth()
- [ ] T095 [US4] Implement APK upload to MobSF in backend/src/services/mobsfService.ts::uploadToMobsf() (depends on T093)
- [ ] T096 [US4] Implement scan status polling in backend/src/services/mobsfService.ts::pollScanStatus()
- [ ] T097 [US4] Implement scan results retrieval in backend/src/services/mobsfService.ts::fetchScanResults()
- [ ] T098 [US4] Implement scan summary extraction (permissions, trackers, vulnerableLibs, score) in backend/src/services/mobsfService.ts::extractSummary()
- [ ] T099 [US4] Implement local report download and storage in backend/src/services/mobsfService.ts::saveReport()
- [ ] T100 [US4] Implement POST /api/mobsf/scan route in backend/src/api/routes/mobsfScan.ts (depends on T095-T099)
- [ ] T101 [US4] Implement GET /api/mobsf/scan/:scanId route in backend/src/api/routes/mobsfScan.ts
- [ ] T102 [US4] Add route registrations for mobsfScan in backend/src/index.ts (depends on T100, T101)
- [ ] T103 [US4] Implement MobSFScanResult persistence to project scans directory in backend/src/services/mobsfService.ts::saveScanResult()
- [ ] T104 [US4] Implement MobSF operation logging in backend/src/services/mobsfService.ts::logMobsfOperation()
- [ ] T105 [P] [US4] Create MobSFPanel component in frontend/src/components/MobSFPanel.tsx (Run MobSF button, scan progress, summary display)
- [ ] T106 [US4] Implement scan trigger handler in frontend/src/services/apkClient.ts::triggerMobsfScan()
- [ ] T107 [US4] Implement scan status polling handler in frontend/src/services/apkClient.ts::pollScanStatus()
- [ ] T108 [US4] Integrate MobSFPanel into frontend/src/hooks/useProjectState.ts
- [ ] T109 [US4] Add MobSF UI to main app view (integrate MobSFPanel from T105)
- [ ] T110 [US4] Add error display for MobSF unavailable with installation instructions in frontend/src/components/MobSFPanel.tsx
- [ ] T111 [US4] Add link to full local HTML report in MobSFPanel

**Checkpoint**: All user stories should now be independently functional

---

## Phase 7: Cross-Cutting Concerns & Status Monitoring

**Purpose**: Unified status panel and event logging that spans all user stories

- [ ] T112 [P] Implement GET /api/status unified endpoint in backend/src/api/routes/status.ts (emulator state, current project, Frida session, traffic session)
- [ ] T113 [P] Create StatusPanel component in frontend/src/components/StatusPanel.tsx (unified system status display)
- [ ] T114 Create Events/Logs drawer component in frontend/src/components/EventsDrawer.tsx (timeline of operations from EventLogEntry)
- [ ] T115 Implement event log retrieval endpoint GET /api/events/:projectId in backend/src/api/routes/events.ts
- [ ] T116 Add status endpoint registration in backend/src/index.ts (depends on T112)
- [ ] T117 Integrate StatusPanel into main app view (depends on T113)
- [ ] T118 Implement real-time status polling in frontend/src/hooks/useHealthPoller.ts (extend existing polling to include APK project status)
- [ ] T119 Add legal/ethical use reminder to UI (frontend/src/components/StatusPanel.tsx or dedicated component)
- [ ] T120 Implement "View local logs" link in StatusPanel to open project log directory

---

## Phase 8: Polish & Final Integration

**Purpose**: Refinements and validation

- [ ] T121 [P] Validate all API endpoints match contracts/backend-api.yaml schema
- [ ] T122 [P] Add TypeScript type guards for all data-model.md entities
- [ ] T123 Add comprehensive error messages and logging for all failure scenarios (APK parse errors, adb failures, version mismatches, port conflicts, scan timeouts)
- [ ] T124 Implement retention cleanup cron job (daily scan for projects > 30 days without .pinned marker)
- [ ] T125 Add progress indicators for long-running operations (APK upload, frida-server download, MobSF scan)
- [ ] T126 Validate quickstart.md workflow end-to-end (upload → install → launch → Frida → traffic → scan)
- [ ] T127 [P] Update CLAUDE.md with active technologies from feature 002
- [ ] T128 Add configuration validation for APPTEST_PROJECTS_DIR, proxy port, Frida port
- [ ] T129 Implement graceful shutdown for all background processes (frida-server, mitmproxy, MobSF)
- [ ] T130 Add disk usage monitoring and warnings per constitution retention requirements

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-6)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3 → P4)
- **Cross-Cutting (Phase 7)**: Can start after Phase 2, develops in parallel with user stories
- **Polish (Phase 8)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - No dependencies on other stories (independent)
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - No dependencies on other stories (independent)
- **User Story 4 (P4)**: Can start after Foundational (Phase 2) - No dependencies on other stories (independent)

### Within Each User Story

- Models/types before services
- Services before routes
- Routes before UI components
- Core implementation before integration
- Story complete before moving to next priority

### Parallel Opportunities

- **Phase 1**: All tasks marked [P] (T001, T002, T003, T004) can run in parallel
- **Phase 2**: All tasks marked [P] (T005-T009, T011-T017) can run in parallel
- **Phase 3 (US1)**:
  - T018, T019, T020 can run in parallel
  - T025, T026, T027 can run in parallel
  - T031, T032 can run in parallel
  - T034, T035 can run in parallel
- **Phase 4 (US2)**: T043, T044, T045 can run in parallel; T060 can run in parallel with backend tasks
- **Phase 5 (US3)**: T065, T066, T067, T073, T074 can run in parallel; T084, T085 can run in parallel with backend tasks
- **Phase 6 (US4)**: T092, T093, T094 can run in parallel; T105 can run in parallel with backend tasks
- **Phase 7**: T112, T113 can run in parallel
- **Phase 8**: T121, T122, T127 can run in parallel
- **User Stories 1-4 can all proceed in parallel** if team has capacity (all are independent)

---

## Parallel Example: User Story 1 (APK Upload)

```bash
# Launch all APK parsing tasks together:
Task T018: "Implement APK upload parsing (apk-parser) in backend/src/services/apkManager.ts::parseApk()"
Task T019: "Implement SHA-256 hash computation in backend/src/services/apkManager.ts::computeHash()"
Task T020: "Implement signing certificate extraction in backend/src/services/apkManager.ts::extractSigningInfo()"

# Launch all APK operation tasks together:
Task T025: "Implement APK install via adb in backend/src/services/apkManager.ts::installApk()"
Task T026: "Implement main activity resolution in backend/src/services/apkManager.ts::resolveMainActivity()"
Task T027: "Implement app launch via adb in backend/src/services/apkManager.ts::launchApp()"

# Launch all UI components together:
Task T034: "Create ApkUploader component in frontend/src/components/ApkUploader.tsx"
Task T035: "Create ApkControls component in frontend/src/components/ApkControls.tsx"
```

---

## Parallel Example: User Story 2 (Frida)

```bash
# Launch all Frida detection tasks together:
Task T043: "Implement root access verification in backend/src/services/fridaService.ts::verifyRootAccess()"
Task T044: "Implement device architecture detection in backend/src/services/fridaService.ts::detectDeviceArch()"
Task T045: "Implement host Frida version detection in backend/src/services/fridaService.ts::getHostFridaVersion()"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T004)
2. Complete Phase 2: Foundational (T005-T017) - CRITICAL - blocks all stories
3. Complete Phase 3: User Story 1 (T018-T042)
4. **STOP and VALIDATE**: Test User Story 1 independently per acceptance scenarios
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently per spec.md scenarios → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently per spec.md scenarios → Deploy/Demo
4. Add User Story 3 → Test independently per spec.md scenarios → Deploy/Demo
5. Add User Story 4 (optional) → Test independently per spec.md scenarios → Deploy/Demo
6. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (P1) - APK upload/install
   - Developer B: User Story 2 (P2) - Frida instrumentation
   - Developer C: User Story 3 (P3) - Traffic capture
   - Developer D: User Story 4 (P4) - MobSF scanning (optional)
   - Developer E: Phase 7 - Status monitoring (can start after Phase 2)
3. Stories complete and integrate independently

---

## Summary

- **Total Tasks**: 130
- **User Story 1 (P1 - MVP)**: 25 tasks (T018-T042)
- **User Story 2 (P2)**: 22 tasks (T043-T064)
- **User Story 3 (P3)**: 27 tasks (T065-T091)
- **User Story 4 (P4 - Optional)**: 20 tasks (T092-T111)
- **Cross-Cutting**: 9 tasks (T112-T120)
- **Setup + Foundational**: 17 tasks (T001-T017)
- **Polish**: 10 tasks (T121-T130)
- **Parallel Opportunities**: ~40 tasks can run in parallel within phases
- **MVP Scope**: Phase 1 + Phase 2 + Phase 3 (User Story 1) = 46 tasks

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
- Tests are NOT included per specification (no TDD requested)
