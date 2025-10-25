---

description: "Task list for AutoApp UI Map & Intelligent Flow Engine implementation"
---

# Tasks: AutoApp UI Map & Intelligent Flow Engine

**Input**: Design documents from `/specs/001-ui-map-flow-engine/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Integration test harness included (emulator-driven scenarios as specified in research.md)

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Backend**: `backend/src/`, `backend/tests/`
- **Frontend**: `frontend/src/`, `frontend/tests/`
- **Automation**: `automation/`
- **Storage**: `var/autoapp/{graphs,flows,logs,screenshots}`

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Audit and update existing project structure for UI Map & Flow Engine

- [ ] T001 Audit existing backend package.json and add UIAutomator2, @types/uuid dependencies
- [ ] T002 [P] Audit existing frontend package.json and add zustand, @types/uuid dependencies
- [ ] T003 [P] Verify ESLint/Prettier configuration covers new backend/src/services/* files
- [ ] T004 [P] Verify ESLint/Prettier configuration covers new frontend/src/components/* files
- [ ] T005 Update docker-compose.yml to add var/autoapp volume mount to backend service
- [ ] T006 Add feature-specific environment variables to existing .env templates
- [ ] T007 Create var/autoapp/{graphs,flows,logs,screenshots} directory structure
- [ ] T008 Verify existing Traefik configuration allows API endpoint exposure

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [ ] T009 Setup WebRTC connection manager with constitution timeouts (1.5s) in backend/src/services/webrtc-manager.ts
- [ ] T010 Setup ADB bridge service for UIAutomator2 communication in backend/src/services/adb-bridge.ts
- [ ] T011 [P] Implement JSON file storage service with optimistic locking in backend/src/services/json-storage.ts
- [ ] T012 [P] Create TypeScript interfaces for all data model entities in backend/src/types/models.ts
- [ ] T013 [P] Create base Express API router structure in backend/src/routes/index.ts
- [ ] T014 [P] Setup structured JSON logging service in backend/src/services/logger.ts
- [ ] T015 [P] Create health check endpoint with <500ms performance budget in backend/src/routes/health.ts
- [ ] T016 Setup environment configuration validation in backend/src/config/environment.ts
- [ ] T017 [P] Create frontend Zustand store structure in frontend/src/state/index.ts
- [ ] T017.5 Verify Traefik router configuration for /api/* endpoints in docker-compose.yml
- [ ] T017.6 Add CORS middleware configuration for remote API access in backend/src/middleware/cors.ts
- [ ] T017.7 Test remote API accessibility through Dockploy domain in backend/tests/integration/remote-access.test.ts

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Manual State Discovery & Mapping (Priority: P1) 🎯 MVP

**Goal**: Enable manual navigation through MaynDrive app with automatic UI state capture and deduplication

**Independent Test**: Launch MaynDrive, navigate to different screens, verify each screen capture creates a state node in graph.json with proper activity detection and element identification

### Tests for User Story 1

- [ ] T018 [P] [US1] Integration test for UI state capture via UIAutomator2 in backend/tests/integration/state-capture.test.ts
- [ ] T019 [P] [US1] Integration test for state deduplication accuracy in backend/tests/integration/state-dedup.test.ts
- [ ] T020 [P] [US1] Integration test for graph JSON serialization in backend/tests/integration/graph-serialization.test.ts
- [ ] T037.5 [P] [US1] Integration test for MaynDrive clean-state bootstrap in backend/tests/integration/mayndrive-bootstrap.test.ts
- [ ] T037.6 [P] [US1] Integration test for activity-specific resume procedures in backend/tests/integration/activity-resume.test.ts

### Implementation for User Story 1

- [x] T021 [P] [US1] Create State entity and selector logic in backend/src/models/state.ts ✅ IMPLEMENTED
- [x] T022 [P] [US1] Create Transition entity model in backend/src/models/transition.ts ✅ IMPLEMENTED
- [x] T023 [P] [US1] Create UI Graph (UTG) entity in backend/src/models/graph.ts ✅ IMPLEMENTED
- [x] T024 [US1] Implement UIAutomator2 capture service in backend/src/services/ui-capture.ts (depends on T010) ✅ IMPLEMENTED
- [x] T025 [US1] Implement state deduplication logic with digest-based matching in backend/src/services/state-dedup.ts ✅ IMPLEMENTED
- [ ] T026 [US1] Implement graph storage service in backend/src/services/graph-storage.ts (depends on T011, T023)
- [ ] T027 [US1] Create POST /api/graphs/capture endpoint in backend/src/routes/graph-capture.ts (depends on T024, T025)
- [ ] T028 [US1] Create GET /api/graphs/current endpoint in backend/src/routes/graph-current.ts (depends on T026)
- [ ] T029 [US1] Create POST /api/graphs/transitions endpoint in backend/src/routes/transitions.ts (depends on T022, T026)
- [ ] T030 [US1] Add state capture validation and error handling
- [ ] T031 [US1] Add structured logging for discovery operations (depends on T015)
- [ ] T032 [P] [US1] Create Discovery panel React component in frontend/src/components/DiscoveryPanel.tsx
- [ ] T033 [P] [US1] Create state visualization components in frontend/src/components/StateGraph.tsx
- [ ] T034 [US1] Integrate Discovery panel with backend API in frontend/src/services/discovery-api.ts
- [ ] T035 [US1] Add WebRTC stream display integration in Discovery panel (depends on T009)
- [ ] T036 [US1] Add state snapshot and transition annotation UI in frontend/src/components/StateControls.tsx
- [x] T037 [US1] Create screenshot storage and display functionality in backend/src/services/screenshot-storage.ts ✅ IMPLEMENTED
- [x] T037.1 [US1] Create MaynDrive bootstrap service in backend/src/services/mayndrive-bootstrap.ts ✅ IMPLEMENTED
- [x] T037.2 [US1] Implement clean-state reset for MaynDrive (clear app data, force restart) in backend/src/services/app-reset.ts ✅ IMPLEMENTED
- [x] T037.3 [US1] Create activity-specific resume procedures (MainActivity, LoginScreen, MapScreen) in backend/src/services/activity-resume.ts ✅ IMPLEMENTED
- [x] T037.4 [US1] Add MaynDrive package validation to ensure targeting correct app in backend/src/utils/app-validation.ts ✅ IMPLEMENTED

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Flow Authoring & Definition (Priority: P1)

**Goal**: Enable creation of reusable flows using captured UI states with validation and predicate resolution

**Independent Test**: Create a simple login flow JSON file with existing states and validate that flow structure and predicates are syntactically correct and logically sound

### Tests for User Story 2

- [ ] T038 [P] [US2] Integration test for flow JSON validation in backend/tests/integration/flow-validation.test.ts
- [ ] T039 [P] [US2] Integration test for state predicate resolution in backend/tests/integration/predicate-resolution.test.ts
- [ ] T040 [P] [US2] Integration test for flow CRUD operations in backend/tests/integration/flow-crud.test.ts

### Implementation for User Story 2

- [x] T041 [P] [US2] Create FlowDefinition entity model in backend/src/models/flow-definition.ts ✅ IMPLEMENTED
- [x] T042 [P] [US2] Create FlowStep entity model in backend/src/models/flow-step.ts ✅ IMPLEMENTED
- [x] T043 [P] [US2] Create StatePredicate entity and evaluation logic in backend/src/models/state-predicate.ts ✅ IMPLEMENTED
- [x] T044 [US2] Implement flow validation service in backend/src/services/flow-validator.ts (depends on T043, T021) ✅ IMPLEMENTED
- [x] T045 [US2] Implement flow storage service in backend/src/services/flow-storage.ts (depends on T011) ✅ IMPLEMENTED
- [x] T046 [US2] Create GET /api/flows endpoint in backend/src/routes/flows-list.ts (depends on T045) ✅ IMPLEMENTED
- [x] T047 [US2] Create POST /api/flows endpoint in backend/src/routes/flows-create.ts (depends on T041, T044, T045) ✅ IMPLEMENTED
- [x] T048 [US2] Create PUT /api/flows/{flowId} endpoint in backend/src/routes/flows-update.ts (depends on T041, T044, T045) ✅ IMPLEMENTED
- [x] T049 [US2] Create DELETE /api/flows/{flowId} endpoint in backend/src/routes/flows-delete.ts (depends on T045) ✅ IMPLEMENTED
- [x] T050 [US2] Create POST /api/flows/{flowId}/validate endpoint in backend/src/routes/flows-validate.ts (depends on T044) ✅ IMPLEMENTED
- [ ] T051 [US2] Add flow validation error handling and detailed reporting
- [ ] T052 [US2] Add structured logging for flow operations (depends on T015)
- [ ] T053 [P] [US2] Create Flow management React components in frontend/src/components/FlowManager.tsx
- [ ] T054 [P] [US2] Create flow editor component in frontend/src/components/FlowEditor.tsx
- [ ] T055 [US2] Create state predicate builder UI in frontend/src/components/PredicateBuilder.tsx
- [ ] T056 [US2] Integrate Flow UI with backend API in frontend/src/services/flow-api.ts
- [ ] T057 [US2] Add flow validation result display in frontend/src/components/FlowValidation.tsx

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Intelligent Flow Replay with State Recovery (Priority: P1)

**Goal**: Execute automated flows with state detection, navigation to required starting points, and intelligent recovery

**Independent Test**: Start app in fresh state, initiate unlock flow, verify system automatically detects need to login first, executes login, then completes unlock

### Tests for User Story 3

- [ ] T058 [P] [US3] Integration test for flow replay with state recovery in backend/tests/integration/flow-replay.test.ts
- [ ] T059 [P] [US3] Integration test for state localization and matching in backend/tests/integration/state-localization.test.ts
- [ ] T060 [P] [US3] Integration test for prerequisite flow execution in backend/tests/integration/prerequisite-flows.test.ts

### Implementation for User Story 3

- [ ] T061 [P] [US3] Create FlowExecution entity model in backend/src/models/flow-execution.ts
- [ ] T062 [P] [US3] Create SessionEvent entity model in backend/src/models/session-event.ts
- [ ] T063 [US3] Implement state localization service in backend/src/services/state-localizer.ts (depends on T021, T043)
- [ ] T064 [US3] Implement action execution service in backend/src/services/action-executor.ts (depends on T010)
- [ ] T065 [US3] Implement flow replay engine with recovery logic in backend/src/services/flow-replayer.ts (depends on T061, T062, T063, T064)
- [ ] T066 [US3] Implement prerequisite flow detection and execution in backend/src/services/prerequisite-handler.ts (depends on T065)
- [ ] T067 [US3] Create POST /api/flows/{flowId}/execute endpoint in backend/src/routes/flows-execute.ts (depends on T065)
- [ ] T068 [US3] Create GET /api/executions endpoint in backend/src/routes/executions-list.ts (depends on T061)
- [ ] T069 [US3] Create GET /api/executions/{executionId} endpoint in backend/src/routes/execution-detail.ts (depends on T061)
- [ ] T070 [US3] Add replay retry logic with configurable limits (2 retries per step)
- [ ] T071 [US3] Add replay error handling and structured logging (depends on T015)
- [ ] T072 [US3] Implement session log storage and retrieval in backend/src/services/session-logger.ts
- [ ] T073 [P] [US3] Create flow execution UI components in frontend/src/components/FlowExecution.tsx
- [ ] T074 [P] [US3] Create execution log viewer in frontend/src/components/ExecutionLogs.tsx
- [ ] T075 [US3] Integrate execution UI with backend API in frontend/src/services/execution-api.ts
- [ ] T076 [US3] Add real-time execution status updates in frontend (WebSockets or polling)

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: User Story 4 - LLM-Assisted Flow Management (Priority: P2)

**Goal**: Enable natural language interaction with UI graph and flows through Claude Code integration

**Independent Test**: Ask Claude Code to read graph.json and propose a new flow, verify suggested flow is syntactically correct and uses appropriate state predicates

### Tests for User Story 4

- [ ] T077 [P] [US4] Integration test for LLM flow suggestion parsing in backend/tests/integration/llm-flow-suggestion.test.ts
- [ ] T078 [P] [US4] Integration test for selector ambiguity detection in backend/tests/integration/ambiguity-detection.test.ts

### Implementation for User Story 4

- [ ] T079 [P] [US4] Create LLM prompt templates for flow analysis in backend/src/templates/llm-prompts.ts
- [ ] T080 [US4] Implement graph analysis service for LLM consumption in backend/src/services/graph-analyzer.ts (depends on T023)
- [ ] T081 [US4] Implement flow suggestion service in backend/src/services/flow-suggester.ts (depends on T079, T080)
- [ ] T082 [US4] Implement selector ambiguity detection in backend/src/services/ambiguity-detector.ts (depends on T021)
- [ ] T083 [US4] Create POST /api/graphs/analyze endpoint for LLM consumption in backend/src/routes/graph-analyze.ts
- [ ] T084 [US4] Create POST /api/flows/suggest endpoint for LLM flow suggestions in backend/src/routes/flows-suggest.ts
- [ ] T085 [US4] Add LLM-friendly graph export with state summaries in backend/src/services/graph-exporter.ts
- [ ] T086 [US4] Create Claude Code integration scripts in automation/llm-integration/
- [ ] T087 [US4] Add natural language flow validation feedback in backend/src/services/nl-validator.ts

**Checkpoint**: All user stories including LLM assistance should now be functional

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [ ] T088 [P] Update CONFIG.md with feature-specific environment variables
- [ ] T089 [P] Create CLI helper scripts for graph linting and conflict resolution
- [ ] T090 [P] Implement performance optimizations for graph validation (<2s for 50 states)
- [ ] T091 [P] Add comprehensive error messages for all failure modes
- [ ] T092 [P] Implement graceful degradation when exceeding graph size limits (500 states)
- [ ] T093 [P] Add Docker health checks for all new services
- [ ] T094 [P] Create documentation for API endpoints in backend/docs/api.md
- [ ] T095 [P] Add frontend component documentation and storybook (if needed)
- [ ] T096 Performance testing and optimization for WebRTC streaming (≥720p@15fps)
- [ ] T097 Security hardening for internal API endpoints
- [ ] T098 Run complete quickstart.md validation and update documentation
- [ ] T099 Update agent context scripts for Claude Code integration
- [ ] T100 Final integration testing across all user stories

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3 → P4)
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P1)**: Can start after Foundational (Phase 2) - Integrates with US1 graph structures
- **User Story 3 (P1)**: Can start after Foundational (Phase 2) - Depends on US1 (states) and US2 (flows)
- **User Story 4 (P2)**: Can start after Foundational (Phase 2) - Integrates with US1, US2, US3 outputs

### Within Each User Story

- Tests (if included) MUST be written and FAIL before implementation
- Models before services
- Services before endpoints
- Core implementation before integration
- Story complete before moving to next priority

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, all P1 user stories can start in parallel
- All tests for a user story marked [P] can run in parallel
- Models within a story marked [P] can run in parallel
- Frontend and backend tasks for the same story can often run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all tests for User Story 1 together:
Task: "Integration test for UI state capture via UIAutomator2 in backend/tests/integration/state-capture.test.ts"
Task: "Integration test for state deduplication accuracy in backend/tests/integration/state-dedup.test.ts"
Task: "Integration test for graph JSON serialization in backend/tests/integration/graph-serialization.test.ts"

# Launch all models for User Story 1 together:
Task: "Create State entity and selector logic in backend/src/models/state.ts"
Task: "Create Transition entity model in backend/src/models/transition.ts"
Task: "Create UI Graph (UTG) entity in backend/src/models/graph.ts"

# Launch frontend components for User Story 1 together:
Task: "Create Discovery panel React component in frontend/src/components/DiscoveryPanel.tsx"
Task: "Create state visualization components in frontend/src/components/StateGraph.tsx"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Deploy/Demo
4. Add User Story 3 → Test independently → Deploy/Demo
5. Add User Story 4 → Test independently → Deploy/Demo
6. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (UI Capture & Graph)
   - Developer B: User Story 2 (Flow Definition)
   - Developer C: User Story 3 (Flow Replay)
3. User Story 4 (LLM Integration) can be added by any developer after P1 stories are stable

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing (test-driven approach for integration tests)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
- All JSON artifacts stored under version control with conflict resolution
- WebRTC timeouts must respect 1.5s constitution requirement
- Performance targets: <2s validation for 50-state graphs, ≥80% recovery success rate