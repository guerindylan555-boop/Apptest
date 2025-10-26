# Tasks: MaynDrive State-Aware UI Mapping

**Input**: Design documents from `/specs/001-mayndrive-ui-map/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, quickstart.md

**Tests**: Tests are NOT explicitly requested in the specification, so this task list focuses on implementation tasks only.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

Per plan.md, this project uses:
- **Backend**: `backend/src/`
- **Frontend**: `frontend/src/`
- **Artifacts**: `var/`
- **Scripts**: `scripts/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [x] T001 Create directory structure for UI graph artifacts in var/captures/, var/graphs/, and var/flows/
- [x] T002 [P] Create flow templates directory in var/flows/templates/ with example flow
- [x] T003 [P] Initialize TypeScript types for entities in backend/src/types/graph.ts
- [x] T004 [P] Add configuration schema for detector thresholds in backend/src/config/detector.ts

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T005 Create ScreenSignature entity and hash generation utility in backend/src/models/ScreenSignature.ts
- [x] T006 [P] Create SelectorCandidate entity with ranking logic in backend/src/models/SelectorCandidate.ts
- [x] T007 [P] Create ArtifactBundle entity with checksum validation in backend/src/models/ArtifactBundle.ts
- [x] T008 Create ScreenNode entity with validation rules in backend/src/models/ScreenNode.ts (depends on T005, T006, T007)
- [x] T009 Create ActionEdge entity with guard logic in backend/src/models/ActionEdge.ts (depends on T008)
- [x] T010 [P] Create StartStateProfile entity in backend/src/models/StartStateProfile.ts (depends on T008)
- [x] T011 [P] Create FlowStep entity in backend/src/models/FlowStep.ts
- [x] T012 Create FlowDefinition entity with validation in backend/src/models/FlowDefinition.ts (depends on T009, T011)
- [x] T013 [P] Create StateDetectionResult entity for telemetry in backend/src/models/StateDetectionResult.ts
- [x] T014 Implement graph storage service with JSON persistence in backend/src/services/graphStore.ts
- [x] T015 [P] Implement artifact storage service with filesystem operations in backend/src/services/artifactStore.ts
- [x] T016 Setup ADB/UIAutomator integration utility in backend/src/utils/adb.ts
- [x] T017 [P] Setup Frida hook integration utility in backend/src/utils/frida.ts
- [x] T018 Create base REST API routes structure in backend/src/api/routes.ts
- [x] T019 [P] Setup Zustand store structure in frontend/src/stores/uiGraphStore.ts
- [x] T020 [P] Create API client service in frontend/src/services/apiClient.ts

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Capture & Graph Screens (Priority: P1) 🎯 MVP

**Goal**: Operators can capture any MaynDrive screen (clean boot, arbitrary login credentials, and post-login home variants), assign a human-readable name, store artifacts, and define outgoing actions so the UI graph grows intentionally.

**Independent Test**: Start from an unmapped screen, capture it, define at least one outgoing action, and verify the node plus artifacts persist independently of other stories.

### Implementation for User Story 1

- [ ] T021 [P] [US1] Implement XML dump normalization utility in backend/src/utils/xmlNormalizer.ts
- [ ] T022 [P] [US1] Implement deterministic signature generation from XML dumps in backend/src/services/signatureGenerator.ts
- [ ] T023 [P] [US1] Implement selector extraction and ranking logic in backend/src/services/selectorExtractor.ts
- [x] T024 [US1] Implement screen capture service orchestrating ADB/artifacts/signature in backend/src/services/captureService.ts (depends on T021, T022, T023)
- [x] T025 [US1] Create POST /api/ui-graph/nodes endpoint with validation in backend/src/api/routes/ui-graph.ts
- [ ] T026 [P] [US1] Create capture UI component with name/hints input in frontend/src/components/CapturePanel.tsx
- [ ] T027 [P] [US1] Create start-state tag selector component in frontend/src/components/StartStateSelector.tsx
- [ ] T028 [US1] Integrate capture UI with backend endpoint and graph store in frontend/src/pages/OperatorConsole.tsx
- [ ] T029 [US1] Implement action edge creation service in backend/src/services/edgeService.ts
- [ ] T030 [US1] Create POST /api/captures/action endpoint for recording actions in backend/src/api/captureController.ts
- [ ] T031 [P] [US1] Create action definition UI with selector/action-type selection in frontend/src/components/ActionEditor.tsx
- [ ] T032 [US1] Implement action execution and destination capture workflow in backend/src/services/actionExecutor.ts
- [ ] T033 [US1] Add graph visualization component for nodes and edges in frontend/src/components/GraphViewer.tsx
- [ ] T034 [US1] Add node detail panel showing artifacts and metadata in frontend/src/components/NodeDetail.tsx
- [ ] T035 [US1] Implement artifact bundle storage with checksum validation in backend/src/services/captureService.ts
- [ ] T036 [US1] Create GET /api/nodes/:id endpoint for node retrieval in backend/src/api/nodeController.ts
- [ ] T037 [US1] Add error handling and retry logic for capture failures in backend/src/services/captureService.ts
- [ ] T038 [US1] Implement provenance tracking (operator, timestamp, build) in backend/src/services/captureService.ts

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Detect Screen State Reliably (Priority: P2)

**Goal**: The system can ingest a fresh dump from the emulator and identify the most likely node(s) using stored signatures and selectors, or escalate when confidence is low.

**Independent Test**: Provide a mix of known and unknown screen dumps, run detection, and inspect whether top-K scoring plus UNKNOWN handling works without invoking flow execution.

### Implementation for User Story 2

- [ ] T039 [P] [US2] Implement signature matching scorer in backend/src/services/detector/signatureMatcher.ts
- [ ] T040 [P] [US2] Implement selector-based scoring with weighted ranking in backend/src/services/detector/selectorScorer.ts
- [ ] T041 [P] [US2] Implement structural similarity scorer using Jaccard in backend/src/services/detector/structuralScorer.ts
- [x] T042 [US2] Implement composite detector combining all scorers in backend/src/services/detector/stateDetector.ts (depends on T039, T040, T041)
- [x] T043 [US2] Implement top-K candidate ranking with threshold logic in backend/src/services/detector/stateDetector.ts
- [x] T044 [US2] Create POST /api/state-detection endpoint for state detection in backend/src/api/state-detection.ts
- [ ] T045 [P] [US2] Create detection result display component in frontend/src/components/DetectionResult.tsx
- [ ] T046 [P] [US2] Create UNKNOWN state handler UI with map/merge options in frontend/src/components/UnknownStateHandler.tsx
- [ ] T047 [US2] Integrate detector with operator console for manual detection runs in frontend/src/pages/OperatorConsole.tsx
- [ ] T048 [US2] Implement telemetry logging for detection results in backend/src/services/telemetryService.ts
- [ ] T049 [US2] Create GET /api/telemetry/detections endpoint for result history in backend/src/api/telemetryController.ts
- [ ] T050 [US2] Add confidence visualization (green/amber/red) in frontend/src/components/DetectionResult.tsx
- [ ] T051 [US2] Implement node merging service for duplicate detection in backend/src/services/nodeMergeService.ts
- [ ] T052 [US2] Create UI workflow for merging similar nodes in frontend/src/components/NodeMergeDialog.tsx
- [ ] T053 [US2] Add start-state profile filtering to detector for faster scoping in backend/src/services/detector/stateDetector.ts

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Build & Replay Flows (Priority: P3)

**Goal**: Product specialists define flows (login → unlock → lock) declaratively from the graph, and the runner executes them from any starting screen using state-aware routing and recovery, covering both "no rental yet" and "existing rental" unlock/lock behaviors.

**Independent Test**: Author a flow referencing graph nodes, then invoke the runner from arbitrary emulator states to confirm it reaches the target outcome while enforcing postconditions.

### Implementation for User Story 3

- [x] T054 [P] [US3] Implement YAML flow parser with schema validation in backend/src/services/flowParser.ts
- [x] T055 [P] [US3] Implement flow definition storage service in backend/src/services/flowStore.ts
- [x] T056 [P] [US3] Implement pathfinding algorithm for precondition routing in backend/src/services/pathfinder.ts
- [x] T057 [US3] Implement flow step executor with action dispatch in backend/src/services/flowRunner/stepExecutor.ts
- [x] T058 [US3] Implement post-step detection and validation in backend/src/services/flowRunner/stepValidator.ts (depends on T042)
- [x] T059 [US3] Implement recovery action handler (back/dismiss/reopen/relogin) in backend/src/services/flowRunner/recoveryHandler.ts
- [x] T060 [US3] Implement flow runner orchestrator with retry logic in backend/src/services/flowRunner/flowRunner.ts (depends on T056, T057, T058, T059)
- [x] T061 [US3] Create POST /api/flows/run endpoint for flow execution in backend/src/api/flows.ts
- [x] T062 [US3] Create GET /api/flows endpoint for listing flows in backend/src/api/flows.ts
- [ ] T063 [P] [US3] Create flow editor UI component with YAML editing in frontend/src/components/FlowEditor.tsx
- [ ] T064 [P] [US3] Create flow list component with run triggers in frontend/src/components/FlowList.tsx
- [ ] T065 [US3] Create flow execution monitor with step-by-step progress in frontend/src/components/FlowExecutionMonitor.tsx
- [ ] T066 [US3] Implement variable prompt UI for runtime credential input in frontend/src/components/FlowVariablePrompt.tsx
- [ ] T067 [US3] Add unlock policy resolver (any_available vs existing_rental_only) in backend/src/services/flowRunner/unlockPolicyResolver.ts
- [ ] T068 [US3] Implement scooter selection logic for "no rental" flows in backend/src/services/flowRunner/scooterSelector.ts
- [ ] T069 [US3] Implement existing rental verification for "with rental" flows in backend/src/services/flowRunner/rentalVerifier.ts
- [ ] T070 [US3] Create baseline login-home flow definition in var/flows/login-home.yaml
- [ ] T071 [US3] Create baseline unlock-any-scooter flow definition in var/flows/unlock-any.yaml
- [ ] T072 [US3] Create baseline unlock-existing-scooter flow definition in var/flows/unlock-existing.yaml
- [ ] T073 [US3] Create baseline lock-scooter flow definition in var/flows/lock-scooter.yaml
- [ ] T074 [US3] Implement flow validation CLI command in scripts/flows-lint.ts
- [ ] T075 [US3] Implement flow execution CLI command in scripts/flows-run.ts
- [ ] T076 [US3] Add postcondition verification to flow runner in backend/src/services/flowRunner/flowRunner.ts
- [ ] T077 [US3] Add manual intervention prompts for operator escalation in backend/src/services/flowRunner/flowRunner.ts
- [ ] T078 [US3] Create execution telemetry logging in backend/src/services/telemetryService.ts
- [ ] T079 [US3] Create GET /api/telemetry/executions endpoint for flow run history in backend/src/api/telemetryController.ts

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [ ] T080 [P] Create LLM-friendly README in var/flows/README.md with naming rules and safe-action guidance
- [ ] T081 [P] Add artifact size tracking and pruning logic to stay under 1MB per bundle in backend/src/services/artifactStore.ts
- [ ] T082 [P] Update CONFIG.md with detector threshold configuration options
- [ ] T083 [P] Update docker-compose.yml with any new environment variables per Constitution §12
- [ ] T084 Code cleanup: ensure all TypeScript compiles under strict mode per Constitution §9
- [ ] T085 Code cleanup: run linter and fix all violations
- [ ] T086 [P] Add comprehensive logging for capture, detection, and execution workflows
- [ ] T087 [P] Add node/edge status management (active/deprecated/duplicate) UI in frontend/src/components/NodeDetail.tsx
- [ ] T088 Validate quickstart.md scenarios end-to-end
- [ ] T089 Performance optimization: ensure capture actions complete in <30s per SC-001
- [ ] T090 Performance optimization: ensure detector classification runs in <2s per SC-002
- [ ] T091 [P] Add broken reference detection for flows in backend/src/services/flowValidator.ts
- [ ] T092 [P] Add emulator disconnection handling and recovery in backend/src/utils/adb.ts
- [ ] T093 Documentation: add inline code comments for complex algorithms (signature hashing, scoring)
- [ ] T094 Security: implement secure placeholder handling for sensitive variables in backend/src/services/flowRunner/variableResolver.ts

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-5)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3)
- **Polish (Phase 6)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - Integrates with US1's graph nodes but detector is independently testable
- **User Story 3 (P3)**: Depends on US2 completion for detection during flow execution; integrates with US1's graph structure

### Within Each User Story

**User Story 1**:
- T021-T023 can run in parallel (different utilities)
- T024 depends on T021-T023
- T026-T027 can run in parallel (different UI components)
- T031 can run in parallel with T029-T030
- T033-T034 can run in parallel (different UI components)

**User Story 2**:
- T039-T041 can run in parallel (different scoring strategies)
- T042-T043 depend on T039-T041
- T045-T046 can run in parallel (different UI components)

**User Story 3**:
- T054-T056 can run in parallel (different services)
- T063-T064 can run in parallel (different UI components)
- T070-T073 can run in parallel (different flow files)

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, all user stories can start in parallel (if team capacity allows)
- Within each user story, all tasks marked [P] can run in parallel
- Different user stories can be worked on in parallel by different team members

---

## Parallel Example: User Story 1

```bash
# Launch signature generation, selector extraction, and XML normalization together:
Task: "Implement XML dump normalization utility in backend/src/utils/xmlNormalizer.ts"
Task: "Implement deterministic signature generation from XML dumps in backend/src/services/signatureGenerator.ts"
Task: "Implement selector extraction and ranking logic in backend/src/services/selectorExtractor.ts"

# Launch capture UI and start-state selector together:
Task: "Create capture UI component with name/hints input in frontend/src/components/CapturePanel.tsx"
Task: "Create start-state tag selector component in frontend/src/components/StartStateSelector.tsx"

# Launch graph viewer and node detail together:
Task: "Add graph visualization component for nodes and edges in frontend/src/components/GraphViewer.tsx"
Task: "Add node detail panel showing artifacts and metadata in frontend/src/components/NodeDetail.tsx"
```

---

## Parallel Example: User Story 2

```bash
# Launch all scoring strategies together:
Task: "Implement signature matching scorer in backend/src/services/detector/signatureMatcher.ts"
Task: "Implement selector-based scoring with weighted ranking in backend/src/services/detector/selectorScorer.ts"
Task: "Implement structural similarity scorer using Jaccard in backend/src/services/detector/structuralScorer.ts"

# Launch detection result display and unknown state handler together:
Task: "Create detection result display component in frontend/src/components/DetectionResult.tsx"
Task: "Create UNKNOWN state handler UI with map/merge options in frontend/src/components/UnknownStateHandler.tsx"
```

---

## Parallel Example: User Story 3

```bash
# Launch flow parser, storage, and pathfinding together:
Task: "Implement YAML flow parser with schema validation in backend/src/services/flowParser.ts"
Task: "Implement flow definition storage service in backend/src/services/flowStore.ts"
Task: "Implement pathfinding algorithm for precondition routing in backend/src/services/pathfinder.ts"

# Launch all baseline flows together:
Task: "Create baseline login-home flow definition in var/flows/login-home.yaml"
Task: "Create baseline unlock-any-scooter flow definition in var/flows/unlock-any.yaml"
Task: "Create baseline unlock-existing-scooter flow definition in var/flows/unlock-existing.yaml"
Task: "Create baseline lock-scooter flow definition in var/flows/lock-scooter.yaml"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (4 tasks)
2. Complete Phase 2: Foundational (16 tasks - CRITICAL, blocks all stories)
3. Complete Phase 3: User Story 1 - Capture & Graph Screens (18 tasks)
4. **STOP and VALIDATE**: Manually capture multiple screens, define actions, verify artifacts persist
5. Demo capture workflow to stakeholders

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready (20 tasks)
2. Add User Story 1 → Test independently → Deploy/Demo (MVP! 18 additional tasks = 38 total)
3. Add User Story 2 → Test independently → Deploy/Demo (15 additional tasks = 53 total)
4. Add User Story 3 → Test independently → Deploy/Demo (26 additional tasks = 79 total)
5. Polish phase → Production ready (15 additional tasks = 94 total)
6. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together (20 tasks)
2. Once Foundational is done:
   - Developer A: User Story 1 (capture system - 18 tasks)
   - Developer B: User Story 2 (detector system - 15 tasks, can start in parallel)
   - Developer C: User Story 3 (flow runner system - 26 tasks, starts after US2 detection service is complete)
3. Stories complete and integrate independently

---

## Success Criteria Alignment

Tasks are designed to satisfy the spec's measurable outcomes:

- **SC-001** (Capture in <30s): Validated by T089 performance optimization
- **SC-002** (Detect ≥90% accuracy, <2s): Validated by T090 performance optimization
- **SC-003** (Flow execution ≤1 intervention 95% runs): Validated by T088 quickstart scenarios
- **SC-004** (Author flow <60min, <1MB artifacts): Validated by T080 README and T081 size tracking

---

## Notes

- [P] tasks = different files, no dependencies within their group
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
- All TypeScript must compile under strict mode (Constitution §9)
- All artifacts stored under `var/` volume (Constitution §7)
- No new services or ingress introduced (Constitution §§2, 3)
- WebRTC bridge preserved, no ws-scrcpy (Constitution §4)
