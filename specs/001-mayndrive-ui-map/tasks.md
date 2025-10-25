# Tasks: MaynDrive State-Aware UI Mapping

**Input**: Design documents from `/specs/001-mayndrive-ui-map/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/, quickstart.md

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Prepare artifact directories and authoring scaffolds referenced by every story.

- [X] T001 Seed the artifact index scaffold at `var/graphs/index.json` with empty `nodes`/`edges` arrays plus checksum metadata placeholders.
- [X] T002 Create the reusable flow template file `var/flows/templates/flow-example.yaml` covering `precondition`, `steps`, `postcondition`, and `recovery` keys.
- [X] T003 Draft the contributor README at `var/flows/README.md` documenting naming rules, safe actions, and LLM editing guidance from the spec.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Establish shared types, validation, and storage helpers required by all user stories.

- [X] T004 Define data-model interfaces (ScreenNode, ActionEdge, FlowDefinition, StateDetectionResult) in `backend/src/types/uiGraph.ts` to mirror `data-model.md`.
- [X] T005 [P] Implement Zod-based validation + serialization helpers in `backend/src/utils/validation/uiGraphSchema.ts` for nodes, edges, and flows.
- [X] T006 Build the artifact storage utility in `backend/src/services/storage/artifactStore.ts` to manage writes to `var/captures`, `var/graphs`, and `var/flows`.
- [X] T007 [P] Create shared frontend types and a base Zustand slice in `frontend/src/stores/uiGraphStore.ts` for loading/saving graph state.
- [X] T008 Document detector threshold env vars (`STATE_DETECTOR_CONFIDENCE_MIN`, etc.) in `CONFIG.md` and `.env.example`.

**Checkpoint**: Base types, validation, storage, and config ready → user story phases may begin.

---

## Phase 3: User Story 1 – Capture & Graph Screens (Priority: P1) 🎯 MVP

**Goal**: Allow operators to capture MaynDrive screens, persist artifacts, and add outgoing actions so the UI graph grows intentionally.

**Independent Test**: From an unmapped screen, capture it, add at least one outgoing action, and confirm the node plus artifacts persist independently of other stories.

### Implementation

- [X] T009 [P] [US1] Create the signature builder (stable traits → SHA-256 hash) in `backend/src/services/ui-graph/signatureBuilder.ts`.
- [X] T010 [US1] Implement `NodeCaptureService` in `backend/src/services/ui-graph/nodeCaptureService.ts` to orchestrate screenshot/UI dump capture and selector ranking.
- [X] T011 [P] [US1] Implement `GraphStore` read/write helpers in `backend/src/services/ui-graph/graphStore.ts` to version graphs under `var/graphs/<timestamp>/`.
- [X] T012 [US1] Add Express routes for `POST /ui-graph/nodes`, `GET /ui-graph/nodes/:id`, and `POST /ui-graph/nodes/:id/actions` in `backend/src/api/ui-graph/routes.ts` using contracts/ui-map.openapi.yaml.
- [X] T013 [P] [US1] Extend the frontend graph store in `frontend/src/stores/uiGraphStore.ts` with actions for loading nodes, capturing signatures, and optimistic edge creation.
- [X] T014 [P] [US1] Build the capture panel UI in `frontend/src/components/discovery/CapturePanel.tsx` (name, hints, selector ranking, artifact upload progress).
- [X] T015 [US1] Wire the Discovery page at `frontend/src/pages/DiscoveryPage.tsx` to list nodes, trigger captures, and visualize outgoing edges.
- [X] T016 [US1] Add the artifact integrity CLI at `scripts/graph/update-index.ts` to recalculate checksums and sync `var/graphs/index.json` during capture sessions.

**Checkpoint**: Operators can capture nodes/actions and see them reflected in the UI graph plus filesystem artifacts.

---

## Phase 4: User Story 2 – Detect Screen State Reliably (Priority: P2)

**Goal**: Given a fresh dump, compute the most likely node (top-K with scores) using stored signatures/selectors and escalate UNKNOWN when confidence is low.

**Independent Test**: Feed mixed known/unknown dumps, run detection, and verify high-confidence matches plus UNKNOWN prompts without invoking flow execution.

### Implementation

- [ ] T017 [P] [US2] Implement the weighted scoring engine in `backend/src/services/state-detector/scoring.ts` (hash match + selector weights + layout similarity).
- [ ] T018 [US2] Build `StateDetectorService` in `backend/src/services/state-detector/stateDetectorService.ts` to run scoring, apply thresholds, and log telemetry.
- [ ] T019 [US2] Expose `POST /state-detection` in `backend/src/api/state-detection.ts` returning top-K candidates + UNKNOWN prompts per OpenAPI contract.
- [ ] T020 [P] [US2] Create the CLI helper `scripts/detector/run-detector.ts` to analyze `var/captures/<nodeId>/ui.xml` dumps locally.
- [ ] T021 [P] [US2] Add the Detection Panel UI in `frontend/src/components/detector/DetectionPanel.tsx` to upload dumps, display scores, and accept/merge decisions.
- [ ] T022 [US2] Integrate detection workflows into `frontend/src/pages/DiscoveryPage.tsx` so operators can re-detect after each action and resolve UNKNOWN states.

**Checkpoint**: Detector delivers ≥90% top-1 accuracy and flags UNKNOWN with operator prompts.

---

## Phase 5: User Story 3 – Build & Replay Flows (Priority: P3)

**Goal**: Define flows (login → unlock → lock) declaratively from the graph and run them from any starting state with state-aware routing plus recovery.

**Independent Test**: Author a flow referencing graph nodes, run it from arbitrary emulator states, and confirm it reaches the target postcondition while enforcing recovery rules.

### Implementation

- [ ] T023 [P] [US3] Implement YAML flow parsing + repository utilities in `backend/src/services/flows/flowRepository.ts` (load/save/list under `var/flows/`).
- [ ] T024 [US3] Build `FlowRunner` in `backend/src/services/flows/flowRunner.ts` to compute precondition paths, execute steps, and invoke detector/recovery hooks.
- [ ] T025 [US3] Add endpoints `GET/POST /flows`, `POST /flows/{name}/validate`, and `POST /flows/{name}/run` in `backend/src/api/flows.ts` per OpenAPI.
- [ ] T026 [P] [US3] Add the flow lint CLI `scripts/flows/lint-flow.ts` to validate references, recovery coverage, and YAML schema compliance.
- [ ] T027 [P] [US3] Build the Flow Builder page at `frontend/src/pages/FlowsPage.tsx` to edit YAML-backed flows, variables, and recovery rules.
- [ ] T028 [US3] Add the runtime control drawer in `frontend/src/components/flows/RunFlowDrawer.tsx` for selecting flows, injecting variables, and monitoring execution logs.

**Checkpoint**: Flows can be authored, validated, and executed with state-aware recovery from any detected node.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Finalize documentation, telemetry, and smoke validation spanning multiple stories.

- [ ] T029 [P] Capture detector + flow telemetry aggregation in `backend/src/services/state-detector/telemetryLogger.ts` and surface summaries in `var/graphs/index.json`.
- [ ] T030 Update `quickstart.md` and `docs/MAYNDRIVE_AUTOMATION.md` with the end-to-end capture → detect → flow workflow plus new CLI commands.
- [ ] T031 [P] Add a smoke script `scripts/flows/run-baseline.sh` that chains login/unlock/lock flows to validate success criteria before releases.

---

## Dependencies & Execution Order

1. **Phase 1 → Phase 2**: Artifact scaffolding must exist before types/storage reference them.
2. **Phase 2 → All User Stories**: Shared types/validation/config are prerequisites for capture, detection, and flows.
3. **User Stories**: US1 (P1) should land first (MVP). US2 can begin once Foundational tasks finish but benefits from sample nodes. US3 depends on both the graph (US1) and detector (US2) to satisfy pathfinding and recovery.
4. **Polish**: Runs after desired stories complete.

### User Story Completion Order

| Order | Story | Reason |
|-------|-------|--------|
| 1 | US1 – Capture & Graph Screens | Required to produce nodes/edges for everything else (MVP). |
| 2 | US2 – Detect Screen State Reliably | Needs existing nodes to score against; enables resilience. |
| 3 | US3 – Build & Replay Flows | Relies on graph + detector to compute paths and recoveries. |

### Parallel Opportunities

- Tasks marked **[P]** touch distinct files and can run concurrently (e.g., T005 vs T006, T009 vs T011, frontend vs backend work per story).
- After Phase 2, teams can work on US1 frontend (T014–T015) while backend finalizes detectors (T017–T019) provided contracts are stable.
- Flow parsing (T023) and Flow UI (T027) can proceed in parallel once US1 artifacts exist.

### Implementation Strategy

- **MVP**: Complete Phases 1–3 to deliver manual capture + graphing; verify via independent test before proceeding.
- **Incremental Delivery**: After MVP, layer US2 (detector) to harden state awareness, then US3 (flows) to operationalize automation. Each phase ends with its checkpoint validation.
- **Parallel Teams**: One developer can drive backend services (T009–T025) while another focuses on frontend UIs (T013–T028) and a third maintains CLI/docs (T016, T020, T026, T029–T031), coordinating through the shared contracts and types created in Phases 1–2.
