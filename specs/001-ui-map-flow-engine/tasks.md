---

description: "Task list for UI Map & Discovery System implementation"
---

# Tasks: UI Map & Discovery System

**Input**: Design documents from `/specs/001-ui-map-flow-engine/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Tests are not explicitly requested in the feature specification for Phase 1 - focusing on discovery functionality.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Web app**: `backend/src/`, `frontend/src/` (per plan.md)
- **Data volume**: `/app/data/` for graph.json and session logs

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and data volume configuration

- [X] T001 Add discovery-data volume to docker-compose.yml for persistent graph storage
- [X] T002 [P] Add discovery system environment variables to .env configuration
- [X] T003 [P] Create /app/data directory structure with proper permissions

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T004 Copy TypeScript types from contracts/types.ts to backend/src/types/graph.ts
- [X] T005 [P] Create ADB connection utilities in backend/src/utils/adb.ts
- [X] T006 [P] Create XML processing utilities in backend/src/utils/xml.ts
- [X] T007 Create state hash utilities in backend/src/utils/hash.ts
- [X] T008 Create discovery system configuration in backend/src/config/discovery.ts
- [X] T009 Add /api/healthz endpoint to backend/src/routes/health.ts for system monitoring
- [X] T009.5 [P] Add frontend health endpoint in frontend/src/components/HealthEndpoint.tsx for constitution compliance

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Manual State Discovery & Mapping (Priority: P1) 🎯 MVP

**Goal**: Enable manual navigation with automatic UI state capture and graph building

**Independent Test**: Launch MaynDrive, navigate to different screens, verify each screen capture creates a state node with proper activity detection and element identification

### Implementation for User Story 1

- [X] T010 [P] [US1] Create introspection service in backend/src/services/introspectService.ts with ADB command execution
- [X] T011 [P] [US1] Create graph service in backend/src/services/graphService.ts with state management and merging logic
- [X] T012 [US1] Implement state snapshot endpoint in backend/src/routes/graph.ts (POST /api/graph/snapshot)
- [X] T013 [US1] Implement get current state endpoint in backend/src/routes/graph.ts (GET /api/state/current)
- [X] T014 [US1] Implement get graph endpoint in backend/src/routes/graph.ts (GET /api/graph)
- [X] T015 [US1] Create useDiscovery hook in frontend/src/hooks/useDiscovery.ts for API integration
- [X] T016 [US1] Create DiscoveryPanel component in frontend/src/components/apps/DiscoveryPanel.tsx
- [X] T017 [US1] Update featureFlagsStore.ts to enable discoveryPanel and disable gpsPanel
- [X] T018 [US1] Add DiscoveryPanel to app layout alongside existing StreamViewer
- [X] T019 [US1] Implement state capture UI controls and current state display
- [X] T020 [US1] Add element selector display and screenshot capture functionality
- [X] T021 [US1] Implement basic graph mini-map visualization for captured states

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Flow Authoring & Definition (Priority: P1)

**Goal**: Define reusable flows using captured UI states with JSON DSL

**Independent Test**: Create a simple login flow JSON file with existing states and validate that flow structure and predicates are syntactically correct

### Implementation for User Story 2

- [X] T022 [P] [US2] Create flow types and interfaces in backend/src/types/flow.ts
- [X] T023 [P] [US2] Create flow service in backend/src/services/flowService.ts for validation and management
- [X] T024 [US2] Implement flow endpoints in backend/src/routes/graph.ts (GET/POST /api/flows/*)
- [X] T025 [US2] Add flow validation logic to ensure predicates resolve to known states
- [X] T026 [US2] Create flow management UI in DiscoveryPanel component
- [ ] T027 [US2] Add flow editor with state predicate selection
- [ ] T028 [US2] Implement semantic selector support for flow actions
- [ ] T029 [US2] Add precondition validation for flow completeness
- [ ] T030 [US2] [CRITICAL] Implement internal API endpoints without authentication per FR-012 requirement
  - Create /api/graph/* endpoints accessible without authentication
  - Add /api/flows/* endpoints for internal access only
  - Ensure endpoints are properly documented as internal-only

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Intelligent Flow Replay with State Recovery (Priority: P1)

**Goal**: Execute automated flows with state detection and intelligent navigation to required starting points

**Independent Test**: Start app in fresh state, initiate unlock flow, verify system automatically detects need to login first, executes login, then completes unlock

### Implementation for User Story 3

- [ ] T030 [P] [US3] Create replay service in backend/src/services/replayService.ts with state detection
- [ ] T031 [P] [US3] Create state matching algorithms in backend/src/utils/stateMatching.ts
- [ ] T032 [P] [US3] Create path finding utilities in backend/src/utils/pathFinding.ts for graph navigation
- [ ] T033 [US3] Implement flow execution endpoint in backend/src/routes/graph.ts (POST /api/flows/{id}/execute)
- [ ] T034 [US3] Add state recovery logic with re-localization capabilities
- [ ] T035 [US3] Implement action execution with ADB commands for tap/type/swipe
- [ ] T036 [US3] Add post-state verification after each action
- [ ] T037 [US3] Create replay UI controls in DiscoveryPanel component
- [ ] T038 [US3] Add real-time replay progress display and logging

**Checkpoint**: All user stories should now be independently functional

---

## Phase 6: User Story 4 - LLM-Assisted Flow Management (Priority: P2)

**Goal**: Enable natural language interaction with UI graph and flows through Claude Code integration

**Independent Test**: Ask Claude Code to read graph.json and propose a new flow, verify suggested flow is syntactically correct and uses appropriate state predicates

### Implementation for User Story 4

- [ ] T039 [P] [US4] Create LLM integration service in backend/src/services/llmService.ts
- [ ] T040 [P] [US4] Add graph analysis endpoints for LLM consumption in backend/src/routes/graph.ts
- [ ] T041 [US4] Create flow suggestion algorithms based on graph analysis
- [ ] T042 [US4] Implement ambiguous selector detection and clarification
- [ ] T043 [US4] Add session log analysis for replay failure explanations
- [ ] T044 [US4] Create Claude Code integration utilities for natural language flow creation
- [ ] T045 [US4] Add LLM assistance UI in DiscoveryPanel component

**Checkpoint**: All user stories should now be independently functional

---

## Phase 7: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [ ] T046 [P] Add comprehensive error handling and logging across all services
- [ ] T047 [P] Implement session logging in backend/src/services/sessionService.ts
- [ ] T047.5 [P] Implement JSONL session logging format in backend/src/services/sessionService.ts
  - Timestamped log entries with structured fields
  - Event types: state_capture, action_execution, flow_progress, error
  - File rotation and cleanup policies per constitution
- [ ] T048 [P] Add performance monitoring and optimization for graph operations
- [ ] T049 Update quickstart.md with complete setup and usage instructions
- [ ] T050 [P] Add input validation and sanitization for all API endpoints
- [ ] T051 Implement graph compaction and cleanup utilities
- [ ] T052 Add comprehensive documentation and code comments
- [ ] T053 Validate all performance targets (<1s capture, <2s validation, <500ms API)
- [ ] T054 End-to-end testing with MaynDrive app for complete workflow validation

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-6)**: All depend on Foundational phase completion
  - User stories can then proceed in priority order (P1 → P2) or in parallel
- **Polish (Phase 7)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational - Core discovery functionality
- **User Story 2 (P1)**: Can start after US1 - Depends on captured states and graph structure
- **User Story 3 (P1)**: Can start after US2 - Depends on flow definitions and state graph
- **User Story 4 (P2)**: Can start after US3 - Depends on complete graph and flow system

### Within Each User Story

- Utilities and services before endpoints and UI components
- Core functionality before integration and advanced features
- Each story should be independently testable before proceeding

### Parallel Opportunities

- **Phase 1**: All setup tasks marked [P] can run in parallel
- **Phase 2**: All foundational tasks marked [P] can run in parallel
- **Within Stories**: Tasks marked [P] can run in parallel by different developers
- **Across Stories**: US1, US2, US3 can be developed in parallel by different team members after foundational phase

---

## Parallel Example: User Story 1

```bash
# Launch all backend services for User Story 1 together:
Task: "Create introspection service in backend/src/services/introspectService.ts"
Task: "Create graph service in backend/src/services/graphService.ts"
Task: "Create useDiscovery hook in frontend/src/hooks/useDiscovery.ts"

# Launch all UI components for User Story 1 together:
Task: "Create DiscoveryPanel component in frontend/src/components/apps/DiscoveryPanel.tsx"
Task: "Update featureFlagsStore.ts to enable discoveryPanel and disable gpsPanel"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1 (Manual discovery)
4. **STOP and VALIDATE**: Test state capture and graph building independently
5. Deploy/demo core discovery functionality

### Incremental Delivery

1. Complete Setup + Foundational → Discovery foundation ready
2. Add User Story 1 → Test independently → Core discovery MVP
3. Add User Story 2 → Test independently → Flow authoring capability
4. Add User Story 3 → Test independently → Intelligent replay system
5. Add User Story 4 → Test independently → LLM assistance features
6. Each story adds value without breaking previous functionality

### Performance Targets

- **State capture**: <1s total including ADB operations
- **Graph validation**: <2s for 50 states, 100 transitions
- **API responses**: <500ms p95
- **Memory usage**: <100MB for typical graphs
- **Graph size**: Support up to 500 states, 2000 transitions

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Follow performance targets defined in plan.md and research.md
- All data persisted to /app/data volume for version control
- TypeScript strict mode maintained throughout implementation
- Container-based architecture per constitution requirements