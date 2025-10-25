# Feature Specification: AutoApp UI Map & Intelligent Flow Engine for MaynDrive

**Feature Branch**: `001-ui-map-flow-engine`
**Created**: 2025-10-25
**Status**: Draft
**Input**: User description: "AutoApp UI Map & Intelligent Flow Engine for MaynDrive..."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Manual State Discovery & Mapping (Priority: P1)

As a security researcher exploring the MaynDrive app, I want to manually navigate through the app interface and automatically capture UI states so that I can build a complete map of screens, widgets, and transitions without manual note-taking.

**Why this priority**: This is the foundational capability that enables all other automation features. Without state discovery and mapping, users cannot create flows or perform intelligent replay.

**Independent Test**: Can be fully tested by launching MaynDrive, navigating to different screens, and verifying that each screen capture creates a state node in the graph with proper activity detection and element identification.

**Acceptance Scenarios**:

1. **Given** MaynDrive is visible in the WebRTC stream, **When** I click "Snapshot state", **Then** a new state node appears in graph.json with activity name, view hierarchy digest, and element selectors
2. **Given** I capture the same screen multiple times, **When** I view the graph, **Then** duplicate captures are merged into a single state node
3. **Given** I capture two different screens sequentially, **When** I annotate the transition between them, **Then** a directed edge connects the state nodes with the action details

---

### User Story 2 - Flow Authoring & Definition (Priority: P1)

As an automation author, I want to define reusable flows using the captured UI states so that I can create automated sequences for common tasks like login, unlock, and lock operations.

**Why this priority**: Flow definition is the primary user value - it transforms manual exploration into reusable automation that saves time and ensures consistency.

**Independent Test**: Can be fully tested by creating a simple login flow JSON file with existing states and validating that the flow structure and predicates are syntactically correct and logically sound.

**Acceptance Scenarios**:

1. **Given** an existing UI graph with multiple states, **When** I create flows/login.json with state predicates and actions, **Then** validation passes confirming all predicates resolve to known states
2. **Given** I define a flow with preconditions, **When** the system validates the flow, **Then** it confirms that all preconditions can be satisfied through paths in the UI graph
3. **Given** I create a flow step with semantic selectors, **When** I save the flow file, **Then** the selectors are stored and can be resolved to specific UI elements during replay

---

### User Story 3 - Intelligent Flow Replay with State Recovery (Priority: P1)

As a security researcher, I want to execute automated flows that can detect the current app state and intelligently navigate to the required starting point so that I can run reliable automation even when the app is in an unexpected state.

**Why this priority**: This delivers the core automation value - making flows robust enough to handle real-world variability without constant manual intervention.

**Independent Test**: Can be fully tested by starting the app in a fresh state, initiating the unlock flow, and verifying that the system automatically detects the need to login first, executes login, then proceeds with unlock.

**Acceptance Scenarios**:

1. **Given** the app is in a fresh/unauthenticated state, **When** I start the unlock flow, **Then** the system detects missing login precondition, executes login flow first, then completes unlock
2. **Given** replay encounters an unexpected dialog, **When** the system cannot match expected post-state, **Then** it attempts re-localization and either recovers or stops with clear logging
3. **Given** a flow is executing successfully, **When** each step completes, **Then** the system verifies the expected post-state before proceeding to the next step

---

### User Story 4 - LLM-Assisted Flow Management (Priority: P2)

As a Claude Code user, I want to interact with the UI graph and flows through natural language so that I can quickly understand the automation capabilities and get help with flow creation and debugging.

**Why this priority**: This makes the system accessible to non-technical users and dramatically improves productivity for technical users by enabling rapid iteration through natural language interaction.

**Independent Test**: Can be fully tested by asking Claude Code to read the graph.json and propose a new flow, then verifying that the suggested flow is syntactically correct and uses appropriate state predicates.

**Acceptance Scenarios**:

1. **Given** an existing UI graph, **When** I ask Claude Code to suggest a flow, **Then** it analyzes the graph and proposes a valid flow JSON with appropriate states and transitions
2. **Given** ambiguous selectors in a flow, **When** I run validation, **Then** Claude Code identifies the ambiguity and suggests clarifying questions or alternative selectors
3. **Given** a failed replay session, **When** I ask for explanation, **Then** Claude Code analyzes the session log and provides a clear explanation of why the replay failed and how to fix it

---

### Edge Cases

- What happens when the app undergoes UI updates that change view hierarchies?
- How does the system handle dynamic content like timers, notifications, or location-based elements?
- What occurs when WebRTC stream disconnects during state capture or flow execution?
- How are network errors or app crashes handled during flow replay?
- What happens when multiple similar UI elements match a selector (ambiguous selectors)?
- How does the system handle app permissions dialogs or system notifications?
- What occurs when the app is in an unknown state that doesn't match any captured states?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST capture UI state including activity name, view hierarchy digest, visible text snippets, element bounds, and screenshot hash
- **FR-002**: System MUST merge duplicate states by normalizing screens to the same node key based on activity and structural similarity
- **FR-003**: System MUST store UI graph as LLM-readable JSON with states, transitions, canonical selectors, and semantic labels
- **FR-004**: System MUST support flow definition via JSON DSL with name, goal predicates, preconditions, and action steps
- **FR-005**: System MUST validate flow syntax and resolve all state predicates to known graph states or explicit TODOs
- **FR-006**: System MUST detect current app state during replay and compute shortest path to satisfy flow preconditions
- **FR-007**: System MUST execute flow steps with semantic selectors and verify expected post-state after each action
- **FR-008**: System MUST provide detailed logging for replay decisions including detours, recovery attempts, and failure reasons
- **FR-009**: System MUST support state recovery by re-localizing when unexpected states are encountered during replay
- **FR-010**: System MUST maintain session logs with timestamped action/state events for debugging and analysis
- **FR-011**: System MUST provide clean-state and resume-from-activity bootstrap procedures
- **FR-012**: System MUST expose flow management API endpoints for reading/writing graphs and flows without authentication requirements (internal-only API)
- **FR-013**: System MUST tolerate minor UI layout shifts and dynamic text for robust state detection
- **FR-014**: System MUST halt replay with clear error messages when encountering unknown states without recovery options
- **FR-015**: System MUST store all artifacts under version control with stable JSON format

### Non-Functional Requirements

- **NFR-001**: System MUST support graphs up to 500 states with sub-2-second validation performance
- ~~**NFR-002**: System MUST operate without external network dependencies for core functionality~~
  - ~~WebRTC streaming is internal-only within Docker Compose network (existing functionality preserved)~~
  - ~~No external internet connectivity required for state capture, graph operations, or flow execution~~
  - ~~External WebRTC access continues through existing Traefik proxy configuration~~
- **NFR-002**: System MUST be fully accessible through remote Dockploy deployment for MaynDrive automation
  - All APIs accessible via Traefik proxy through Dockploy domain
  - WebRTC streaming works remotely through Dockploy configuration
  - Full remote workflow support for MaynDrive automation operations
- **NFR-003**: System MUST provide CLI interface compatible with standard shell scripting
- **NFR-004**: System MUST maintain JSON file compatibility across minor version updates
- **NFR-005**: System MUST handle concurrent access to graph files with proper conflict detection
- **NFR-006**: WebRTC streaming MUST support at least 720p resolution at 15fps for UI element visibility
- **NFR-007**: System MUST provide graceful degradation when exceeding graph size limits

### Key Entities

- **State**: Unique UI situation representing a screen with salient widgets, activity name, view hierarchy digest, selectors, text snippets, and screenshot hash
- **Action**: User-like interaction (tap, type, swipe, back, intent launch) with target selector and optional parameters
- **Transition**: Directed edge connecting two states via a specific action with before/after state evidence
- **UI Graph (UTG)**: Directed graph structure containing all discovered states, transitions, and semantic relationships
- **Flow**: Goal-oriented automation sequence with preconditions, steps, success criteria, and recovery logic
- **Session Event**: Timestamped log entry capturing state detection, action execution, results, and optional screenshot hash
- **State Predicate**: Logical expression that matches specific UI states based on activity, elements, or semantic properties
  - **Examples**:
    - `activity.equals("MainActivity")`
    - `elements.contains("resource-id:login_button")`
    - `text.matches(".*Login.*") AND activity.startsWith("Auth")`
    - `semantic.isLoginScreen()`
  - **Operators**: `equals`, `contains`, `matches`, `startsWith`, `AND`, `OR`, `NOT`

## Technical Constraints & Architecture

### Technology Stack
- **Android UI Automation**: UIAutomator2 v2.3.0 + Accessibility Services for element identification and interaction
  - Use ADB bridge for command execution to emulator
  - Minimum API level: Android 8.0 (API 26) required for UIAutomator2 compatibility
- **WebRTC Implementation**: Browser-based client receiving Android screen capture stream
- **Data Persistence**: JSON files under version control (Git) with conflict resolution utilities
- **Deployment Model**: Primary CLI tool with optional web dashboard for visualization
- **Graph Size Limits**: Optimized for up to 500 states and 2000 transitions for acceptable performance

### Integration Requirements
- Android device accessibility via ADB for UI automation
- WebRTC signaling server for screen streaming coordination
- Local file system access for graph and flow storage
- No external network dependencies for core functionality

## Clarifications

### Session 2025-10-25

- Q: What Android UI automation framework should be used for the implementation? → A: UIAutomator2 + Accessibility Services (standard approach with good element identification)
- Q: How should the system handle WebRTC streaming integration? → A: Browser-based WebRTC client connecting to Android screen capture (web interface receives stream)
- Q: What should be the maximum UI graph size for acceptable performance? → A: 500 states, 2000 transitions (medium complexity apps)
- Q: How should the system persist and manage UI graph data? → A: JSON files in Git with conflict resolution helpers (version-controlled approach)
- Q: What deployment model should the system support? → A: CLI tool + optional web dashboard (primary CLI with visualization)

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can capture and merge UI states with 95% accuracy in deduplication across multiple captures of the same screen
- **SC-002**: Flow validation completes in under 2 seconds for graphs with up to 50 states and 100 transitions
- **SC-003**: Intelligent replay successfully reaches flow goals 90% of the time when starting from any valid app state
- **SC-004**: State detection and matching occurs in under 1 second on local hardware during replay operations
- **SC-005**: System recovers from unexpected states and successfully completes flows 80% of the time without manual intervention
- **SC-006**: Claude Code can successfully propose syntactically correct flows 85% of the time when given natural language requirements
- **SC-007**: Users report saving 70% of time on automation tasks compared to manual script writing methods
- **SC-008**: UI graphs remain stable across app version updates with less than 15% state node changes for minor releases