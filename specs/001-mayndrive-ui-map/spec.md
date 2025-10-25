# Feature Specification: MaynDrive State-Aware UI Mapping

**Feature Branch**: `001-mayndrive-ui-map`  
**Created**: 2025-10-25  
**Status**: Draft  
**Input**: User description: "Discover MaynDrive manually, auto-produce an LLM-friendly UI graph, and replay flows (login → unlock → lock) intelligently."

## User Scenarios & Testing *(mandatory)*

<!--
  IMPORTANT: User stories should be PRIORITIZED as user journeys ordered by importance.
  Each user story/journey must be INDEPENDENTLY TESTABLE - meaning if you implement just ONE of them,
  you should still have a viable MVP (Minimum Viable Product) that delivers value.
  
  Assign priorities (P1, P2, P3, etc.) to each story, where P1 is the most critical.
  Think of each story as a standalone slice of functionality that can be:
  - Developed independently
  - Tested independently
  - Deployed independently
  - Demonstrated to users independently
-->

### User Story 1 - Capture & Graph Screens (Priority: P1)

Operators can capture any MaynDrive screen, assign a human-readable name, store artifacts, and define outgoing actions so the UI graph grows intentionally.

**Why this priority**: Without reliable manual discovery, there is no baseline graph for downstream automation or LLM reasoning.

**Independent Test**: Start from an unmapped screen, capture it, define at least one outgoing action, and verify the node plus artifacts persist independently of other stories.

**Acceptance Scenarios**:

1. **Given** the operator is on an unmapped screen, **When** they capture the screen signature and annotate it, **Then** a new node with screenshot, XML dump, metadata, and selector ranking is saved to the graph store.
2. **Given** the operator records an action (tap/type/back) from a captured node, **When** the next screen loads, **Then** a directed edge with action metadata and destination node reference is added automatically.

---

### User Story 2 - Detect Screen State Reliably (Priority: P2)

The system can ingest a fresh dump from the emulator and identify the most likely node(s) using stored signatures and selectors, or escalate when confidence is low.

**Why this priority**: State awareness is required before flows can run safely or recover from deviations.

**Independent Test**: Provide a mix of known and unknown screen dumps, run detection, and inspect whether top-K scoring plus UNKNOWN handling works without invoking flow execution.

**Acceptance Scenarios**:

1. **Given** a UI dump whose signature matches a stored node, **When** the detector runs, **Then** it outputs the node as top-ranked with a confidence score above the configured threshold.
2. **Given** a UI dump that does not meet any node's threshold, **When** detection completes, **Then** the system emits UNKNOWN with prompts to map/merge and does not guess blindly.

---

### User Story 3 - Build & Replay Flows (Priority: P3)

Product specialists define flows (login → unlock → lock) declaratively from the graph, and the runner executes them from any starting screen using state-aware routing and recovery.

**Why this priority**: Flows demonstrate business value by proving the graph can drive MaynDrive operations end-to-end.

**Independent Test**: Author a flow referencing graph nodes, then invoke the runner from arbitrary emulator states to confirm it reaches the target outcome while enforcing postconditions.

**Acceptance Scenarios**:

1. **Given** a declared flow with pre/postconditions and variable slots, **When** the runner starts from a mismatched node, **Then** it computes the shortest known path to the precondition before executing flow steps.
2. **Given** the runner executes a step and lands on an unexpected screen, **When** re-detection fails to match the expected node, **Then** the runner retries or applies recovery actions (back/dismiss/reopen) before escalating to the operator.

---

[Additional user stories can be appended if deeper coverage is needed.]

### Edge Cases

- Conflicting signatures: two screens share the same layout but differ by volatile content; system must merge them deliberately or treat them as separate nodes with guard conditions.
- Missing artifacts: if screenshot or XML capture fails mid-action, graph creation pauses and prompts operator rather than storing partial nodes.
- Obstructive overlays: system dialogs or permission pop-ups should be captured either as their own nodes or dismissed via recovery actions before resuming the main flow.
- Broken references: flows referencing deleted nodes or edges must be flagged during validation so the runner declines to start until references are fixed.
- Emulator disconnection: if a WebRTC or ADB session drops during capture or execution, the tool records the interruption and resumes only after reconnection plus state re-detection.

## Requirements *(mandatory)*

<!--
  ACTION REQUIRED: The content in this section represents placeholders.
  Fill them out with the right functional requirements.
-->

### Functional Requirements

- **FR-001**: Provide a manual discovery UI that captures the current MaynDrive screen signature, activity/class metadata, and operator-supplied name in a single action.
- **FR-002**: Persist per-screen artifacts (screenshot, XML/UI dump, structured metadata) and link them to the node so LLMs can reference concrete evidence.
- **FR-003**: Allow operators to add outgoing actions (tap, type, wait, back, custom intent) that automatically capture the resulting screen and create graph edges with `{from, to, action}` payloads.
- **FR-004**: Generate deterministic signatures by hashing stable traits (activity, resource IDs, required texts, layout fingerprint) while excluding volatile tokens such as timestamps.
- **FR-005**: Maintain selector candidates ordered by reliability (resource-id > content-desc > text > xpath > coordinates) and associate each with a confidence score the runner can consume.
- **FR-006**: Implement a state detector that ingests a fresh dump, outputs top-K node candidates with scores, and marks UNKNOWN with a merge/mapping prompt when confidence dips below the threshold.
- **FR-007**: Support declarative flow definitions (JSON/YAML) specifying name, variables, precondition node/query, ordered steps (edge reference or inline action), and postcondition validation.
- **FR-008**: Ship baseline flows for `login → home`, `unlock_scooter → ride_active`, and `lock_scooter → ride_closed`, each parameterized for credentials or vehicle identifiers.
- **FR-009**: Equip the flow runner with pathfinding that uses the UI graph to reach the required precondition from any detected state, or escalates if no route exists.
- **FR-010**: After every executed step, trigger re-detection; on mismatch, retry the action once, then apply minimal recovery options (back, dismiss dialog, reopen app, re-login) before requesting operator help.
- **FR-011**: Allow flow definitions to declare variables/prompts so operators can input phone/email/OTP at runtime, with secure placeholder handling in stored artifacts.
- **FR-012**: Produce a lightweight README aimed at LLM contributors that explains naming rules, how to add nodes/edges, how to author flows safely, and how to keep artifacts compact.
- **FR-013**: Track provenance (who captured, when, emulator build) for every node and edge so future edits and merges stay auditable.
- **FR-014**: Provide guard conditions on edges (e.g., `mustMatchSignature`) so flows only traverse transitions when the originating screen signature still matches expectations.

### Key Entities *(include if feature involves data)*

- **ScreenNode**: Represents a unique MaynDrive screen with id, human-readable name, deterministic signature, sorted selector list, hints, provenance, and artifact references (XML, screenshot, metadata bundle).
- **ActionEdge**: Directed connection between two nodes containing the action type, selector reference or text/keycode payload, optional guard signature, notes, and capture timestamp.
- **ScreenSignature**: Normalized hash inputs (activity, stable resource IDs, structural fingerprint) plus the resulting hash, used by the detector and guard checks.
- **SelectorCandidate**: A selector string plus type (resource-id, content-desc, text, xpath, coordinates) and confidence score; nodes store arrays of these ranked by reliability.
- **FlowDefinition**: Declarative document containing name, description, variable schema, precondition, ordered steps (edge references or inline actions), and expected postcondition node/query.
- **FlowStep**: Atomic action within a FlowDefinition referencing an ActionEdge or describing an ad-hoc operation (e.g., OTP entry) plus optional guard and retry strategy.
- **StateDetectionResult**: Output from the detector with ordered candidate nodes, confidence scores, chosen node, and threshold evaluations (OK vs UNKNOWN).
- **ArtifactBundle**: Collection of files per node (screenshot, XML dump, optional notes) including storage path and checksum so LLMs can fetch lightweight samples.

### Assumptions

- Operators have stable emulator access via WebRTC plus ADB/Frida tooling, so connectivity considerations remain out of scope for this spec.
- Storage for screenshots/XML is available under project-managed directories (`var/`) with sufficient retention for iterative discovery.
- MaynDrive app builds remain consistent enough that deterministic signatures stay valid between discovery and flow playback; drastic UI redesigns will trigger re-capture efforts.

## Success Criteria *(mandatory)*

<!--
  ACTION REQUIRED: Define measurable success criteria.
  These must be technology-agnostic and measurable.
-->

### Measurable Outcomes

- **SC-001**: Operators can capture and annotate any new MaynDrive screen (node plus artifacts) in under 30 seconds once the screen is ready, measured across five consecutive captures.
- **SC-002**: The state detector selects the correct node as top-1 with ≥90% accuracy for mapped screens and flags UNKNOWN within 2 seconds when confidence drops below 60%.
- **SC-003**: Each baseline flow (login, unlock, lock) executes from an arbitrary starting state with no more than one manual intervention in 95% of trial runs.
- **SC-004**: New contributors can author or edit a flow using the README in under 60 minutes, validated by onboarding dry-runs, and produce artifacts that stay under 1 MB per screen bundle to remain LLM-friendly.
