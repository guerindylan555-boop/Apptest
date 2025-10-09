# Feature Specification: Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

**Feature Branch**: `001-web-ui-read`  
**Created**: 2025-10-08  
**Status**: Draft  
**Input**: User description: "Single-page localhost UI that streams the Android emulator in read-only mode and provides start/stop control with clear state feedback."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Start emulator and view live stream (Priority: P1)

A solo tester opens the localhost page, starts the rooted emulator, and sees the Android screen streaming within the target startup window.

**Why this priority**: Without the ability to start the emulator and view the stream, the page delivers no value.

**Independent Test**: Launch the page, trigger Start Emulator, and confirm the stream appears within the required time while the button and badge reflect state changes.

**Acceptance Scenarios**:

1. **Given** the tester loads the page in a browser, **When** they click Start Emulator, **Then** the state badge shows Booting… until the emulator is running.
2. **Given** the emulator reaches Running state, **When** the stream attaches successfully, **Then** the tester sees the Android screen with ≤500 ms perceived latency.

---

### User Story 2 - Stop emulator safely from the UI (Priority: P2)

A solo tester stops the running emulator from the same page and sees the stream end gracefully with state reverting to Stopped.

**Why this priority**: Testers must be able to release resources without leaving the interface; however, the capability depends on the emulator already running.

**Independent Test**: With the emulator streaming, click Stop Emulator and confirm the state transitions to Stopping… then Stopped while the stream area resets.

**Acceptance Scenarios**:

1. **Given** the emulator is running, **When** the tester clicks Stop Emulator, **Then** the state badge shows Stopping… and the button disables until completion.
2. **Given** stop succeeds, **When** the operation completes, **Then** the stream pane displays a placeholder and the badge reads Stopped.

---

### User Story 3 - Understand failures and access logs (Priority: P3)

A solo tester encounters a failure (start, stop, or stream attach) and receives actionable messaging plus a link to local logs for follow-up.

**Why this priority**: Clear failure feedback prevents confusion and supports troubleshooting, though it is exercised less frequently than the primary happy paths.

**Independent Test**: Simulate a start failure, confirm the Error badge appears with a human-readable message and the logs link, and verify the primary button offers an appropriate recovery action.

**Acceptance Scenarios**:

1. **Given** a start attempt times out, **When** the UI detects the failure, **Then** it displays an Error badge with “Boot timeout” messaging and exposes a Retry Start action.
2. **Given** the stream cannot attach while the emulator reports Running, **When** retries continue, **Then** the UI shows a non-blocking banner about stream retrying and keeps polling health.
3. **Given** stream attach retries hit their timeout while the emulator is still Running, **When** the timeout elapses, **Then** the UI switches to Error, stops retrying, and offers a Retry Stream action.
4. **Given** a stop attempt fails because the emulator process is unresponsive, **When** the tester selects Force Stop, **Then** the UI issues a hard kill via the backend, updates logs, and returns the badge to Stopped once successful.

---

### Edge Cases

- If the health endpoint becomes unreachable while the emulator reports Running, the UI immediately switches to Error, disables Start/Stop, and directs the tester to restore the backend before retrying.
- If stream attach retries exceed the timeout while the emulator remains Running, the UI switches to Error, halts retries, and prompts the tester with a Retry Stream action.
- If a stop attempt fails because the emulator process is unresponsive, the UI switches to Error, surfaces a Force Stop action that issues a hard kill via the backend, and updates the badge once recovery completes.
- If the emulator is stopped outside the UI (manual host kill), health polling detects the transition and the UI resets badges and stream pane to Stopped without manual refresh.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The web UI MUST be served only via `http://127.0.0.1:8080` (configurable port in local settings) and reject non-localhost access.
- **FR-002**: The primary button MUST display Start Emulator when the emulator state is Stopped and Stop Emulator when the state is Running.
- **FR-003**: During state transitions (Booting…, Stopping…), the primary button MUST disable input and show an inline loading indicator.
- **FR-004**: The interface MUST present a state badge with values Stopped, Booting…, Running, Stopping…, or Error that always reflects backend-reported truth.
- **FR-005**: The stream pane MUST render the Android display in read-only mode with pointer and keyboard input ignored.
- **FR-006**: When state becomes Running, the UI MUST retry attaching to the stream until success or a configurable timeout is reached; on timeout it MUST switch the badge to Error, stop further retries, display an error banner, and surface a Retry Stream action for the tester.
- **FR-007**: On Stop Emulator, the backend MUST terminate the emulator session, release the stream, and notify the UI to revert to Stopped within the target window; if the emulator process is unresponsive, the UI MUST switch to Error and expose a Force Stop action that issues a hard kill through the backend before resetting state.
- **FR-008**: When any start/stop/attach error occurs, the UI MUST display an error banner containing a concise reason and a link to local logs.
- **FR-009**: A health polling mechanism MUST query a localhost endpoint at defined intervals to synchronize UI state and detect divergence; if polling fails while the emulator was Running, the UI MUST switch to Error, disable the Start/Stop control, and require backend recovery before further interaction.
- **FR-010**: The page MUST include a “View local logs” link that points to the documented log location or opens a static log view.
- **FR-011**: All network calls initiated by the UI or backend MUST remain on localhost with no external telemetry.

### Key Entities *(include if feature involves data)*

- **Emulator Session State**: Represents the current lifecycle stage (Stopped, Booting…, Running, Stopping…, Error) plus timestamps for last transition and any error code.
- **Stream Availability**: Captures whether the video stream is attached, pending retry, or failed, along with retry counters and timeout settings.
- **Log Reference**: Provides the filesystem path or local viewer URI for recent emulator orchestration logs.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 95% of Start Emulator actions display the live stream within 45 seconds on the reference host.
- **SC-002**: Average end-to-end stream latency stays at or below 500 ms during a 10-minute observation window.
- **SC-003**: The state badge reflects the backend-reported emulator status within one polling cycle for 99% of checks.
- **SC-004**: 100% of error conditions surface a human-readable banner and an accessible logs link without requiring page reload.

## Assumptions

- localhost port 8080 is available; operators can change it via local configuration if needed.
- The underlying streaming component can provide a read-only feed compatible with the emulator profile.
- Log files are stored on the same host with read access for the tester.
- Auto-start on page load remains disabled by default; enabling it requires an explicit local configuration flag.

## Dependencies

- Rooted Android emulator runtime capable of single-instance lifecycle control.
- Local streaming service that can expose the emulator screen without accepting input.
- Backend orchestrator responsible for emulator control, state reporting, and health endpoint exposure.

## Risks & Mitigations

- **Risk**: Stream attach may lag behind state transitions. **Mitigation**: Implement retry with user-facing messaging and timeout reporting.
- **Risk**: Emulator stop may hang, leaving stale UI state. **Mitigation**: Surface a Force Stop action with clear messaging and direct testers to consult logs if the hard kill also fails.
- **Risk**: High resource usage could sluggish UI updates. **Mitigation**: Keep polling lightweight and prioritize state updates over diagnostics drawer refresh.

## Clarifications

### Session 2025-10-08
- Q: How should the UI behave when the health endpoint becomes unreachable while the emulator was previously Running? → A: Switch to Error, disable controls until backend fixed.
- Q: What should the UI do when stream attach retries hit their timeout while the emulator remains in Running state? → A: Switch to Error, stop retries, require Retry Stream action.
- Q: If a stop attempt fails because the emulator process is unresponsive, how should the UI respond? → A: Switch to Error, expose Force Stop hard kill.
