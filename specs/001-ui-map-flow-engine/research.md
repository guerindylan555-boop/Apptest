# Research — AutoApp UI Map & Intelligent Flow Engine

## 1. Testing Harness for Graph + Flow Features (NEEDS CLARIFICATION Resolved)
- **Decision**: Use a two-layer approach—(a) backend integration suite that runs inside the containerized emulator, drives UIAutomator2 to capture sample states, and asserts graph JSON outputs; (b) scripted flow-replay scenarios executed via npm scripts (`npm run test:flows`) that boot the emulator, seed mock flows, and validate replay logs. Unit-level tests remain lint/build, but these integration suites become CI blockers.
- **Rationale**: Matches constitution requirements for container-only execution, leverages existing emulator artifacts, and keeps verification close to real-world usage (state capture + replay). Provides deterministic datasets for flow validation (<2 s requirement) without inventing a new harness.
- **Alternatives considered**:
  - Pure unit tests around graph serializers → rejected because they cannot prove UIAutomator2 + WebRTC wiring or replay recovery logic.
  - External device-farm testing → rejected due to constitution's “no external dependency” guidance and slower feedback loops.

## 2. UIAutomator2 Capture & Dedup Best Practices
- **Decision**: Capture each snapshot as (activity, view-hierarchy XML hash, screenshot hash, top selectors/text). Use canonicalized bounds + resource IDs to generate a deterministic digest; dedup by digest plus heuristics (activity + dominant selector). Store capture metadata (method, duration, element count) for analytics.
- **Rationale**: Aligns with spec’s requirement for 95% dedup accuracy and JSON persistence while keeping state nodes lightweight (<10 KB). Digest-first dedup avoids storing duplicate screenshots and speeds validation.
- **Alternatives considered**:
  - Pixel-by-pixel screenshot diffing → too expensive (720p frames) and fragile to animations.
  - Pure heuristic matching (activity + text) → insufficient for screens that reuse activity names with different fragments.

## 3. JSON Artifact Versioning & Conflict Resolution
- **Decision**: Store UTG + flows under `var/autoapp/{graphs,flows}` with semantic version headers and `lastModifiedBy` metadata. All write operations go through a backend service that performs optimistic locking via file hash comparison; conflicting writes produce `.conflict` copies for manual merge. Add CLI helper `npm run graph:lint` to verify schema compliance before commit.
- **Rationale**: Satisfies NFR-004 (compatibility) and NFR-005 (conflict detection) while keeping the Git-based workflow simple. Optimistic locking covers collaboration scenarios without needing a DB.
- **Alternatives considered**:
  - Introducing a lightweight DB (SQLite) → violates “JSON files under version control” decision and adds container complexity.
  - Relying on Git merge alone → poor UX because binary screenshot hashes make diffing hard and conflicts surface late.

## 4. Flow Replay & Recovery Strategy
- **Decision**: Implement a replay engine that, before each step, re-localizes current state via selector digest matching; if mismatch occurs, it evaluates declared preconditions and executes prerequisite flows (e.g., login) before resuming. Recovery attempts limited to 2 retries per step, after which the system stops with structured error logs for Claude Code consumption.
- **Rationale**: Directly satisfies User Story 3 and success criteria SC-003/SC-005 by ensuring flows remain robust even when app drifts. Limiting retries prevents infinite loops and keeps replay under control for 500-state graphs.
- **Alternatives considered**:
  - Blind sequential execution → fails reliability goals and cannot satisfy “intelligent recovery.”
  - Full AI planning during replay → overkill for current scope and would introduce additional dependencies not covered by the spec.

## 5. WebRTC Stream Integration Patterns
- **Decision**: Keep using `android-emulator-webrtc` front-end component but wrap it with a connection manager that enforces constitution timeouts (1.5 s), retries with exponential backoff, and surfaces connectivity state to the Discovery/Flow UI. Expose env-driven ICE/TURN config surfaced from constitution vars.
- **Rationale**: Aligns with Constitution §§3–4, reduces flakes seen during state capture, and ensures researchers see stream health next to discovery tools (important for usability).
- **Alternatives considered**:
  - Switching back to `ws-scrcpy` → explicitly prohibited (§14).
  - Building a custom WebRTC client → unnecessary since existing package already satisfies requirements; we only need better state handling.
