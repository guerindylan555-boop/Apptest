<!--
Sync Impact Report:
- Version change: N/A → 1.0.0
- Modified principles: N/A (initial ratification)
- Added sections: Core Principles; Scope & Boundaries; Architecture & Runtime Constraints; Quality & Reliability Standards; Security & Privacy Posture; Data & Artifact Management; UX Principles; Governance; Acceptance Criteria (v1); Future Evolution
- Templates requiring updates:
  ✅ .specify/templates/plan-template.md (reviewed, no changes needed)
  ✅ .specify/templates/spec-template.md (reviewed, no changes needed)
  ✅ .specify/templates/tasks-template.md (reviewed, no changes needed)
  ✅ .codex/prompts/speckit.constitution.md (reviewed, no changes needed)
- Follow-up TODOs: none
-->
# Android Emulation & Automation Platform (Local-Only v1) Constitution

## Core Principles

### Local-Only Networking
- All services MUST bind exclusively to 127.0.0.1; no WAN or LAN exposure is permitted.
- Runs MUST avoid telemetry or third-party calls; every network interaction stays on the host.
- System configuration MUST disable assumptions about public access (e.g., no implicit CORS relaxations).
Rationale: The platform exists for local, authorized testing and must remain isolated to limit risk.

### Rooted Emulator Access
- The Android 14 emulator image MUST remain rooted for test tooling flexibility.
- ADB MUST accept connections only from localhost, with debugging ports never exposed externally.
Rationale: Root access is required for deep inspection, but confinement to localhost prevents misuse.

### Single Device Focus
- The stack MUST operate exactly one virtual device at a time in v1.
- Lifecycle tooling MUST enforce exclusive ownership (create, reset, destroy) of that emulator instance.
Rationale: Simplifying to a single device keeps automation deterministic and resource usage predictable.

### Element-Aware Automation
- Recording and replay MUST rely on UIAutomator selectors (resource-id, content-desc, class).
- Coordinate-based interactions MAY only be used as a last resort and MUST be documented when chosen.
- Selector storage MUST prefer resilient strategies (fallback chain rather than brittle single value).
Rationale: Element semantics survive UI shifts better than coordinates, preserving replay stability.

### Stable Replay Discipline
- Every action MUST wait for target readiness (visible, clickable, enabled) before execution.
- Replay routines MUST support bounded retries and abort fast with clear failure reasons.
- On failure, the system MUST capture a screenshot, UI dump, and final action log entry.
Rationale: Deterministic, observable runs build trust in recorded scripts and highlight regressions quickly.

### Project Isolation
- Each APK MUST map to its own project directory for artifacts, preventing cross-contamination.
- Shared resources (emulator images, base configs) MAY only store read-only templates common to all projects.
Rationale: Isolation protects sensitive data and keeps investigation trails auditable per app.

### Data Lifecycle Stewardship
- APKs, UI dumps, scripts, screenshots, and logs MUST be retained for 30 days by default.
- Users MUST be able to pin artifacts to exempt them from automated cleanup.
- Cleanup routines MUST run deterministically and log deletions for traceability.
Rationale: Defined retention balances storage constraints with repeatability needs for security reviews.

### No AI in Runtime
- v1 MUST exclude LLM-based analysis or assistants from recording and replay flows.
- Any future AI augmentation MUST be explicitly ratified as a constitution change before implementation.
Rationale: Deterministic, explainable behavior is required during early validation and auditing.

### Zero External Security Tooling
- The runtime MUST NOT integrate Frida, MobSF, or similar third-party introspection tools in v1.
- Manual use of such tools outside the platform MUST remain clearly out of scope for support and automation.
Rationale: Limiting bundled tooling keeps the surface area manageable and respects licensing and ethics.

## Scope & Boundaries
- Purpose: deliver a local-only Android emulation and automation platform for authorized security testing with a single rooted emulator, web UI, recording, and deterministic replay.
- Scope covers APK installation, emulator interaction in browser, element-aware recording, and replay management.
- Out of scope: device farms, remote access, ARM-only slow targets, advanced security suites, and multi-tenant auth.
Rationale: Tight scope enables a reliable v1 foundation before expanding breadth.

## Architecture & Runtime Constraints
- Host baseline: Ubuntu 25.04 with ≥6 vCPU and ≥12 GB RAM dedicated to the stack.
- Runtime mix MUST use host processes and containers with all internal communications on localhost.
- Emulator profile: Android 14 (API 34), 1080×1920, ~420 dpi, allocated ~4 vCPU and 4–6 GB RAM.
- Control plane MUST leverage scrcpy-web (or equivalent) for live streaming and input relays.
- Automation engine MUST use ADB + UIAutomator for control and instrumentation.

## Quality & Reliability Standards
- Replays MUST produce consistent UI state transitions when inputs and device profile are unchanged.
- Wait logic MUST prefer presence/visibility/clickable checks; fixed sleeps are limited to bounded backoff.
- Smoke checks MUST confirm device boot, ADB connectivity, and app install/launch before recording or replay.
- Failure handling MUST emit screenshot, UI dump, and last action log line for every abort.

## Security & Privacy Posture
- Network boundary MUST remain localhost-only; no telemetry or diagnostic calls to third parties.
- Secrets SHOULD stay out of scripts; unavoidable credentials MUST live inside the project’s private area and be redacted in logs.
- Platform use MUST stay within legal/ethical permission for analyzed apps.

## Data & Artifact Management
- Artifacts live under per-project directories keyed by APK name and hash.
- Every replay MUST create a new run folder containing scripts, logs, UI dumps, and screenshots.
- Retention automation MUST enforce the 30-day policy while respecting pinned exemptions.

## UX Principles
- Provide a single-page UI with emulator stream on the left and controls/artifacts on the right.
- Essential controls include: Upload/Install/Launch APK, Start/Pause/Stop Recording, Save/Rename Script, Replay Script, and artifact viewers.
- Input mapping MUST translate mouse/touch to taps, Enter to IME enter, Esc to back, and expose shortcuts for home/app-switch.
- Evidence (screenshots, dumps, logs) MUST remain one click away from any run for rapid diagnosis.

## Acceptance Criteria (v1)
- From a clean machine, operators MUST launch the stack locally and open a single local webpage.
- Users MUST upload, install, and launch an APK successfully through the UI.
- Emulator stream MUST stay responsive and interactive in the browser.
- Recorder MUST capture ≥10 steps (taps and text), save scripts, and replay to completion without manual edits.
- Artifacts MUST surface under the project directory and obey the 30-day retention with pinning support.

## Future Evolution
- Target future features include multi-device orchestration, device farm UI, and optional Frida/MobSF integrations.
- Consider local-only AI summarization of runs and diffs after governance approval.
- Plan for adaptive selectors to support cross-device tolerant replays and varying screen sizes in later versions.

## Governance
- This constitution supersedes other practice guides for the platform; teams MUST validate compliance during reviews and test runs.
- Workflow order: `/speckit.constitution` → `/speckit.specify` → `/speckit.clarify` → `/speckit.plan` → `/speckit.tasks` → `/speckit.implement` → `/speckit.analyze`.
- Decision log entries MUST capture any principle exceptions or tech-debt acceptances with rationale and revisit dates before implementation begins.
- Features conflicting with non-negotiable principles MUST be revised or accompany a ratified constitution amendment.
- Constitution versions MUST follow semantic versioning (MAJOR for conflicting changes, MINOR for new principles/sections, PATCH for clarifications).
- Compliance reviews MUST verify localhost boundaries, single-device enforcement, artifact isolation, and automation selector quality before sign-off.

**Version**: 1.0.0 | **Ratified**: 2025-10-08 | **Last Amended**: 2025-10-08
