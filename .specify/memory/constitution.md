<!--
SYNC IMPACT REPORT
==================
Version Change: [1.0.0 → 1.1.0]
Change Type: MINOR (Expanded guidance for Principle VIII)

Modified Principles:
- [AMENDED] VIII. Zero External Security Tooling in v1 → VIII. External Security Tooling (Opt-In)
  - Now permits Frida, MobSF, and mitmproxy as opt-in features with strict localhost/safety requirements
  - Added decision log with rationale and revisit date

Added Sections:
- Out of Scope (v1)
- Architecture Constraints & Defaults
- Quality & Reliability Standards
- Security & Privacy Posture
- Data & Artifacts
- UX Principles (v1)
- Governance & Workflow
- Acceptance Criteria (v1)
- Future Evolution

Templates Requiring Updates:
- ✅ .specify/templates/plan-template.md (Constitution Check section validated)
- ✅ .specify/templates/spec-template.md (Requirements aligned with principles)
- ✅ .specify/templates/tasks-template.md (Task organization aligns with principles)
- ✅ .claude/commands/speckit.*.md (No agent-specific naming conflicts)

Follow-up TODOs: None
-->

# Android Emulation & Automation Platform Constitution (Local-Only v1)

## Purpose & Scope

Build a local-only Android emulation and automation platform for authorized security testing. v1 targets single user, single rooted emulator, and a one-page web UI that lets you: (a) install an APK, (b) interact with the emulator in the browser, (c) record element-aware flows, and (d) replay them deterministically.

## Core Principles (Non-Negotiable)

### I. Local-Only Networking

All services bind to 127.0.0.1. No WAN/LAN exposure; no telemetry; no third-party calls during runs.

**Rationale**: Security testing environments must not leak data externally. Localhost-only operation ensures controlled, auditable network boundaries and prevents accidental exposure of potentially sensitive test artifacts or application data.

### II. Rooted Emulator (Single Device v1)

The Android device image MUST be rooted; ADB is localhost-only. Exactly one virtual device at a time.

**Rationale**: Security testing and automation require root access for comprehensive instrumentation. Single-device constraint in v1 reduces complexity and ensures stable, predictable resource allocation.

### III. Element-Aware Automation

Recording and replay use UIAutomator view hierarchy (resource-id/content-desc/class) with resilient selectors; raw coordinates are last resort.

**Rationale**: Coordinate-based automation is brittle and fails with minor UI changes. Semantic selectors provide deterministic, maintainable test scripts that survive app updates and screen size variations.

### IV. Stable Replay

Each action waits for readiness (visible/clickable), supports retries, and fails fast with screenshots and a clear reason.

**Rationale**: Deterministic replay is essential for reliable automation. Explicit waits eliminate race conditions; fast failure with evidence (screenshots, UI dumps) accelerates debugging.

### V. Project Separation

Every APK maps to its own "project" area for artifacts; no cross-contamination.

**Rationale**: Clean separation prevents test interference, simplifies artifact management, and supports concurrent testing of multiple applications without namespace collisions.

### VI. Data Lifecycle

Keep APKs, UI dumps, scripts, screenshots, and run logs for 30 days; allow pinning to exempt from cleanup.

**Rationale**: Automated retention prevents unbounded disk growth while preserving recent evidence. Pinning mechanism supports long-term regression test retention without manual intervention.

### VII. No AI in v1

Do not include LLM-based analysis or assistants in the runtime path.

**Rationale**: Focus v1 on deterministic, reproducible automation. AI features introduce non-determinism and complexity; defer until core platform is stable.

### VIII. External Security Tooling (Opt-In)

Frida, MobSF, and mitmproxy integrations are permitted as **opt-in features** with safe defaults. Each tool MUST:

- Run strictly localhost-only
- Provide clear enable/disable controls in the UI
- Include version/arch compatibility checks (Frida)
- Never send data externally (MobSF local-only mode enforced)
- Surface clear status and errors to the user

**Rationale**: Security testing workflows require instrumentation and traffic analysis. Opt-in design preserves simplicity while enabling essential capabilities. Frida/proxy tools are industry-standard for Android security research.

**Decision Log**: Amended 2025-10-09 to support core security testing workflows in v1. Original principle deferred these to v2, but user requirements demonstrate they are foundational to the platform's value proposition. Revisit before v2 planning to evaluate complexity impact and consider whether any tools should remain opt-in or become defaults.

## Out of Scope (v1)

The following features are explicitly excluded from v1 to maintain focus and reduce complexity:

- Multiple devices, device farms, or remote access
- ARM-only targets requiring slow emulation (x86/x86_64 images preferred for v1)
- AI-driven analysis or cloud storage
- Multi-tenant auth, RBAC, or SSO
- Advanced Frida scripting/gadgets or app repackaging (basic instrumentation via opt-in Frida server is permitted per Principle VIII)

## Architecture Constraints & Defaults

**Host Environment**: Ubuntu 25.04 with at least 6 vCPU / 12 GB RAM reserved for the stack.

**Runtime Mix**: Combination of host and containers; keep internal comms on localhost.

**Device Profile**: Android 14 (API 34), phone 1080×1920 ~420 dpi.

**Control Plane**: scrcpy-web for live stream + input from the browser.

**Automation Engine**: ADB + UIAutomator (record/replay with selectors, not coordinates).

**Resource Targets**: Allocate ~4 vCPU / 4–6 GB RAM to the emulator to keep interactive latency acceptable under typical test flows.

## Quality & Reliability Standards

**Determinism**: Replays MUST produce the same UI state transitions given unchanged inputs and device profile.

**Robust Selectors**: Prefer resource-id and content-desc; backstop with class+index and a minimized XPath-lite only if necessary.

**Waits & Timing**: Use presence/visibility/clickable waits; never rely on arbitrary fixed sleeps except as bounded backoff.

**Failure Evidence**: On any failure, capture the current UI dump, a screenshot, and the last action log line.

**Smoke Checks**: Before recording or replay, verify device booted, ADB connected, app installed/launchable.

## Security & Privacy Posture

**Network Boundary**: All services listen only on 127.0.0.1; disable CORS/auth assumptions since not exposed.

**No Telemetry**: Do not emit analytics or diagnostics to third parties.

**Secrets**: Avoid storing credentials in scripts; if unavoidable for test data, store inside the project's private area and redact in logs.

**Legal/Ethical Use**: The platform is for testing apps you are authorized to analyze.

## Data & Artifacts

**Persist**: Uploaded APKs (deduped), recording scripts, per-run event logs, UI dumps (pre/post per step), screenshots, and automation logs.

**Retention**: 30-day rolling deletion for unpinned artifacts; pinned items are exempt.

**Organization**: Artifacts live under a per-project directory keyed by APK name and hash; every replay produces a new run folder.

## UX Principles (v1)

**Single Page**: Emulator stream on the left; controls and artifacts on the right.

**Essential Controls**: Upload/Install/Launch APK, Start/Pause/Stop Recording, Save/Rename Script, Replay Script, view run status and artifacts.

**Input Mapping**: Mouse/touch → taps; Enter → IME enter; Esc → back; include shortcuts for home/app-switch.

**Clarity Over Density**: Evidence (screenshots, dumps, logs) is one click away from any run.

## Governance & Workflow

**Constitution Authority**: This constitution supersedes all other development practices. All feature specifications, plans, and tasks created via Spec Kit MUST comply with these principles.

**Spec Kit Workflow**:
1. `/speckit.constitution` → Establish/update governing principles
2. `/speckit.specify` → Define functional "what/why" requirements
3. `/speckit.clarify` → Resolve specification ambiguities
4. `/speckit.plan` → Create technical architecture and approach
5. `/speckit.tasks` → Generate work breakdown
6. `/speckit.implement` → Execute implementation
7. `/speckit.analyze` → Cross-artifact consistency validation before shipping

**Decision Log**: Record any principle exceptions or tech-debt acceptances with rationale and expiry/revisit dates before implementation begins.

**Change Control**: If a proposed feature conflicts with "Core Principles," either (a) revise the feature, or (b) explicitly amend this constitution with a decision log entry and version increment.

**Compliance Review**: All PRs/reviews must verify compliance with this constitution. Complexity must be justified against simpler alternatives. Violations require explicit governance approval.

## Acceptance Criteria (v1)

From a clean machine, the platform MUST support the following end-to-end workflow:

1. Bring up the stack locally and open a single local webpage
2. Upload an APK, install, and launch it successfully
3. See a responsive, interactive emulator stream
4. Record ≥10 steps (taps + text), save the script, and replay to completion with no manual tweaks
5. All artifacts appear under the project and are automatically handled by the 30-day retention (with pinning support)

## Future Evolution (Beyond v1)

The following features are deferred to post-v1 releases:

- Multi-device orchestration; device farm UI
- Advanced Frida scripting, gadgets, and app repackaging (v1 supports basic instrumentation server)
- Optional local-only AI summarization of runs and diffs
- Cross-device tolerant replays (adaptive selectors; screen-size strategies)

**Version**: 1.1.0 | **Ratified**: 2025-10-09 | **Last Amended**: 2025-10-09
