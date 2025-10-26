# Research: MaynDrive State-Aware UI Mapping (Phase 0)

## 1. Deterministic Screen Signature Hashing
- **Decision**: Build signatures from a sorted tuple of `(activity|fragment class, stable resource-id list, required text tokens, structural fingerprint derived from XML depth walk)` hashed with SHA-256 and truncated to 16 bytes.
- **Rationale**: Combining structural + semantic anchors keeps hashes stable across cosmetic changes and aligns with Android UIAutomator dumps. Sorting/normalizing inputs removes drift from ordering and casing.
- **Alternatives Considered**:
  - **Raw XML hash** – volatile attributes (timestamps, counters) cause constant churn.
  - **Activity-only signature** – cannot differentiate distinct states within the same activity.
  - **ML embedding similarity** – heavier investment and opaque to LLM edits.

## 2. Selector Ranking & Referencing
- **Decision**: Store selectors per node as ordered buckets (resource-id, content-desc, text, accessibility label, XPath, fallback coordinates). Each entry tracks `confidence` (0-1) and evidence sample; edges reference selectors via `selectorId`.
- **Rationale**: Ranking mirrors Android stability hierarchy, and confidence enables the runner to demote brittle selectors over time while keeping artifacts compact.
- **Alternatives Considered**:
  - Single selector per element (insufficient fallbacks).
  - Rank-by-creation-order (unpredictable for recovery logic).
  - Inline selectors on edges (bloats JSON, difficult to update).

## 3. State Detector Scoring Strategy
- **Decision**: Weighted scoring across signature hash match, selector hits (resource-id weight 3, content-desc 2, text 1), and structural similarity (Jaccard). Normalize to 0-100 with thresholds: ≥70 matched, 50-69 ambiguous (prompt operator), <50 UNKNOWN.
- **Rationale**: Provides deterministic behavior, tolerates minor UI drift, and maps to UX cues (green/amber/red) needed for fast operator decisions while meeting ≥90% top-1 accuracy.
- **Alternatives Considered**:
  - Exact hash equality (too brittle).
  - ML classifier (needs labeled data, slower iteration).
  - Unweighted heuristics (over-values unreliable selectors).

## 4. Flow Definition Schema
- **Decision**: YAML documents with `name`, `description`, `variables[]`, `precondition`, `steps[]`, `postcondition`, `recovery`. Steps support `edgeRef` or inline `{action, selectorId|text, guard}`; recovery lists permitted fallback actions per trigger.
- **Rationale**: YAML is LLM-friendly, keeps flows declarative, and codifies recovery patterns demanded by the spec (back/dismiss/reopen/relogin).
- **Alternatives Considered**:
  - JSON-only (harder for manual edits).
  - Imperative DSL (mixes logic + config, harder to audit).
  - TypeScript modules (breaks LLM editing requirement).

## 5. Artifact Storage Layout
- **Decision**: Store captures under `var/captures/<nodeId>/` (screenshot.png, ui.xml, metadata.json), graphs under `var/graphs/<version>/ui-graph.json`, flows under `var/flows/*.yaml`, and README guidance at `var/flows/README.md`, plus a global `index.json` with checksums.
- **Rationale**: Respects constitution §7 (single artifact volume), keeps binary churn out of git, and provides deterministic lookup paths for both operators and LLMs.
- **Alternatives Considered**:
  - Database (unneeded complexity, harder to review artifacts).
  - Storing artifacts within repo (bloats diffs, conflicts with lightweight goal).
  - Cloud object store (requires credentials and contradicts local-first assumption).

## 6. Start-State Profiling & Unlock Policies
- **Decision**: Introduce `StartStateProfile` documents tagging ScreenNodes into `clean`, `logged_out_home`, `logged_in_no_rental`, and `logged_in_with_rental` groups, each carrying detector hints and unlock policies (`any_available` vs `existing_rental_only`).
- **Rationale**: Explicit profiles let the detector narrow candidates quickly and help the runner choose the correct unlock strategy without re-deriving context on every run.
- **Alternatives Considered**:
  - Implicit tagging via node names (too brittle and hard for LLM edits).
  - Flow-specific branching logic (duplicates logic across flows).
  - Separate graphs per state (would fragment discovery data and increase maintenance).
