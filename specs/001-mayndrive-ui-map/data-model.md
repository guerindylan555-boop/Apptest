# Data Model: MaynDrive State-Aware UI Mapping

## Overview
The feature stores discovery outputs, flow definitions, and detector telemetry in filesystem-friendly JSON/YAML. Entities below describe the logical schema that both backend services and frontend tools must honor.

## Entities

### 1. ScreenNode
| Field | Type | Constraints / Notes |
|-------|------|---------------------|
| `id` | string (hex, 16 bytes) | Deterministic hash created during capture; immutable primary key. |
| `name` | string | Human-readable label (e.g., "Login/Enter Phone"); 3-80 chars. |
| `signature` | object | See ScreenSignature; required for detector + guards. |
| `selectors` | SelectorCandidate[] | Ranked array (highest reliability first). At least one entry required. |
| `hints` | string[] | Optional callouts describing unique traits; max 5 entries. |
| `samples` | ArtifactBundle | Screenshot, XML path, checksum references. |
| `metadata` | object | Activity/class, package, emulator build, capture timestamp, operator id. |
| `startStateTag` | enum(`clean`,`logged_out_home`,`logged_in_no_rental`,`logged_in_with_rental`,`other`) | Optional tag used by StartStateProfile and flow routing. |
| `outgoingEdgeIds` | string[] | Populated post-capture to speed lookup. |
| `incomingEdgeIds` | string[] | Optional; helps pathfinding heuristics. |
| `status` | enum(`active`,`deprecated`,`duplicate`) | Discovery lifecycle flag to prevent stale nodes from running. |

### 2. ScreenSignature
| Field | Type | Notes |
|-------|------|-------|
| `activity` | string | Fully qualified Android activity/fragment class. |
| `resourceIds` | string[] | Stable ids sorted ascending; used in hashing. |
| `requiredTexts` | string[] | Language-normalized strings the detector expects to see. |
| `layoutFingerprint` | string | Deterministic digest of XML depth walk. |
| `hash` | string | SHA-256 (16-byte truncated) computed from normalized tuple. |
| `version` | int | Incremented when the signature definition changes (e.g., layout update). |

### 3. SelectorCandidate
| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Unique within a node; referenced by edges/steps. |
| `type` | enum(`resource-id`,`content-desc`,`text`,`accessibility`,`xpath`,`coords`) | Determines reliability weighting. |
| `value` | string | Actual selector payload; coords stored as `x,y`. |
| `confidence` | float (0-1) | Derived from capture heuristics; values <0.4 flagged as risky. |
| `lastValidatedAt` | ISO datetime | Updated when runner confirms the selector still works. |

### 4. ArtifactBundle
| Field | Type | Notes |
|-------|------|-------|
| `screenshotPath` | string | Relative path under `var/captures/<nodeId>/`. |
| `xmlPath` | string | Relative path to UIAutomator dump. |
| `metadataPath` | string | Optional JSON with device/app context. |
| `checksum` | string | SHA-1 or SHA-256 to verify artifact integrity. |

### 5. ActionEdge
| Field | Type | Constraints / Notes |
|-------|------|---------------------|
| `id` | string | UUID or semantic `nodeId-action`. |
| `fromNodeId` | string | FK to ScreenNode.id (required). |
| `toNodeId` | string | FK to ScreenNode.id (can be unknown until target captured; temporarily `null`). |
| `action` | object | `{ kind: tap|type|wait|back|intent, selectorId?, text?, keycode?, delayMs? }`. |
| `guard` | object | `{ mustMatchSignatureHash?: string, requiredTexts?: string[] }`. |
| `notes` | string | Operator hints for LLM editing. |
| `createdAt` | ISO datetime | Capture timestamp. |
| `createdBy` | string | Operator id / automation agent. |
| `confidence` | float | Historical success rate; <0.6 flagged for review. |
| `startStateConstraint` | string | Optional StartStateProfile.id indicating this edge only applies in a given start-state family. |

### 6. FlowDefinition
| Field | Type | Constraints / Notes |
|-------|------|---------------------|
| `name` | string | kebab-case (e.g., `login-home`). |
| `description` | string | 1-2 sentence summary. |
| `version` | semver | Incremented per change. |
| `variables` | array | Each `{ name, description, type, required, prompt }`. |
| `precondition` | object | `{ nodeId? , query? }` query resolves to ScreenNode. |
| `steps` | FlowStep[] | Ordered actions referencing ActionEdge or inline instructions. |
| `postcondition` | object | Mirror of precondition verifying final state. |
| `recovery` | array | Each rule defines trigger (`unexpected_node`, `system_dialog`, `timeout`) + allowed actions (back, dismiss, reopen, relogin). |
| `metadata` | object | Owner, lastUpdatedAt, validation status. |

### 7. FlowStep
| Field | Type | Notes |
|-------|------|-------|
| `kind` | enum(`edgeRef`,`inline`) | Determines payload. |
| `edgeId` | string | Required when `kind=edgeRef`. |
| `inlineAction` | object | `{ action, selectorId?, text?, keycode?, waitMs? }`. |
| `guard` | object | Same schema as ActionEdge guard. |
| `retryPolicy` | object | `{ maxAttempts, delayMs }`. |
| `expectNodeId` | string | Optional explicit node expectation after the step. |

### 8. StateDetectionResult (telemetry)
| Field | Type | Notes |
|-------|------|-------|
| `timestamp` | ISO datetime | When detection ran. |
| `dumpSource` | string | Path to evaluated XML. |
| `topCandidates` | array | Each `{ nodeId, score (0-100) }`. |
| `selectedNodeId` | string | Highest-scoring node if >= threshold. |
| `status` | enum(`matched`,`ambiguous`,`unknown`) | Derived from thresholds. |
| `operatorAction` | enum(`accept`,`map_new`,`merge`,`retry`) | Used to improve detector tuning. |

### 9. StartStateProfile
| Field | Type | Notes |
|-------|------|-------|
| `id` | string | slug (e.g., `clean`, `logged-in-no-rental`). |
| `description` | string | Human-readable summary of the start state. |
| `nodeIds` | string[] | Set of ScreenNodes that compose this profile. |
| `preferredEntryEdgeIds` | string[] | Recommended edges to reach this state from clean boot. |
| `unlockPolicy` | enum(`any_available`,`existing_rental_only`, `n/a`) | Used by flows to determine scooter selection. |
| `detectorHints` | object | Additional selector/text cues that distinguish this start state. |

## Relationships & Constraints
- `ActionEdge.fromNodeId`/`toNodeId` enforce referential integrity; edges referencing unknown future nodes must be revisited before flows reference them.
- `FlowStep.edgeId` must exist in ActionEdge; validation prevents deletion of edges currently referenced by a FlowDefinition.
- `ScreenNode.selectors` form a one-to-many relationship; selectors cannot be shared across nodes to avoid accidental cross-state targeting.
- `ArtifactBundle` uses relative paths anchored to `var/` to satisfy constitution §7 (single artifact volume).
- `StartStateProfile.nodeIds` references ScreenNode ids; detector uses `startStateTag` to quickly scope candidate nodes for a profile.
- `StateDetectionResult` entries link back to `ScreenNode.id` for drift analysis; storing telemetry separately avoids bloating the node object.

## Validation Rules
1. New ScreenNodes must include at least one selector with confidence ≥0.6 and a signature hash.
2. Any ActionEdge with `kind=type` must specify which variable or literal text it sends; literals stored in secure vault if sensitive (e.g., OTP placeholder).
3. FlowDefinitions require `precondition` and `postcondition`; runner refuses to execute flows missing either.
4. Recovery rules must cover at minimum `unexpected_node` and `system_dialog` triggers to align with spec's minimal recovery requirement.
5. Artifact bundles need checksums to detect corrupted captures during LLM editing or git merges.
6. StartStateProfiles must include at least one node and specify unlockPolicy when applicable (logged-in states).
