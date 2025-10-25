# Data Model — AutoApp UI Map & Intelligent Flow Engine

## 1. State
| Field | Type | Description | Validation |
|-------|------|-------------|------------|
| `id` | string (UUID) | Stable identifier for the captured state node | Required, unique across graph |
| `package` | string | Android package detected for the activity | Required |
| `activity` | string | Fully-qualified activity name | Required |
| `digest` | string (sha256) | Hash of view-hierarchy XML + selectors | Required; used for deduplication |
| `selectors` | Selector[] | Top-level interactable elements | 1–N entries, normalized bounds/resource-id |
| `visibleText` | string[] | Key text strings found on screen | Optional |
| `screenshot` | string (path/hash) | Reference to screenshot asset | Optional but recommended |
| `tags` | string[] | User-supplied labels | Optional |
| `metadata.captureMethod` | enum (`adb`,`frida`) | Capture channel | Default `adb` |
| `metadata.captureDuration` | number (ms) | Snapshot time | Must be ≥0 |
| `metadata.elementCount` | number | Count of nodes in hierarchy | ≥0 |
| `metadata.hierarchyDepth` | number | Deepest node depth | ≥0 |
| `createdAt` / `updatedAt` | ISO timestamp | Lifecycle tracking | Required |

Relationships: State nodes live inside a single UI Graph and are referenced by transitions, flow predicates, and session events.

## 2. Selector
| Field | Type | Description | Validation |
| `rid` | string | Android resource-id | Optional |
| `text` | string | Visible text | Optional |
| `desc` | string | Content description | Optional |
| `cls` | string | Fully-qualified class | Optional |
| `bounds` | `[number, number, number, number]` | Screen bounds (left,top,right,bottom) | Optional; enforce 0 ≤ value ≤ screen size |
| `xpath` | string | Hierarchy path | Optional |

Selectors inherit state metadata. Used in flows (actions + predicates).

## 3. Action
| Field | Type | Description |
| `type` | enum(`tap`,`type`,`swipe`,`back`,`intent`,`long_press`) | Interaction type |
| `target` | Selector | Element to act upon | Required for tap/type/long_press |
| `text` | string | Input text for `type` | Required when `type=type` |
| `swipe.direction` | enum(`up`,`down`,`left`,`right`) | Swipe direction |
| `swipe.distance` | number (0–1) | Normalized distance |
| `intent.*` | strings/object | Android intent parameters |
| `metadata.duration` | number | Duration override (ms) |
| `metadata.confidence` | number | 0–1 guidance |
| `semanticSelector` | object | Semantic hints (type/purpose/nearText) |

## 4. Transition
| Field | Type | Description | Validation |
| `id` | string | Stable identifier | Required |
| `from` | state.id | Source node | Required |
| `to` | state.id | Destination node | Required |
| `action` | Action | Triggering action | Required |
| `evidence.beforeDigest/afterDigest` | string | Optional hashed proof | Must match state digests when provided |
| `evidence.timestamp` | ISO timestamp | Capture time | Optional |
| `evidence.notes` | string | Analyst notes | Optional |
| `confidence` | number (0–1) | Transition certainty | Optional |
| `tags` | string[] | Classifications | Optional |
| `createdAt` | ISO timestamp | | Required |

Transitions belong to a UI Graph and power flow validation.

## 5. UI Graph (UTG)
| Field | Type | Description |
| `version` | semver | Schema version |
| `createdAt` / `updatedAt` | ISO timestamp | Graph lifecycle |
| `packageName` | string | Target Android package |
| `states` | State[] | Captured nodes |
| `transitions` | Transition[] | Directed edges |
| `stats.stateCount` | number | Derived count |
| `stats.transitionCount` | number | Derived |
| `stats.averageDegree` | number | Derived (out+in / states) |
| `stats.isolatedStates` | number | Derived |
| `stats.lastCapture` | ISO timestamp | Latest snapshot |
| `metadata.captureTool` | string | e.g., `uiautomator2` |
| `metadata.androidVersion` | string | Optional |
| `metadata.appVersion` | string | Optional |
| `metadata.deviceInfo` | string | Optional |
| `metadata.totalCaptureTime` | number | Accumulated ms |
| `metadata.totalSessions` | number | Capture sessions |

Constraints: Graphs limited to 500 states / 2000 transitions (NFR).

## 6. FlowDefinition
| Field | Type | Description |
| `id` | string | Flow identifier (slug) |
| `name` | string | Human-friendly name |
| `description` | string | Optional summary |
| `version` | semver | Flow schema version |
| `packageName` | string | Target package |
| `steps` | FlowStep[] | Ordered execution steps |
| `entryPoint` | StatePredicate | Starting condition |
| `exitPoint` | StatePredicate | Optional completion check |
| `metadata.createdAt/updatedAt` | ISO timestamp | Audit fields |
| `metadata.author` | string | Owner |
| `metadata.tags` | string[] | Labels (login/unlock/etc.) |
| `metadata.estimatedDuration` | number (s) | Perf hint |
| `metadata.complexity` | number (1–5) | Custom scale |
| `metadata.executionCount` | number | Historical runs |
| `metadata.successRate` | number (0–1) | Historical success |
| `config.defaultTimeout` | number (s) | Wait per step |
| `config.retryAttempts` | number | Step retries |
| `config.allowParallel` | boolean | Future use |
| `config.priority` | enum(`low`,`medium`,`high`) | Scheduling hint |

## 7. FlowStep
| Field | Type | Description |
| `id` | string | Step identifier |
| `name` | string | Step title |
| `description` | string | Optional detail |
| `preconditions` | StatePredicate[] | Must all match before executing |
| `action` | Action | Interaction to perform |
| `expectedState` | StatePredicate | Post-condition |
| `timeout` | number (s) | Override for this step |
| `critical` | boolean | If failure aborts flow |
| `metadata.confidence` | number | 0–1 |
| `metadata.notes` / `tags` | string[] | Additional annotations |

## 8. StatePredicate
Represents logical expressions used across flows, validation, and recovery.
| Field | Type | Description |
| `type` | enum(`exact`,`contains`,`matches`,`fuzzy`) | Matching strategy |
| `stateId` | string | Direct reference (exact) |
| `activity` | string | Activity name constraint |
| `containsText` | string[] | Text fragments required |
| `matches.activity/text/selectors` | string | Regex expressions |
| `fuzzyThreshold` | number (0–1) | For digest similarity |
| `hasSelectors` | Array<{`rid`,`text`,`desc`}> | Sub-selector hints |

Predicates can be combined using AND/OR/NOT expressions defined in flow metadata.

## 9. FlowExecution (runtime telemetry)
| Field | Type | Description |
| `executionId` | string | Run identifier |
| `flowId` | string | FlowDefinition ID |
| `status` | enum(`pending`,`running`,`completed`,`failed`,`paused`,`cancelled`) | Lifecycle |
| `startedAt` / `completedAt` | ISO timestamp | Timing |
| `duration` | number (ms) | Derived |
| `currentStep` | number | Index |
| `stepHistory` | Array<StepResult> | Ordered log |
| `summary` | object | Aggregated counts (total/success/failed/skipped/avgDuration) |
| `logs` | SessionEvent[] | Linked runtime events |

## 10. SessionEvent
| Field | Type | Description |
| `id` | string | Event id |
| `timestamp` | ISO timestamp | When event occurred |
| `level` | enum(`debug`,`info`,`warn`,`error`) | Severity |
| `message` | string | Human-readable message |
| `stepId` | string | FlowStep reference |
| `data` | object | Arbitrary structured payload (selector snapshots, errors, screenshot refs) |

## Relationships Summary
- **UI Graph** aggregates **States** and **Transitions**.
- **Flows** reference graph nodes through **StatePredicates** and **FlowSteps**.
- **FlowExecutions** emit **SessionEvents** tied to FlowSteps and graph states.
- **Selectors** and **Actions** bridge UI capture data with replay instructions.
