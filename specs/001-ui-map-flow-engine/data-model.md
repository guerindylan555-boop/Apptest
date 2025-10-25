# Data Model: UI Map & Discovery System

**Feature**: AutoApp UI Map & Intelligent Flow Engine (Phase 1: Discovery)
**Date**: 2025-10-25
**Schema Version**: 1.0.0

## Overview

This document defines the data model for UI state discovery, graph management, and transition tracking. The model supports LLM-readable JSON artifacts, state deduplication, and transition recording for the MaynDrive app automation system.

## Core Entities

### Selector

Represents a canonical UI element selector for reliable element identification.

```typescript
type Selector = {
  /** Resource ID (highest priority selector) */
  rid?: string;

  /** Content description (accessibility label) */
  desc?: string;

  /** Visible text content */
  text?: string;

  /** UI element class name */
  cls?: string;

  /** Element bounds [left, top, right, bottom] */
  bounds?: [number, number, number, number];

  /** Additional XPath-like selector for complex elements */
  xpath?: string;
};
```

**Validation Rules**:
- At least one selector field must be present
- Bounds must be valid coordinates (left < right, top < bottom)
- Resource ID takes precedence over other selectors
- Text and desc are normalized (trimmed, lowercase for matching)

### StateRecord

Represents a unique UI state with all necessary information for identification and replay.

```typescript
type StateRecord = {
  /** SHA256 hash: package + activity + normalized digest */
  id: string;

  /** Android package name */
  package: string;

  /** Current activity name */
  activity: string;

  /** Normalized hash of UI hierarchy */
  digest: string;

  /** Canonical selectors for interactive elements */
  selectors: Selector[];

  /** Visible text content (non-empty, trimmed) */
  visibleText: string[];

  /** Optional screenshot filename */
  screenshot?: string;

  /** User-defined tags for organization */
  tags?: string[];

  /** Creation timestamp */
  createdAt: string;

  /** Last update timestamp */
  updatedAt: string;

  /** State metadata */
  metadata?: {
    captureMethod: 'adb' | 'frida';
    captureDuration: number; // ms
    elementCount: number;
    hierarchyDepth: number;
  };
};
```

**Validation Rules**:
- ID must be valid SHA256 hash
- Package and activity must match Android naming conventions
- Digest must be consistent with normalized XML
- Selectors array must be unique (no duplicate bounds/text combinations)
- Screenshot filename must exist in screenshots directory

### UserAction

Represents a user interaction that can be performed on UI elements.

```typescript
type UserAction = {
  /** Action type */
  type: 'tap' | 'type' | 'swipe' | 'back' | 'intent' | 'long_press';

  /** Target element selector */
  target?: Selector;

  /** Text to type (for 'type' actions) */
  text?: string;

  /** Swipe direction and distance (for 'swipe' actions) */
  swipe?: {
    direction: 'up' | 'down' | 'left' | 'right';
    distance: number;
  };

  /** Intent details (for 'intent' actions) */
  intent?: {
    action: string;
    package?: string;
    component?: string;
    extras?: Record<string, any>;
  };

  /** Action metadata */
  metadata?: {
    duration?: number; // for long_press
    confidence?: number; // 0-1, selector confidence
  };
};
```

**Validation Rules**:
- Tap/LongPress actions require target selector
- Type actions require both target and text
- Swipe actions require swipe configuration
- Intent actions require intent action
- Confidence must be between 0 and 1

### TransitionRecord

Represents a directed edge between two UI states via a specific action.

```typescript
type TransitionRecord = {
  /** SHA256 hash: fromState + toState + action */
  id: string;

  /** Source state ID */
  from: string;

  /** Destination state ID */
  to: string;

  /** Action that triggered this transition */
  action: UserAction;

  /** Evidence for transition validity */
  evidence?: {
    /** Digest before action execution */
    beforeDigest: string;

    /** Digest after action completion */
    afterDigest: string;

    /** Action execution timestamp */
    timestamp: string;

    /** User notes or observations */
    notes?: string;

    /** Screenshot before action */
    beforeScreenshot?: string;

    /** Screenshot after action */
    afterScreenshot?: string;
  };

  /** Transition confidence score */
  confidence?: number;

  /** Creation timestamp */
  createdAt: string;

  /** User-defined tags */
  tags?: string[];
};
```

**Validation Rules**:
- From and To states must be valid StateRecord IDs
- Action must be valid UserAction
- BeforeDigest must match from state digest
- AfterDigest must match to state digest
- Confidence must be between 0 and 1

### SessionEvent

Represents a timestamped log entry for debugging and analysis.

```typescript
type SessionEvent = {
  /** Unique event identifier */
  id: string;

  /** Event timestamp (ISO 8601) */
  timestamp: string;

  /** Event type */
  type: 'state_capture' | 'action_execute' | 'transition_create' | 'error' | 'info';

  /** Event severity */
  severity: 'debug' | 'info' | 'warn' | 'error';

  /** Human-readable message */
  message: string;

  /** Associated state ID (if applicable) */
  stateId?: string;

  /** Associated transition ID (if applicable) */
  transitionId?: string;

  /** Action performed (if applicable) */
  action?: UserAction;

  /** Additional event data */
  data?: Record<string, any>;

  /** Screenshot reference (if captured) */
  screenshot?: string;
};
```

## Graph Structure

### UIGraph

The complete UI graph containing all states and transitions.

```typescript
type UIGraph = {
  /** Graph schema version */
  version: string;

  /** Graph creation timestamp */
  createdAt: string;

  /** Last modification timestamp */
  updatedAt: string;

  /** Package name this graph represents */
  packageName: string;

  /** All discovered states */
  states: StateRecord[];

  /** All recorded transitions */
  transitions: TransitionRecord[];

  /** Graph statistics */
  stats: {
    stateCount: number;
    transitionCount: number;
    averageDegree: number;
    isolatedStates: number;
    lastCapture?: string;
  };

  /** Graph metadata */
  metadata: {
    captureTool: string;
    androidVersion?: string;
    appVersion?: string;
    deviceInfo?: string;
    totalCaptureTime: number; // ms
    totalSessions: number;
  };
};
```

## Data Relationships

### Primary Keys
- `StateRecord.id`: SHA256(package + activity + digest)
- `TransitionRecord.id`: SHA256(from + to + action)
- `SessionEvent.id`: UUID v4

### Foreign Keys
- `TransitionRecord.from` → `StateRecord.id`
- `TransitionRecord.to` → `StateRecord.id`
- `SessionEvent.stateId` → `StateRecord.id`
- `SessionEvent.transitionId` → `TransitionRecord.id`

### Indexes for Performance
```typescript
// States by activity for fast lookup
type StatesByActivity = Record<string, StateRecord[]>;

// Transitions by source state
type TransitionsBySource = Record<string, TransitionRecord[]>;

// Selectors by text for element finding
type SelectorsByText = Record<string, Selector[]>;
```

## File Formats

### graph.json
```json
{
  "version": "1.0.0",
  "createdAt": "2025-10-25T15:30:00.000Z",
  "updatedAt": "2025-10-25T16:45:00.000Z",
  "packageName": "fr.mayndrive.app",
  "states": [...],
  "transitions": [...],
  "stats": {
    "stateCount": 42,
    "transitionCount": 89,
    "averageDegree": 2.1,
    "isolatedStates": 3,
    "lastCapture": "2025-10-25T16:45:00.000Z"
  },
  "metadata": {
    "captureTool": "AutoApp Discovery v1.0",
    "androidVersion": "30",
    "appVersion": "3.2.1",
    "deviceInfo": "Pixel_4_API_30",
    "totalCaptureTime": 12500,
    "totalSessions": 8
  }
}
```

### sessions/{timestamp}.jsonl
```jsonl
{"id":"evt-1","timestamp":"2025-10-25T16:45:01.000Z","type":"state_capture","severity":"info","message":"Captured state: MainActivity","stateId":"abc123","data":{"captureDuration":850}}
{"id":"evt-2","timestamp":"2025-10-25T16:45:02.500Z","type":"action_execute","severity":"info","message":"Tapped login button","stateId":"abc123","action":{"type":"tap","target":{"rid":"btn_login"}}}
{"id":"evt-3","timestamp":"2025-10-25T16:45:03.200Z","type":"transition_create","severity":"info","message":"Created transition to Dashboard","transitionId":"trans-1","data":{"confidence":0.95}}
```

## State Management Operations

### State Deduplication
```typescript
function shouldMergeStates(state1: StateRecord, state2: StateRecord): boolean {
  // States can merge if:
  // 1. Same package and activity
  // 2. Digests are identical OR
  // 3. Jaccard similarity of selectors >= 0.9

  if (state1.package !== state2.package || state1.activity !== state2.activity) {
    return false;
  }

  if (state1.digest === state2.digest) {
    return true;
  }

  // Calculate Jaccard similarity of selector sets
  const similarity = calculateJaccardSimilarity(state1.selectors, state2.selectors);
  return similarity >= 0.9;
}
```

### Transition Validation
```typescript
function validateTransition(
  transition: TransitionRecord,
  states: Map<string, StateRecord>
): boolean {
  const fromState = states.get(transition.from);
  const toState = states.get(transition.to);

  if (!fromState || !toState) {
    return false;
  }

  // Verify evidence matches actual states
  if (transition.evidence?.beforeDigest !== fromState.digest) {
    return false;
  }

  if (transition.evidence?.afterDigest !== toState.digest) {
    return false;
  }

  return true;
}
```

## Performance Considerations

### State ID Calculation
```typescript
function calculateStateId(packageName: string, activity: string, digest: string): string {
  const crypto = require('crypto');
  const input = `${packageName}:${activity}:${digest}`;
  return crypto.createHash('sha256').update(input).digest('hex');
}
```

### Graph Validation Performance
- O(N) for state existence checks using Map lookups
- O(1) for transition validation using hash maps
- O(N log N) for graph sorting and statistics
- Target: <2s validation for 50 states, 100 transitions

### Memory Usage
- Each StateRecord: ~2-5KB (depending on selectors and text)
- Each TransitionRecord: ~1-3KB
- Graph with 500 states, 2000 transitions: ~15-25MB in memory
- JSON file size: ~5-10MB for large graphs

## Integration Points

### Backend API Integration
```typescript
// GET /api/graph/current-state
interface CurrentStateResponse {
  state?: StateRecord;
  confidence: number;
  candidates: Array<{
    state: StateRecord;
    similarity: number;
  }>;
}

// POST /api/graph/snapshot
interface SnapshotRequest {
  forceScreenshot?: boolean;
  tags?: string[];
}

interface SnapshotResponse {
  state: StateRecord;
  merged: boolean;
  mergedInto?: string; // ID of existing state if merged
}
```

### Frontend Component Integration
```typescript
// React hook for state management
interface UseGraphReturn {
  graph: UIGraph | null;
  currentState: StateRecord | null;
  isLoading: boolean;
  captureState: (options?: SnapshotRequest) => Promise<SnapshotResponse>;
  createTransition: (action: UserAction) => Promise<TransitionRecord>;
  mergeStates: (sourceId: string, targetId: string) => Promise<boolean>;
}
```

---

*Data model complete. Ready for API contract definition and implementation.*