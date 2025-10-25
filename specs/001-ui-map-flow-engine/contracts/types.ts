/**
 * AutoApp UI Discovery API Types
 *
 * TypeScript types for UI state discovery, graph management, and transition recording.
 * Compatible with backend/src/types/graph.ts usage.
 */

// ============================================================================
// Core Types
// ============================================================================

export interface Selector {
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
}

export interface UserAction {
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
}

// ============================================================================
// Entity Types
// ============================================================================

export interface StateRecord {
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
}

export interface TransitionRecord {
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
}

export interface SessionEvent {
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
}

export interface UIGraph {
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
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface SnapshotRequest {
  /** Force screenshot capture even if exists */
  forceScreenshot?: boolean;

  /** Tags to apply to captured state */
  tags?: string[];
}

export interface SnapshotResponse {
  /** Captured or existing state */
  state: StateRecord;

  /** Whether state was merged with existing */
  merged: boolean;

  /** ID of existing state if merged */
  mergedInto?: string;
}

export interface CreateTransitionRequest {
  /** Source state ID */
  fromStateId?: string;

  /** Action performed */
  action: UserAction;

  /** Destination state ID (optional, can be bound later) */
  toStateId?: string;

  /** Transition evidence */
  evidence?: {
    beforeDigest?: string;
    afterDigest?: string;
    notes?: string;
  };
}

export interface MergeStatesRequest {
  /** Source state ID (to be merged) */
  sourceId: string;

  /** Target state ID (to keep) */
  targetId: string;
}

export interface MergeStatesResponse {
  /** Whether merge was successful */
  success: boolean;

  /** Number of states merged */
  mergedCount: number;

  /** IDs of updated transitions */
  updatedTransitions: string[];

  /** IDs of removed transitions (self-loops) */
  removedTransitions: string[];
}

export interface CurrentStateResponse {
  /** Best match current state */
  state?: StateRecord;

  /** Match confidence score */
  confidence: number;

  /** Alternative candidates with similarity scores */
  candidates: Array<{
    state: StateRecord;
    similarity: number;
  }>;
}

export interface SessionsResponse {
  /** List of capture sessions */
  sessions: Array<{
    id: string;
    timestamp: string;
    eventCount: number;
    duration: number;
  }>;
}

export interface SessionResponse {
  /** Session ID */
  id: string;

  /** Session events */
  events: SessionEvent[];
}

// ============================================================================
// Error Types
// ============================================================================

export interface ApiError {
  /** Error code */
  error: string;

  /** Human-readable error message */
  message: string;

  /** Additional error details */
  details?: Record<string, any>;
}

// ============================================================================
// Utility Types
// ============================================================================

/** States grouped by activity for fast lookup */
export type StatesByActivity = Record<string, StateRecord[]>;

/** Transitions grouped by source state */
export type TransitionsBySource = Record<string, TransitionRecord[]>;

/** Selectors grouped by text for element finding */
export type SelectorsByText = Record<string, Selector[]>;

/** Graph statistics calculation result */
export interface GraphStats {
  stateCount: number;
  transitionCount: number;
  averageDegree: number;
  isolatedStates: number;
  lastCapture?: string;
}

/** State similarity comparison result */
export interface StateSimilarity {
  /** Jaccard similarity of selector sets */
  selectorSimilarity: number;

  /** Text similarity score */
  textSimilarity: number;

  /** Overall similarity score */
  overallSimilarity: number;

  /** Whether states should be merged */
  shouldMerge: boolean;

  /** Similarity threshold used */
  threshold: number;
}

// ============================================================================
// Validation Types
// ============================================================================

export interface ValidationError {
  field: string;
  message: string;
  code: string;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface GraphConfig {
  /** Path to graph JSON file */
  graphPath: string;

  /** Directory for session logs */
  sessionsDir: string;

  /** Directory for screenshots */
  screenshotsDir: string;

  /** Similarity threshold for state merging (0-1) */
  mergeThreshold: number;

  /** Maximum states before performance warnings */
  maxStates: number;

  /** Maximum transitions before performance warnings */
  maxTransitions: number;

  /** Session log retention (days) */
  retentionDays: number;

  /** Enable debug logging */
  debug: boolean;
}

export interface ADBConfig {
  /** ADB host */
  host: string;

  /** ADB port */
  port: number;

  /** Device serial */
  serial: string;

  /** Connection timeout (ms) */
  timeout: number;

  /** Maximum retry attempts */
  maxRetries: number;

  /** Connection pool size */
  poolSize: number;
}

export interface CaptureConfig {
  /** Capture timeout (ms) */
  timeout: number;

  /** Force screenshot capture */
  forceScreenshot: boolean;

  /** XML normalization options */
  normalizeOptions: {
    /** Remove index attributes */
    removeIndexes: boolean;

    /** Remove timestamp attributes */
    removeTimestamps: boolean;

    /** Remove selection state attributes */
    removeSelectionStates: boolean;

    /** Remove dynamic ID attributes */
    removeDynamicIds: boolean;
  };

  /** Performance targets */
  performanceTargets: {
    /** Target capture time (ms) */
    captureTime: number;

    /** Target validation time (ms) */
    validationTime: number;
  };
}

// ============================================================================
// Export all types for easy import
// ============================================================================

export type {
  // Re-export for backward compatibility
  Selector as UISelector,
  UserAction as UIAction,
  StateRecord as UIState,
  TransitionRecord as UITransition,
  UIGraph as UIGraphData,
};