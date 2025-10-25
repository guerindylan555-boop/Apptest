/**
 * AutoApp UI Map & Intelligent Flow Engine - Data Model Types
 *
 * TypeScript interfaces for all data model entities defined in the specification.
 * This file provides type safety and consistency for all graph and flow data structures.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md
 */

// ============================================================================
// Enum Definitions
// ============================================================================

/**
 * Capture method enumeration for state metadata
 */
export type CaptureMethod = 'adb' | 'frida';

/**
 * Action type enumeration for user interactions
 */
export type ActionType = 'tap' | 'type' | 'swipe' | 'back' | 'intent' | 'long_press';

/**
 * Swipe direction enumeration for swipe actions
 */
export type SwipeDirection = 'up' | 'down' | 'left' | 'right';

/**
 * State predicate matching strategies
 */
export type PredicateType = 'exact' | 'contains' | 'matches' | 'fuzzy';

/**
 * Flow execution status enumeration
 */
export type ExecutionStatus = 'pending' | 'running' | 'completed' | 'failed' | 'paused' | 'cancelled';

/**
 * Event severity levels for session events
 */
export type EventLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Flow priority enumeration for scheduling
 */
export type FlowPriority = 'low' | 'medium' | 'high';

// ============================================================================
// Core Entity Interfaces
// ============================================================================

/**
 * UI element selector interface for identifying interactive elements
 */
export interface Selector {
  /** Android resource-id (highest priority selector) */
  rid?: string;

  /** Visible text content */
  text?: string;

  /** Content description (accessibility label) */
  desc?: string;

  /** Fully-qualified class name */
  cls?: string;

  /** Screen bounds [left, top, right, bottom] */
  bounds?: [number, number, number, number];

  /** Hierarchy path for complex elements */
  xpath?: string;
}

/**
 * Action interface for user interactions
 */
export interface Action {
  /** Interaction type */
  type: ActionType;

  /** Element to act upon (required for tap/type/long_press) */
  target?: Selector;

  /** Input text for type actions (required when type=type) */
  text?: string;

  /** Swipe configuration */
  swipe?: {
    direction: SwipeDirection;
    distance: number; // 0-1 normalized distance
  };

  /** Android intent parameters */
  intent?: Record<string, any>;

  /** Action metadata */
  metadata?: {
    duration?: number; // Duration override in ms
    confidence?: number; // 0-1 guidance confidence
  };

  /** Semantic hints for enhanced element targeting */
  semanticSelector?: {
    type?: string;
    purpose?: string;
    nearText?: string[];
  };
}

/**
 * State predicate interface for matching states
 */
export interface StatePredicate {
  /** Matching strategy */
  type: PredicateType;

  /** Direct state reference (for exact matching) */
  stateId?: string;

  /** Activity name constraint */
  activity?: string;

  /** Text fragments required to be present */
  containsText?: string[];

  /** Regular expression patterns */
  matches?: {
    activity?: string;
    text?: string;
    selectors?: string;
  };

  /** Fuzzy matching threshold (0-1) */
  fuzzyThreshold?: number;

  /** Sub-selector hints */
  hasSelectors?: Array<{
    rid?: string;
    text?: string;
    desc?: string;
  }>;
}

// ============================================================================
// Entity Interfaces
// ============================================================================

/**
 * State entity representing a captured UI state
 */
export interface State {
  /** Stable identifier for the captured state node */
  id: string;

  /** Android package detected for the activity */
  package: string;

  /** Fully-qualified activity name */
  activity: string;

  /** Hash of view-hierarchy XML + selectors for deduplication */
  digest: string;

  /** Top-level interactable elements (1-N entries) */
  selectors: Selector[];

  /** Key text strings found on screen */
  visibleText?: string[];

  /** Reference to screenshot asset */
  screenshot?: string;

  /** User-supplied labels */
  tags?: string[];

  /** Capture metadata */
  metadata: {
    /** Capture channel */
    captureMethod: CaptureMethod;

    /** Snapshot time in milliseconds */
    captureDuration: number;

    /** Count of nodes in hierarchy */
    elementCount: number;

    /** Deepest node depth */
    hierarchyDepth: number;
  };

  /** Lifecycle tracking timestamps */
  createdAt: string;
  updatedAt: string;
}

/**
 * Transition entity for state connections
 */
export interface Transition {
  /** Stable identifier */
  id: string;

  /** Source state node */
  from: string;

  /** Destination state node */
  to: string;

  /** Triggering action */
  action: Action;

  /** Optional hashed proof */
  evidence?: {
    beforeDigest?: string;
    afterDigest?: string;
    timestamp?: string;
    notes?: string;
  };

  /** Transition certainty (0-1) */
  confidence?: number;

  /** Classifications */
  tags?: string[];

  /** Creation timestamp */
  createdAt: string;
}

/**
 * UI Graph (UTG) entity containing states and transitions
 */
export interface UIGraph {
  /** Schema version */
  version: string;

  /** Graph lifecycle timestamps */
  createdAt: string;
  updatedAt: string;

  /** Target Android package */
  packageName: string;

  /** Captured nodes */
  states: State[];

  /** Directed edges */
  transitions: Transition[];

  /** Derived statistics */
  stats: {
    stateCount: number;
    transitionCount: number;
    averageDegree: number;
    isolatedStates: number;
    lastCapture?: string;
  };

  /** Capture metadata */
  metadata: {
    captureTool: string;
    androidVersion?: string;
    appVersion?: string;
    deviceInfo?: string;
    totalCaptureTime: number; // Accumulated ms
    totalSessions: number;
  };
}

/**
 * Flow step entity representing individual steps in a flow
 */
export interface FlowStep {
  /** Step identifier */
  id: string;

  /** Step title */
  name: string;

  /** Optional detail description */
  description?: string;

  /** Preconditions that must all match before executing */
  preconditions: StatePredicate[];

  /** Interaction to perform */
  action: Action;

  /** Post-condition expected state */
  expectedState?: StatePredicate;

  /** Timeout override for this step in seconds */
  timeout?: number;

  /** Whether failure aborts the flow */
  critical?: boolean;

  /** Step metadata */
  metadata?: {
    confidence?: number; // 0-1
    notes?: string;
    tags?: string[];
  };
}

/**
 * Flow definition entity with steps and predicates
 */
export interface FlowDefinition {
  /** Flow identifier (slug) */
  id: string;

  /** Human-friendly name */
  name: string;

  /** Optional summary */
  description?: string;

  /** Flow schema version */
  version: string;

  /** Target package */
  packageName: string;

  /** Ordered execution steps */
  steps: FlowStep[];

  /** Starting condition */
  entryPoint: StatePredicate;

  /** Optional completion check */
  exitPoint?: StatePredicate;

  /** Audit fields */
  metadata: {
    createdAt: string;
    updatedAt: string;
    author?: string;
    tags?: string[];
    estimatedDuration?: number; // Performance hint in seconds
    complexity?: number; // Custom scale 1-5
    executionCount?: number; // Historical runs
    successRate?: number; // Historical success 0-1
  };

  /** Flow configuration */
  config: {
    defaultTimeout: number; // Wait per step in seconds
    retryAttempts: number; // Step retries
    allowParallel: boolean; // Future use
    priority: FlowPriority; // Scheduling hint
  };
}

/**
 * Step result interface for execution tracking
 */
export interface StepResult {
  /** Step identifier */
  stepId: string;

  /** Execution status */
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

  /** Execution timestamps */
  startedAt: string;
  completedAt?: string;

  /** Execution duration in milliseconds */
  duration?: number;

  /** Success status */
  success?: boolean;

  /** Error message if failed */
  error?: string;

  /** Retry count */
  retryCount?: number;

  /** Additional execution data */
  data?: Record<string, any>;
}

/**
 * Flow execution entity for runtime telemetry
 */
export interface FlowExecution {
  /** Run identifier */
  executionId: string;

  /** FlowDefinition ID */
  flowId: string;

  /** Lifecycle status */
  status: ExecutionStatus;

  /** Timing information */
  startedAt: string;
  completedAt?: string;
  duration?: number; // Derived in milliseconds

  /** Current step index */
  currentStep: number;

  /** Ordered execution log */
  stepHistory: StepResult[];

  /** Aggregated counts */
  summary: {
    total: number;
    success: number;
    failed: number;
    skipped: number;
    avgDuration?: number;
  };

  /** Linked runtime events */
  logs: SessionEvent[];
}

/**
 * Session event entity for execution logs
 */
export interface SessionEvent {
  /** Event identifier */
  id: string;

  /** Event timestamp */
  timestamp: string;

  /** Event severity */
  level: EventLevel;

  /** Human-readable message */
  message: string;

  /** FlowStep reference */
  stepId?: string;

  /** Arbitrary structured payload */
  data?: Record<string, any>;
}

// ============================================================================
// Creation Interfaces (without generated fields)
// ============================================================================

/**
 * Interface for creating new states (without generated fields)
 */
export interface CreateStateRequest {
  /** Android package detected for the activity */
  package: string;

  /** Fully-qualified activity name */
  activity: string;

  /** Top-level interactable elements */
  selectors: Selector[];

  /** Key text strings found on screen */
  visibleText?: string[];

  /** User-supplied labels */
  tags?: string[];

  /** Capture metadata */
  metadata: {
    /** Capture channel */
    captureMethod: CaptureMethod;

    /** Snapshot time in milliseconds */
    captureDuration: number;

    /** Count of nodes in hierarchy */
    elementCount: number;

    /** Deepest node depth */
    hierarchyDepth: number;
  };
}

/**
 * Interface for creating new transitions (without generated fields)
 */
export interface CreateTransitionRequest {
  /** Source state node */
  from: string;

  /** Destination state node */
  to: string;

  /** Triggering action */
  action: Action;

  /** Optional hashed proof */
  evidence?: {
    beforeDigest?: string;
    afterDigest?: string;
    notes?: string;
  };

  /** Transition certainty (0-1) */
  confidence?: number;

  /** Classifications */
  tags?: string[];
}

/**
 * Interface for creating new flow definitions (without generated fields)
 */
export interface CreateFlowDefinitionRequest {
  /** Human-friendly name */
  name: string;

  /** Optional summary */
  description?: string;

  /** Target package */
  packageName: string;

  /** Ordered execution steps */
  steps: Omit<FlowStep, 'id'>[];

  /** Starting condition */
  entryPoint: StatePredicate;

  /** Optional completion check */
  exitPoint?: StatePredicate;

  /** Author information */
  author?: string;

  /** Labels for organization */
  tags?: string[];

  /** Performance hint in seconds */
  estimatedDuration?: number;

  /** Custom scale 1-5 */
  complexity?: number;

  /** Flow configuration */
  config?: Partial<FlowDefinition['config']>;
}

// ============================================================================
// Update Interfaces (optional fields)
// ============================================================================

/**
 * Interface for updating existing states
 */
export interface UpdateStateRequest {
  /** Top-level interactable elements */
  selectors?: Selector[];

  /** Key text strings found on screen */
  visibleText?: string[];

  /** Reference to screenshot asset */
  screenshot?: string;

  /** User-supplied labels */
  tags?: string[];

  /** Capture metadata */
  metadata?: Partial<State['metadata']>;
}

/**
 * Interface for updating existing transitions
 */
export interface UpdateTransitionRequest {
  /** Triggering action */
  action?: Action;

  /** Optional hashed proof */
  evidence?: {
    beforeDigest?: string;
    afterDigest?: string;
    notes?: string;
  };

  /** Transition certainty (0-1) */
  confidence?: number;

  /** Classifications */
  tags?: string[];
}

/**
 * Interface for updating existing flow definitions
 */
export interface UpdateFlowDefinitionRequest {
  /** Human-friendly name */
  name?: string;

  /** Optional summary */
  description?: string;

  /** Ordered execution steps */
  steps?: FlowStep[];

  /** Starting condition */
  entryPoint?: StatePredicate;

  /** Optional completion check */
  exitPoint?: StatePredicate;

  /** Labels for organization */
  tags?: string[];

  /** Performance hint in seconds */
  estimatedDuration?: number;

  /** Custom scale 1-5 */
  complexity?: number;

  /** Flow configuration */
  config?: Partial<FlowDefinition['config']>;
}

// ============================================================================
// Validation Interfaces
// ============================================================================

/**
 * Validation rule interface
 */
export interface ValidationRule {
  /** Rule identifier */
  name: string;

  /** Rule description */
  description: string;

  /** Whether this rule is required */
  required: boolean;

  /** Validation function type */
  validator: 'string' | 'number' | 'email' | 'uuid' | 'url' | 'regex' | 'custom';

  /** Validation parameters */
  params?: {
    min?: number;
    max?: number;
    pattern?: string;
    enum?: string[];
    custom?: string;
  };

  /** Error message for failed validation */
  message: string;
}

/**
 * Validation result interface
 */
export interface ValidationResult {
  /** Overall validation status */
  isValid: boolean;

  /** Validation errors */
  errors: ValidationError[];

  /** Validation warnings */
  warnings: ValidationWarning[];
}

/**
 * Validation error interface
 */
export interface ValidationError {
  /** Field name with error */
  field: string;

  /** Error message */
  message: string;

  /** Error code */
  code: string;

  /** Invalid value */
  value?: any;

  /** Error severity */
  severity: 'error';
}

/**
 * Validation warning interface
 */
export interface ValidationWarning {
  /** Field name with warning */
  field: string;

  /** Warning message */
  message: string;

  /** Warning code */
  code: string;

  /** Questionable value */
  value?: any;

  /** Warning severity */
  severity: 'warning';
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Base error interface for all model-related errors
 */
export interface ModelError {
  /** Error code */
  code: string;

  /** Error message */
  message: string;

  /** Error details */
  details?: {
    entityType?: string;
    entityId?: string;
    field?: string;
    value?: any;
    constraint?: string;
  };

  /** Stack trace if available */
  stack?: string;

  /** Timestamp when error occurred */
  timestamp: string;
}

/**
 * State-specific error interface
 */
export interface StateError extends ModelError {
  entityType: 'State';
  stateId?: string;
}

/**
 * Transition-specific error interface
 */
export interface TransitionError extends ModelError {
  entityType: 'Transition';
  transitionId?: string;
}

/**
 * Flow-specific error interface
 */
export interface FlowError extends ModelError {
  entityType: 'FlowDefinition';
  flowId?: string;
}

/**
 * Execution-specific error interface
 */
export interface ExecutionError extends ModelError {
  entityType: 'FlowExecution';
  executionId?: string;
}

// ============================================================================
// Utility Types and Type Guards
// ============================================================================

/**
 * UUID type alias for better type documentation
 */
export type UUID = string;

/**
 * ISO timestamp type alias for better type documentation
 */
export type ISOTimestamp = string;

/**
 * SemVer type alias for version strings
 */
export type SemVer = string;

/**
 * Type guard for ActionType
 */
export function isValidActionType(value: string): value is ActionType {
  return ['tap', 'type', 'swipe', 'back', 'intent', 'long_press'].includes(value);
}

/**
 * Type guard for ExecutionStatus
 */
export function isValidExecutionStatus(value: string): value is ExecutionStatus {
  return ['pending', 'running', 'completed', 'failed', 'paused', 'cancelled'].includes(value);
}

/**
 * Type guard for EventLevel
 */
export function isValidEventLevel(value: string): value is EventLevel {
  return ['debug', 'info', 'warn', 'error'].includes(value);
}

/**
 * Type guard for PredicateType
 */
export function isValidPredicateType(value: string): value is PredicateType {
  return ['exact', 'contains', 'matches', 'fuzzy'].includes(value);
}

// ============================================================================
// Type Aliases
// ============================================================================

// All types and enums are already exported above where they are defined

// Export all interfaces for easy importing
export type {
  State as IState,
  Transition as ITransition,
  Selector as ISelector,
  Action as IAction,
  StatePredicate as IStatePredicate,
  UIGraph as IUIGraph,
  FlowDefinition as IFlowDefinition,
  FlowStep as IFlowStep,
  FlowExecution as IFlowExecution,
  SessionEvent as ISessionEvent,
  StepResult as IStepResult,
};