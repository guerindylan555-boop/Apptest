/**
 * AutoApp Flow Types
 *
 * TypeScript types for flow authoring, definition, and execution.
 * Extends graph types for reusable UI automation flows.
 */

import { UserAction, StateRecord } from './graph';

// ============================================================================
// Core Flow Types
// ============================================================================

export interface StatePredicate {
  /** Predicate type for state matching */
  type: 'exact' | 'contains' | 'matches' | 'fuzzy';

  /** State ID for exact matching */
  stateId?: string;

  /** Activity name pattern */
  activity?: string;

  /** Text patterns that must be present */
  containsText?: string[];

  /** Regular expression patterns */
  matches?: {
    activity?: string;
    text?: string;
    selectors?: string;
  };

  /** Fuzzy matching threshold */
  fuzzyThreshold?: number;

  /** Additional selector requirements */
  hasSelectors?: Array<{
    rid?: string;
    text?: string;
    desc?: string;
  }>;
}

export interface FlowStep {
  /** Unique step identifier */
  id: string;

  /** Step name for readability */
  name: string;

  /** Optional step description */
  description?: string;

  /** Preconditions that must be met before executing this step */
  preconditions: StatePredicate[];

  /** Action to execute in this step */
  action: UserAction;

  /** Expected post-state after action execution */
  expectedState?: StatePredicate;

  /** Step timeout in milliseconds */
  timeout?: number;

  /** Whether this step is critical (flow fails if step fails) */
  critical?: boolean;

  /** Step metadata */
  metadata?: {
    confidence?: number;
    notes?: string;
    tags?: string[];
  };
}

export interface FlowDefinition {
  /** Unique flow identifier */
  id: string;

  /** Human-readable flow name */
  name: string;

  /** Optional flow description */
  description?: string;

  /** Flow version for tracking changes */
  version: string;

  /** Target package name */
  packageName: string;

  /** Ordered list of flow steps */
  steps: FlowStep[];

  /** Flow entry point (initial state requirements) */
  entryPoint: StatePredicate;

  /** Expected end state */
  exitPoint?: StatePredicate;

  /** Flow metadata */
  metadata: {
    /** Creation timestamp */
    createdAt: string;

    /** Last update timestamp */
    updatedAt: string;

    /** Flow author */
    author?: string;

    /** Flow tags for organization */
    tags?: string[];

    /** Estimated execution time */
    estimatedDuration?: number;

    /** Flow complexity score */
    complexity?: number;

    /** Success rate from previous executions */
    successRate?: number;

    /** Number of times this flow has been executed */
    executionCount?: number;
  };

  /** Flow configuration */
  config?: {
    /** Default timeout for steps */
    defaultTimeout: number;

    /** Retry attempts for failed steps */
    retryAttempts: number;

    /** Parallel execution allowed */
    allowParallel: boolean;

    /** Flow priority */
    priority: 'low' | 'medium' | 'high';
  };
}

// ============================================================================
// Flow Execution Types
// ============================================================================

export interface FlowExecutionContext {
  /** Execution session ID */
  executionId: string;

  /** Flow being executed */
  flow: FlowDefinition;

  /** Current step index */
  currentStep: number;

  /** Execution start timestamp */
  startedAt: string;

  /** Execution status */
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';

  /** Current state information */
  currentState?: {
    stateId: string;
    activity: string;
    screenshot?: string;
    matchedAt: string;
  };

  /** Step execution history */
  stepHistory: FlowStepExecution[];

  /** Execution variables for dynamic behavior */
  variables: Record<string, any>;

  /** Execution configuration overrides */
  config?: {
    timeout?: number;
    dryRun?: boolean;
    debugMode?: boolean;
  };
}

export interface FlowStepExecution {
  /** Step being executed */
  stepId: string;

  /** Execution status */
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

  /** Execution start time */
  startedAt: string;

  /** Execution completion time */
  completedAt?: string;

  /** State before step execution */
  beforeState?: {
    stateId: string;
    activity: string;
    screenshot?: string;
  };

  /** State after step execution */
  afterState?: {
    stateId: string;
    activity: string;
    screenshot?: string;
  };

  /** Execution result */
  result?: {
    success: boolean;
    error?: string;
    duration: number;
    retryCount: number;
  };

  /** Additional execution data */
  data?: Record<string, any>;
}

export interface FlowExecutionResult {
  /** Execution session ID */
  executionId: string;

  /** Flow ID */
  flowId: string;

  /** Final execution status */
  status: 'completed' | 'failed' | 'partial' | 'cancelled';

  /** Execution start timestamp */
  startedAt: string;

  /** Execution completion timestamp */
  completedAt: string;

  /** Total execution duration */
  duration: number;

  /** Number of steps completed */
  stepsCompleted: number;

  /** Number of steps failed */
  stepsFailed: number;

  /** Final state information */
  finalState?: {
    stateId: string;
    activity: string;
    screenshot?: string;
  };

  /** Execution summary */
  summary: {
    totalSteps: number;
    successfulSteps: number;
    failedSteps: number;
    skippedSteps: number;
    averageStepDuration: number;
  };

  /** Execution errors if any */
  errors?: Array<{
    stepId: string;
    error: string;
    timestamp: string;
  }>;

  /** Execution logs */
  logs: FlowExecutionLog[];
}

export interface FlowExecutionLog {
  /** Log entry ID */
  id: string;

  /** Timestamp */
  timestamp: string;

  /** Log level */
  level: 'debug' | 'info' | 'warn' | 'error';

  /** Log message */
  message: string;

  /** Associated step ID */
  stepId?: string;

  /** Additional log data */
  data?: Record<string, any>;
}

// ============================================================================
// Flow Validation Types
// ============================================================================

export interface FlowValidationResult {
  /** Overall validation status */
  isValid: boolean;

  /** Validation errors */
  errors: FlowValidationError[];

  /** Validation warnings */
  warnings: FlowValidationWarning[];

  /** Validation summary */
  summary: {
    totalSteps: number;
    validSteps: number;
    invalidSteps: number;
    unreachableStates: number;
    circularDependencies: number;
  };
}

export interface FlowValidationError {
  /** Error type */
  type: 'syntax' | 'semantic' | 'logic' | 'reference';

  /** Error severity */
  severity: 'error' | 'warning';

  /** Error message */
  message: string;

  /** Affected step ID */
  stepId?: string;

  /** Error location in flow definition */
  location?: {
    line?: number;
    column?: number;
    property?: string;
  };

  /** Error code for programmatic handling */
  code: string;

  /** Additional error details */
  details?: Record<string, any>;
}

export interface FlowValidationWarning {
  /** Warning type */
  type: 'performance' | 'reliability' | 'best_practice';

  /** Warning message */
  message: string;

  /** Affected step ID */
  stepId?: string;

  /** Warning suggestion */
  suggestion?: string;
}

// ============================================================================
// Flow Management Types
// ============================================================================

export interface FlowTemplate {
  /** Template ID */
  id: string;

  /** Template name */
  name: string;

  /** Template description */
  description?: string;

  /** Template category */
  category: 'login' | 'navigation' | 'form' | 'search' | 'custom';

  /** Template parameters */
  parameters: Array<{
    name: string;
    type: 'string' | 'number' | 'boolean' | 'selector' | 'state_predicate';
    required: boolean;
    description?: string;
    defaultValue?: any;
  }>;

  /** Template flow definition with parameter placeholders */
  template: Omit<FlowDefinition, 'id' | 'name' | 'description' | 'metadata' | 'steps'> & {
    steps: Array<Omit<FlowStep, 'action'> & {
      action: any; // Template action with parameter references
    }>;
  };

  /** Template metadata */
  metadata: {
    createdAt: string;
    updatedAt: string;
    author?: string;
    usage?: number;
  };
}

export interface FlowLibrary {
  /** Library version */
  version: string;

  /** Available flows */
  flows: FlowDefinition[];

  /** Available templates */
  templates: FlowTemplate[];

  /** Flow categories */
  categories: Array<{
    name: string;
    description?: string;
    flowCount: number;
  }>;

  /** Library statistics */
  stats: {
    totalFlows: number;
    totalTemplates: number;
    totalExecutions: number;
    averageFlowDuration: number;
    successRate: number;
  };

  /** Library metadata */
  metadata: {
    createdAt: string;
    updatedAt: string;
    packageName: string;
    version: string;
  };
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface CreateFlowRequest {
  /** Flow definition */
  flow: Omit<FlowDefinition, 'id' | 'metadata'>;

  /** Validation options */
  validate?: boolean;

  /** Auto-save options */
  autoSave?: boolean;
}

export interface CreateFlowResponse {
  /** Created flow ID */
  flowId: string;

  /** Validation result */
  validation?: FlowValidationResult;

  /** Created flow */
  flow: FlowDefinition;
}

export interface UpdateFlowRequest {
  /** Flow ID */
  flowId: string;

  /** Updated flow definition */
  flow: Partial<FlowDefinition>;

  /** Merge strategy */
  mergeStrategy?: 'replace' | 'merge' | 'patch';
}

export interface UpdateFlowResponse {
  /** Updated flow */
  flow: FlowDefinition;

  /** Changes made */
  changes: Array<{
    field: string;
    oldValue: any;
    newValue: any;
  }>;

  /** Validation result */
  validation?: FlowValidationResult;
}

export interface ExecuteFlowRequest {
  /** Flow ID */
  flowId: string;

  /** Execution configuration */
  config?: {
    /** Custom timeout */
    timeout?: number;

    /** Dry run mode */
    dryRun?: boolean;

    /** Debug mode */
    debugMode?: boolean;

    /** Initial variables */
    variables?: Record<string, any>;

    /** Start from specific step */
    startFromStep?: number;

    /** Stop at specific step */
    stopAtStep?: number;
  };
}

export interface ExecuteFlowResponse {
  /** Execution session ID */
  executionId: string;

  /** Execution status */
  status: 'started' | 'queued' | 'failed';

  /** Estimated duration */
  estimatedDuration?: number;

  /** Execution context */
  context?: FlowExecutionContext;
}

export interface GetFlowExecutionRequest {
  /** Execution ID */
  executionId: string;

  /** Include detailed logs */
  includeLogs?: boolean;

  /** Include step history */
  includeStepHistory?: boolean;
}

export interface GetFlowExecutionResponse {
  /** Execution result */
  execution: FlowExecutionResult;

  /** Current execution context if running */
  context?: FlowExecutionContext;

  /** Live execution logs */
  logs?: FlowExecutionLog[];
}

export interface ListFlowsRequest {
  /** Filter options */
  filter?: {
    /** Package name filter */
    package?: string;

    /** Tag filter */
    tags?: string[];

    /** Author filter */
    author?: string;

    /** Complexity range */
    complexity?: {
      min?: number;
      max?: number;
    };

    /** Search query */
    search?: string;
  };

  /** Sort options */
  sort?: {
    field: 'name' | 'createdAt' | 'updatedAt' | 'successRate' | 'executionCount';
    order: 'asc' | 'desc';
  };

  /** Pagination options */
  pagination?: {
    page: number;
    limit: number;
  };
}

export interface ListFlowsResponse {
  /** Matching flows */
  flows: FlowDefinition[];

  /** Pagination info */
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };

  /** Filter summary */
  summary: {
    totalFlows: number;
    filteredFlows: number;
    averageSuccessRate: number;
    averageComplexity: number;
  };
}

export interface ValidateFlowRequest {
  /** Flow definition to validate */
  flow: FlowDefinition;

  /** Validation options */
  options?: {
    /** Check state predicates against graph */
    checkStates?: boolean;

    /** Check action validity */
    checkActions?: boolean;

    /** Check for logical inconsistencies */
    checkLogic?: boolean;

    /** Performance impact analysis */
    analyzePerformance?: boolean;
  };
}

export interface ValidateFlowResponse {
  /** Validation result */
  result: FlowValidationResult;

  /** Analysis results */
  analysis?: {
    /** Estimated execution time */
    estimatedDuration: number;

    /** Reliability score */
    reliabilityScore: number;

    /** Complexity score */
    complexityScore: number;

    /** Performance impact */
    performanceImpact: 'low' | 'medium' | 'high';

    /** Optimization suggestions */
    suggestions: string[];
  };
}

// ============================================================================
// Error Types
// ============================================================================

export interface FlowError {
  /** Error code */
  code: string;

  /** Error message */
  message: string;

  /** Error details */
  details?: {
    flowId?: string;
    stepId?: string;
    executionId?: string;
    field?: string;
    value?: any;
  };

  /** Stack trace if available */
  stack?: string;
}

// ============================================================================
// Export all types
// ============================================================================

export type {
  FlowDefinition as Flow,
  FlowExecutionContext as ExecutionContext,
  FlowExecutionResult as ExecutionResult,
  FlowValidationResult as ValidationResult,
  FlowTemplate as Template,
  FlowLibrary as Library,
};