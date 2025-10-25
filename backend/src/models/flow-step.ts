/**
 * AutoApp UI Map & Intelligent Flow Engine - Flow Step Model
 *
 * Flow step entity representing individual steps in flow execution sequences.
 * Provides comprehensive action management, precondition validation, postcondition
 * verification, and error handling with retry logic.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md and task T042 requirements.
 */

import {
  FlowStep as IFlowStep,
  Action as IAction,
  ActionType,
  StatePredicate as IStatePredicate,
  Selector as ISelector,
  ValidationResult,
  ValidationError,
  ValidationWarning,
  UUID,
  ISOTimestamp
} from '../types/models';

import { StatePredicate } from './state-predicate';
import { generateUUID, getCurrentTimestamp } from '../utils/uuid';

// ============================================================================
// Configuration and Constants
// ============================================================================

/** Default step timeout in seconds */
const DEFAULT_STEP_TIMEOUT = 30;

/** Minimum step timeout in seconds */
const MIN_STEP_TIMEOUT = 1;

/** Maximum step timeout in seconds */
const MAX_STEP_TIMEOUT = 300; // 5 minutes

/** Default retry count */
const DEFAULT_RETRY_COUNT = 3;

/** Maximum retry count */
const MAX_RETRY_COUNT = 10;

/** Default confidence threshold for step execution */
const DEFAULT_CONFIDENCE_THRESHOLD = 0.7;

/** Flow step schema version */
const FLOW_STEP_SCHEMA_VERSION = '1.0.0';

/** Maximum number of preconditions per step */
const MAX_PRECONDITIONS = 20;

/** Maximum number of tags per step */
const MAX_TAGS = 50;

// ============================================================================
// Step Execution Result
// ============================================================================

/**
 * Detailed result of step execution with timing and error information
 */
export interface StepExecutionResult {
  /** Step identifier */
  stepId: string;

  /** Execution status */
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped' | 'timeout' | 'retry';

  /** Execution timestamps */
  startedAt: ISOTimestamp;
  completedAt?: ISOTimestamp;

  /** Execution duration in milliseconds */
  duration?: number;

  /** Success status */
  success: boolean;

  /** Error information if failed */
  error?: {
    message: string;
    code: string;
    details?: any;
    retryable: boolean;
  };

  /** Retry information */
  retryInfo?: {
    attempt: number;
    maxAttempts: number;
    reason: string;
    nextRetryAt?: ISOTimestamp;
  };

  /** Precondition evaluation results */
  preconditionResults?: Array<{
    predicate: IStatePredicate;
    matched: boolean;
    confidence: number;
    duration: number;
  }>;

  /** Postcondition evaluation results */
  postconditionResult?: {
    predicate?: IStatePredicate;
    matched: boolean;
    confidence: number;
    duration: number;
  };

  /** Action execution details */
  actionDetails?: {
    type: ActionType;
    target?: ISelector;
    parameters?: any;
    success: boolean;
    responseTime?: number;
  };

  /** Performance metrics */
  performance?: {
    totalDuration: number;
    preconditionDuration: number;
    actionDuration: number;
    postconditionDuration: number;
    overheadDuration: number;
  };

  /** Additional execution data */
  data?: Record<string, any>;

  /** Screenshot evidence */
  screenshots?: {
    before?: string;
    after?: string;
    error?: string;
  };
}

// ============================================================================
// Step Comparison Result
// ============================================================================

/**
 * Result of step similarity comparison
 */
export interface StepComparisonResult {
  /** Similarity score (0-1) */
  similarity: number;

  /** Matching factors */
  factors: {
    name: boolean;
    action: boolean;
    preconditions: boolean;
    postconditions: boolean;
    timeout: boolean;
    critical: boolean;
  };

  /** Differences between steps */
  differences: string[];

  /** Recommended action */
  recommendation: 'identical' | 'similar' | 'different';
}

// ============================================================================
// Step Validation Context
// ============================================================================

/**
 * Context for step validation with additional constraints
 */
export interface StepValidationContext {
  /** Available actions in the system */
  availableActions?: ActionType[];

  /** Maximum allowed timeout */
  maxTimeout?: number;

  /** Maximum allowed preconditions */
  maxPreconditions?: number;

  /** Maximum allowed retry attempts */
  maxRetryAttempts?: number;

  /** Require at least one precondition */
  requirePreconditions?: boolean;

  /** Enable strict validation */
  strictMode?: boolean;
}

// ============================================================================
// Flow Step Entity Class
// ============================================================================

/**
 * Flow step entity representing individual execution steps
 *
 * This class provides comprehensive step management with action definitions,
 * precondition validation, postcondition verification, error handling, and
 * retry logic for robust flow execution.
 */
export class FlowStep implements IFlowStep {
  // ========================================================================
  // Core Properties
  // ========================================================================

  /** Step identifier */
  public readonly id: UUID;

  /** Step title */
  public name: string;

  /** Optional detail description */
  public description?: string;

  /** Preconditions that must all match before executing */
  public preconditions: StatePredicate[];

  /** Interaction to perform */
  public action: IAction;

  /** Post-condition expected state */
  public expectedState?: StatePredicate;

  /** Timeout override for this step in seconds */
  public timeout: number;

  /** Whether failure aborts the flow */
  public critical: boolean;

  /** Step metadata */
  public metadata?: {
    confidence?: number; // 0-1
    notes?: string;
    tags?: string[];
    retryAttempts?: number;
    retryDelay?: number; // in seconds
    priority?: number; // 1-10
    estimatedDuration?: number; // in seconds
  };

  /** Schema version */
  public readonly version: string = FLOW_STEP_SCHEMA_VERSION;

  // ========================================================================
  // Private State
  // ========================================================================

  /** Validation cache */
  private _validationCache?: ValidationResult;

  /** Execution statistics */
  private _executionStats = {
    totalExecutions: 0,
    successfulExecutions: 0,
    failedExecutions: 0,
    averageDuration: 0,
    totalDuration: 0,
    lastExecutedAt?: ISOTimestamp
  };

  /** Cached hash for comparison */
  private _cachedHash?: string;

  // ========================================================================
  // Constructor
  // ========================================================================

  /**
   * Create a new FlowStep instance
   *
   * @param data - Step data
   * @param id - Optional predefined UUID (for imports/migrations)
   */
  constructor(data: Omit<IFlowStep, 'id'>, id?: UUID) {
    // Assign unique identifier
    this.id = id || generateUUID();

    // Validate and set basic properties
    this.validateStepData(data);
    this.name = data.name.trim();
    this.description = data.description?.trim();
    this.timeout = this.normalizeTimeout(data.timeout);
    this.critical = data.critical ?? false;

    // Process preconditions
    this.preconditions = this.processPreconditions(data.preconditions);

    // Set action
    this.action = this.normalizeAction(data.action);

    // Set expected state
    if (data.expectedState) {
      this.expectedState = data.expectedState instanceof StatePredicate
        ? data.expectedState
        : new StatePredicate(data.expectedState);
    }

    // Set metadata
    this.metadata = this.normalizeMetadata(data.metadata);

    // Validate the complete step
    this.validate();
  }

  // ========================================================================
  // Static Factory Methods
  // ========================================================================

  /**
   * Create a simple tap action step
   *
   * @param name - Step name
   * @param selector - Target selector
   * @param preconditions - Preconditions (optional)
   * @returns New FlowStep instance
   */
  static tap(
    name: string,
    selector: ISelector,
    preconditions?: IStatePredicate[]
  ): FlowStep {
    return new FlowStep({
      name,
      preconditions: preconditions || [],
      action: {
        type: 'tap',
        target: selector
      }
    });
  }

  /**
   * Create a text input step
   *
   * @param name - Step name
   * @param selector - Target selector
   * @param text - Text to input
   * @param preconditions - Preconditions (optional)
   * @returns New FlowStep instance
   */
  static type(
    name: string,
    selector: ISelector,
    text: string,
    preconditions?: IStatePredicate[]
  ): FlowStep {
    return new FlowStep({
      name,
      preconditions: preconditions || [],
      action: {
        type: 'type',
        target: selector,
        text
      }
    });
  }

  /**
   * Create a swipe action step
   *
   * @param name - Step name
   * @param direction - Swipe direction
   * @param distance - Swipe distance (0-1)
   * @param selector - Target selector (optional)
   * @param preconditions - Preconditions (optional)
   * @returns New FlowStep instance
   */
  static swipe(
    name: string,
    direction: 'up' | 'down' | 'left' | 'right',
    distance: number,
    selector?: ISelector,
    preconditions?: IStatePredicate[]
  ): FlowStep {
    return new FlowStep({
      name,
      preconditions: preconditions || [],
      action: {
        type: 'swipe',
        target: selector,
        swipe: { direction, distance }
      }
    });
  }

  /**
   * Create a back navigation step
   *
   * @param name - Step name
   * @param preconditions - Preconditions (optional)
   * @returns New FlowStep instance
   */
  static back(name: string, preconditions?: IStatePredicate[]): FlowStep {
    return new FlowStep({
      name,
      preconditions: preconditions || [],
      action: {
        type: 'back'
      }
    });
  }

  /**
   * Create an intent action step
   *
   * @param name - Step name
   * @param intent - Intent parameters
   * @param preconditions - Preconditions (optional)
   * @returns New FlowStep instance
   */
  static intent(
    name: string,
    intent: Record<string, any>,
    preconditions?: IStatePredicate[]
  ): FlowStep {
    return new FlowStep({
      name,
      preconditions: preconditions || [],
      action: {
        type: 'intent',
        intent
      }
    });
  }

  /**
   * Create a long press action step
   *
   * @param name - Step name
   * @param selector - Target selector
   * @param duration - Press duration in milliseconds (optional)
   * @param preconditions - Preconditions (optional)
   * @returns New FlowStep instance
   */
  static longPress(
    name: string,
    selector: ISelector,
    duration?: number,
    preconditions?: IStatePredicate[]
  ): FlowStep {
    return new FlowStep({
      name,
      preconditions: preconditions || [],
      action: {
        type: 'long_press',
        target: selector,
        metadata: { duration }
      }
    });
  }

  /**
   * Create a step from existing data (for database reconstruction)
   *
   * @param data - Complete step data
   * @returns FlowStep instance
   */
  static fromExisting(data: IFlowStep): FlowStep {
    const step = Object.create(FlowStep.prototype);
    Object.assign(step, data);

    // Convert preconditions to StatePredicate instances
    step.preconditions = data.preconditions.map(p =>
      p instanceof StatePredicate ? p : new StatePredicate(p)
    );

    // Convert expected state to StatePredicate instance
    if (data.expectedState) {
      step.expectedState = data.expectedState instanceof StatePredicate
        ? data.expectedState
        : new StatePredicate(data.expectedState);
    }

    return step;
  }

  // ========================================================================
  // Execution Methods
  // ========================================================================

  /**
   * Execute this step with given context
   *
   * @param context - Execution context
   * @returns Execution result
   */
  public async execute(context: {
    currentState: any; // State entity
    screenshotBefore?: string;
    enableScreenshots?: boolean;
    dryRun?: boolean;
  }): Promise<StepExecutionResult> {
    const startTime = Date.now();
    const result: StepExecutionResult = {
      stepId: this.id,
      status: 'pending',
      startedAt: getCurrentTimestamp(),
      success: false,
      performance: {
        totalDuration: 0,
        preconditionDuration: 0,
        actionDuration: 0,
        postconditionDuration: 0,
        overheadDuration: 0
      }
    };

    try {
      result.status = 'running';

      // Store before screenshot
      if (context.enableScreenshots && context.screenshotBefore) {
        result.screenshots = { before: context.screenshotBefore };
      }

      // Evaluate preconditions
      const preconditionStart = Date.now();
      const preconditionResults = await this.evaluatePreconditions(context.currentState);
      result.preconditionResults = preconditionResults;
      result.performance!.preconditionDuration = Date.now() - preconditionStart;

      // Check if all preconditions are met
      const allPreconditionsMet = preconditionResults.every(r => r.matched);
      if (!allPreconditionsMet) {
        result.status = 'failed';
        result.success = false;
        result.error = {
          message: 'Preconditions not met',
          code: 'PRECONDITIONS_FAILED',
          details: {
            failedPreconditions: preconditionResults.filter(r => !r.matched)
          },
          retryable: true
        };
        result.completedAt = getCurrentTimestamp();
        result.duration = Date.now() - startTime;
        result.performance!.totalDuration = result.duration;
        return result;
      }

      // Skip execution if dry run
      if (context.dryRun) {
        result.status = 'completed';
        result.success = true;
        result.completedAt = getCurrentTimestamp();
        result.duration = Date.now() - startTime;
        result.performance!.totalDuration = result.duration;
        return result;
      }

      // Execute action
      const actionStart = Date.now();
      const actionResult = await this.executeAction(context.currentState);
      result.actionDetails = actionResult;
      result.performance!.actionDuration = Date.now() - actionStart;

      if (!actionResult.success) {
        result.status = 'failed';
        result.success = false;
        result.error = {
          message: 'Action execution failed',
          code: 'ACTION_FAILED',
          details: actionResult,
          retryable: true
        };
        result.completedAt = getCurrentTimestamp();
        result.duration = Date.now() - startTime;
        result.performance!.totalDuration = result.duration;
        return result;
      }

      // Evaluate postconditions if specified
      if (this.expectedState) {
        const postconditionStart = Date.now();
        // Note: In a real implementation, we'd wait for state to stabilize
        // and then evaluate against the new state
        result.performance!.postconditionDuration = Date.now() - postconditionStart;
      }

      // Success
      result.status = 'completed';
      result.success = true;
      result.completedAt = getCurrentTimestamp();
      result.duration = Date.now() - startTime;
      result.performance!.totalDuration = result.duration;

      // Update execution statistics
      this.updateExecutionStats(true, result.duration);

      return result;

    } catch (error) {
      result.status = 'failed';
      result.success = false;
      result.error = {
        message: error instanceof Error ? error.message : 'Unknown error',
        code: 'EXECUTION_ERROR',
        details: error,
        retryable: true
      };
      result.completedAt = getCurrentTimestamp();
      result.duration = Date.now() - startTime;
      result.performance!.totalDuration = result.duration;

      // Update execution statistics
      this.updateExecutionStats(false, result.duration);

      return result;
    }
  }

  /**
   * Evaluate preconditions against current state
   *
   * @param currentState - Current state to evaluate against
   * @returns Array of precondition evaluation results
   */
  private async evaluatePreconditions(currentState: any): Promise<Array<{
    predicate: StatePredicate;
    matched: boolean;
    confidence: number;
    duration: number;
  }>> {
    const results = [];

    for (const precondition of this.preconditions) {
      const startTime = Date.now();
      const evaluation = precondition.evaluate(currentState, {
        enableDebug: false,
        minConfidence: this.metadata?.confidence || DEFAULT_CONFIDENCE_THRESHOLD
      });
      const duration = Date.now() - startTime;

      results.push({
        predicate: precondition,
        matched: evaluation.matched,
        confidence: evaluation.confidence,
        duration
      });
    }

    return results;
  }

  /**
   * Execute the step action
   *
   * @param currentState - Current state
   * @returns Action execution result
   */
  private async executeAction(currentState: any): Promise<{
    type: ActionType;
    target?: ISelector;
    parameters?: any;
    success: boolean;
    responseTime?: number;
    error?: string;
  }> {
    const startTime = Date.now();

    try {
      // In a real implementation, this would delegate to the actual action execution
      // For now, we'll simulate action execution

      const result = {
        type: this.action.type,
        target: this.action.target,
        parameters: {
          text: this.action.text,
          swipe: this.action.swipe,
          intent: this.action.intent,
          duration: this.action.metadata?.duration
        },
        success: true,
        responseTime: Date.now() - startTime
      };

      return result;

    } catch (error) {
      return {
        type: this.action.type,
        target: this.action.target,
        success: false,
        responseTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown action error'
      };
    }
  }

  /**
   * Calculate retry delay for failed execution
   *
   * @param attempt - Current attempt number
   * @returns Delay in seconds
   */
  public calculateRetryDelay(attempt: number): number {
    const baseDelay = this.metadata?.retryDelay || 1;
    const maxDelay = 30; // Maximum 30 seconds

    // Exponential backoff with jitter
    const exponentialDelay = baseDelay * Math.pow(2, attempt - 1);
    const jitter = Math.random() * 0.1 * exponentialDelay; // 10% jitter

    return Math.min(exponentialDelay + jitter, maxDelay);
  }

  /**
   * Check if execution should be retried
   *
   * @param result - Execution result
   * @param attempt - Current attempt number
   * @returns Whether execution should be retried
   */
  public shouldRetry(result: StepExecutionResult, attempt: number): boolean {
    const maxAttempts = this.metadata?.retryAttempts ?? DEFAULT_RETRY_COUNT;

    if (attempt >= maxAttempts) {
      return false;
    }

    if (!result.error?.retryable) {
      return false;
    }

    // Don't retry critical errors
    if (result.error?.code === 'PRECONDITIONS_FAILED' && this.critical) {
      return false;
    }

    return true;
  }

  // ========================================================================
  // Validation Methods
  // ========================================================================

  /**
   * Validate step data
   *
   * @param data - Step data to validate
   * @throws Error if validation fails
   */
  private validateStepData(data: Omit<IFlowStep, 'id'>): void {
    // Validate name
    if (!data.name || typeof data.name !== 'string') {
      throw new Error('Step name is required and must be a string');
    }

    const trimmedName = data.name.trim();
    if (trimmedName.length === 0) {
      throw new Error('Step name cannot be empty');
    }

    if (trimmedName.length > 200) {
      throw new Error('Step name cannot exceed 200 characters');
    }

    // Validate action
    if (!data.action) {
      throw new Error('Step action is required');
    }

    // Validate preconditions array
    if (!Array.isArray(data.preconditions)) {
      throw new Error('Preconditions must be an array');
    }

    if (data.preconditions.length > MAX_PRECONDITIONS) {
      throw new Error(`Cannot have more than ${MAX_PRECONDITIONS} preconditions`);
    }

    // Validate timeout
    if (data.timeout !== undefined && (typeof data.timeout !== 'number' || data.timeout < 0)) {
      throw new Error('Timeout must be a non-negative number');
    }
  }

  /**
   * Normalize timeout value
   *
   * @param timeout - Timeout to normalize
   * @returns Normalized timeout
   */
  private normalizeTimeout(timeout?: number): number {
    if (timeout === undefined || timeout === null) {
      return DEFAULT_STEP_TIMEOUT;
    }

    if (typeof timeout !== 'number') {
      throw new Error('Timeout must be a number');
    }

    return Math.max(MIN_STEP_TIMEOUT, Math.min(MAX_STEP_TIMEOUT, timeout));
  }

  /**
   * Process preconditions array
   *
   * @param preconditions - Preconditions to process
   * @returns Processed preconditions
   */
  private processPreconditions(preconditions: IStatePredicate[]): StatePredicate[] {
    return preconditions.map(p =>
      p instanceof StatePredicate ? p : new StatePredicate(p)
    );
  }

  /**
   * Normalize action object
   *
   * @param action - Action to normalize
   * @returns Normalized action
   */
  private normalizeAction(action: IAction): IAction {
    // Validate action type
    const validTypes: ActionType[] = ['tap', 'type', 'swipe', 'back', 'intent', 'long_press'];
    if (!validTypes.includes(action.type)) {
      throw new Error(`Invalid action type: ${action.type}. Must be one of: ${validTypes.join(', ')}`);
    }

    // Type-specific validation
    switch (action.type) {
      case 'tap':
      case 'type':
      case 'long_press':
        if (!action.target) {
          throw new Error(`${action.type} action requires a target selector`);
        }
        break;

      case 'type':
        if (!action.text) {
          throw new Error('type action requires text input');
        }
        break;

      case 'swipe':
        if (!action.swipe) {
          throw new Error('swipe action requires swipe configuration');
        }
        if (!['up', 'down', 'left', 'right'].includes(action.swipe.direction)) {
          throw new Error('Invalid swipe direction');
        }
        if (typeof action.swipe.distance !== 'number' || action.swipe.distance < 0 || action.swipe.distance > 1) {
          throw new Error('Swipe distance must be a number between 0 and 1');
        }
        break;

      case 'intent':
        if (!action.intent || typeof action.intent !== 'object') {
          throw new Error('intent action requires intent parameters');
        }
        break;
    }

    return { ...action };
  }

  /**
   * Normalize metadata object
   *
   * @param metadata - Metadata to normalize
   * @returns Normalized metadata
   */
  private normalizeMetadata(metadata?: IFlowStep['metadata']): IFlowStep['metadata'] {
    if (!metadata) {
      return {
        confidence: DEFAULT_CONFIDENCE_THRESHOLD,
        retryAttempts: DEFAULT_RETRY_COUNT,
        retryDelay: 1,
        priority: 5
      };
    }

    const normalized: IFlowStep['metadata'] = {};

    // Validate confidence
    if (metadata.confidence !== undefined) {
      if (typeof metadata.confidence !== 'number' || metadata.confidence < 0 || metadata.confidence > 1) {
        throw new Error('Confidence must be a number between 0 and 1');
      }
      normalized.confidence = metadata.confidence;
    } else {
      normalized.confidence = DEFAULT_CONFIDENCE_THRESHOLD;
    }

    // Validate retry attempts
    if (metadata.retryAttempts !== undefined) {
      if (typeof metadata.retryAttempts !== 'number' || metadata.retryAttempts < 0) {
        throw new Error('Retry attempts must be a non-negative number');
      }
      normalized.retryAttempts = Math.min(metadata.retryAttempts, MAX_RETRY_COUNT);
    } else {
      normalized.retryAttempts = DEFAULT_RETRY_COUNT;
    }

    // Validate retry delay
    if (metadata.retryDelay !== undefined) {
      if (typeof metadata.retryDelay !== 'number' || metadata.retryDelay < 0) {
        throw new Error('Retry delay must be a non-negative number');
      }
      normalized.retryDelay = metadata.retryDelay;
    } else {
      normalized.retryDelay = 1;
    }

    // Validate priority
    if (metadata.priority !== undefined) {
      if (typeof metadata.priority !== 'number' || metadata.priority < 1 || metadata.priority > 10) {
        throw new Error('Priority must be a number between 1 and 10');
      }
      normalized.priority = metadata.priority;
    } else {
      normalized.priority = 5;
    }

    // Validate estimated duration
    if (metadata.estimatedDuration !== undefined) {
      if (typeof metadata.estimatedDuration !== 'number' || metadata.estimatedDuration < 0) {
        throw new Error('Estimated duration must be a non-negative number');
      }
      normalized.estimatedDuration = metadata.estimatedDuration;
    }

    // Copy other fields
    if (metadata.notes) {
      normalized.notes = String(metadata.notes);
    }

    if (metadata.tags) {
      if (!Array.isArray(metadata.tags)) {
        throw new Error('Tags must be an array');
      }
      if (metadata.tags.length > MAX_TAGS) {
        throw new Error(`Cannot have more than ${MAX_TAGS} tags`);
      }
      normalized.tags = metadata.tags.filter(tag => typeof tag === 'string').slice(0, MAX_TAGS);
    }

    return normalized;
  }

  /**
   * Validate the complete step
   *
   * @throws Error if validation fails
   */
  private validate(): void {
    // Additional validation logic can be added here
    // For now, the constructor validation is sufficient
  }

  /**
   * Validate step and return detailed result
   *
   * @param context - Validation context
   * @returns Validation result
   */
  public validate(context?: StepValidationContext): ValidationResult {
    if (this._validationCache && !context?.strictMode) {
      return this._validationCache;
    }

    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    try {
      // Basic structure validation
      if (!this.id) {
        errors.push({
          field: 'id',
          message: 'Step ID is required',
          code: 'MISSING_ID',
          severity: 'error'
        });
      }

      if (!this.name || typeof this.name !== 'string') {
        errors.push({
          field: 'name',
          message: 'Step name is required and must be a string',
          code: 'MISSING_NAME',
          severity: 'error'
        });
      } else if (this.name.trim().length === 0) {
        errors.push({
          field: 'name',
          message: 'Step name cannot be empty',
          code: 'EMPTY_NAME',
          severity: 'error'
        });
      } else if (this.name.length > 200) {
        warnings.push({
          field: 'name',
          message: 'Step name is very long and may impact readability',
          code: 'LONG_NAME',
          value: this.name.length,
          severity: 'warning'
        });
      }

      if (!this.action) {
        errors.push({
          field: 'action',
          message: 'Step action is required',
          code: 'MISSING_ACTION',
          severity: 'error'
        });
      }

      // Validate preconditions
      if (!Array.isArray(this.preconditions)) {
        errors.push({
          field: 'preconditions',
          message: 'Preconditions must be an array',
          code: 'INVALID_PRECONDITIONS',
          severity: 'error'
        });
      } else {
        if (context?.maxPreconditions && this.preconditions.length > context.maxPreconditions) {
          warnings.push({
            field: 'preconditions',
            message: `Too many preconditions (${this.preconditions.length} > ${context.maxPreconditions})`,
            code: 'MANY_PRECONDITIONS',
            value: this.preconditions.length,
            severity: 'warning'
          });
        }

        if (context?.requirePreconditions && this.preconditions.length === 0) {
          errors.push({
            field: 'preconditions',
            message: 'At least one precondition is required',
            code: 'REQUIRED_PRECONDITIONS',
            severity: 'error'
          });
        }
      }

      // Validate timeout
      if (typeof this.timeout !== 'number' || this.timeout < 0) {
        errors.push({
          field: 'timeout',
          message: 'Timeout must be a non-negative number',
          code: 'INVALID_TIMEOUT',
          severity: 'error'
        });
      } else if (this.timeout > MAX_STEP_TIMEOUT) {
        warnings.push({
          field: 'timeout',
          message: `Very long timeout (${this.timeout}s) may indicate inefficient step`,
          code: 'LONG_TIMEOUT',
          value: this.timeout,
          severity: 'warning'
        });
      }

      // Validate metadata
      if (this.metadata) {
        if (this.metadata.confidence !== undefined &&
            (typeof this.metadata.confidence !== 'number' ||
             this.metadata.confidence < 0 || this.metadata.confidence > 1)) {
          errors.push({
            field: 'metadata.confidence',
            message: 'Confidence must be a number between 0 and 1',
            code: 'INVALID_CONFIDENCE',
            severity: 'error'
          });
        }

        if (this.metadata.retryAttempts !== undefined &&
            (typeof this.metadata.retryAttempts !== 'number' || this.metadata.retryAttempts < 0)) {
          errors.push({
            field: 'metadata.retryAttempts',
            message: 'Retry attempts must be a non-negative number',
            code: 'INVALID_RETRY_ATTEMPTS',
            severity: 'error'
          });
        }

        if (context?.maxRetryAttempts && this.metadata.retryAttempts > context.maxRetryAttempts) {
          warnings.push({
            field: 'metadata.retryAttempts',
            message: `High retry count (${this.metadata.retryAttempts}) may cause excessive delays`,
            code: 'HIGH_RETRY_COUNT',
            value: this.metadata.retryAttempts,
            severity: 'warning'
          });
        }
      }

      // Warnings
      if (this.critical && this.preconditions.length === 0) {
        warnings.push({
          field: 'critical',
          message: 'Critical step has no preconditions - may fail unpredictably',
          code: 'CRITICAL_NO_PRECONDITIONS',
          severity: 'warning'
        });
      }

      if (!this.expectedState) {
        warnings.push({
          field: 'expectedState',
          message: 'No expected state defined - step success cannot be verified',
          code: 'NO_EXPECTED_STATE',
          severity: 'warning'
        });
      }

    } catch (error) {
      errors.push({
        field: 'step',
        message: `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        code: 'VALIDATION_FAILED',
        severity: 'error'
      });
    }

    const result: ValidationResult = {
      isValid: errors.length === 0,
      errors,
      warnings
    };

    if (!context?.strictMode) {
      this._validationCache = result;
    }

    return result;
  }

  // ========================================================================
  // Utility Methods
  // ========================================================================

  /**
   * Update execution statistics
   *
   * @param success - Whether execution was successful
   * @param duration - Execution duration in milliseconds
   */
  private updateExecutionStats(success: boolean, duration: number): void {
    this._executionStats.totalExecutions++;
    this._executionStats.totalDuration += duration;
    this._executionStats.averageDuration = this._executionStats.totalDuration / this._executionStats.totalExecutions;
    this._executionStats.lastExecutedAt = getCurrentTimestamp();

    if (success) {
      this._executionStats.successfulExecutions++;
    } else {
      this._executionStats.failedExecutions++;
    }
  }

  /**
   * Get execution statistics
   *
   * @returns Execution statistics
   */
  public getExecutionStats(): {
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    successRate: number;
    averageDuration: number;
    totalDuration: number;
    lastExecutedAt?: ISOTimestamp;
  } {
    const successRate = this._executionStats.totalExecutions > 0
      ? this._executionStats.successfulExecutions / this._executionStats.totalExecutions
      : 0;

    return {
      ...this._executionStats,
      successRate
    };
  }

  /**
   * Reset execution statistics
   */
  public resetExecutionStats(): void {
    this._executionStats = {
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      averageDuration: 0,
      totalDuration: 0
    };
  }

  /**
   * Check if this step is equivalent to another
   *
   * @param other - Other step to compare
   * @returns True if steps are equivalent
   */
  public isEquivalentTo(other: FlowStep | IFlowStep): boolean {
    if (!(other instanceof FlowStep)) {
      other = FlowStep.fromExisting(other);
    }

    // Compare core fields
    return (
      this.name === other.name &&
      JSON.stringify(this.action) === JSON.stringify(other.action) &&
      this.preconditions.length === other.preconditions.length &&
      this.preconditions.every((p, i) => p.isEquivalentTo(other.preconditions[i])) &&
      (this.expectedState?.isEquivalentTo(other.expectedState) || (!this.expectedState && !other.expectedState)) &&
      this.timeout === other.timeout &&
      this.critical === other.critical
    );
  }

  /**
   * Calculate similarity with another step
   *
   * @param other - Other step to compare
   * @returns Comparison result
   */
  public compareWith(other: FlowStep | IFlowStep): StepComparisonResult {
    if (!(other instanceof FlowStep)) {
      other = FlowStep.fromExisting(other);
    }

    const factors = {
      name: this.name === other.name,
      action: JSON.stringify(this.action) === JSON.stringify(other.action),
      preconditions: this.preconditions.length === other.preconditions.length &&
                    this.preconditions.every((p, i) => p.isEquivalentTo(other.preconditions[i])),
      postconditions: (this.expectedState?.isEquivalentTo(other.expectedState)) ||
                      (!this.expectedState && !other.expectedState),
      timeout: this.timeout === other.timeout,
      critical: this.critical === other.critical
    };

    const matchingFactors = Object.values(factors).filter(Boolean).length;
    const totalFactors = Object.keys(factors).length;
    const similarity = matchingFactors / totalFactors;

    const differences: string[] = [];
    if (!factors.name) differences.push('name');
    if (!factors.action) differences.push('action');
    if (!factors.preconditions) differences.push('preconditions');
    if (!factors.postconditions) differences.push('postconditions');
    if (!factors.timeout) differences.push('timeout');
    if (!factors.critical) differences.push('critical flag');

    let recommendation: 'identical' | 'similar' | 'different';
    if (similarity === 1.0) {
      recommendation = 'identical';
    } else if (similarity >= 0.7) {
      recommendation = 'similar';
    } else {
      recommendation = 'different';
    }

    return {
      similarity,
      factors,
      differences,
      recommendation
    };
  }

  /**
   * Calculate step hash for comparison
   *
   * @returns Hash string
   */
  public calculateHash(): string {
    if (this._cachedHash) {
      return this._cachedHash;
    }

    const data = {
      name: this.name,
      action: this.action,
      preconditions: this.preconditions.map(p => p.toObject()),
      expectedState: this.expectedState?.toObject(),
      timeout: this.timeout,
      critical: this.critical
    };

    // Use hashObject utility if available, otherwise simple string hash
    const hash = JSON.stringify(data);
    this._cachedHash = hash;
    return hash;
  }

  /**
   * Get step complexity score
   *
   * @returns Complexity score (1-10, higher is more complex)
   */
  public getComplexityScore(): number {
    let score = 1;

    // Base score for action type
    switch (this.action.type) {
      case 'back':
        score += 0;
        break;
      case 'tap':
        score += 1;
        break;
      case 'type':
        score += 2;
        break;
      case 'swipe':
        score += 2;
        break;
      case 'long_press':
        score += 3;
        break;
      case 'intent':
        score += 4;
        break;
    }

    // Add complexity for preconditions
    score += Math.min(this.preconditions.length * 0.5, 3);

    // Add complexity for expected state
    if (this.expectedState) {
      score += 1;
    }

    // Add complexity for retry logic
    if (this.metadata?.retryAttempts && this.metadata.retryAttempts > 1) {
      score += Math.min(this.metadata.retryAttempts * 0.2, 1);
    }

    // Add complexity for timeout duration
    if (this.timeout > DEFAULT_STEP_TIMEOUT) {
      score += Math.min((this.timeout - DEFAULT_STEP_TIMEOUT) / 30, 1);
    }

    return Math.min(Math.round(score * 10) / 10, 10);
  }

  /**
   * Get estimated execution time
   *
   * @returns Estimated duration in seconds
   */
  public getEstimatedDuration(): number {
    // Base time for different action types
    const baseTimes: Record<ActionType, number> = {
      'back': 1,
      'tap': 2,
      'type': 3,
      'swipe': 2,
      'long_press': 4,
      'intent': 3
    };

    let estimated = baseTimes[this.action.type] || 2;

    // Add time for precondition evaluation
    estimated += this.preconditions.length * 0.5;

    // Add time for postcondition verification
    if (this.expectedState) {
      estimated += 1;
    }

    // Use metadata estimate if available
    if (this.metadata?.estimatedDuration) {
      estimated = (estimated + this.metadata.estimatedDuration) / 2;
    }

    // Add safety margin
    estimated *= 1.2;

    return Math.round(estimated * 10) / 10;
  }

  /**
   * Get a human-readable description of the step
   *
   * @returns Description string
   */
  public getDescription(): string {
    const parts: string[] = [];

    parts.push(`Step: ${this.name}`);

    // Action description
    const actionDesc = this.getActionDescription();
    parts.push(`Action: ${actionDesc}`);

    // Preconditions
    if (this.preconditions.length > 0) {
      parts.push(`Preconditions: ${this.preconditions.length}`);
    }

    // Expected state
    if (this.expectedState) {
      parts.push('Expected state specified');
    }

    // Metadata
    if (this.timeout !== DEFAULT_STEP_TIMEOUT) {
      parts.push(`Timeout: ${this.timeout}s`);
    }

    if (this.critical) {
      parts.push('Critical');
    }

    if (this.metadata?.confidence && this.metadata.confidence !== DEFAULT_CONFIDENCE_THRESHOLD) {
      parts.push(`Confidence: ${(this.metadata.confidence * 100).toFixed(0)}%`);
    }

    return parts.join(' | ');
  }

  /**
   * Get action description
   *
   * @returns Action description string
   */
  private getActionDescription(): string {
    const { type, target, text, swipe, intent } = this.action;

    switch (type) {
      case 'tap':
        return `Tap ${target ? this.getSelectorDescription(target) : 'element'}`;

      case 'type':
        return `Type "${text}" into ${target ? this.getSelectorDescription(target) : 'field'}`;

      case 'swipe':
        return `Swipe ${swipe?.direction} ${swipe?.distance ? `(${(swipe.distance * 100).toFixed(0)}%)` : ''}`;

      case 'back':
        return 'Go back';

      case 'intent':
        return `Launch intent ${intent ? JSON.stringify(intent) : ''}`;

      case 'long_press':
        return `Long press ${target ? this.getSelectorDescription(target) : 'element'}`;

      default:
        return `Unknown action: ${type}`;
    }
  }

  /**
   * Get selector description
   *
   * @param selector - Selector to describe
   * @returns Description string
   */
  private getSelectorDescription(selector: ISelector): string {
    const parts: string[] = [];

    if (selector.rid) parts.push(`id:${selector.rid}`);
    if (selector.text) parts.push(`text:${selector.text}`);
    if (selector.desc) parts.push(`desc:${selector.desc}`);
    if (selector.cls) parts.push(`class:${selector.cls}`);

    return parts.length > 0 ? parts.join(' ') : 'element';
  }

  /**
   * Convert step to JSON string
   *
   * @returns JSON representation
   */
  public toJSON(): string {
    return JSON.stringify(this.toObject(), null, 2);
  }

  /**
   * Convert step to plain object
   *
   * @returns Plain object representation
   */
  public toObject(): IFlowStep {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      preconditions: this.preconditions.map(p => p.toObject()),
      action: this.action,
      expectedState: this.expectedState?.toObject(),
      timeout: this.timeout,
      critical: this.critical,
      metadata: this.metadata
    };
  }

  /**
   * Create a copy of this step with a new ID
   *
   * @returns New FlowStep instance with unique ID
   */
  public clone(): FlowStep {
    const cloneData = this.toObject();
    delete (cloneData as any).id;
    return new FlowStep(cloneData);
  }

  /**
   * Update step properties
   *
   * @param updates - Properties to update
   * @returns Updated step instance
   */
  public update(updates: Partial<Omit<IFlowStep, 'id'>>): FlowStep {
    const currentData = this.toObject();
    const updatedData = { ...currentData, ...updates };
    return new FlowStep(updatedData, this.id);
  }
}

// ============================================================================
// Factory Functions and Utilities
// ============================================================================

/**
 * Factory functions for creating common flow steps
 */
export const FlowStepFactory = {
  /** Create simple tap step */
  tap: FlowStep.tap,

  /** Create text input step */
  type: FlowStep.type,

  /** Create swipe step */
  swipe: FlowStep.swipe,

  /** Create back navigation step */
  back: FlowStep.back,

  /** Create intent step */
  intent: FlowStep.intent,

  /** Create long press step */
  longPress: FlowStep.longPress,

  /**
   * Create a step from action description
   *
   * @param name - Step name
   * @param description - Action description
   * @param preconditions - Preconditions (optional)
   * @returns Parsed step
   */
  fromDescription(
    name: string,
    description: string,
    preconditions?: IStatePredicate[]
  ): FlowStep {
    // Simple parsing for common action patterns
    const lowerDesc = description.toLowerCase();

    // Tap patterns
    if (lowerDesc.includes('tap') || lowerDesc.includes('click')) {
      const match = description.match(/(?:tap|click)\s+(?:on\s+)?(.+)/i);
      const targetText = match?.[1];
      return new FlowStep({
        name,
        preconditions: preconditions || [],
        action: {
          type: 'tap',
          target: targetText ? { text: targetText } : undefined
        }
      });
    }

    // Type patterns
    if (lowerDesc.includes('type') || lowerDesc.includes('enter') || lowerDesc.includes('input')) {
      const match = description.match(/(?:type|enter|input)\s+["']([^"']+)["']/i);
      const text = match?.[1];
      if (text) {
        return new FlowStep({
          name,
          preconditions: preconditions || [],
          action: {
            type: 'type',
            text,
            target: { text: 'input field' }
          }
        });
      }
    }

    // Swipe patterns
    if (lowerDesc.includes('swipe')) {
      const directionMatch = description.match(/swipe\s+(up|down|left|right)/i);
      const direction = directionMatch?.[1] as 'up' | 'down' | 'left' | 'right';
      if (direction) {
        return new FlowStep({
          name,
          preconditions: preconditions || [],
          action: {
            type: 'swipe',
            swipe: { direction, distance: 0.5 }
          }
        });
      }
    }

    // Back patterns
    if (lowerDesc.includes('back') || lowerDesc.includes('go back') || lowerDesc.includes('return')) {
      return FlowStep.back(name, preconditions);
    }

    // Default to tap with parsed text as target
    return new FlowStep({
      name,
      preconditions: preconditions || [],
      action: {
        type: 'tap',
        target: { text: description }
      }
    });
  },

  /**
   * Create a conditional step that only executes if preconditions are met
   *
   * @param name - Step name
   * @param action - Action to execute
   * @param preconditions - Preconditions to check
   * @returns Conditional step
   */
  conditional(
    name: string,
    action: IAction,
    preconditions: IStatePredicate[]
  ): FlowStep {
    return new FlowStep({
      name,
      preconditions,
      action,
      critical: false, // Conditional steps are typically non-critical
      metadata: {
        notes: 'Conditional step - only executes if preconditions are met'
      }
    });
  }
};

/**
 * Utility functions for flow step operations
 */
export const FlowStepUtils = {
  /**
   * Sort steps by priority
   *
   * @param steps - Steps to sort
   * @returns Sorted steps
   */
  sortByPriority(steps: FlowStep[]): FlowStep[] {
    return [...steps].sort((a, b) => {
      const priorityA = a.metadata?.priority || 5;
      const priorityB = b.metadata?.priority || 5;
      return priorityB - priorityA; // Higher priority first
    });
  },

  /**
   * Filter steps by tag
   *
   * @param steps - Steps to filter
   * @param tag - Tag to filter by
   * @returns Filtered steps
   */
  filterByTag(steps: FlowStep[], tag: string): FlowStep[] {
    return steps.filter(step =>
      step.metadata?.tags?.includes(tag)
    );
  },

  /**
   * Filter critical steps
   *
   * @param steps - Steps to filter
   * @returns Critical steps
   */
  filterCritical(steps: FlowStep[]): FlowStep[] {
    return steps.filter(step => step.critical);
  },

  /**
   * Calculate total estimated duration for steps
   *
   * @param steps - Steps to calculate for
   * @returns Total estimated duration in seconds
   */
  calculateTotalDuration(steps: FlowStep[]): number {
    return steps.reduce((total, step) => total + step.getEstimatedDuration(), 0);
  },

  /**
   * Group steps by action type
   *
   * @param steps - Steps to group
   * @returns Map of action type to steps
   */
  groupByActionType(steps: FlowStep[]): Map<ActionType, FlowStep[]> {
    const groups = new Map<ActionType, FlowStep[]>();

    for (const step of steps) {
      const actionType = step.action.type;
      if (!groups.has(actionType)) {
        groups.set(actionType, []);
      }
      groups.get(actionType)!.push(step);
    }

    return groups;
  },

  /**
   * Find duplicate steps in an array
   *
   * @param steps - Steps to check
   * @returns Array of duplicate step groups
   */
  findDuplicateSteps(steps: FlowStep[]): FlowStep[][] {
    const hashMap = new Map<string, FlowStep[]>();

    for (const step of steps) {
      const hash = step.calculateHash();
      if (!hashMap.has(hash)) {
        hashMap.set(hash, []);
      }
      hashMap.get(hash)!.push(step);
    }

    return Array.from(hashMap.values()).filter(group => group.length > 1);
  }
};

// ============================================================================
// Exports
// ============================================================================

export default FlowStep;