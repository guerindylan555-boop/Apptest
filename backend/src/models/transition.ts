/**
 * AutoApp UI Map & Intelligent Flow Engine - Transition Entity Model
 *
 * Transition entity representing connections between UI states in the graph.
 * Captures user interactions, state changes, and evidence for the Discovery system.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md
 */

import {
  Transition as ITransition,
  Action as IAction,
  Selector as ISelector,
  ActionType,
  SwipeDirection,
  CreateTransitionRequest,
  UpdateTransitionRequest,
    ValidationResult,
  ValidationError,
  ValidationWarning,
  UUID,
  ISOTimestamp
} from '../types/models';

import { generateUUID, getCurrentTimestamp } from '../utils/uuid';
import { calculateDigest } from '../utils/crypto';

// ============================================================================
// Configuration and Constants
// ============================================================================

/** Default confidence score for new transitions */
const DEFAULT_CONFIDENCE = 0.8;

/** Minimum confidence score for valid transitions */
const MIN_CONFIDENCE = 0.1;

/** Maximum confidence score for transitions */
const MAX_CONFIDENCE = 1.0;

/** Maximum transition duration in milliseconds before flagging as suspicious */
const MAX_TRANSITION_DURATION = 30000; // 30 seconds

/** Default action timeout in milliseconds */
const DEFAULT_ACTION_TIMEOUT = 5000; // 5 seconds

/** Supported action types */
const VALID_ACTION_TYPES: ActionType[] = ['tap', 'type', 'swipe', 'back', 'intent', 'long_press'];

/** Supported swipe directions */
const VALID_SWIPE_DIRECTIONS: SwipeDirection[] = ['up', 'down', 'left', 'right'];

/** Transition schema version */
const TRANSITION_SCHEMA_VERSION = '1.0.0';

// ============================================================================
// Evidence Interface
// ============================================================================

/**
 * Transition error class
 */
export class TransitionError extends Error {
  public readonly code: string;
  public readonly details?: any;
  public readonly timestamp: string;

  constructor(details: { code: string; message: string; details?: any }) {
    super(details.message);
    this.name = 'TransitionError';
    this.code = details.code;
    this.details = details.details;
    this.timestamp = new Date().toISOString();
  }
}

export interface TransitionEvidence {
  /** Hash of source state hierarchy */
  beforeDigest?: string;

  /** Hash of destination state hierarchy */
  afterDigest?: string;

  /** Transition timestamp */
  timestamp: ISOTimestamp;

  /** Transition duration in milliseconds */
  duration?: number;

  /** Screenshot evidence references */
  screenshots?: {
    before?: string;
    after?: string;
  };

  /** Performance metrics */
  metrics?: {
    responseTime?: number;
    renderTime?: number;
    animationTime?: number;
    networkRequests?: number;
  };

  /** Analyst notes and observations */
  notes?: string;

  /** Additional context data */
  context?: Record<string, any>;
}

// ============================================================================
// Action Validation Result
// ============================================================================

/**
 * Action validation result with detailed feedback
 */
export interface ActionValidationResult {
  /** Overall validation status */
  isValid: boolean;

  /** Validation errors */
  errors: ValidationError[];

  /** Validation warnings */
  warnings: ValidationWarning[];

  /** Normalized action object */
  normalizedAction?: IAction;

  /** Estimated confidence in action execution */
  estimatedConfidence?: number;
}

// ============================================================================
// Transition Comparison Result
// ============================================================================

/**
 * Result of transition similarity comparison
 */
export interface TransitionComparisonResult {
  /** Similarity score (0-1) */
  similarity: number;

  /** Matching factors */
  factors: {
    actionType: boolean;
    targetSelector: boolean;
    sourceState: boolean;
    destinationState: boolean;
    parameters: boolean;
  };

  /** Differences between transitions */
  differences: string[];

  /** Recommended action */
  recommendation: 'identical' | 'similar' | 'different';
}

// ============================================================================
// Transition Entity Class
// ============================================================================

/**
 * Transition entity representing a connection between UI states
 *
 * This class models the directed edges in the UI Transition Graph (UTG),
 * capturing the action that moves from one state to another along with
 * supporting evidence and confidence metrics.
 */
export class Transition implements ITransition {
  // ========================================================================
  // Core Properties
  // ========================================================================

  /** Stable identifier for this transition */
  public readonly id: UUID;

  /** Source state node identifier */
  public readonly from: string;

  /** Destination state node identifier */
  public to: string;

  /** Triggering action definition */
  public action: IAction;

  /** Evidence and proof data */
  public evidence?: TransitionEvidence;

  /** Transition certainty score (0-1) */
  public confidence: number;

  /** Classification tags */
  public tags: string[];

  /** Creation timestamp */
  public readonly createdAt: ISOTimestamp;

  /** Last update timestamp */
  public updatedAt: ISOTimestamp;

  /** Schema version */
  public readonly version: string = TRANSITION_SCHEMA_VERSION;

  // ========================================================================
  // Private State
  // ========================================================================

  /** Cached action validation result */
  private _actionValidation?: ActionValidationResult;

  /** Cached transition hash */
  private _cachedHash?: string;

  /** Validation errors cache */
  private _validationErrors?: ValidationError[];

  /** Validation warnings cache */
  private _validationWarnings?: ValidationWarning[];

  // ========================================================================
  // Constructor
  // ========================================================================

  /**
   * Create a new Transition instance
   *
   * @param request - Transition creation request
   * @param id - Optional predefined UUID (for imports/migrations)
   */
  constructor(request: CreateTransitionRequest, id?: UUID) {
    // Validate required fields
    this.validateCreationRequest(request);

    // Assign unique identifier
    this.id = id || generateUUID();

    // Set core properties
    this.from = request.from;
    this.to = request.to;
    this.action = this.normalizeAction(request.action);
    this.confidence = this.normalizeConfidence(request.confidence);
    this.tags = request.tags || [];

    // Set evidence
    if (request.evidence) {
      this.evidence = {
        timestamp: getCurrentTimestamp(),
        ...request.evidence
      };
    }

    // Set timestamps
    const now = getCurrentTimestamp();
    this.createdAt = now;
    this.updatedAt = now;

    // Validate the complete transition
    this.validate();
  }

  // ========================================================================
  // Static Factory Methods
  // ========================================================================

  /**
   * Create a transition from action execution
   *
   * @param fromState - Source state identifier
   * @param toState - Destination state identifier
   * @param action - Executed action
   * @param beforeDigest - Source state digest
   * @param afterDigest - Destination state digest
   * @param duration - Transition duration in milliseconds
   * @returns New Transition instance
   */
  static fromExecution(
    fromState: string,
    toState: string,
    action: IAction,
    beforeDigest?: string,
    afterDigest?: string,
    duration?: number
  ): Transition {
    return new Transition({
      from: fromState,
      to: toState,
      action,
      evidence: {
        beforeDigest,
        afterDigest,
        notes: `Transition completed in ${duration}ms`
      } as any
    });
  }

  /**
   * Create a transition with evidence
   *
   * @param request - Transition creation request
   * @param evidence - Transition evidence
   * @returns New Transition instance
   */
  static withEvidence(
    request: CreateTransitionRequest,
    evidence: Omit<TransitionEvidence, 'timestamp'>
  ): Transition {
    return new Transition({
      ...request,
      evidence: {
        ...evidence,
              } as any
    });
  }

  /**
   * Create a mock transition for testing
   *
   * @param overrides - Property overrides
   * @returns Mock Transition instance
   */
  static createMock(overrides: Partial<CreateTransitionRequest> = {}): Transition {
    const mockRequest: CreateTransitionRequest = {
      from: 'mock-state-1',
      to: 'mock-state-2',
      action: {
        type: 'tap',
        target: { text: 'Mock Button' }
      },
      confidence: 0.9,
      ...overrides
    };

    return new Transition(mockRequest, 'mock-transition-id');
  }

  // ========================================================================
  // Action Validation and Normalization
  // ========================================================================

  /**
   * Validate and normalize an action definition
   *
   * @param action - Action to validate
   * @returns Normalized action
   * @throws TransitionError if action is invalid
   */
  private normalizeAction(action: IAction): IAction {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const normalizedAction = { ...action };

    // Validate action type
    if (!action.type) {
      errors.push({
        field: 'action.type',
        message: 'Action type is required',
        code: 'REQUIRED_FIELD',
        value: action.type,
        severity: 'error'
      });
    } else if (!VALID_ACTION_TYPES.includes(action.type)) {
      errors.push({
        field: 'action.type',
        message: `Invalid action type: ${action.type}. Valid types: ${VALID_ACTION_TYPES.join(', ')}`,
        code: 'INVALID_VALUE',
        value: action.type,
        severity: 'error'
      });
    }

    // Type-specific validation
    if (action.type === 'type' && !action.text) {
      errors.push({
        field: 'action.text',
        message: 'Text input is required for type actions',
        code: 'REQUIRED_FIELD',
        value: action.text,
        severity: 'error'
      });
    }

    if (action.type === 'swipe') {
      if (!action.swipe) {
        errors.push({
          field: 'action.swipe',
          message: 'Swipe configuration is required for swipe actions',
          code: 'REQUIRED_FIELD',
          value: action.swipe,
          severity: 'error'
        });
      } else {
        if (!action.swipe.direction) {
          errors.push({
            field: 'action.swipe.direction',
            message: 'Swipe direction is required',
            code: 'REQUIRED_FIELD',
            value: action.swipe.direction,
            severity: 'error'
          });
        } else if (!VALID_SWIPE_DIRECTIONS.includes(action.swipe.direction)) {
          errors.push({
            field: 'action.swipe.direction',
            message: `Invalid swipe direction: ${action.swipe.direction}`,
            code: 'INVALID_VALUE',
            value: action.swipe.direction,
            severity: 'error'
          });
        }

        if (typeof action.swipe.distance !== 'number' ||
            action.swipe.distance < 0 ||
            action.swipe.distance > 1) {
          errors.push({
            field: 'action.swipe.distance',
            message: 'Swipe distance must be a number between 0 and 1',
            code: 'INVALID_RANGE',
            value: action.swipe.distance,
            severity: 'error'
          });
        }
      }
    }

    // Target validation for interactive actions
    if (['tap', 'type', 'long_press'].includes(action.type) && !action.target) {
      warnings.push({
        field: 'action.target',
        message: `Target selector is recommended for ${action.type} actions`,
        code: 'MISSING_TARGET',
        value: action.target,
        severity: 'warning'
      });
    }

    // Intent validation
    if (action.type === 'intent' && !action.intent) {
      errors.push({
        field: 'action.intent',
        message: 'Intent parameters are required for intent actions',
        code: 'REQUIRED_FIELD',
        value: action.intent,
        severity: 'error'
      });
    }

    // Cache validation result
    this._actionValidation = {
      isValid: errors.length === 0,
      errors,
      warnings,
      normalizedAction,
      estimatedConfidence: this.calculateActionConfidence(action, errors, warnings)
    };

    if (errors.length > 0) {
      throw new TransitionError({
        code: 'INVALID_ACTION',
        message: `Action validation failed: ${errors.map(e => e.message).join(', ')}`,
        details: {
          entityType: 'Transition',
          field: 'action',
          errors: errors.map(e => ({ code: e.code, message: e.message }))
        }
      });
    }

    return normalizedAction;
  }

  /**
   * Calculate confidence score for an action based on validation results
   *
   * @param action - Action to evaluate
   * @param errors - Validation errors
   * @param warnings - Validation warnings
   * @returns Confidence score (0-1)
   */
  private calculateActionConfidence(
    action: IAction,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): number {
    let confidence = 1.0;

    // Penalize errors heavily
    confidence -= errors.length * 0.3;

    // Penalize warnings moderately
    confidence -= warnings.length * 0.1;

    // Bonus for well-defined targets
    if (action.target && (action.target.rid || action.target.text)) {
      confidence += 0.1;
    }

    // Bonus for semantic selectors
    if (action.semanticSelector) {
      confidence += 0.05;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  /**
   * Validate the action with detailed results
   *
   * @returns Action validation result
   */
  public validateAction(): ActionValidationResult {
    if (!this._actionValidation) {
      this._actionValidation = {
        isValid: true,
        errors: [],
        warnings: [],
        normalizedAction: this.action,
        estimatedConfidence: this.confidence
      };
    }
    return this._actionValidation;
  }

  // ========================================================================
  // Evidence Management
  // ========================================================================

  /**
   * Add or update transition evidence
   *
   * @param evidence - Evidence data
   */
  public addEvidence(evidence: Partial<TransitionEvidence>): void {
    if (!this.evidence) {
      this.evidence = {
        timestamp: getCurrentTimestamp()
      };
    }

    // Update evidence fields
    Object.assign(this.evidence, evidence);

    // Update timestamp
    this.evidence.timestamp = getCurrentTimestamp();

    // Mark as updated
    this.updatedAt = getCurrentTimestamp();

    // Clear validation cache
    this._validationErrors = undefined;
    this._validationWarnings = undefined;
  }

  /**
   * Add screenshot evidence
   *
   * @param beforeScreenshot - Screenshot before transition
   * @param afterScreenshot - Screenshot after transition
   */
  public addScreenshots(beforeScreenshot?: string, afterScreenshot?: string): void {
    if (!this.evidence) {
      this.evidence = {
        timestamp: getCurrentTimestamp()
      };
    }

    if (!this.evidence.screenshots) {
      this.evidence.screenshots = {};
    }

    if (beforeScreenshot) {
      this.evidence.screenshots.before = beforeScreenshot;
    }

    if (afterScreenshot) {
      this.evidence.screenshots.after = afterScreenshot;
    }

    this.updatedAt = getCurrentTimestamp();
  }

  /**
   * Set transition performance metrics
   *
   * @param metrics - Performance metrics
   */
  public setPerformanceMetrics(metrics: TransitionEvidence['metrics']): void {
    this.addEvidence({
      metrics
    });
  }

  /**
   * Check if transition has sufficient evidence
   *
   * @returns True if evidence is sufficient
   */
  public hasSufficientEvidence(): boolean {
    if (!this.evidence) {
      return false;
    }

    const hasDigests = !!(this.evidence.beforeDigest && this.evidence.afterDigest);
    const hasTimestamp = !!this.evidence.timestamp;
    const hasDuration = typeof this.evidence.duration === 'number';

    return hasDigests && hasTimestamp && hasDuration;
  }

  // ========================================================================
  // Transition Analysis and Utilities
  // ========================================================================

  /**
   * Compare this transition with another for similarity
   *
   * @param other - Other transition to compare
   * @returns Similarity comparison result
   */
  public compareWith(other: Transition): TransitionComparisonResult {
    const factors = {
      actionType: this.action.type === other.action.type,
      targetSelector: this.compareSelectors(this.action.target, other.action.target),
      sourceState: this.from === other.from,
      destinationState: this.to === other.to,
      parameters: this.compareActionParameters(this.action, other.action)
    };

    const matchingFactors = Object.values(factors).filter(Boolean).length;
    const similarity = matchingFactors / Object.keys(factors).length;

    const differences: string[] = [];
    if (!factors.actionType) differences.push('Different action types');
    if (!factors.targetSelector) differences.push('Different target selectors');
    if (!factors.sourceState) differences.push('Different source states');
    if (!factors.destinationState) differences.push('Different destination states');
    if (!factors.parameters) differences.push('Different action parameters');

    let recommendation: 'identical' | 'similar' | 'different';
    if (similarity >= 0.9) {
      recommendation = 'identical';
    } else if (similarity >= 0.6) {
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
   * Check if this transition is a reversal of another
   *
   * @param other - Other transition to check
   * @returns True if this is a reversal
   */
  public isReversalOf(other: Transition): boolean {
    // Check if states are swapped
    const statesReversed = this.from === other.to && this.to === other.from;

    if (!statesReversed) {
      return false;
    }

    // Check if actions are compatible reversals
    return this.areReversalActions(this.action, other.action);
  }

  /**
   * Categorize the transition type
   *
   * @returns Transition category
   */
  public categorize(): string {
    const { type } = this.action;

    // Navigation actions
    if (type === 'back' || type === 'swipe') {
      return 'navigation';
    }

    // Input actions
    if (type === 'type' || type === 'long_press') {
      return 'input';
    }

    // System actions
    if (type === 'intent') {
      return 'system';
    }

    // Default interaction
    return 'interaction';
  }

  /**
   * Calculate transition hash for deduplication
   *
   * @returns SHA-256 hash of transition
   */
  public calculateHash(): string {
    if (this._cachedHash) {
      return this._cachedHash;
    }

    const hashData = {
      from: this.from,
      to: this.to,
      action: this.action,
      confidence: this.confidence
    };

    this._cachedHash = calculateDigest(JSON.stringify(hashData));
    return this._cachedHash;
  }

  /**
   * Check if transition is circular (same source and destination)
   *
   * @returns True if circular
   */
  public isCircular(): boolean {
    return this.from === this.to;
  }

  /**
   * Estimate transition execution time
   *
   * @returns Estimated duration in milliseconds
   */
  public estimateExecutionTime(): number {
    const baseTime = 1000; // Base 1 second

    switch (this.action.type) {
      case 'tap':
        return baseTime;
      case 'type':
        return baseTime + (this.action.text?.length || 0) * 50; // 50ms per character
      case 'swipe':
        return baseTime * 1.5;
      case 'long_press':
        return this.action.metadata?.duration || baseTime * 2;
      case 'intent':
        return baseTime * 2;
      case 'back':
        return baseTime * 0.5;
      default:
        return baseTime;
    }
  }

  // ========================================================================
  // Validation
  // ========================================================================

  /**
   * Validate the complete transition
   *
   * @returns Validation result
   */
  public validate(): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Core field validation
    if (!this.from) {
      errors.push({
        field: 'from',
        message: 'Source state identifier is required',
        code: 'REQUIRED_FIELD',
        value: this.from,
        severity: 'error'
      });
    }

    if (!this.to) {
      errors.push({
        field: 'to',
        message: 'Destination state identifier is required',
        code: 'REQUIRED_FIELD',
        value: this.to,
        severity: 'error'
      });
    }

    // Circular transition warning
    if (this.from === this.to) {
      warnings.push({
        field: 'from,to',
        message: 'Circular transition detected (same source and destination)',
        code: 'CIRCULAR_TRANSITION',
        value: { from: this.from, to: this.to },
        severity: 'warning'
      });
    }

    // Action validation
    const actionValidation = this.validateAction();
    errors.push(...actionValidation.errors);
    warnings.push(...actionValidation.warnings);

    // Confidence validation
    if (this.confidence < MIN_CONFIDENCE) {
      warnings.push({
        field: 'confidence',
        message: `Low confidence score: ${this.confidence}`,
        code: 'LOW_CONFIDENCE',
        value: this.confidence,
        severity: 'warning'
      });
    }

    // Evidence validation
    if (this.evidence) {
      if (this.evidence.duration && this.evidence.duration > MAX_TRANSITION_DURATION) {
        warnings.push({
          field: 'evidence.duration',
          message: `Long transition duration: ${this.evidence.duration}ms`,
          code: 'LONG_DURATION',
          value: this.evidence.duration,
          severity: 'warning'
        });
      }

      // Check evidence consistency
      if (this.evidence.beforeDigest && this.evidence.afterDigest) {
        if (this.evidence.beforeDigest === this.evidence.afterDigest) {
          warnings.push({
            field: 'evidence.digests',
            message: 'Before and after state digests are identical - possible no-op transition',
            code: 'IDENTICAL_STATES',
            severity: 'warning'
          });
        }
      }
    } else {
      warnings.push({
        field: 'evidence',
        message: 'No evidence provided for transition',
        code: 'MISSING_EVIDENCE',
        severity: 'warning'
      });
    }

    // Cache validation results
    this._validationErrors = errors;
    this._validationWarnings = warnings;

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Get cached validation errors
   *
   * @returns Validation errors
   */
  public getValidationErrors(): ValidationError[] {
    if (this._validationErrors === undefined) {
      this.validate();
    }
    return this._validationErrors || [];
  }

  /**
   * Get cached validation warnings
   *
   * @returns Validation warnings
   */
  public getValidationWarnings(): ValidationWarning[] {
    if (this._validationWarnings === undefined) {
      this.validate();
    }
    return this._validationWarnings || [];
  }

  // ========================================================================
  // Update Operations
  // ========================================================================

  /**
   * Update transition properties
   *
   * @param updates - Properties to update
   */
  public update(updates: UpdateTransitionRequest): void {
    let hasChanges = false;

    // Update action
    if (updates.action) {
      this.action = this.normalizeAction(updates.action);
      hasChanges = true;
    }

    // Update evidence
    if (updates.evidence) {
      if (!this.evidence) {
        this.evidence = {
          timestamp: getCurrentTimestamp()
        };
      }
      Object.assign(this.evidence, updates.evidence);
      hasChanges = true;
    }

    // Update confidence
    if (typeof updates.confidence === 'number') {
      this.confidence = this.normalizeConfidence(updates.confidence);
      hasChanges = true;
    }

    // Update tags
    if (updates.tags) {
      this.tags = updates.tags;
      hasChanges = true;
    }

    if (hasChanges) {
      this.updatedAt = getCurrentTimestamp();

      // Clear caches
      this._actionValidation = undefined;
      this._validationErrors = undefined;
      this._validationWarnings = undefined;
      this._cachedHash = undefined;
    }
  }

  /**
   * Add tags to the transition
   *
   * @param tags - Tags to add
   */
  public addTags(...tags: string[]): void {
    const newTags = tags.filter(tag => !this.tags.includes(tag));
    if (newTags.length > 0) {
      this.tags.push(...newTags);
      this.updatedAt = getCurrentTimestamp();
    }
  }

  /**
   * Remove tags from the transition
   *
   * @param tags - Tags to remove
   */
  public removeTags(...tags: string[]): void {
    const originalLength = this.tags.length;
    this.tags = this.tags.filter(tag => !tags.includes(tag));
    if (this.tags.length !== originalLength) {
      this.updatedAt = getCurrentTimestamp();
    }
  }

  // ========================================================================
  // Serialization and Export
  // ========================================================================

  /**
   * Convert to plain object for JSON serialization
   *
   * @returns Plain object representation
   */
  public toJSON(): ITransition {
    return {
      id: this.id,
      from: this.from,
      to: this.to,
      action: this.action,
      evidence: this.evidence,
      confidence: this.confidence,
      tags: this.tags,
      createdAt: this.createdAt
    };
  }

  /**
   * Convert to compact representation for storage
   *
   * @returns Compact object
   */
  public toStorage(): Record<string, any> {
    return {
      id: this.id,
      from: this.from,
      to: this.to,
      action: this.action,
      evidence: this.evidence,
      confidence: this.confidence,
      tags: this.tags,
      createdAt: this.createdAt,
      version: this.version
    };
  }

  /**
   * Create Transition from storage data
   *
   * @param data - Storage data
   * @returns Transition instance
   */
  public static fromStorage(data: Record<string, any>): Transition {
    const transition = Object.create(Transition.prototype);

    transition.id = data.id;
    transition.from = data.from;
    transition.to = data.to;
    transition.action = data.action;
    transition.evidence = data.evidence;
    transition.confidence = data.confidence;
    transition.tags = data.tags || [];
    transition.createdAt = data.createdAt;
    transition.updatedAt = data.updatedAt;
    transition.version = data.version || TRANSITION_SCHEMA_VERSION;

    return transition;
  }

  // ========================================================================
  // Utility Methods
  // ========================================================================

  /**
   * Validate creation request
   *
   * @param request - Creation request to validate
   * @throws TransitionError if invalid
   */
  private validateCreationRequest(request: CreateTransitionRequest): void {
    if (!request) {
      throw new TransitionError({
        code: 'INVALID_REQUEST',
        message: 'Transition creation request is required',
        details: {
          entityType: 'Transition'
        },
              });
    }

    if (!request.from) {
      throw new TransitionError({
        code: 'REQUIRED_FIELD',
        message: 'Source state identifier (from) is required',
        details: {
          entityType: 'Transition',
          field: 'from',
          value: request.from
        },
              });
    }

    if (!request.to) {
      throw new TransitionError({
        code: 'REQUIRED_FIELD',
        message: 'Destination state identifier (to) is required',
        details: {
          entityType: 'Transition',
          field: 'to',
          value: request.to
        },
              });
    }

    if (!request.action) {
      throw new TransitionError({
        code: 'REQUIRED_FIELD',
        message: 'Action definition is required',
        details: {
          entityType: 'Transition',
          field: 'action',
          value: request.action
        },
              });
    }
  }

  /**
   * Normalize confidence value
   *
   * @param confidence - Confidence value to normalize
   * @returns Normalized confidence
   */
  private normalizeConfidence(confidence?: number): number {
    if (typeof confidence !== 'number') {
      return DEFAULT_CONFIDENCE;
    }

    return Math.max(MIN_CONFIDENCE, Math.min(MAX_CONFIDENCE, confidence));
  }

  /**
   * Compare two selectors for equality
   *
   * @param selector1 - First selector
   * @param selector2 - Second selector
   * @returns True if selectors match
   */
  private compareSelectors(selector1?: ISelector, selector2?: ISelector): boolean {
    if (!selector1 || !selector2) {
      return selector1 === selector2;
    }

    return (
      selector1.rid === selector2.rid ||
      selector1.text === selector2.text ||
      selector1.desc === selector2.desc ||
      selector1.cls === selector2.cls
    );
  }

  /**
   * Compare action parameters
   *
   * @param action1 - First action
   * @param action2 - Second action
   * @returns True if parameters match
   */
  private compareActionParameters(action1: IAction, action2: IAction): boolean {
    // Compare text input
    if (action1.text !== action2.text) {
      return false;
    }

    // Compare swipe configuration
    if (action1.swipe && action2.swipe) {
      return (
        action1.swipe.direction === action2.swipe.direction &&
        action1.swipe.distance === action2.swipe.distance
      );
    }

    // Compare intent parameters
    if (action1.intent && action2.intent) {
      return JSON.stringify(action1.intent) === JSON.stringify(action2.intent);
    }

    // Compare metadata
    if (action1.metadata && action2.metadata) {
      return JSON.stringify(action1.metadata) === JSON.stringify(action2.metadata);
    }

    return true;
  }

  /**
   * Check if two actions are reversals of each other
   *
   * @param action1 - First action
   * @param action2 - Second action
   * @returns True if actions are reversals
   */
  private areReversalActions(action1: IAction, action2: IAction): boolean {
    // Back button is its own reversal
    if (action1.type === 'back' && action2.type === 'back') {
      return true;
    }

    // Swipe directions
    if (action1.type === 'swipe' && action2.type === 'swipe') {
      const reversals: Record<SwipeDirection, SwipeDirection> = {
        'up': 'down',
        'down': 'up',
        'left': 'right',
        'right': 'left'
      };
      return action1.swipe?.direction === reversals[action2.swipe?.direction || ''];
    }

    // Other actions typically don't have clear reversals
    return false;
  }

  // ========================================================================
  // String Representations
  // ========================================================================

  /**
   * String representation of the transition
   *
   * @returns Human-readable description
   */
  public toString(): string {
    const actionDesc = this.describeAction();
    return `Transition[${this.id}]: ${this.from} → ${this.to} (${actionDesc})`;
  }

  /**
   * Describe the action in human-readable format
   *
   * @returns Action description
   */
  public describeAction(): string {
    const { type, target, text, swipe } = this.action;

    switch (type) {
      case 'tap':
        return target ? `tap ${target.text || target.desc || target.rid || 'element'}` : 'tap';
      case 'type':
        return target ? `type "${text}" in ${target.text || target.desc || target.rid || 'field'}` : `type "${text}"`;
      case 'swipe':
        return `swipe ${swipe?.direction} (${Math.round((swipe?.distance || 0) * 100)}%)`;
      case 'back':
        return 'back';
      case 'intent':
        return `intent ${JSON.stringify(this.action.intent)}`;
      case 'long_press':
        return target ? `long press ${target.text || target.desc || target.rid || 'element'}` : 'long press';
      default:
        return type;
    }
  }

  /**
   * Detailed description of the transition
   *
   * @returns Detailed description
   */
  public describe(): string {
    const parts = [
      `Transition: ${this.from} → ${this.to}`,
      `Action: ${this.describeAction()}`,
      `Confidence: ${Math.round(this.confidence * 100)}%`,
      `Category: ${this.categorize()}`
    ];

    if (this.evidence) {
      parts.push(`Evidence: ${this.evidence.duration ? `${this.evidence.duration}ms` : 'present'}`);
    }

    if (this.tags.length > 0) {
      parts.push(`Tags: ${this.tags.join(', ')}`);
    }

    return parts.join('\n');
  }
}

// ============================================================================
// Exports
// ============================================================================

export default Transition;

