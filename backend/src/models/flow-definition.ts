/**
 * AutoApp UI Map & Intelligent Flow Engine - Flow Definition Model
 *
 * Flow definition entity representing complete automation flows with steps,
 * entry/exit points, configuration, and execution metadata. Provides comprehensive
 * flow management, validation, execution planning, and lifecycle management.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md and task T041 requirements.
 */

import {
  FlowDefinition as IFlowDefinition,
  FlowStep as IFlowStep,
  StatePredicate as IStatePredicate,
  CreateFlowDefinitionRequest,
  UpdateFlowDefinitionRequest,
  FlowPriority,
  ValidationResult,
  ValidationError,
  ValidationWarning,
  UUID,
  ISOTimestamp,
  ExecutionStatus,
  StepResult
} from '../types/models';

import { FlowStep } from './flow-step';
import { StatePredicate } from './state-predicate';
import { generateUUID, getCurrentTimestamp } from '../utils/uuid';
import { hashObject } from '../utils/crypto';

// ============================================================================
// Configuration and Constants
// ============================================================================

/** Default flow schema version */
const DEFAULT_FLOW_VERSION = '1.0.0';

/** Default timeout for flow steps in seconds */
const DEFAULT_TIMEOUT = 30;

/** Default retry attempts for flow steps */
const DEFAULT_RETRY_ATTEMPTS = 3;

/** Default flow priority */
const DEFAULT_PRIORITY: FlowPriority = 'medium';

/** Maximum number of steps per flow */
const MAX_STEPS_PER_FLOW = 100;

/** Maximum flow name length */
const MAX_FLOW_NAME_LENGTH = 200;

/** Maximum flow description length */
const MAX_FLOW_DESCRIPTION_LENGTH = 1000;

/** Maximum number of tags per flow */
const MAX_TAGS_PER_FLOW = 20;

/** Flow definition schema version */
const FLOW_DEFINITION_SCHEMA_VERSION = '1.0.0';

// ============================================================================
// Flow Execution Plan
// ============================================================================

/**
 * Execution plan for a flow with optimized step ordering and dependencies
 */
export interface FlowExecutionPlan {
  /** Flow identifier */
  flowId: string;

  /** Plan version */
  version: string;

  /** Optimized step execution order */
  stepOrder: string[];

  /** Step dependencies */
  dependencies: Map<string, string[]>;

  /** Parallel execution groups */
  parallelGroups: string[][];

  /** Estimated total duration in seconds */
  estimatedDuration: number;

  /** Critical path steps */
  criticalPath: string[];

  /** Risk assessment */
  riskAssessment: {
    overallRisk: 'low' | 'medium' | 'high';
    riskFactors: string[];
    mitigation: string[];
  };

  /** Resource requirements */
  resourceRequirements: {
    maxMemory?: number;
    maxCpu?: number;
    requiredPermissions: string[];
    estimatedNetworkUsage?: number;
  };

  /** Execution checkpoints */
  checkpoints: Array<{
    stepId: string;
    name: string;
    critical: boolean;
  }>;

  /** Rollback strategies */
  rollbackStrategies: Array<{
    stepId: string;
    strategy: 'reverse' | 'reset' | 'custom';
    customSteps?: string[];
  }>;

  /** Plan creation timestamp */
  createdAt: ISOTimestamp;
}

// ============================================================================
// Flow Validation Context
// ============================================================================

/**
 * Context for flow validation with additional constraints
 */
export interface FlowValidationContext {
  /** Available packages in the system */
  availablePackages?: string[];

  /** Maximum allowed steps */
  maxSteps?: number;

  /** Maximum allowed timeout */
  maxTimeout?: number;

  /** Maximum allowed retry attempts */
  maxRetryAttempts?: number;

  /** Require entry point */
  requireEntryPoint?: boolean;

  /** Enable strict validation */
  strictMode?: boolean;

  /** Validate against available states */
  availableStates?: any[]; // State entities

  /** Validate action compatibility */
  validateActions?: boolean;
}

// ============================================================================
// Flow Statistics
// ============================================================================

/**
 * Comprehensive flow execution statistics
 */
export interface FlowStatistics {
  /** Total execution count */
  totalExecutions: number;

  /** Successful executions */
  successfulExecutions: number;

  /** Failed executions */
  failedExecutions: number;

  /** Average execution time in seconds */
  averageExecutionTime: number;

  /** Fastest execution time in seconds */
  fastestExecutionTime: number;

  /** Slowest execution time in seconds */
  slowestExecutionTime: number;

  /** Success rate (0-1) */
  successRate: number;

  /** Last execution timestamp */
  lastExecutedAt?: ISOTimestamp;

  /** Last successful execution timestamp */
  lastSuccessfulExecutionAt?: ISOTimestamp;

  /** Step-specific statistics */
  stepStatistics: Map<string, {
    executions: number;
    successes: number;
    failures: number;
    averageDuration: number;
    lastExecutedAt?: ISOTimestamp;
  }>;

  /** Error statistics */
  errorStatistics: Map<string, {
    count: number;
    lastOccurred: ISOTimestamp;
    stepId?: string;
  }>;

  /** Performance trends */
  performanceTrends: {
    last7Days: number[];
    last30Days: number[];
    improvement: number; // Percentage change
  };
}

// ============================================================================
// Flow Comparison Result
// ============================================================================

/**
 * Result of flow similarity comparison
 */
export interface FlowComparisonResult {
  /** Similarity score (0-1) */
  similarity: number;

  /** Matching factors */
  factors: {
    name: boolean;
    packageName: boolean;
    steps: boolean;
    entryPoint: boolean;
    exitPoint: boolean;
    configuration: boolean;
  };

  /** Differences between flows */
  differences: string[];

  /** Step-by-step comparison */
  stepComparison: Array<{
    step1Index?: number;
    step2Index?: number;
    similarity: number;
    action: string;
  }>;

  /** Recommended action */
  recommendation: 'identical' | 'similar' | 'different' | 'conflict';
}

// ============================================================================
// Flow Definition Entity Class
// ============================================================================

/**
 * Flow definition entity representing complete automation flows
 *
 * This class provides comprehensive flow management with step sequencing,
 * entry/exit point validation, configuration management, execution planning,
 * and detailed lifecycle tracking.
 */
export class FlowDefinition implements IFlowDefinition {
  // ========================================================================
  // Core Properties
  // ========================================================================

  /** Flow identifier */
  public readonly id: UUID;

  /** Human-friendly name */
  public name: string;

  /** Optional summary */
  public description?: string;

  /** Flow schema version */
  public version: string;

  /** Target package */
  public packageName: string;

  /** Ordered execution steps */
  public steps: FlowStep[];

  /** Starting condition */
  public entryPoint: StatePredicate;

  /** Optional completion check */
  public exitPoint?: StatePredicate;

  /** Audit fields */
  public metadata: {
    createdAt: ISOTimestamp;
    updatedAt: ISOTimestamp;
    author?: string;
    tags?: string[];
    estimatedDuration?: number; // Performance hint in seconds
    complexity?: number; // Custom scale 1-5
    executionCount?: number; // Historical runs
    successRate?: number; // Historical success 0-1
  };

  /** Flow configuration */
  public config: {
    defaultTimeout: number; // Wait per step in seconds
    retryAttempts: number; // Step retries
    allowParallel: boolean; // Future use
    priority: FlowPriority; // Scheduling hint
  };

  /** Schema version */
  public readonly schemaVersion: string = FLOW_DEFINITION_SCHEMA_VERSION;

  // ========================================================================
  // Private State
  // ========================================================================

  /** Validation cache */
  private _validationCache?: ValidationResult;

  /** Execution statistics */
  private _executionStats: FlowStatistics = {
    totalExecutions: 0,
    successfulExecutions: 0,
    failedExecutions: 0,
    averageExecutionTime: 0,
    fastestExecutionTime: Infinity,
    slowestExecutionTime: 0,
    successRate: 0,
    stepStatistics: new Map(),
    errorStatistics: new Map(),
    performanceTrends: {
      last7Days: [],
      last30Days: [],
      improvement: 0
    }
  };

  /** Cached execution plan */
  private _executionPlan?: FlowExecutionPlan;

  /** Cached flow hash */
  private _cachedHash?: string;

  /** Performance monitoring data */
  private _performanceData = {
    lastValidationAt?: ISOTimestamp,
    lastPlanGenerationAt?: ISOTimestamp,
    cacheHits: 0,
    cacheMisses: 0
  };

  // ========================================================================
  // Constructor
  // ========================================================================

  /**
   * Create a new FlowDefinition instance
   *
   * @param data - Flow creation data
   * @param id - Optional predefined UUID (for imports/migrations)
   */
  constructor(data: CreateFlowDefinitionRequest, id?: UUID) {
    // Assign unique identifier
    this.id = id || generateUUID();

    // Set timestamps
    const now = getCurrentTimestamp();

    // Validate and set basic properties
    this.validateFlowData(data);
    this.name = data.name.trim();
    this.description = data.description?.trim();
    this.version = DEFAULT_FLOW_VERSION;
    this.packageName = data.packageName.trim();

    // Process steps
    this.steps = this.processSteps(data.steps);

    // Set entry and exit points
    this.entryPoint = data.entryPoint instanceof StatePredicate
      ? data.entryPoint
      : new StatePredicate(data.entryPoint);

    if (data.exitPoint) {
      this.exitPoint = data.exitPoint instanceof StatePredicate
        ? data.exitPoint
        : new StatePredicate(data.exitPoint);
    }

    // Set metadata
    this.metadata = {
      createdAt: now,
      updatedAt: now,
      author: data.author,
      tags: this.processTags(data.tags),
      estimatedDuration: data.estimatedDuration,
      complexity: data.complexity,
      executionCount: 0,
      successRate: 0
    };

    // Set configuration
    this.config = this.normalizeConfig(data.config);

    // Validate the complete flow
    this.validate();

    // Calculate initial hash
    this._cachedHash = this.calculateHash();
  }

  // ========================================================================
  // Static Factory Methods
  // ========================================================================

  /**
   * Create a flow from existing data (for database reconstruction)
   *
   * @param data - Complete flow data
   * @returns FlowDefinition instance
   */
  static fromExisting(data: IFlowDefinition): FlowDefinition {
    const flow = Object.create(FlowDefinition.prototype);
    Object.assign(flow, data);

    // Convert steps to FlowStep instances
    flow.steps = data.steps.map(step =>
      step instanceof FlowStep ? step : FlowStep.fromExisting(step)
    );

    // Convert entry point to StatePredicate instance
    flow.entryPoint = data.entryPoint instanceof StatePredicate
      ? data.entryPoint
      : new StatePredicate(data.entryPoint);

    // Convert exit point to StatePredicate instance
    if (data.exitPoint) {
      flow.exitPoint = data.exitPoint instanceof StatePredicate
        ? data.exitPoint
        : new StatePredicate(data.exitPoint);
    }

    // Initialize private properties
    flow._executionStats = {
      totalExecutions: data.metadata.executionCount || 0,
      successfulExecutions: Math.floor((data.metadata.successRate || 0) * (data.metadata.executionCount || 0)),
      failedExecutions: Math.ceil((1 - (data.metadata.successRate || 0)) * (data.metadata.executionCount || 0)),
      averageExecutionTime: data.metadata.estimatedDuration || 0,
      fastestExecutionTime: Infinity,
      slowestExecutionTime: 0,
      successRate: data.metadata.successRate || 0,
      stepStatistics: new Map(),
      errorStatistics: new Map(),
      performanceTrends: {
        last7Days: [],
        last30Days: [],
        improvement: 0
      }
    };

    flow._validationCache = undefined;
    flow._executionPlan = undefined;
    flow._cachedHash = flow.calculateHash();

    return flow;
  }

  /**
   * Create a minimal flow for testing
   *
   * @param name - Flow name
   * @param packageName - Target package
   * @param steps - Flow steps
   * @returns Simple flow definition
   */
  static createSimple(
    name: string,
    packageName: string,
    steps: FlowStep[]
  ): FlowDefinition {
    return new FlowDefinition({
      name,
      packageName,
      steps,
      entryPoint: StatePredicate.activity(packageName, 'exact')
    });
  }

  /**
   * Create a flow from a template
   *
   * @param template - Flow template
   * @param customizations - Custom overrides
   * @returns Customized flow definition
   */
  static fromTemplate(
    template: {
      name: string;
      description?: string;
      packageName: string;
      steps: Omit<IFlowStep, 'id'>[];
      entryPoint: IStatePredicate;
      exitPoint?: IStatePredicate;
    },
    customizations: {
      name?: string;
      description?: string;
      author?: string;
      tags?: string[];
      config?: Partial<FlowDefinition['config']>;
    } = {}
  ): FlowDefinition {
    return new FlowDefinition({
      name: customizations.name || template.name,
      description: customizations.description || template.description,
      packageName: template.packageName,
      steps: template.steps,
      entryPoint: template.entryPoint,
      exitPoint: template.exitPoint,
      author: customizations.author,
      tags: customizations.tags,
      config: customizations.config
    });
  }

  // ========================================================================
  // Flow Planning and Execution Methods
  // ========================================================================

  /**
   * Generate execution plan for this flow
   *
   * @param options - Planning options
   * @returns Execution plan
   */
  public generateExecutionPlan(options: {
    optimizeOrder?: boolean;
    includeParallelization?: boolean;
    generateCheckpoints?: boolean;
  } = {}): FlowExecutionPlan {
    if (this._executionPlan && !options.optimizeOrder) {
      this._performanceData.cacheHits++;
      return this._executionPlan;
    }

    this._performanceData.cacheMisses++;
    this._performanceData.lastPlanGenerationAt = getCurrentTimestamp();

    const plan: FlowExecutionPlan = {
      flowId: this.id,
      version: this.version,
      stepOrder: this.steps.map(step => step.id),
      dependencies: new Map(),
      parallelGroups: [],
      estimatedDuration: this.calculateEstimatedDuration(),
      criticalPath: this.identifyCriticalPath(),
      riskAssessment: this.assessRisks(),
      resourceRequirements: this.estimateResourceRequirements(),
      checkpoints: [],
      rollbackStrategies: [],
      createdAt: getCurrentTimestamp()
    };

    // Optimize step order if requested
    if (options.optimizeOrder) {
      plan.stepOrder = this.optimizeStepOrder();
    }

    // Identify parallel execution groups
    if (options.includeParallelization && this.config.allowParallel) {
      plan.parallelGroups = this.identifyParallelGroups();
    }

    // Generate checkpoints
    if (options.generateCheckpoints) {
      plan.checkpoints = this.generateCheckpoints();
    }

    // Generate rollback strategies
    plan.rollbackStrategies = this.generateRollbackStrategies();

    // Cache the plan
    this._executionPlan = plan;
    return plan;
  }

  /**
   * Calculate estimated flow execution duration
   *
   * @returns Estimated duration in seconds
   */
  public calculateEstimatedDuration(): number {
    let totalDuration = 0;

    for (const step of this.steps) {
      totalDuration += step.getEstimatedDuration();
    }

    // Add contingency time (20% buffer)
    totalDuration *= 1.2;

    // Add entry point validation time
    totalDuration += 2;

    // Add exit point validation time if specified
    if (this.exitPoint) {
      totalDuration += 2;
    }

    return Math.round(totalDuration * 10) / 10;
  }

  /**
   * Identify critical path through the flow
   *
   * @returns Array of step IDs on critical path
   */
  public identifyCriticalPath(): string[] {
    const criticalSteps = this.steps
      .filter(step => step.critical)
      .map(step => step.id);

    // If no critical steps, assume all steps are critical
    if (criticalSteps.length === 0) {
      return this.steps.map(step => step.id);
    }

    return criticalSteps;
  }

  /**
   * Assess flow execution risks
   *
   * @returns Risk assessment
   */
  public assessRisks(): {
    overallRisk: 'low' | 'medium' | 'high';
    riskFactors: string[];
    mitigation: string[];
  } {
    const riskFactors: string[] = [];
    const mitigation: string[] = [];

    // Check for complex steps
    const complexSteps = this.steps.filter(step => step.getComplexityScore() >= 7);
    if (complexSteps.length > 0) {
      riskFactors.push(`${complexSteps.length} complex steps identified`);
      mitigation.push('Consider breaking down complex steps into simpler ones');
    }

    // Check for long timeout values
    const longTimeouts = this.steps.filter(step => step.timeout > 60);
    if (longTimeouts.length > 0) {
      riskFactors.push(`${longTimeouts.length} steps with long timeouts`);
      mitigation.push('Review timeout values for optimal performance');
    }

    // Check for critical steps without proper preconditions
    const criticalWithoutPreconditions = this.steps.filter(
      step => step.critical && step.preconditions.length === 0
    );
    if (criticalWithoutPreconditions.length > 0) {
      riskFactors.push(`${criticalWithoutPreconditions.length} critical steps without preconditions`);
      mitigation.push('Add preconditions to critical steps for better reliability');
    }

    // Check for many retry attempts
    const highRetryCount = this.steps.filter(
      step => (step.metadata?.retryAttempts || 0) > 3
    );
    if (highRetryCount.length > 0) {
      riskFactors.push(`${highRetryCount.length} steps with high retry counts`);
      mitigation.push('Review retry logic to prevent excessive delays');
    }

    // Check flow complexity
    if (this.steps.length > 20) {
      riskFactors.push('High flow complexity with many steps');
      mitigation.push('Consider splitting into smaller, focused flows');
    }

    // Determine overall risk
    let overallRisk: 'low' | 'medium' | 'high' = 'low';
    if (riskFactors.length >= 3) {
      overallRisk = 'high';
    } else if (riskFactors.length >= 1) {
      overallRisk = 'medium';
    }

    if (mitigation.length === 0) {
      mitigation.push('Flow appears to be well-designed with minimal risks');
    }

    return {
      overallRisk,
      riskFactors,
      mitigation
    };
  }

  /**
   * Estimate resource requirements for flow execution
   *
   * @returns Resource requirements
   */
  public estimateResourceRequirements(): {
    maxMemory?: number;
    maxCpu?: number;
    requiredPermissions: string[];
    estimatedNetworkUsage?: number;
  } {
    const requiredPermissions = new Set<string>();

    // Analyze steps to determine required permissions
    for (const step of this.steps) {
      switch (step.action.type) {
        case 'tap':
        case 'type':
        case 'swipe':
        case 'long_press':
          requiredPermissions.add('android.permission.INTERNET'); // For UI interaction
          break;
        case 'intent':
          requiredPermissions.add('android.permission.INTERNET');
          // Add specific permissions based on intent
          if (step.action.intent?.action?.includes('CALL')) {
            requiredPermissions.add('android.permission.CALL_PHONE');
          }
          if (step.action.intent?.action?.includes('CAMERA')) {
            requiredPermissions.add('android.permission.CAMERA');
          }
          break;
      }
    }

    // Estimate memory usage based on flow complexity
    const estimatedMemory = 50 + (this.steps.length * 5); // Base 50MB + 5MB per step

    // Estimate CPU usage based on action complexity
    const cpuIntensiveSteps = this.steps.filter(step =>
      ['intent', 'swipe'].includes(step.action.type)
    );
    const estimatedCpu = 20 + (cpuIntensiveSteps.length * 10); // Base 20% + 10% per intensive step

    return {
      maxMemory: estimatedMemory,
      maxCpu: estimatedCpu,
      requiredPermissions: Array.from(requiredPermissions),
      estimatedNetworkUsage: this.steps.length * 0.1 // Estimate 0.1MB per step
    };
  }

  /**
   * Optimize step execution order
   *
   * @returns Optimized step order
   */
  private optimizeStepOrder(): string[] {
    // For now, return original order
    // In a more sophisticated implementation, this could analyze dependencies
    // and optimize for execution efficiency
    return this.steps.map(step => step.id);
  }

  /**
   * Identify parallel execution groups
   *
   * @returns Array of parallel step groups
   */
  private identifyParallelGroups(): string[][] {
    // For now, return no parallelization
    // In a more sophisticated implementation, this would analyze dependencies
    // between steps and identify which can run in parallel
    return [];
  }

  /**
   * Generate execution checkpoints
   *
   * @returns Array of checkpoints
   */
  private generateCheckpoints(): Array<{
    stepId: string;
    name: string;
    critical: boolean;
  }> {
    const checkpoints = [];

    // Add checkpoint after each critical step
    for (const step of this.steps) {
      if (step.critical) {
        checkpoints.push({
          stepId: step.id,
          name: `After ${step.name}`,
          critical: true
        });
      }
    }

    // Add checkpoint at 25%, 50%, 75% completion
    const quarterPoints = [
      Math.floor(this.steps.length * 0.25),
      Math.floor(this.steps.length * 0.5),
      Math.floor(this.steps.length * 0.75)
    ];

    for (const index of quarterPoints) {
      if (index < this.steps.length && !this.steps[index].critical) {
        checkpoints.push({
          stepId: this.steps[index].id,
          name: `Checkpoint ${Math.round((index + 1) / this.steps.length * 100)}%`,
          critical: false
        });
      }
    }

    return checkpoints;
  }

  /**
   * Generate rollback strategies
   *
   * @returns Array of rollback strategies
   */
  private generateRollbackStrategies(): Array<{
    stepId: string;
    strategy: 'reverse' | 'reset' | 'custom';
    customSteps?: string[];
  }> {
    const strategies = [];

    for (const step of this.steps) {
      if (step.critical) {
        strategies.push({
          stepId: step.id,
          strategy: 'reverse' // Default to reverse execution for critical steps
        });
      }
    }

    return strategies;
  }

  // ========================================================================
  // Flow Execution Tracking
  // ========================================================================

  /**
   * Record flow execution start
   *
   * @param executionId - Execution identifier
   */
  public recordExecutionStart(executionId: string): void {
    this._executionStats.totalExecutions++;
    this._executionStats.lastExecutedAt = getCurrentTimestamp();

    // Update metadata
    this.metadata.executionCount = this._executionStats.totalExecutions;
    this.metadata.updatedAt = getCurrentTimestamp();

    // Clear cached plan as it might need updating
    this._executionPlan = undefined;
  }

  /**
   * Record flow execution completion
   *
   * @param executionId - Execution identifier
   * @param success - Whether execution was successful
   * @param duration - Execution duration in seconds
   * @param stepResults - Step execution results
   */
  public recordExecutionCompletion(
    executionId: string,
    success: boolean,
    duration: number,
    stepResults?: StepResult[]
  ): void {
    if (success) {
      this._executionStats.successfulExecutions++;
      this._executionStats.lastSuccessfulExecutionAt = getCurrentTimestamp();
    } else {
      this._executionStats.failedExecutions++;
    }

    // Update timing statistics
    this._executionStats.averageExecutionTime =
      (this._executionStats.averageExecutionTime * (this._executionStats.totalExecutions - 1) + duration) /
      this._executionStats.totalExecutions;

    this._executionStats.fastestExecutionTime = Math.min(
      this._executionStats.fastestExecutionTime,
      duration
    );

    this._executionStats.slowestExecutionTime = Math.max(
      this._executionStats.slowestExecutionTime,
      duration
    );

    // Update success rate
    this._executionStats.successRate =
      this._executionStats.successfulExecutions / this._executionStats.totalExecutions;

    // Update step statistics
    if (stepResults) {
      this.updateStepStatistics(stepResults);
    }

    // Update metadata
    this.metadata.successRate = this._executionStats.successRate;
    this.metadata.updatedAt = getCurrentTimestamp();
  }

  /**
   * Update step execution statistics
   *
   * @param stepResults - Step execution results
   */
  private updateStepStatistics(stepResults: StepResult[]): void {
    for (const result of stepResults) {
      const existing = this._executionStats.stepStatistics.get(result.stepId) || {
        executions: 0,
        successes: 0,
        failures: 0,
        averageDuration: 0
      };

      existing.executions++;
      existing.lastExecutedAt = getCurrentTimestamp();

      if (result.status === 'completed') {
        existing.successes++;
        if (result.duration) {
          const durationInSeconds = result.duration / 1000;
          existing.averageDuration =
            (existing.averageDuration * (existing.executions - 1) + durationInSeconds) /
            existing.executions;
        }
      } else {
        existing.failures++;
      }

      this._executionStats.stepStatistics.set(result.stepId, existing);
    }
  }

  /**
   * Record execution error
   *
   * @param executionId - Execution identifier
   * @param error - Error information
   * @param stepId - Step ID where error occurred (optional)
   */
  public recordExecutionError(
    executionId: string,
    error: {
      message: string;
      code: string;
      stepId?: string;
    },
    stepId?: string
  ): void {
    const errorKey = `${error.code}:${error.stepId || 'flow'}`;
    const existing = this._executionStats.errorStatistics.get(errorKey) || {
      count: 0,
      lastOccurred: getCurrentTimestamp(),
      stepId: error.stepId
    };

    existing.count++;
    existing.lastOccurred = getCurrentTimestamp();

    this._executionStats.errorStatistics.set(errorKey, existing);
  }

  /**
   * Get comprehensive execution statistics
   *
   * @returns Flow statistics
   */
  public getExecutionStatistics(): FlowStatistics {
    return { ...this._executionStats };
  }

  /**
   * Reset execution statistics
   */
  public resetExecutionStatistics(): void {
    this._executionStats = {
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      averageExecutionTime: 0,
      fastestExecutionTime: Infinity,
      slowestExecutionTime: 0,
      successRate: 0,
      stepStatistics: new Map(),
      errorStatistics: new Map(),
      performanceTrends: {
        last7Days: [],
        last30Days: [],
        improvement: 0
      }
    };

    // Update metadata
    this.metadata.executionCount = 0;
    this.metadata.successRate = 0;
    this.metadata.updatedAt = getCurrentTimestamp();
  }

  // ========================================================================
  // Validation Methods
  // ========================================================================

  /**
   * Validate flow data
   *
   * @param data - Flow data to validate
   * @throws Error if validation fails
   */
  private validateFlowData(data: CreateFlowDefinitionRequest): void {
    // Validate name
    if (!data.name || typeof data.name !== 'string') {
      throw new Error('Flow name is required and must be a string');
    }

    const trimmedName = data.name.trim();
    if (trimmedName.length === 0) {
      throw new Error('Flow name cannot be empty');
    }

    if (trimmedName.length > MAX_FLOW_NAME_LENGTH) {
      throw new Error(`Flow name cannot exceed ${MAX_FLOW_NAME_LENGTH} characters`);
    }

    // Validate description
    if (data.description && data.description.length > MAX_FLOW_DESCRIPTION_LENGTH) {
      throw new Error(`Flow description cannot exceed ${MAX_FLOW_DESCRIPTION_LENGTH} characters`);
    }

    // Validate package name
    if (!data.packageName || typeof data.packageName !== 'string') {
      throw new Error('Package name is required and must be a string');
    }

    const trimmedPackage = data.packageName.trim();
    if (trimmedPackage.length === 0) {
      throw new Error('Package name cannot be empty');
    }

    // Validate Android package name format (basic validation)
    if (!trimmedPackage.match(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/)) {
      throw new Error('Invalid Android package name format');
    }

    // Validate steps
    if (!Array.isArray(data.steps)) {
      throw new Error('Steps must be an array');
    }

    if (data.steps.length === 0) {
      throw new Error('Flow must have at least one step');
    }

    if (data.steps.length > MAX_STEPS_PER_FLOW) {
      throw new Error(`Flow cannot have more than ${MAX_STEPS_PER_FLOW} steps`);
    }

    // Validate entry point
    if (!data.entryPoint) {
      throw new Error('Entry point is required');
    }

    // Validate complexity
    if (data.complexity !== undefined) {
      if (typeof data.complexity !== 'number' || data.complexity < 1 || data.complexity > 5) {
        throw new Error('Complexity must be a number between 1 and 5');
      }
    }

    // Validate estimated duration
    if (data.estimatedDuration !== undefined) {
      if (typeof data.estimatedDuration !== 'number' || data.estimatedDuration < 0) {
        throw new Error('Estimated duration must be a non-negative number');
      }
    }
  }

  /**
   * Process steps array
   *
   * @param steps - Steps to process
   * @returns Processed steps
   */
  private processSteps(steps: Omit<IFlowStep, 'id'>[]): FlowStep[] {
    return steps.map((stepData, index) => {
      if (stepData instanceof FlowStep) {
        return stepData;
      }

      try {
        return new FlowStep(stepData);
      } catch (error) {
        throw new Error(`Error processing step at index ${index}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });
  }

  /**
   * Process tags array
   *
   * @param tags - Tags to process
   * @returns Processed tags
   */
  private processTags(tags?: string[]): string[] | undefined {
    if (!tags) {
      return undefined;
    }

    if (!Array.isArray(tags)) {
      throw new Error('Tags must be an array');
    }

    const processedTags = tags
      .filter(tag => typeof tag === 'string')
      .map(tag => tag.trim())
      .filter(tag => tag.length > 0)
      .slice(0, MAX_TAGS_PER_FLOW);

    // Remove duplicates
    return Array.from(new Set(processedTags));
  }

  /**
   * Normalize configuration object
   *
   * @param config - Configuration to normalize
   * @returns Normalized configuration
   */
  private normalizeConfig(config?: Partial<FlowDefinition['config']>): FlowDefinition['config'] {
    const normalizedConfig: FlowDefinition['config'] = {
      defaultTimeout: DEFAULT_TIMEOUT,
      retryAttempts: DEFAULT_RETRY_ATTEMPTS,
      allowParallel: false,
      priority: DEFAULT_PRIORITY
    };

    if (!config) {
      return normalizedConfig;
    }

    // Validate and normalize default timeout
    if (config.defaultTimeout !== undefined) {
      if (typeof config.defaultTimeout !== 'number' || config.defaultTimeout < 1) {
        throw new Error('Default timeout must be a positive number');
      }
      normalizedConfig.defaultTimeout = Math.min(config.defaultTimeout, 300); // Max 5 minutes
    }

    // Validate and normalize retry attempts
    if (config.retryAttempts !== undefined) {
      if (typeof config.retryAttempts !== 'number' || config.retryAttempts < 0) {
        throw new Error('Retry attempts must be a non-negative number');
      }
      normalizedConfig.retryAttempts = Math.min(config.retryAttempts, 10);
    }

    // Validate allow parallel
    if (config.allowParallel !== undefined) {
      if (typeof config.allowParallel !== 'boolean') {
        throw new Error('Allow parallel must be a boolean');
      }
      normalizedConfig.allowParallel = config.allowParallel;
    }

    // Validate priority
    if (config.priority !== undefined) {
      const validPriorities: FlowPriority[] = ['low', 'medium', 'high'];
      if (!validPriorities.includes(config.priority)) {
        throw new Error(`Priority must be one of: ${validPriorities.join(', ')}`);
      }
      normalizedConfig.priority = config.priority;
    }

    return normalizedConfig;
  }

  /**
   * Validate the complete flow
   *
   * @throws Error if validation fails
   */
  private validate(): void {
    // Additional validation logic can be added here
    // For now, the constructor validation is sufficient
  }

  /**
   * Validate flow and return detailed result
   *
   * @param context - Validation context
   * @returns Validation result
   */
  public validate(context?: FlowValidationContext): ValidationResult {
    if (this._validationCache && !context?.strictMode) {
      return this._validationCache;
    }

    this._performanceData.lastValidationAt = getCurrentTimestamp();

    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    try {
      // Basic structure validation
      if (!this.id) {
        errors.push({
          field: 'id',
          message: 'Flow ID is required',
          code: 'MISSING_ID',
          severity: 'error'
        });
      }

      if (!this.name || typeof this.name !== 'string') {
        errors.push({
          field: 'name',
          message: 'Flow name is required and must be a string',
          code: 'MISSING_NAME',
          severity: 'error'
        });
      } else if (this.name.trim().length === 0) {
        errors.push({
          field: 'name',
          message: 'Flow name cannot be empty',
          code: 'EMPTY_NAME',
          severity: 'error'
        });
      }

      if (!this.packageName || typeof this.packageName !== 'string') {
        errors.push({
          field: 'packageName',
          message: 'Package name is required and must be a string',
          code: 'MISSING_PACKAGE',
          severity: 'error'
        });
      } else if (!this.packageName.match(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/)) {
        errors.push({
          field: 'packageName',
          message: 'Invalid Android package name format',
          code: 'INVALID_PACKAGE_FORMAT',
          severity: 'error'
        });
      }

      // Validate steps
      if (!Array.isArray(this.steps)) {
        errors.push({
          field: 'steps',
          message: 'Steps must be an array',
          code: 'INVALID_STEPS',
          severity: 'error'
        });
      } else {
        if (this.steps.length === 0) {
          errors.push({
            field: 'steps',
            message: 'Flow must have at least one step',
            code: 'EMPTY_STEPS',
            severity: 'error'
          });
        }

        if (context?.maxSteps && this.steps.length > context.maxSteps) {
          warnings.push({
            field: 'steps',
            message: `Flow has many steps (${this.steps.length} > ${context.maxSteps})`,
            code: 'MANY_STEPS',
            value: this.steps.length,
            severity: 'warning'
          });
        }

        // Validate individual steps
        this.steps.forEach((step, index) => {
          const stepValidation = step.validate({
            maxTimeout: context?.maxTimeout,
            maxRetryAttempts: context?.maxRetryAttempts,
            strictMode: context?.strictMode
          });

          if (!stepValidation.isValid) {
            errors.push(...stepValidation.errors.map(error => ({
              ...error,
              field: `steps[${index}].${error.field}`
            })));
          }

          warnings.push(...stepValidation.warnings.map(warning => ({
            ...warning,
            field: `steps[${index}].${warning.field}`
          })));
        });

        // Check for duplicate steps
        const stepHashes = new Set<string>();
        for (let i = 0; i < this.steps.length; i++) {
          const hash = this.steps[i].calculateHash();
          if (stepHashes.has(hash)) {
            warnings.push({
              field: `steps[${i}]`,
              message: 'Duplicate step detected',
              code: 'DUPLICATE_STEP',
              severity: 'warning'
            });
          }
          stepHashes.add(hash);
        }
      }

      // Validate entry point
      if (!this.entryPoint) {
        errors.push({
          field: 'entryPoint',
          message: 'Entry point is required',
          code: 'MISSING_ENTRY_POINT',
          severity: 'error'
        });
      } else {
        const entryValidation = this.entryPoint.validate();
        if (!entryValidation.isValid) {
          errors.push(...entryValidation.errors.map(error => ({
            ...error,
            field: `entryPoint.${error.field}`
          })));
        }
        warnings.push(...entryValidation.warnings.map(warning => ({
          ...warning,
          field: `entryPoint.${warning.field}`
        })));
      }

      // Validate exit point
      if (this.exitPoint) {
        const exitValidation = this.exitPoint.validate();
        if (!exitValidation.isValid) {
          errors.push(...exitValidation.errors.map(error => ({
            ...error,
            field: `exitPoint.${error.field}`
          })));
        }
        warnings.push(...exitValidation.warnings.map(warning => ({
          ...warning,
          field: `exitPoint.${warning.field}`
          })));
        }
      }

      // Validate configuration
      if (!this.config) {
        errors.push({
          field: 'config',
          message: 'Flow configuration is required',
          code: 'MISSING_CONFIG',
          severity: 'error'
        });
      } else {
        if (typeof this.config.defaultTimeout !== 'number' || this.config.defaultTimeout < 1) {
          errors.push({
            field: 'config.defaultTimeout',
            message: 'Default timeout must be a positive number',
            code: 'INVALID_DEFAULT_TIMEOUT',
            severity: 'error'
          });
        }

        if (typeof this.config.retryAttempts !== 'number' || this.config.retryAttempts < 0) {
          errors.push({
            field: 'config.retryAttempts',
            message: 'Retry attempts must be a non-negative number',
            code: 'INVALID_RETRY_ATTEMPTS',
            severity: 'error'
          });
        }

        if (typeof this.config.allowParallel !== 'boolean') {
          errors.push({
            field: 'config.allowParallel',
            message: 'Allow parallel must be a boolean',
            code: 'INVALID_ALLOW_PARALLEL',
            severity: 'error'
          });
        }

        const validPriorities: FlowPriority[] = ['low', 'medium', 'high'];
        if (!validPriorities.includes(this.config.priority)) {
          errors.push({
            field: 'config.priority',
            message: `Priority must be one of: ${validPriorities.join(', ')}`,
            code: 'INVALID_PRIORITY',
            severity: 'error'
          });
        }
      }

      // Validate metadata
      if (this.metadata) {
        if (this.metadata.complexity !== undefined &&
            (typeof this.metadata.complexity !== 'number' || this.metadata.complexity < 1 || this.metadata.complexity > 5)) {
          errors.push({
            field: 'metadata.complexity',
            message: 'Complexity must be a number between 1 and 5',
            code: 'INVALID_COMPLEXITY',
            severity: 'error'
          });
        }

        if (this.metadata.estimatedDuration !== undefined &&
            (typeof this.metadata.estimatedDuration !== 'number' || this.metadata.estimatedDuration < 0)) {
          errors.push({
            field: 'metadata.estimatedDuration',
            message: 'Estimated duration must be a non-negative number',
            code: 'INVALID_ESTIMATED_DURATION',
            severity: 'error'
          });
        }

        if (this.metadata.successRate !== undefined &&
            (typeof this.metadata.successRate !== 'number' || this.metadata.successRate < 0 || this.metadata.successRate > 1)) {
          errors.push({
            field: 'metadata.successRate',
            message: 'Success rate must be a number between 0 and 1',
            code: 'INVALID_SUCCESS_RATE',
            severity: 'error'
          });
        }
      }

      // Additional warnings
      if (this.steps.length > 10) {
        warnings.push({
          field: 'steps',
          message: 'Flow has many steps - consider breaking into smaller flows',
          code: 'LONG_FLOW',
          value: this.steps.length,
          severity: 'warning'
        });
      }

      if (!this.exitPoint) {
        warnings.push({
          field: 'exitPoint',
          message: 'No exit point defined - flow completion cannot be verified',
          code: 'NO_EXIT_POINT',
          severity: 'warning'
        });
      }

      const criticalSteps = this.steps.filter(step => step.critical);
      if (criticalSteps.length === 0) {
        warnings.push({
          field: 'steps',
          message: 'No critical steps defined - flow success may be difficult to verify',
          code: 'NO_CRITICAL_STEPS',
          severity: 'warning'
        });
      }

      const stepsWithoutPreconditions = this.steps.filter(step => step.preconditions.length === 0);
      if (stepsWithoutPreconditions.length > this.steps.length * 0.5) {
        warnings.push({
          field: 'steps',
          message: 'Many steps without preconditions may reduce reliability',
          code: 'MANY_STEPS_WITHOUT_PRECONDITIONS',
          value: stepsWithoutPreconditions.length,
          severity: 'warning'
        });
      }

    } catch (error) {
      errors.push({
        field: 'flow',
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
   * Calculate flow hash for comparison
   *
   * @returns Hash string
   */
  public calculateHash(): string {
    if (this._cachedHash) {
      return this._cachedHash;
    }

    const data = {
      name: this.name,
      description: this.description,
      packageName: this.packageName,
      steps: this.steps.map(step => step.toObject()),
      entryPoint: this.entryPoint.toObject(),
      exitPoint: this.exitPoint?.toObject(),
      config: this.config
    };

    this._cachedHash = hashObject(data);
    return this._cachedHash;
  }

  /**
   * Check if this flow is equivalent to another
   *
   * @param other - Other flow to compare
   * @returns True if flows are equivalent
   */
  public isEquivalentTo(other: FlowDefinition | IFlowDefinition): boolean {
    if (!(other instanceof FlowDefinition)) {
      other = FlowDefinition.fromExisting(other);
    }

    // Compare core fields
    return (
      this.name === other.name &&
      this.packageName === other.packageName &&
      this.steps.length === other.steps.length &&
      this.steps.every((step, i) => step.isEquivalentTo(other.steps[i])) &&
      this.entryPoint.isEquivalentTo(other.entryPoint) &&
      (this.exitPoint?.isEquivalentTo(other.exitPoint) || (!this.exitPoint && !other.exitPoint)) &&
      JSON.stringify(this.config) === JSON.stringify(other.config)
    );
  }

  /**
   * Calculate similarity with another flow
   *
   * @param other - Other flow to compare
   * @returns Comparison result
   */
  public compareWith(other: FlowDefinition | IFlowDefinition): FlowComparisonResult {
    if (!(other instanceof FlowDefinition)) {
      other = FlowDefinition.fromExisting(other);
    }

    const factors = {
      name: this.name === other.name,
      packageName: this.packageName === other.packageName,
      steps: this.compareSteps(this.steps, other.steps),
      entryPoint: this.entryPoint.isEquivalentTo(other.entryPoint),
      exitPoint: (this.exitPoint?.isEquivalentTo(other.exitPoint)) ||
                 (!this.exitPoint && !other.exitPoint),
      configuration: JSON.stringify(this.config) === JSON.stringify(other.config)
    };

    const matchingFactors = Object.values(factors).filter(Boolean).length;
    const totalFactors = Object.keys(factors).length;
    const similarity = matchingFactors / totalFactors;

    const differences: string[] = [];
    if (!factors.name) differences.push('name');
    if (!factors.packageName) differences.push('package name');
    if (!factors.steps) differences.push('steps');
    if (!factors.entryPoint) differences.push('entry point');
    if (!factors.exitPoint) differences.push('exit point');
    if (!factors.configuration) differences.push('configuration');

    // Step-by-step comparison
    const stepComparison = this.generateStepComparison(this.steps, other.steps);

    let recommendation: 'identical' | 'similar' | 'different' | 'conflict';
    if (similarity === 1.0) {
      recommendation = 'identical';
    } else if (similarity >= 0.8) {
      recommendation = 'similar';
    } else if (similarity >= 0.5) {
      recommendation = 'different';
    } else {
      recommendation = 'conflict';
    }

    return {
      similarity,
      factors,
      differences,
      stepComparison,
      recommendation
    };
  }

  /**
   * Compare step arrays
   *
   * @param steps1 - First step array
   * @param steps2 - Second step array
   * @returns Similarity score (0-1)
   */
  private compareSteps(steps1: FlowStep[], steps2: FlowStep[]): boolean {
    if (steps1.length !== steps2.length) {
      return false;
    }

    return steps1.every((step, index) => step.isEquivalentTo(steps2[index]));
  }

  /**
   * Generate step-by-step comparison
   *
   * @param steps1 - First step array
   * @param steps2 - Second step array
   * @returns Step comparison array
   */
  private generateStepComparison(
    steps1: FlowStep[],
    steps2: FlowStep[]
  ): Array<{
    step1Index?: number;
    step2Index?: number;
    similarity: number;
    action: string;
  }> {
    const comparison = [];
    const maxLength = Math.max(steps1.length, steps2.length);

    for (let i = 0; i < maxLength; i++) {
      const step1 = steps1[i];
      const step2 = steps2[i];

      if (step1 && step2) {
        const stepComp = step1.compareWith(step2);
        comparison.push({
          step1Index: i,
          step2Index: i,
          similarity: stepComp.similarity,
          action: step1.action.type
        });
      } else if (step1) {
        comparison.push({
          step1Index: i,
          similarity: 0,
          action: step1.action.type
        });
      } else if (step2) {
        comparison.push({
          step2Index: i,
          similarity: 0,
          action: step2.action.type
        });
      }
    }

    return comparison;
  }

  /**
   * Get flow complexity score
   *
   * @returns Complexity score (1-5, higher is more complex)
   */
  public getComplexityScore(): number {
    if (this.metadata?.complexity) {
      return this.metadata.complexity;
    }

    let score = 1;

    // Base score for step count
    score += Math.min(this.steps.length / 10, 2);

    // Add complexity for critical steps
    const criticalSteps = this.steps.filter(step => step.critical).length;
    score += Math.min(criticalSteps / 5, 1);

    // Add complexity for steps with preconditions
    const stepsWithPreconditions = this.steps.filter(step => step.preconditions.length > 0).length;
    score += Math.min(stepsWithPreconditions / 10, 0.5);

    // Add complexity for different action types
    const actionTypes = new Set(this.steps.map(step => step.action.type));
    score += Math.min(actionTypes.size / 6, 0.5);

    // Add complexity for exit point
    if (this.exitPoint) {
      score += 0.2;
    }

    // Add complexity for parallel execution
    if (this.config.allowParallel) {
      score += 0.3;
    }

    return Math.min(Math.round(score * 10) / 10, 5);
  }

  /**
   * Get a human-readable description of the flow
   *
   * @returns Description string
   */
  public getDescription(): string {
    const parts: string[] = [];

    parts.push(`Flow: ${this.name}`);
    parts.push(`Package: ${this.packageName}`);
    parts.push(`Steps: ${this.steps.length}`);

    if (this.description) {
      parts.push(`Description: ${this.description}`);
    }

    parts.push(`Entry: ${this.entryPoint.getDescription()}`);

    if (this.exitPoint) {
      parts.push(`Exit: ${this.exitPoint.getDescription()}`);
    }

    if (this.metadata?.estimatedDuration) {
      parts.push(`Est. Duration: ${this.metadata.estimatedDuration}s`);
    }

    parts.push(`Priority: ${this.config.priority}`);

    if (this.metadata?.tags && this.metadata.tags.length > 0) {
      parts.push(`Tags: [${this.metadata.tags.join(', ')}]`);
    }

    return parts.join(' | ');
  }

  /**
   * Convert flow to JSON string
   *
   * @returns JSON representation
   */
  public toJSON(): string {
    return JSON.stringify(this.toObject(), null, 2);
  }

  /**
   * Convert flow to plain object
   *
   * @returns Plain object representation
   */
  public toObject(): IFlowDefinition {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      version: this.version,
      packageName: this.packageName,
      steps: this.steps.map(step => step.toObject()),
      entryPoint: this.entryPoint.toObject(),
      exitPoint: this.exitPoint?.toObject(),
      metadata: { ...this.metadata },
      config: { ...this.config }
    };
  }

  /**
   * Create a copy of this flow with a new ID
   *
   * @param newName - Optional new name for the copy
   * @returns New FlowDefinition instance with unique ID
   */
  public clone(newName?: string): FlowDefinition {
    const cloneData = this.toObject();
    delete (cloneData as any).id;

    if (newName) {
      cloneData.name = newName;
    }

    // Reset execution statistics
    delete cloneData.metadata.executionCount;
    delete cloneData.metadata.successRate;

    return new FlowDefinition(cloneData);
  }

  /**
   * Update flow properties
   *
   * @param updates - Properties to update
   * @returns Updated flow instance
   */
  public update(updates: UpdateFlowDefinitionRequest): FlowDefinition {
    const currentData = this.toObject();
    const updatedData = { ...currentData, ...updates };
    return FlowDefinition.fromExisting(updatedData);
  }

  /**
   * Add a step to the flow
   *
   * @param step - Step to add
   * @param index - Optional position to insert at (default: end)
   * @returns Updated flow instance
   */
  public addStep(step: FlowStep | Omit<IFlowStep, 'id'>, index?: number): FlowDefinition {
    const stepInstance = step instanceof FlowStep ? step : new FlowStep(step);
    const newSteps = [...this.steps];

    if (index !== undefined && index >= 0 && index <= this.steps.length) {
      newSteps.splice(index, 0, stepInstance);
    } else {
      newSteps.push(stepInstance);
    }

    return this.update({ steps: newSteps.map(s => s.toObject()) });
  }

  /**
   * Remove a step from the flow
   *
   * @param stepId - ID of step to remove
   * @returns Updated flow instance
   */
  public removeStep(stepId: string): FlowDefinition {
    const newSteps = this.steps.filter(step => step.id !== stepId);
    return this.update({ steps: newSteps.map(s => s.toObject()) });
  }

  /**
   * Reorder steps in the flow
   *
   * @param stepIds - New order of step IDs
   * @returns Updated flow instance
   */
  public reorderSteps(stepIds: string[]): FlowDefinition {
    const stepMap = new Map(this.steps.map(step => [step.id, step]));
    const newSteps: FlowStep[] = [];

    for (const stepId of stepIds) {
      const step = stepMap.get(stepId);
      if (step) {
        newSteps.push(step);
      }
    }

    // Add any steps not included in the new order
    for (const step of this.steps) {
      if (!stepIds.includes(step.id)) {
        newSteps.push(step);
      }
    }

    return this.update({ steps: newSteps.map(s => s.toObject()) });
  }

  /**
   * Get performance metrics
   *
   * @returns Performance metrics
   */
  public getPerformanceMetrics(): {
    validationCache: {
      hits: number;
      misses: number;
      lastValidation?: ISOTimestamp;
    };
    planCache: {
      hits: number;
      misses: number;
      lastPlanGeneration?: ISOTimestamp;
    };
  } {
    return {
      validationCache: {
        hits: this._validationCache ? 1 : 0,
        misses: this._validationCache ? 0 : 1,
        lastValidation: this._performanceData.lastValidationAt
      },
      planCache: {
        hits: this._performanceData.cacheHits,
        misses: this._performanceData.cacheMisses,
        lastPlanGeneration: this._performanceData.lastPlanGenerationAt
      }
    };
  }
}

// ============================================================================
// Factory Functions and Utilities
// ============================================================================

/**
 * Factory functions for creating common flow definitions
 */
export const FlowDefinitionFactory = {
  /** Create simple flow */
  createSimple: FlowDefinition.createSimple,

  /** Create flow from template */
  fromTemplate: FlowDefinition.fromTemplate,

  /**
   * Create a linear flow from a sequence of actions
   *
   * @param name - Flow name
   * @param packageName - Target package
   * @param actions - Array of action descriptions
   * @returns Linear flow definition
   */
  createLinear(
    name: string,
    packageName: string,
    actions: Array<{
      name: string;
      description: string;
      critical?: boolean;
    }>
  ): FlowDefinition {
    const steps = actions.map((action, index) => {
      // Create a step from action description
      const step = FlowStepFactory.fromDescription(
        action.name,
        action.description,
        // Add simple precondition for subsequent steps
        index > 0 ? [StatePredicate.textContent(['previous step completed'])] : undefined
      );

      if (action.critical) {
        step.critical = true;
      }

      return step;
    });

    return new FlowDefinition({
      name,
      packageName,
      steps,
      entryPoint: StatePredicate.activity(packageName, 'exact')
    });
  },

  /**
   * Create a conditional flow with branches
   *
   * @param name - Flow name
   * @param packageName - Target package
   * @param branches - Flow branches
   * @returns Conditional flow definition
   */
  createConditional(
    name: string,
    packageName: string,
    branches: Array<{
      condition: IStatePredicate;
      steps: Omit<IFlowStep, 'id'>[];
      name: string;
    }>
  ): FlowDefinition {
    // This is a simplified implementation
    // In a more sophisticated version, this would create proper branching logic
    const allSteps: Omit<IFlowStep, 'id'>[] = [];

    for (const branch of branches) {
      const branchSteps = branch.steps.map(step => ({
        ...step,
        preconditions: [branch.condition, ...(step.preconditions || [])]
      }));
      allSteps.push(...branchSteps);
    }

    return new FlowDefinition({
      name,
      packageName,
      steps: allSteps,
      entryPoint: StatePredicate.activity(packageName, 'exact')
    });
  }
};

/**
 * Utility functions for flow definition operations
 */
export const FlowDefinitionUtils = {
  /**
   * Sort flows by priority
   *
   * @param flows - Flows to sort
   * @returns Sorted flows
   */
  sortByPriority(flows: FlowDefinition[]): FlowDefinition[] {
    const priorityOrder = { high: 3, medium: 2, low: 1 };
    return [...flows].sort((a, b) =>
      priorityOrder[b.config.priority] - priorityOrder[a.config.priority]
    );
  },

  /**
   * Filter flows by package
   *
   * @param flows - Flows to filter
   * @param packageName - Package name to filter by
   * @returns Filtered flows
   */
  filterByPackage(flows: FlowDefinition[], packageName: string): FlowDefinition[] {
    return flows.filter(flow => flow.packageName === packageName);
  },

  /**
   * Filter flows by tag
   *
   * @param flows - Flows to filter
   * @param tag - Tag to filter by
   * @returns Filtered flows
   */
  filterByTag(flows: FlowDefinition[], tag: string): FlowDefinition[] {
    return flows.filter(flow =>
      flow.metadata.tags?.includes(tag)
    );
  },

  /**
   * Group flows by package
   *
   * @param flows - Flows to group
   * @returns Map of package name to flows
   */
  groupByPackage(flows: FlowDefinition[]): Map<string, FlowDefinition[]> {
    const groups = new Map<string, FlowDefinition[]>();

    for (const flow of flows) {
      const packageName = flow.packageName;
      if (!groups.has(packageName)) {
        groups.set(packageName, []);
      }
      groups.get(packageName)!.push(flow);
    }

    return groups;
  },

  /**
   * Find duplicate flows in an array
   *
   * @param flows - Flows to check
   * @returns Array of duplicate flow groups
   */
  findDuplicateFlows(flows: FlowDefinition[]): FlowDefinition[][] {
    const hashMap = new Map<string, FlowDefinition[]>();

    for (const flow of flows) {
      const hash = flow.calculateHash();
      if (!hashMap.has(hash)) {
        hashMap.set(hash, []);
      }
      hashMap.get(hash)!.push(flow);
    }

    return Array.from(hashMap.values()).filter(group => group.length > 1);
  },

  /**
   * Calculate total estimated duration for multiple flows
   *
   * @param flows - Flows to calculate for
   * @returns Total estimated duration in seconds
   */
  calculateTotalDuration(flows: FlowDefinition[]): number {
    return flows.reduce((total, flow) => total + flow.calculateEstimatedDuration(), 0);
  },

  /**
   * Get flows by complexity range
   *
   * @param flows - Flows to filter
   * @param minComplexity - Minimum complexity (inclusive)
   * @param maxComplexity - Maximum complexity (inclusive)
   * @returns Filtered flows
   */
  filterByComplexity(
    flows: FlowDefinition[],
    minComplexity: number = 1,
    maxComplexity: number = 5
  ): FlowDefinition[] {
    return flows.filter(flow => {
      const complexity = flow.getComplexityScore();
      return complexity >= minComplexity && complexity <= maxComplexity;
    });
  }
};

// ============================================================================
// Exports
// ============================================================================

export default FlowDefinition;