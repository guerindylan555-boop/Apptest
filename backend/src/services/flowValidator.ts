/**
 * AutoApp UI Map & Intelligent Flow Engine - Flow Validation Service
 *
 * Comprehensive flow definition validation and predicate resolution service.
 * Implements multi-level validation with structural, semantic, execution,
 * security, and integration validation capabilities.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md and task T044 requirements.
 */

import { EventEmitter } from 'events';
import { performance } from 'perf_hooks';
import {
  FlowDefinition,
  FlowStep,
  StatePredicate,
  ValidationResult,
  ValidationError,
  ValidationWarning,
  FlowDefinition as IFlowDefinition,
  FlowStep as IFlowStep,
  StatePredicate as IStatePredicate,
  UUID,
  ISOTimestamp,
  ExecutionStatus,
  StepResult
} from '../types/models';

import { UIGraph, StateRecord } from '../types/graph';
import { GraphService } from './graphService';
import { hashObject } from '../utils/crypto';

// ============================================================================
// Configuration and Constants
// ============================================================================

/** Maximum validation time per flow (ms) */
const MAX_VALIDATION_TIME = 5000;

/** Maximum number of states to cache for predicate resolution */
const MAX_CACHED_STATES = 1000;

/** Default confidence threshold for predicate resolution */
const DEFAULT_CONFIDENCE_THRESHOLD = 0.7;

/** Cache TTL for validation results (ms) */
const VALIDATION_CACHE_TTL = 300000; // 5 minutes

/** Cache TTL for predicate resolution (ms) */
const PREDICATE_CACHE_TTL = 600000; // 10 minutes

/** Performance impact thresholds */
const PERFORMANCE_THRESHOLDS = {
  FAST_VALIDATION: 2000, // <2s for ≤50 states/100 transitions
  MEDIUM_VALIDATION: 5000, // <5s for ≤200 states/500 transitions
  SLOW_VALIDATION: 10000 // <10s for larger flows
};

// ============================================================================
// Validation Types and Interfaces
// ============================================================================

/**
 * Validation severity levels
 */
export type ValidationSeverity = 'info' | 'warning' | 'error' | 'critical';

/**
 * Validation categories
 */
export type ValidationCategory =
  | 'structural'
  | 'semantic'
  | 'execution'
  | 'security'
  | 'integration'
  | 'performance';

/**
 * Comprehensive validation context
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
  availableStates?: StateRecord[];

  /** Validate action compatibility */
  validateActions?: boolean;

  /** Enable performance analysis */
  analyzePerformance?: boolean;

  /** Enable security checks */
  checkSecurity?: boolean;

  /** Enable integration validation */
  validateIntegration?: boolean;

  /** Confidence threshold for predicate resolution */
  confidenceThreshold?: number;

  /** Enable detailed logging */
  enableDetailedLogging?: boolean;

  /** Cache results */
  enableCaching?: boolean;
}

/**
 * Comprehensive validation result
 */
export interface ComprehensiveValidationResult extends ValidationResult {
  /** Validation category results */
  categoryResults: {
    structural: ValidationResult;
    semantic: ValidationResult;
    execution: ValidationResult;
    security: ValidationResult;
    integration: ValidationResult;
  };

  /** Performance metrics */
  performance: {
    totalTime: number;
    structuralTime: number;
    semanticTime: number;
    executionTime: number;
    securityTime: number;
    integrationTime: number;
    impact: 'low' | 'medium' | 'high';
    complexity: number;
    reliability: number;
  };

  /** Predicate resolution results */
  predicateResolutions: Array<{
    predicate: IStatePredicate;
    resolved: boolean;
    confidence: number;
    matchingStates: StateRecord[];
    resolutionTime: number;
  }>;

  /** Flow analysis results */
  analysis: {
    stepCount: number;
    criticalSteps: number;
    conditionalSteps: number;
    averageStepComplexity: number;
    estimatedDuration: number;
    riskFactors: string[];
    suggestions: string[];
  };

  /** Validation metadata */
  metadata: {
    validatedAt: ISOTimestamp;
    validatorVersion: string;
    cacheHit: boolean;
    context: FlowValidationContext;
  };
}

/**
 * Validation error with enhanced information
 */
export interface EnhancedValidationError extends ValidationError {
  /** Validation category */
  category: ValidationCategory;

  /** Severity level */
  severity: ValidationSeverity;

  /** Step index (if applicable) */
  stepIndex?: number;

  /** Predicate type (if applicable) */
  predicateType?: string;

  /** Action type (if applicable) */
  actionType?: string;

  /** Fix suggestions */
  suggestions?: string[];

  /** Related errors/warnings */
  relatedIssues?: string[];

  /** Performance impact */
  performanceImpact?: 'low' | 'medium' | 'high';
}

/**
 * Validation warning with enhanced information
 */
export interface EnhancedValidationWarning extends ValidationWarning {
  /** Validation category */
  category: ValidationCategory;

  /** Severity level */
  severity: ValidationSeverity;

  /** Step index (if applicable) */
  stepIndex?: number;

  /** Fix suggestions */
  suggestions?: string[];

  /** Performance impact */
  performanceImpact?: 'low' | 'medium' | 'high';
}

/**
 * Cache entry for validation results
 */
interface ValidationCacheEntry {
  result: ComprehensiveValidationResult;
  timestamp: number;
  flowHash: string;
  contextHash: string;
}

/**
 * Cache entry for predicate resolution
 */
interface PredicateResolutionCacheEntry {
  resolution: {
    resolved: boolean;
    confidence: number;
    matchingStates: StateRecord[];
  };
  timestamp: number;
  predicateHash: string;
}

// ============================================================================
// Flow Validator Class
// ============================================================================

/**
 * Comprehensive flow validation service
 *
 * This service provides multi-level validation for flow definitions including
 * structural validation, semantic validation with predicate resolution,
 * execution validation with performance analysis, security validation,
 * and integration validation with graph states.
 */
export class FlowValidator extends EventEmitter {
  private graphService: GraphService;
  private validationCache: Map<string, ValidationCacheEntry> = new Map();
  private predicateCache: Map<string, PredicateResolutionCacheEntry> = new Map();
  private metrics = {
    totalValidations: 0,
    cacheHits: 0,
    averageValidationTime: 0,
    validationsByCategory: {
      structural: 0,
      semantic: 0,
      execution: 0,
      security: 0,
      integration: 0
    }
  };

  /**
   * Create a new FlowValidator instance
   *
   * @param graphService - Graph service for state resolution
   */
  constructor(graphService: GraphService) {
    super();
    this.graphService = graphService;

    // Setup periodic cache cleanup
    setInterval(() => this.cleanupCache(), VALIDATION_CACHE_TTL);
  }

  // ============================================================================
  // Main Validation Methods
  // ============================================================================

  /**
   * Validate a flow definition comprehensively
   *
   * @param flow - Flow definition to validate
   * @param context - Validation context
   * @returns Comprehensive validation result
   */
  public async validateFlow(
    flow: FlowDefinition | IFlowDefinition,
    context: FlowValidationContext = {}
  ): Promise<ComprehensiveValidationResult> {
    const startTime = performance.now();

    try {
      // Convert to FlowDefinition if needed
      const flowInstance = flow instanceof FlowDefinition
        ? flow
        : FlowDefinition.fromExisting(flow);

      // Check cache first
      if (context.enableCaching !== false) {
        const cachedResult = this.getCachedValidation(flowInstance, context);
        if (cachedResult) {
          this.metrics.cacheHits++;
          this.emit('validation-cache-hit', { flowId: flowInstance.id });
          return cachedResult;
        }
      }

      this.metrics.totalValidations++;
      this.emit('validation-started', { flowId: flowInstance.id, context });

      // Initialize category results
      const categoryResults = {
        structural: { isValid: true, errors: [], warnings: [] },
        semantic: { isValid: true, errors: [], warnings: [] },
        execution: { isValid: true, errors: [], warnings: [] },
        security: { isValid: true, errors: [], warnings: [] },
        integration: { isValid: true, errors: [], warnings: [] }
      };

      let structuralTime = 0, semanticTime = 0, executionTime = 0;
      let securityTime = 0, integrationTime = 0;

      // 1. Structural Validation
      if (context.enableDetailedLogging) {
        console.log(`[FlowValidator] Starting structural validation for flow ${flowInstance.id}`);
      }

      const structuralStart = performance.now();
      categoryResults.structural = await this.validateStructural(flowInstance, context);
      structuralTime = performance.now() - structuralStart;

      // 2. Semantic Validation (only if structural validation passes)
      if (categoryResults.structural.isValid) {
        if (context.enableDetailedLogging) {
          console.log(`[FlowValidator] Starting semantic validation for flow ${flowInstance.id}`);
        }

        const semanticStart = performance.now();
        categoryResults.semantic = await this.validateSemantic(flowInstance, context);
        semanticTime = performance.now() - semanticStart;
      }

      // 3. Execution Validation
      if (context.enableDetailedLogging) {
        console.log(`[FlowValidator] Starting execution validation for flow ${flowInstance.id}`);
      }

      const executionStart = performance.now();
      categoryResults.execution = await this.validateExecution(flowInstance, context);
      executionTime = performance.now() - executionStart;

      // 4. Security Validation
      if (context.checkSecurity !== false) {
        if (context.enableDetailedLogging) {
          console.log(`[FlowValidator] Starting security validation for flow ${flowInstance.id}`);
        }

        const securityStart = performance.now();
        categoryResults.security = await this.validateSecurity(flowInstance, context);
        securityTime = performance.now() - securityStart;
      }

      // 5. Integration Validation
      if (context.validateIntegration !== false) {
        if (context.enableDetailedLogging) {
          console.log(`[FlowValidator] Starting integration validation for flow ${flowInstance.id}`);
        }

        const integrationStart = performance.now();
        categoryResults.integration = await this.validateIntegration(flowInstance, context);
        integrationTime = performance.now() - integrationStart;
      }

      // Resolve predicates
      const predicateStart = performance.now();
      const predicateResolutions = await this.resolvePredicates(flowInstance, context);
      const predicateTime = performance.now() - predicateStart;

      // Analyze flow
      const analysis = this.analyzeFlow(flowInstance, categoryResults);

      // Calculate performance metrics
      const totalTime = performance.now() - startTime;
      const performance = {
        totalTime,
        structuralTime,
        semanticTime,
        executionTime,
        securityTime,
        integrationTime,
        impact: this.calculatePerformanceImpact(totalTime, flowInstance),
        complexity: analysis.stepCount * analysis.averageStepComplexity,
        reliability: this.calculateReliability(categoryResults)
      };

      // Combine all errors and warnings
      const allErrors = [
        ...categoryResults.structural.errors,
        ...categoryResults.semantic.errors,
        ...categoryResults.execution.errors,
        ...categoryResults.security.errors,
        ...categoryResults.integration.errors
      ];

      const allWarnings = [
        ...categoryResults.structural.warnings,
        ...categoryResults.semantic.warnings,
        ...categoryResults.execution.warnings,
        ...categoryResults.security.warnings,
        ...categoryResults.integration.warnings
      ];

      const result: ComprehensiveValidationResult = {
        isValid: allErrors.length === 0,
        errors: allErrors,
        warnings: allWarnings,
        categoryResults,
        performance,
        predicateResolutions,
        analysis,
        metadata: {
          validatedAt: new Date().toISOString(),
          validatorVersion: '1.0.0',
          cacheHit: false,
          context
        }
      };

      // Cache the result
      if (context.enableCaching !== false) {
        this.cacheValidation(flowInstance, context, result);
      }

      // Update metrics
      this.updateMetrics(totalTime);

      this.emit('validation-completed', {
        flowId: flowInstance.id,
        result,
        duration: totalTime
      });

      return result;

    } catch (error) {
      const totalTime = performance.now() - startTime;

      this.emit('validation-error', {
        flowId: flow.id,
        error,
        duration: totalTime
      });

      // Return error result
      return {
        isValid: false,
        errors: [{
          field: 'validation',
          message: `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          code: 'VALIDATION_FAILED',
          severity: 'critical',
          category: 'structural',
          suggestions: ['Check flow definition and try again']
        }],
        warnings: [],
        categoryResults: {
          structural: { isValid: false, errors: [], warnings: [] },
          semantic: { isValid: true, errors: [], warnings: [] },
          execution: { isValid: true, errors: [], warnings: [] },
          security: { isValid: true, errors: [], warnings: [] },
          integration: { isValid: true, errors: [], warnings: [] }
        },
        performance: {
          totalTime,
          structuralTime: 0,
          semanticTime: 0,
          executionTime: 0,
          securityTime: 0,
          integrationTime: 0,
          impact: 'high',
          complexity: 0,
          reliability: 0
        },
        predicateResolutions: [],
        analysis: {
          stepCount: 0,
          criticalSteps: 0,
          conditionalSteps: 0,
          averageStepComplexity: 0,
          estimatedDuration: 0,
          riskFactors: ['Validation failed'],
          suggestions: ['Fix validation errors']
        },
        metadata: {
          validatedAt: new Date().toISOString(),
          validatorVersion: '1.0.0',
          cacheHit: false,
          context
        }
      };
    }
  }

  /**
   * Validate multiple flows in batch
   *
   * @param flows - Array of flow definitions to validate
   * @param context - Validation context
   * @returns Array of validation results
   */
  public async validateFlowsBatch(
    flows: (FlowDefinition | IFlowDefinition)[],
    context: FlowValidationContext = {}
  ): Promise<ComprehensiveValidationResult[]> {
    const startTime = performance.now();

    this.emit('batch-validation-started', {
      flowCount: flows.length,
      context
    });

    const results: ComprehensiveValidationResult[] = [];

    // Process flows in parallel with concurrency limit
    const concurrencyLimit = 5;
    for (let i = 0; i < flows.length; i += concurrencyLimit) {
      const batch = flows.slice(i, i + concurrencyLimit);
      const batchPromises = batch.map(flow =>
        this.validateFlow(flow, context)
      );

      const batchResults = await Promise.all(batchPromises);
      results.push(...batchResults);

      // Emit progress
      this.emit('batch-validation-progress', {
        completed: Math.min(i + concurrencyLimit, flows.length),
        total: flows.length,
        progress: Math.min((i + concurrencyLimit) / flows.length, 1)
      });
    }

    const totalTime = performance.now() - startTime;

    this.emit('batch-validation-completed', {
      flowCount: flows.length,
      results,
      duration: totalTime
    });

    return results;
  }

  // ============================================================================
  // Structural Validation
  // ============================================================================

  /**
   * Validate flow structure and basic requirements
   *
   * @param flow - Flow definition to validate
   * @param context - Validation context
   * @returns Structural validation result
   */
  private async validateStructural(
    flow: FlowDefinition,
    context: FlowValidationContext
  ): Promise<ValidationResult> {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    // Basic structure validation
    if (!flow.id) {
      errors.push({
        field: 'id',
        message: 'Flow ID is required',
        code: 'MISSING_ID',
        severity: 'critical',
        category: 'structural',
        suggestions: ['Ensure flow has a valid ID']
      });
    }

    if (!flow.name || typeof flow.name !== 'string' || flow.name.trim().length === 0) {
      errors.push({
        field: 'name',
        message: 'Flow name is required and must be a non-empty string',
        code: 'MISSING_NAME',
        severity: 'critical',
        category: 'structural',
        suggestions: ['Provide a descriptive name for the flow']
      });
    } else if (flow.name.length > 200) {
      warnings.push({
        field: 'name',
        message: 'Flow name is very long and may impact readability',
        code: 'LONG_NAME',
        severity: 'warning',
        category: 'structural',
        value: flow.name.length,
        suggestions: ['Consider using a shorter, more descriptive name']
      });
    }

    if (!flow.packageName || typeof flow.packageName !== 'string') {
      errors.push({
        field: 'packageName',
        message: 'Package name is required and must be a string',
        code: 'MISSING_PACKAGE',
        severity: 'critical',
        category: 'structural',
        suggestions: ['Specify the target Android package name']
      });
    } else if (!flow.packageName.match(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/)) {
      errors.push({
        field: 'packageName',
        message: 'Invalid Android package name format',
        code: 'INVALID_PACKAGE_FORMAT',
        severity: 'error',
        category: 'structural',
        suggestions: ['Use standard Java package naming (e.g., com.example.app)']
      });
    }

    // Steps validation
    if (!flow.steps || !Array.isArray(flow.steps)) {
      errors.push({
        field: 'steps',
        message: 'Steps must be an array',
        code: 'INVALID_STEPS',
        severity: 'critical',
        category: 'structural',
        suggestions: ['Ensure flow has a valid steps array']
      });
    } else if (flow.steps.length === 0) {
      errors.push({
        field: 'steps',
        message: 'Flow must have at least one step',
        code: 'EMPTY_STEPS',
        severity: 'critical',
        category: 'structural',
        suggestions: ['Add at least one step to the flow']
      });
    } else if (context.maxSteps && flow.steps.length > context.maxSteps) {
      warnings.push({
        field: 'steps',
        message: `Flow has many steps (${flow.steps.length} > ${context.maxSteps})`,
        code: 'MANY_STEPS',
        severity: 'warning',
        category: 'structural',
        value: flow.steps.length,
        suggestions: ['Consider breaking into smaller, focused flows'],
        performanceImpact: 'medium'
      });
    }

    // Validate individual steps
    if (flow.steps) {
      for (let i = 0; i < flow.steps.length; i++) {
        const step = flow.steps[i];
        const stepValidation = this.validateStepStructure(step, i, context);

        errors.push(...stepValidation.errors);
        warnings.push(...stepValidation.warnings);
      }

      // Check for duplicate steps
      const stepHashes = new Set<string>();
      for (let i = 0; i < flow.steps.length; i++) {
        const hash = this.calculateStepHash(flow.steps[i]);
        if (stepHashes.has(hash)) {
          warnings.push({
            field: `steps[${i}]`,
            message: 'Duplicate step detected',
            code: 'DUPLICATE_STEP',
            severity: 'warning',
            category: 'structural',
            stepIndex: i,
            suggestions: ['Remove or modify duplicate steps']
          });
        }
        stepHashes.add(hash);
      }
    }

    // Entry point validation
    if (!flow.entryPoint) {
      errors.push({
        field: 'entryPoint',
        message: 'Entry point is required',
        code: 'MISSING_ENTRY_POINT',
        severity: 'critical',
        category: 'structural',
        suggestions: ['Define an entry point predicate for the flow']
      });
    } else {
      const entryValidation = this.validatePredicateStructure(flow.entryPoint, 'entryPoint', context);
      errors.push(...entryValidation.errors);
      warnings.push(...entryValidation.warnings);
    }

    // Exit point validation
    if (flow.exitPoint) {
      const exitValidation = this.validatePredicateStructure(flow.exitPoint, 'exitPoint', context);
      errors.push(...exitValidation.errors);
      warnings.push(...exitValidation.warnings);
    }

    // Configuration validation
    if (!flow.config) {
      errors.push({
        field: 'config',
        message: 'Flow configuration is required',
        code: 'MISSING_CONFIG',
        severity: 'error',
        category: 'structural',
        suggestions: ['Provide flow configuration with timeout and retry settings']
      });
    } else {
      const configValidation = this.validateConfigStructure(flow.config, context);
      errors.push(...configValidation.errors);
      warnings.push(...configValidation.warnings);
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate step structure
   *
   * @param step - Step to validate
   * @param index - Step index
   * @param context - Validation context
   * @returns Step validation result
   */
  private validateStepStructure(
    step: FlowStep,
    index: number,
    context: FlowValidationContext
  ): { errors: EnhancedValidationError[], warnings: EnhancedValidationWarning[] } {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    if (!step.id) {
      errors.push({
        field: `steps[${index}].id`,
        message: `Step ${index + 1} missing ID`,
        code: 'MISSING_STEP_ID',
        severity: 'critical',
        category: 'structural',
        stepIndex: index,
        suggestions: ['Add a unique ID to the step']
      });
    }

    if (!step.name || typeof step.name !== 'string' || step.name.trim().length === 0) {
      errors.push({
        field: `steps[${index}].name`,
        message: `Step ${index + 1} missing name`,
        code: 'MISSING_STEP_NAME',
        severity: 'critical',
        category: 'structural',
        stepIndex: index,
        suggestions: ['Provide a descriptive name for the step']
      });
    }

    if (!step.action) {
      errors.push({
        field: `steps[${index}].action`,
        message: `Step ${index + 1} missing action`,
        code: 'MISSING_STEP_ACTION',
        severity: 'critical',
        category: 'structural',
        stepIndex: index,
        suggestions: ['Define an action for the step']
      });
    } else {
      const actionValidation = this.validateActionStructure(step.action, index, context);
      errors.push(...actionValidation.errors);
      warnings.push(...actionValidation.warnings);
    }

    if (!step.preconditions || !Array.isArray(step.preconditions)) {
      errors.push({
        field: `steps[${index}].preconditions`,
        message: `Step ${index + 1} preconditions must be an array`,
        code: 'INVALID_PRECONDITIONS',
        severity: 'error',
        category: 'structural',
        stepIndex: index,
        suggestions: ['Ensure preconditions is a valid array']
      });
    } else if (context.maxRetryAttempts && step.preconditions.length > context.maxRetryAttempts) {
      warnings.push({
        field: `steps[${index}].preconditions`,
        message: `Step ${index + 1} has many preconditions (${step.preconditions.length})`,
        code: 'MANY_PRECONDITIONS',
        severity: 'warning',
        category: 'structural',
        stepIndex: index,
        value: step.preconditions.length,
        suggestions: ['Consider reducing preconditions for better reliability']
      });
    } else if (step.preconditions.length === 0) {
      warnings.push({
        field: `steps[${index}].preconditions`,
        message: `Step ${index + 1} has no preconditions`,
        code: 'NO_PRECONDITIONS',
        severity: 'warning',
        category: 'structural',
        stepIndex: index,
        suggestions: ['Add preconditions to ensure step executes in correct context']
      });
    }

    if (step.expectedState) {
      const expectedStateValidation = this.validatePredicateStructure(
        step.expectedState,
        `steps[${index}].expectedState`,
        context
      );
      errors.push(...expectedStateValidation.errors);
      warnings.push(...expectedStateValidation.warnings);
    }

    if (typeof step.timeout !== 'number' || step.timeout < 0) {
      errors.push({
        field: `steps[${index}].timeout`,
        message: `Step ${index + 1} timeout must be a non-negative number`,
        code: 'INVALID_TIMEOUT',
        severity: 'error',
        category: 'structural',
        stepIndex: index,
        suggestions: ['Set a reasonable timeout value in seconds']
      });
    } else if (context.maxTimeout && step.timeout > context.maxTimeout) {
      warnings.push({
        field: `steps[${index}].timeout`,
        message: `Step ${index + 1} timeout exceeds maximum (${step.timeout}s > ${context.maxTimeout}s)`,
        code: 'TIMEOUT_EXCEEDS_MAXIMUM',
        severity: 'warning',
        category: 'structural',
        stepIndex: index,
        value: step.timeout,
        suggestions: ['Consider reducing timeout or breaking down into smaller steps'],
        performanceImpact: 'medium'
      });
    }

    return { errors, warnings };
  }

  /**
   * Validate action structure
   *
   * @param action - Action to validate
   * @param stepIndex - Parent step index
   * @param context - Validation context
   * @returns Action validation result
   */
  private validateActionStructure(
    action: any,
    stepIndex: number,
    context: FlowValidationContext
  ): { errors: EnhancedValidationError[], warnings: EnhancedValidationWarning[] } {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    const validTypes = ['tap', 'type', 'swipe', 'back', 'intent', 'long_press'];

    if (!action.type) {
      errors.push({
        field: `steps[${stepIndex}].action.type`,
        message: 'Action type is required',
        code: 'MISSING_ACTION_TYPE',
        severity: 'critical',
        category: 'structural',
        stepIndex,
        actionType: action.type,
        suggestions: ['Specify a valid action type']
      });
    } else if (!validTypes.includes(action.type)) {
      errors.push({
        field: `steps[${stepIndex}].action.type`,
        message: `Invalid action type: ${action.type}`,
        code: 'INVALID_ACTION_TYPE',
        severity: 'error',
        category: 'structural',
        stepIndex,
        actionType: action.type,
        suggestions: [`Use one of: ${validTypes.join(', ')}`]
      });
    }

    // Type-specific validation
    switch (action.type) {
      case 'tap':
      case 'type':
      case 'long_press':
        if (!action.target) {
          warnings.push({
            field: `steps[${stepIndex}].action.target`,
            message: `${action.type} action without target selector may be unreliable`,
            code: 'NO_TARGET_SELECTOR',
            severity: 'warning',
            category: 'structural',
            stepIndex,
            actionType: action.type,
            suggestions: ['Add target selector for better reliability']
          });
        }
        break;

      case 'type':
        if (!action.text) {
          errors.push({
            field: `steps[${stepIndex}].action.text`,
            message: 'Type action requires text',
            code: 'MISSING_TYPE_TEXT',
            severity: 'error',
            category: 'structural',
            stepIndex,
            actionType: action.type,
            suggestions: ['Specify the text to type']
          });
        }
        break;

      case 'swipe':
        if (!action.swipe) {
          errors.push({
            field: `steps[${stepIndex}].action.swipe`,
            message: 'Swipe action requires swipe configuration',
            code: 'MISSING_SWIPE_CONFIG',
            severity: 'error',
            category: 'structural',
            stepIndex,
            actionType: action.type,
            suggestions: ['Provide swipe direction and distance']
          });
        } else {
          if (!action.swipe.direction || !['up', 'down', 'left', 'right'].includes(action.swipe.direction)) {
            errors.push({
              field: `steps[${stepIndex}].action.swipe.direction`,
              message: 'Invalid swipe direction',
              code: 'INVALID_SWIPE_DIRECTION',
              severity: 'error',
              category: 'structural',
              stepIndex,
              actionType: action.type,
              suggestions: ['Use one of: up, down, left, right']
            });
          }

          if (typeof action.swipe.distance !== 'number' || action.swipe.distance < 0 || action.swipe.distance > 1) {
            errors.push({
              field: `steps[${stepIndex}].action.swipe.distance`,
              message: 'Swipe distance must be a number between 0 and 1',
              code: 'INVALID_SWIPE_DISTANCE',
              severity: 'error',
              category: 'structural',
              stepIndex,
              actionType: action.type,
              suggestions: ['Use a value between 0 (short) and 1 (full screen)']
            });
          }
        }
        break;

      case 'intent':
        if (!action.intent) {
          errors.push({
            field: `steps[${stepIndex}].action.intent`,
            message: 'Intent action requires intent configuration',
            code: 'MISSING_INTENT_CONFIG',
            severity: 'error',
            category: 'structural',
            stepIndex,
            actionType: action.type,
            suggestions: ['Provide intent action, package, and other parameters']
          });
        }
        break;
    }

    return { errors, warnings };
  }

  /**
   * Validate predicate structure
   *
   * @param predicate - Predicate to validate
   * @param fieldPath - Field path for error reporting
   * @param context - Validation context
   * @returns Predicate validation result
   */
  private validatePredicateStructure(
    predicate: StatePredicate | IStatePredicate,
    fieldPath: string,
    context: FlowValidationContext
  ): { errors: EnhancedValidationError[], warnings: EnhancedValidationWarning[] } {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    const validTypes = ['exact', 'contains', 'matches', 'fuzzy'];

    if (!predicate.type) {
      errors.push({
        field: `${fieldPath}.type`,
        message: 'Predicate type is required',
        code: 'MISSING_PREDICATE_TYPE',
        severity: 'critical',
        category: 'structural',
        predicateType: predicate.type,
        suggestions: [`Use one of: ${validTypes.join(', ')}`]
      });
    } else if (!validTypes.includes(predicate.type)) {
      errors.push({
        field: `${fieldPath}.type`,
        message: `Invalid predicate type: ${predicate.type}`,
        code: 'INVALID_PREDICATE_TYPE',
        severity: 'error',
        category: 'structural',
        predicateType: predicate.type,
        suggestions: [`Use one of: ${validTypes.join(', ')}`]
      });
    }

    // Type-specific validation
    switch (predicate.type) {
      case 'exact':
        if (!predicate.stateId && !predicate.activity) {
          errors.push({
            field: `${fieldPath}`,
            message: 'Exact match predicate must specify either stateId or activity',
            code: 'INVALID_EXACT_MATCH',
            severity: 'error',
            category: 'structural',
            predicateType: predicate.type,
            suggestions: ['Add stateId for exact state matching or activity for exact activity matching']
          });
        }
        break;

      case 'contains':
        if (!predicate.activity &&
            (!predicate.containsText || predicate.containsText.length === 0) &&
            (!predicate.hasSelectors || predicate.hasSelectors.length === 0)) {
          errors.push({
            field: `${fieldPath}`,
            message: 'Contains match predicate must specify activity, containsText, or hasSelectors',
            code: 'INVALID_CONTAINS_MATCH',
            severity: 'error',
            category: 'structural',
            predicateType: predicate.type,
            suggestions: ['Add activity name, text fragments, or selectors for matching']
          });
        }
        break;

      case 'matches':
        if (!predicate.matches ||
            (!predicate.matches.activity &&
             !predicate.matches.text &&
             !predicate.matches.selectors)) {
          errors.push({
            field: `${fieldPath}`,
            message: 'Regex match predicate must specify at least one pattern',
            code: 'INVALID_MATCHES_CRITERIA',
            severity: 'error',
            category: 'structural',
            predicateType: predicate.type,
            suggestions: ['Add regex patterns for activity, text, or selectors']
          });
        } else {
          // Validate regex patterns
          if (predicate.matches.activity) {
            try {
              new RegExp(predicate.matches.activity);
            } catch (error) {
              errors.push({
                field: `${fieldPath}.matches.activity`,
                message: `Invalid activity regex: ${predicate.matches.activity}`,
                code: 'INVALID_REGEX',
                severity: 'error',
                category: 'structural',
                predicateType: predicate.type,
                suggestions: ['Fix regex syntax or use a simpler pattern']
              });
            }
          }

          if (predicate.matches.text) {
            try {
              new RegExp(predicate.matches.text);
            } catch (error) {
              errors.push({
                field: `${fieldPath}.matches.text`,
                message: `Invalid text regex: ${predicate.matches.text}`,
                code: 'INVALID_REGEX',
                severity: 'error',
                category: 'structural',
                predicateType: predicate.type,
                suggestions: ['Fix regex syntax or use a simpler pattern']
              });
            }
          }

          if (predicate.matches.selectors) {
            try {
              new RegExp(predicate.matches.selectors);
            } catch (error) {
              errors.push({
                field: `${fieldPath}.matches.selectors`,
                message: `Invalid selectors regex: ${predicate.matches.selectors}`,
                code: 'INVALID_REGEX',
                severity: 'error',
                category: 'structural',
                predicateType: predicate.type,
                suggestions: ['Fix regex syntax or use a simpler pattern']
              });
            }
          }
        }
        break;

      case 'fuzzy':
        if (!predicate.activity &&
            (!predicate.containsText || predicate.containsText.length === 0) &&
            (!predicate.hasSelectors || predicate.hasSelectors.length === 0)) {
          errors.push({
            field: `${fieldPath}`,
            message: 'Fuzzy match predicate must specify activity, containsText, or hasSelectors',
            code: 'INVALID_FUZZY_MATCH',
            severity: 'error',
            category: 'structural',
            predicateType: predicate.type,
            suggestions: ['Add activity name, text fragments, or selectors for fuzzy matching']
          });
        }

        if (predicate.fuzzyThreshold !== undefined) {
          if (typeof predicate.fuzzyThreshold !== 'number' ||
              predicate.fuzzyThreshold < 0 ||
              predicate.fuzzyThreshold > 1) {
            errors.push({
              field: `${fieldPath}.fuzzyThreshold`,
              message: 'Fuzzy threshold must be a number between 0 and 1',
              code: 'INVALID_FUZZY_THRESHOLD',
              severity: 'error',
              category: 'structural',
              predicateType: predicate.type,
              suggestions: ['Use a value between 0 (very permissive) and 1 (exact match)']
            });
          } else if (predicate.fuzzyThreshold < 0.5) {
            warnings.push({
              field: `${fieldPath}.fuzzyThreshold`,
              message: 'Low fuzzy threshold may result in many false positives',
              code: 'LOW_FUZZY_THRESHOLD',
              severity: 'warning',
              category: 'structural',
              predicateType: predicate.type,
              value: predicate.fuzzyThreshold,
              suggestions: ['Consider using a higher threshold for better precision']
            });
          }
        }
        break;
    }

    return { errors, warnings };
  }

  /**
   * Validate configuration structure
   *
   * @param config - Configuration to validate
   * @param context - Validation context
   * @returns Configuration validation result
   */
  private validateConfigStructure(
    config: any,
    context: FlowValidationContext
  ): { errors: EnhancedValidationError[], warnings: EnhancedValidationWarning[] } {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    if (typeof config.defaultTimeout !== 'number' || config.defaultTimeout < 1) {
      errors.push({
        field: 'config.defaultTimeout',
        message: 'Default timeout must be a positive number',
        code: 'INVALID_DEFAULT_TIMEOUT',
        severity: 'error',
        category: 'structural',
        suggestions: ['Set a reasonable default timeout in seconds (e.g., 30)']
      });
    } else if (config.defaultTimeout > 300) {
      warnings.push({
        field: 'config.defaultTimeout',
        message: 'Very long default timeout may indicate inefficient flow',
        code: 'LONG_DEFAULT_TIMEOUT',
        severity: 'warning',
        category: 'structural',
        value: config.defaultTimeout,
        suggestions: ['Consider optimizing flow steps or reducing timeout'],
        performanceImpact: 'medium'
      });
    }

    if (typeof config.retryAttempts !== 'number' || config.retryAttempts < 0) {
      errors.push({
        field: 'config.retryAttempts',
        message: 'Retry attempts must be a non-negative number',
        code: 'INVALID_RETRY_ATTEMPTS',
        severity: 'error',
        category: 'structural',
        suggestions: ['Set a reasonable number of retry attempts (e.g., 3)']
      });
    } else if (config.retryAttempts > 10) {
      warnings.push({
        field: 'config.retryAttempts',
        message: 'High retry count may cause excessive delays',
        code: 'HIGH_RETRY_COUNT',
        severity: 'warning',
        category: 'structural',
        value: config.retryAttempts,
        suggestions: ['Consider reducing retry attempts or improving step reliability'],
        performanceImpact: 'medium'
      });
    }

    if (typeof config.allowParallel !== 'boolean') {
      errors.push({
        field: 'config.allowParallel',
        message: 'Allow parallel must be a boolean',
        code: 'INVALID_ALLOW_PARALLEL',
        severity: 'error',
        category: 'structural',
        suggestions: ['Set to true or false based on flow requirements']
      });
    }

    const validPriorities = ['low', 'medium', 'high'];
    if (!validPriorities.includes(config.priority)) {
      errors.push({
        field: 'config.priority',
        message: `Priority must be one of: ${validPriorities.join(', ')}`,
        code: 'INVALID_PRIORITY',
        severity: 'error',
        category: 'structural',
        suggestions: [`Use one of: ${validPriorities.join(', ')}`]
      });
    }

    return { errors, warnings };
  }

  // ============================================================================
  // Semantic Validation
  // ============================================================================

  /**
   * Validate flow semantics and logic
   *
   * @param flow - Flow definition to validate
   * @param context - Validation context
   * @returns Semantic validation result
   */
  private async validateSemantic(
    flow: FlowDefinition,
    context: FlowValidationContext
  ): Promise<ValidationResult> {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    // Validate flow logic consistency
    await this.validateFlowLogic(flow, errors, warnings, context);

    // Validate state predicate resolvability
    await this.validatePredicateResolvability(flow, errors, warnings, context);

    // Validate step transitions
    await this.validateStepTransitions(flow, errors, warnings, context);

    // Validate entry/exit point accessibility
    await this.validateEntryPointAccessibility(flow, errors, warnings, context);

    if (flow.exitPoint) {
      await this.validateExitPointAccessibility(flow, errors, warnings, context);
    }

    // Check for logical inconsistencies
    await this.validateLogicalConsistency(flow, errors, warnings, context);

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate overall flow logic
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateFlowLogic(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check for circular dependencies
    const circularDeps = this.detectCircularDependencies(flow);
    if (circularDeps.length > 0) {
      for (const cycle of circularDeps) {
        errors.push({
          field: 'flow.steps',
          message: `Circular dependency detected: ${cycle.join(' -> ')} -> ${cycle[0]}`,
          code: 'CIRCULAR_DEPENDENCY',
          severity: 'critical',
          category: 'semantic',
          suggestions: [
            'Break the circular dependency by restructuring steps',
            'Remove or modify one of the steps in the cycle',
            'Add conditional logic to prevent the cycle'
          ],
          relatedIssues: cycle.map(stepId => `step:${stepId}`)
        });
      }
    }

    // Check for unreachable steps
    const unreachableSteps = this.findUnreachableSteps(flow);
    for (const stepId of unreachableSteps) {
      warnings.push({
        field: 'flow.steps',
        message: `Step "${stepId}" may be unreachable from entry point`,
        code: 'UNREACHABLE_STEP',
        severity: 'warning',
        category: 'semantic',
        suggestions: [
          'Check step preconditions for consistency',
          'Verify flow structure allows reaching this step',
          'Consider removing the step if truly unnecessary'
        ]
      });
    }

    // Check for potential infinite loops
    const infiniteLoops = this.detectPotentialInfiniteLoops(flow);
    for (const loop of infiniteLoops) {
      warnings.push({
        field: 'flow.steps',
        message: `Potential infinite loop detected involving steps: ${loop.join(', ')}`,
        code: 'POTENTIAL_INFINITE_LOOP',
        severity: 'warning',
        category: 'semantic',
        suggestions: [
          'Add exit conditions to prevent infinite loops',
          'Implement maximum iteration limits',
          'Review flow logic for loop termination conditions'
        ],
        relatedIssues: loop.map(stepId => `step:${stepId}`)
      });
    }
  }

  /**
   * Validate state predicate resolvability
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validatePredicateResolvability(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    const availableStates = context.availableStates || await this.getAvailableStates(flow.packageName);

    // Validate entry point resolvability
    const entryResolution = await this.resolvePredicate(flow.entryPoint, availableStates, context);
    if (!entryResolution.resolved) {
      errors.push({
        field: 'entryPoint',
        message: `Entry point cannot be resolved to any known state`,
        code: 'UNRESOLVABLE_ENTRY_POINT',
        severity: 'critical',
        category: 'semantic',
        predicateType: flow.entryPoint.type,
        suggestions: [
          'Check entry point criteria for accuracy',
          'Ensure the target package has been discovered',
          'Consider using more general matching criteria'
        ],
        relatedIssues: ['flow.entryPoint']
      });
    } else if (entryResolution.confidence < (context.confidenceThreshold || DEFAULT_CONFIDENCE_THRESHOLD)) {
      warnings.push({
        field: 'entryPoint',
        message: `Entry point resolved with low confidence (${entryResolution.confidence.toFixed(2)})`,
        code: 'LOW_CONFIDENCE_ENTRY_POINT',
        severity: 'warning',
        category: 'semantic',
        predicateType: flow.entryPoint.type,
        suggestions: [
          'Make entry point criteria more specific',
          'Add additional matching constraints',
          'Consider using exact state matching if possible'
        ]
      });
    }

    // Validate exit point resolvability (if present)
    if (flow.exitPoint) {
      const exitResolution = await this.resolvePredicate(flow.exitPoint, availableStates, context);
      if (!exitResolution.resolved) {
        warnings.push({
          field: 'exitPoint',
          message: `Exit point cannot be resolved to any known state`,
          code: 'UNRESOLVABLE_EXIT_POINT',
          severity: 'warning',
          category: 'semantic',
          predicateType: flow.exitPoint.type,
          suggestions: [
            'Check exit point criteria for accuracy',
            'Ensure the target state exists in the graph',
            'Consider removing exit point if not needed'
          ],
          relatedIssues: ['flow.exitPoint']
        });
      }
    }

    // Validate step predicate resolvability
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      // Validate preconditions
      for (const precondition of step.preconditions) {
        const resolution = await this.resolvePredicate(precondition, availableStates, context);
        if (!resolution.resolved) {
          errors.push({
            field: `steps[${i}].preconditions`,
            message: `Step precondition cannot be resolved to any known state`,
            code: 'UNRESOLVABLE_PRECONDITION',
            severity: 'error',
            category: 'semantic',
            stepIndex: i,
            predicateType: precondition.type,
            suggestions: [
              'Check precondition criteria for accuracy',
              'Ensure required states exist in the graph',
              'Consider using more general matching criteria'
            ]
          });
        } else if (resolution.confidence < (context.confidenceThreshold || DEFAULT_CONFIDENCE_THRESHOLD)) {
          warnings.push({
            field: `steps[${i}].preconditions`,
            message: `Step precondition resolved with low confidence (${resolution.confidence.toFixed(2)})`,
            code: 'LOW_CONFIDENCE_PRECONDITION',
            severity: 'warning',
            category: 'semantic',
            stepIndex: i,
            predicateType: precondition.type,
            suggestions: [
              'Make precondition criteria more specific',
              'Add additional matching constraints',
              'Consider breaking into multiple steps with clearer conditions'
            ]
          });
        }
      }

      // Validate expected state
      if (step.expectedState) {
        const resolution = await this.resolvePredicate(step.expectedState, availableStates, context);
        if (!resolution.resolved) {
          warnings.push({
            field: `steps[${i}].expectedState`,
            message: `Step expected state cannot be resolved to any known state`,
            code: 'UNRESOLVABLE_EXPECTED_STATE',
            severity: 'warning',
            category: 'semantic',
            stepIndex: i,
            predicateType: step.expectedState.type,
            suggestions: [
              'Check expected state criteria for accuracy',
              'Ensure the target state exists in the graph',
              'Consider removing expected state if not needed'
            ]
          });
        }
      }
    }
  }

  /**
   * Validate step transitions
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateStepTransitions(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check for transition consistency between steps
    for (let i = 0; i < flow.steps.length - 1; i++) {
      const currentStep = flow.steps[i];
      const nextStep = flow.steps[i + 1];

      // If current step has expected state, check if next step can match it
      if (currentStep.expectedState) {
        const canTransition = nextStep.preconditions.some(precondition =>
          this.canPredicateTransition(currentStep.expectedState!, precondition)
        );

        if (!canTransition) {
          warnings.push({
            field: `steps[${i}].expectedState`,
            message: `Step ${i + 1} may not be reachable from step ${i} based on expected state`,
            code: 'INCONSISTENT_TRANSITION',
            severity: 'warning',
            category: 'semantic',
            stepIndex: i,
            suggestions: [
              'Add preconditions to next step that match expected state',
              'Modify expected state to be more general',
              'Review step sequence for logical consistency'
            ],
            relatedIssues: [`steps[${i}]`, `steps[${i + 1}]`]
          });
        }
      }
    }

    // Check for missing transitions
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      // If step has expected state but no following steps can match it
      if (step.expectedState && i === flow.steps.length - 1) {
        if (flow.exitPoint) {
          const canTransitionToExit = this.canPredicateTransition(step.expectedState, flow.exitPoint);
          if (!canTransitionToExit) {
            warnings.push({
              field: `steps[${i}].expectedState`,
              message: `Final step expected state may not lead to exit point`,
              code: 'INCONSISTENT_EXIT_TRANSITION',
              severity: 'warning',
              category: 'semantic',
              stepIndex: i,
              suggestions: [
                'Modify exit point to match final step expected state',
                'Adjust final step expected state',
                'Add an intermediate step to bridge the gap'
              ]
            });
          }
        }
      }
    }
  }

  /**
   * Validate entry point accessibility
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateEntryPointAccessibility(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    const accessibleSteps = flow.steps.filter(step =>
      step.preconditions.some(precondition =>
        this.canPredicateTransition(flow.entryPoint, precondition)
      )
    );

    if (accessibleSteps.length === 0) {
      errors.push({
        field: 'entryPoint',
        message: 'No steps can be reached from the entry point',
        code: 'INACCESSIBLE_ENTRY_POINT',
        severity: 'critical',
        category: 'semantic',
        suggestions: [
          'Modify step preconditions to match entry point',
          'Change entry point to match available steps',
          'Add intermediate steps to bridge the gap'
        ],
        relatedIssues: ['flow.entryPoint', 'flow.steps']
      });
    } else if (accessibleSteps.length < flow.steps.length) {
      const inaccessibleCount = flow.steps.length - accessibleSteps.length;
      warnings.push({
        field: 'entryPoint',
        message: `${inaccessibleCount} steps may not be accessible from the entry point`,
        code: 'PARTIALLY_ACCESSIBLE_STEPS',
        severity: 'warning',
        category: 'semantic',
        suggestions: [
          'Review preconditions of inaccessible steps',
          'Consider restructuring flow for better accessibility',
          'Add alternative entry paths'
        ]
      });
    }
  }

  /**
   * Validate exit point accessibility
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateExitPointAccessibility(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    if (!flow.exitPoint) return;

    const stepsLeadingToExit = flow.steps.filter(step =>
      step.expectedState && this.canPredicateTransition(step.expectedState, flow.exitPoint!)
    );

    if (stepsLeadingToExit.length === 0) {
      warnings.push({
        field: 'exitPoint',
        message: 'No steps lead to the exit point',
        code: 'UNREACHABLE_EXIT_POINT',
        severity: 'warning',
        category: 'semantic',
        suggestions: [
          'Add expected states to steps that lead to exit point',
          'Modify exit point to match existing step outcomes',
          'Consider removing exit point if not needed'
        ]
      });
    }
  }

  /**
   * Validate logical consistency
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateLogicalConsistency(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check for redundant steps
    const redundantSteps = this.findRedundantSteps(flow);
    for (const redundantGroup of redundantSteps) {
      warnings.push({
        field: 'flow.steps',
        message: `Potentially redundant steps detected: ${redundantGroup.join(', ')}`,
        code: 'REDUNDANT_STEPS',
        severity: 'warning',
        category: 'semantic',
        suggestions: [
          'Consider consolidating redundant steps',
          'Review if all steps are necessary',
          'Merge similar steps with different conditions'
        ],
        relatedIssues: redundantGroup.map(stepId => `step:${stepId}`)
      });
    }

    // Check for conflicting preconditions
    const conflictingSteps = this.findConflictingPreconditions(flow);
    for (const conflict of conflictingSteps) {
      warnings.push({
        field: 'flow.steps',
        message: `Steps with potentially conflicting preconditions: ${conflict.stepIds.join(', ')}`,
        code: 'CONFLICTING_PRECONDITIONS',
        severity: 'warning',
        category: 'semantic',
        suggestions: [
          'Review precondition logic for conflicts',
          'Add additional conditions to resolve conflicts',
          'Restructure flow to avoid conflicts'
        ],
        relatedIssues: conflict.stepIds.map(stepId => `step:${stepId}`)
      });
    }

    // Check for critical steps without proper validation
    const criticalStepsWithoutValidation = flow.steps.filter(step =>
      step.critical && (!step.expectedState || step.preconditions.length === 0)
    );

    for (const step of criticalStepsWithoutValidation) {
      warnings.push({
        field: 'flow.steps',
        message: `Critical step "${step.name}" lacks proper validation`,
        code: 'CRITICAL_WITHOUT_VALIDATION',
        severity: 'warning',
        category: 'semantic',
        suggestions: [
          'Add expected state verification for critical steps',
          'Include preconditions to ensure proper context',
          'Consider adding post-condition validation'
        ]
      });
    }
  }

  // ============================================================================
  // Execution Validation
  // ============================================================================

  /**
   * Validate flow execution feasibility and performance
   *
   * @param flow - Flow definition to validate
   * @param context - Validation context
   * @returns Execution validation result
   */
  private async validateExecution(
    flow: FlowDefinition,
    context: FlowValidationContext
  ): Promise<ValidationResult> {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    // Validate action feasibility
    await this.validateActionFeasibility(flow, errors, warnings, context);

    // Validate performance characteristics
    await this.validatePerformanceCharacteristics(flow, errors, warnings, context);

    // Validate resource requirements
    await this.validateResourceRequirements(flow, errors, warnings, context);

    // Validate timeout and retry configurations
    await this.validateTimeoutRetryConfig(flow, errors, warnings, context);

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate action feasibility
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateActionFeasibility(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];
      const action = step.action;

      // Validate selector availability for target-based actions
      if (action.target && ['tap', 'type', 'long_press'].includes(action.type)) {
        const selectorAvailable = await this.validateSelectorAvailability(
          action.target,
          flow.packageName,
          context
        );

        if (!selectorAvailable.available) {
          warnings.push({
            field: `steps[${i}].action.target`,
            message: `Target selector may not be available: ${JSON.stringify(action.target)}`,
            code: 'UNAVAILABLE_SELECTOR',
            severity: 'warning',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            suggestions: [
              'Verify selector exists in target states',
              'Use more general selector criteria',
              'Add fallback selectors for better reliability'
            ],
            performanceImpact: 'medium'
          });
        } else if (selectorAvailable.confidence < (context.confidenceThreshold || DEFAULT_CONFIDENCE_THRESHOLD)) {
          warnings.push({
            field: `steps[${i}].action.target`,
            message: `Target selector resolved with low confidence (${selectorAvailable.confidence.toFixed(2)})`,
            code: 'LOW_CONFIDENCE_SELECTOR',
            severity: 'warning',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            suggestions: [
              'Use more specific selector criteria',
              'Add alternative selectors',
              'Consider using different action type'
            ],
            performanceImpact: 'medium'
          });
        }
      }

      // Validate swipe feasibility
      if (action.type === 'swipe') {
        if (!action.swipe || !action.swipe.direction) {
          errors.push({
            field: `steps[${i}].action.swipe`,
            message: 'Swipe action requires direction configuration',
            code: 'MISSING_SWIPE_DIRECTION',
            severity: 'error',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            suggestions: ['Specify swipe direction (up, down, left, right)']
          });
        }

        if (action.swipe?.distance && (action.swipe.distance < 0.1 || action.swipe.distance > 1)) {
          warnings.push({
            field: `steps[${i}].action.swipe.distance`,
            message: 'Swipe distance outside recommended range (0.1 - 1.0)',
            code: 'EXTREME_SWIPE_DISTANCE',
            severity: 'warning',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            suggestions: ['Use distance between 0.1 (short) and 1.0 (full screen)'],
            performanceImpact: 'low'
          });
        }
      }

      // Validate intent feasibility
      if (action.type === 'intent') {
        if (!action.intent || !action.intent.action) {
          errors.push({
            field: `steps[${i}].action.intent`,
            message: 'Intent action requires intent configuration',
            code: 'MISSING_INTENT_ACTION',
            severity: 'error',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            suggestions: ['Specify intent action, package, and other required parameters']
          });
        }

        // Check for privileged actions
        if (action.intent?.action?.includes('CALL') ||
            action.intent?.action?.includes('CAMERA') ||
            action.intent?.action?.includes('LOCATION')) {
          warnings.push({
            field: `steps[${i}].action.intent`,
            message: 'Intent may require special permissions',
            code: 'REQUIRES_PERMISSIONS',
            severity: 'warning',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            suggestions: [
              'Ensure required permissions are granted',
              'Handle permission requests in flow',
              'Consider alternative approaches if permissions cannot be guaranteed'
            ]
          });
        }
      }

      // Validate text input feasibility
      if (action.type === 'type') {
        if (!action.text) {
          errors.push({
            field: `steps[${i}].action.text`,
            message: 'Type action requires text input',
            code: 'MISSING_TYPE_TEXT',
            severity: 'error',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            suggestions: ['Specify the text to type into the target field']
          });
        } else if (action.text.length > 1000) {
          warnings.push({
            field: `steps[${i}].action.text`,
            message: 'Very long text input may cause issues',
            code: 'LONG_TEXT_INPUT',
            severity: 'warning',
            category: 'execution',
            stepIndex: i,
            actionType: action.type,
            value: action.text.length,
            suggestions: [
              'Consider breaking into multiple smaller inputs',
              'Verify target field can handle long text',
              'Use shorter text if possible'
            ],
            performanceImpact: 'medium'
          });
        }
      }
    }
  }

  /**
   * Validate performance characteristics
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validatePerformanceCharacteristics(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Calculate estimated execution time
    const estimatedDuration = this.estimateExecutionTime(flow);

    if (estimatedDuration > 60000) { // > 1 minute
      warnings.push({
        field: 'flow.performance',
        message: `Flow may take a long time to execute (${Math.round(estimatedDuration / 1000)}s)`,
        code: 'LONG_EXECUTION_TIME',
        severity: 'warning',
        category: 'execution',
        value: estimatedDuration,
        suggestions: [
          'Consider optimizing step sequence',
          'Reduce timeouts where possible',
          'Break into smaller, more focused flows'
        ],
        performanceImpact: 'high'
      });
    }

    // Check for complex predicates that may impact performance
    const complexPredicates = this.findComplexPredicates(flow);
    for (const { stepIndex, predicate, complexity } of complexPredicates) {
      if (complexity > 0.8) {
        warnings.push({
          field: `steps[${stepIndex}].preconditions`,
          message: `Complex predicate may impact performance (complexity: ${complexity.toFixed(2)})`,
          code: 'COMPLEX_PREDICATE',
          severity: 'warning',
          category: 'execution',
          stepIndex,
          predicateType: predicate.type,
          suggestions: [
            'Simplify predicate criteria',
            'Use more specific matching patterns',
            'Consider breaking into multiple simpler predicates'
          ],
          performanceImpact: 'medium'
        });
      }
    }

    // Check for steps with high failure probability
    const highRiskSteps = this.identifyHighRiskSteps(flow);
    for (const { stepIndex, step, riskFactors } of highRiskSteps) {
      warnings.push({
        field: `steps[${stepIndex}]`,
        message: `Step "${step.name}" has high failure probability`,
        code: 'HIGH_FAILURE_PROBABILITY',
        severity: 'warning',
        category: 'execution',
        stepIndex,
        suggestions: [
          'Add more specific preconditions',
          'Implement better error handling',
          'Consider alternative approaches'
        ],
        relatedIssues: riskFactors
      });
    }
  }

  /**
   * Validate resource requirements
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateResourceRequirements(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Estimate memory usage
    const estimatedMemory = this.estimateMemoryUsage(flow);
    if (estimatedMemory > 100) { // > 100MB
      warnings.push({
        field: 'flow.resources',
        message: `Flow may require significant memory (${estimatedMemory}MB)`,
        code: 'HIGH_MEMORY_USAGE',
        severity: 'warning',
        category: 'execution',
        value: estimatedMemory,
        suggestions: [
          'Optimize flow to reduce memory usage',
          'Break into smaller flows',
          'Clear unnecessary data between steps'
        ],
        performanceImpact: 'medium'
      });
    }

    // Check network usage
    const networkIntensiveSteps = flow.steps.filter(step =>
      step.action.type === 'intent' &&
      step.action.intent?.action?.includes('NETWORK')
    );

    if (networkIntensiveSteps.length > 5) {
      warnings.push({
        field: 'flow.resources',
        message: 'Flow has many network-intensive steps',
        code: 'HIGH_NETWORK_USAGE',
        severity: 'warning',
        category: 'execution',
        value: networkIntensiveSteps.length,
        suggestions: [
          'Optimize network requests',
          'Implement caching where possible',
          'Consider offline alternatives'
        ],
        performanceImpact: 'medium'
      });
    }

    // Check for resource-intensive actions
    const resourceIntensiveSteps = flow.steps.filter(step =>
      ['intent', 'swipe'].includes(step.action.type)
    );

    if (resourceIntensiveSteps.length > flow.steps.length * 0.5) {
      warnings.push({
        field: 'flow.resources',
        message: 'High proportion of resource-intensive steps',
        code: 'RESOURCE_INTENSIVE_FLOW',
        severity: 'warning',
        category: 'execution',
        value: resourceIntensiveSteps.length,
        suggestions: [
          'Optimize resource usage',
          'Add delays between intensive operations',
          'Consider resource cleanup strategies'
        ],
        performanceImpact: 'high'
      });
    }
  }

  /**
   * Validate timeout and retry configurations
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateTimeoutRetryConfig(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check for inconsistent timeout configurations
    const timeoutVariance = this.calculateTimeoutVariance(flow);
    if (timeoutVariance > 0.8) {
      warnings.push({
        field: 'flow.config.timeouts',
        message: 'High variance in timeout configurations may indicate inconsistencies',
        code: 'INCONSISTENT_TIMEOUTS',
        severity: 'warning',
        category: 'execution',
        value: timeoutVariance,
        suggestions: [
          'Standardize timeout values where possible',
          'Review unusually long or short timeouts',
          'Use flow-level default where appropriate'
        ],
        performanceImpact: 'medium'
      });
    }

    // Check for excessive retry configurations
    const totalRetryAttempts = flow.steps.reduce((sum, step) =>
      sum + (step.metadata?.retryAttempts || flow.config.retryAttempts), 0
    );

    if (totalRetryAttempts > flow.steps.length * 5) {
      warnings.push({
        field: 'flow.config.retries',
        message: 'High total retry attempts may cause excessive delays',
        code: 'EXCESSIVE_RETRIES',
        severity: 'warning',
        category: 'execution',
        value: totalRetryAttempts,
        suggestions: [
          'Reduce retry attempts for reliable steps',
          'Implement exponential backoff',
          'Add circuit breaker patterns'
        ],
        performanceImpact: 'high'
      });
    }

    // Check for steps without timeout overrides when needed
    const stepsNeedingCustomTimeout = flow.steps.filter(step =>
      ['intent', 'swipe'].includes(step.action.type) &&
      step.timeout === flow.config.defaultTimeout
    );

    for (const step of stepsNeedingCustomTimeout) {
      warnings.push({
        field: `steps[${flow.steps.indexOf(step)}].timeout`,
        message: `${step.action.type} action may need custom timeout configuration`,
        code: 'NEEDS_CUSTOM_TIMEOUT',
        severity: 'warning',
        category: 'execution',
        stepIndex: flow.steps.indexOf(step),
        actionType: step.action.type,
        suggestions: [
          'Set appropriate timeout for this action type',
          'Consider action-specific requirements',
          'Test and adjust timeout values'
        ],
        performanceImpact: 'medium'
      });
    }
  }

  // ============================================================================
  // Security Validation
  // ============================================================================

  /**
   * Validate flow security aspects
   *
   * @param flow - Flow definition to validate
   * @param context - Validation context
   * @returns Security validation result
   */
  private async validateSecurity(
    flow: FlowDefinition,
    context: FlowValidationContext
  ): Promise<ValidationResult> {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    // Validate permission requirements
    await this.validatePermissionRequirements(flow, errors, warnings, context);

    // Validate data security
    await this.validateDataSecurity(flow, errors, warnings, context);

    // Validate input validation
    await this.validateInputSecurity(flow, errors, warnings, context);

    // Validate resource access
    await this.validateResourceAccess(flow, errors, warnings, context);

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate permission requirements
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validatePermissionRequirements(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    const requiredPermissions = this.identifyRequiredPermissions(flow);

    // Check for sensitive permissions
    const sensitivePermissions = [
      'android.permission.CALL_PHONE',
      'android.permission.CAMERA',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.RECORD_AUDIO',
      'android.permission.READ_CONTACTS',
      'android.permission.WRITE_CONTACTS',
      'android.permission.READ_SMS',
      'android.permission.SEND_SMS',
      'android.permission.READ_EXTERNAL_STORAGE',
      'android.permission.WRITE_EXTERNAL_STORAGE'
    ];

    for (const permission of requiredPermissions) {
      if (sensitivePermissions.includes(permission)) {
        warnings.push({
          field: 'flow.permissions',
          message: `Flow requires sensitive permission: ${permission}`,
          code: 'SENSITIVE_PERMISSION',
          severity: 'warning',
          category: 'security',
          suggestions: [
            'Ensure permission is properly requested and handled',
            'Consider user privacy implications',
            'Provide clear explanation for permission usage'
          ]
        });
      }
    }

    // Check for system-level permissions
    const systemPermissions = requiredPermissions.filter(p => p.startsWith('android.permission.'));
    if (systemPermissions.length > 5) {
      warnings.push({
        field: 'flow.permissions',
        message: 'Flow requires many system permissions',
        code: 'MANY_PERMISSIONS',
        severity: 'warning',
        category: 'security',
        value: systemPermissions.length,
        suggestions: [
          'Review if all permissions are necessary',
          'Consider alternative approaches with fewer permissions',
          'Implement permission requests gracefully'
        ]
      });
    }
  }

  /**
   * Validate data security
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateDataSecurity(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check for sensitive data in text inputs
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      if (step.action.type === 'type' && step.action.text) {
        const text = step.action.text;

        // Check for potential sensitive data patterns
        const sensitivePatterns = [
          /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, // Credit card
          /\b\d{3}-\d{2}-\d{4}\b/, // SSN
          /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // Email
          /\b\d{10,}\b/ // Long numbers (potential phone/account numbers)
        ];

        for (const pattern of sensitivePatterns) {
          if (pattern.test(text)) {
            warnings.push({
              field: `steps[${i}].action.text`,
              message: 'Step may be inputting sensitive data',
              code: 'SENSITIVE_DATA_INPUT',
              severity: 'warning',
              category: 'security',
              stepIndex: i,
              suggestions: [
                'Ensure secure handling of sensitive data',
                'Consider data encryption if needed',
                'Implement secure input methods'
              ]
            });
            break;
          }
        }

        // Check for very long text inputs that might contain sensitive data
        if (text.length > 500) {
          warnings.push({
            field: `steps[${i}].action.text`,
            message: 'Long text input may contain sensitive information',
            code: 'LONG_SENSITIVE_INPUT',
            severity: 'info',
            category: 'security',
            stepIndex: i,
            value: text.length,
            suggestions: [
              'Review if all text is necessary',
              'Consider alternative input methods',
              'Implement data masking if appropriate'
            ]
          });
        }
      }
    }
  }

  /**
   * Validate input security
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateInputSecurity(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check for potential injection attacks in text inputs
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      if (step.action.type === 'type' && step.action.text) {
        const text = step.action.text;

        // Check for script patterns
        const scriptPatterns = [
          /<script[^>]*>.*?<\/script>/gi,
          /javascript:/gi,
          /on\w+\s*=/gi
        ];

        for (const pattern of scriptPatterns) {
          if (pattern.test(text)) {
            warnings.push({
              field: `steps[${i}].action.text`,
              message: 'Text input may contain script content',
              code: 'POTENTIAL_SCRIPT_INJECTION',
              severity: 'warning',
              category: 'security',
              stepIndex: i,
              suggestions: [
                'Sanitize input before use',
                'Consider if script content is necessary',
                'Implement input validation'
              ]
            });
            break;
          }
        }

        // Check for SQL injection patterns
        const sqlPatterns = [
          /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)/gi,
          /(\b(UNION|OR|AND)\s+\d+\s*=\s*\d+)/gi,
          /(--|\*\/|\/\*)/g
        ];

        for (const pattern of sqlPatterns) {
          if (pattern.test(text)) {
            warnings.push({
              field: `steps[${i}].action.text`,
              message: 'Text input may contain SQL injection patterns',
              code: 'POTENTIAL_SQL_INJECTION',
              severity: 'warning',
              category: 'security',
              stepIndex: i,
              suggestions: [
                'Use parameterized queries',
                'Sanitize database inputs',
                'Implement input validation'
              ]
            });
            break;
          }
        }
      }
    }
  }

  /**
   * Validate resource access
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateResourceAccess(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check for intent-based access to system resources
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      if (step.action.type === 'intent' && step.action.intent) {
        const intent = step.action.intent;

        // Check for system app access
        if (intent.package && intent.package.startsWith('android')) {
          warnings.push({
            field: `steps[${i}].action.intent.package`,
            message: 'Flow accesses system application',
            code: 'SYSTEM_APP_ACCESS',
            severity: 'warning',
            category: 'security',
            stepIndex: i,
            suggestions: [
              'Ensure system access is necessary',
              'Consider alternative approaches',
              'Handle potential security restrictions'
            ]
          });
        }

        // Check for external app access
        if (intent.package && !intent.package.startsWith(flow.packageName)) {
          warnings.push({
            field: `steps[${i}].action.intent.package`,
            message: `Flow accesses external application: ${intent.package}`,
            code: 'EXTERNAL_APP_ACCESS',
            severity: 'info',
            category: 'security',
            stepIndex: i,
            suggestions: [
              'Verify external app access is intentional',
              'Ensure compatibility with target app',
              'Handle potential app not installed scenarios'
            ]
          });
        }

        // Check for potentially dangerous actions
        const dangerousActions = [
          'android.intent.action.DELETE',
          'android.intent.action.FACTORY_RESET',
          'android.intent.action.CALL',
          'android.intent.action.SEND',
          'android.intent.action.SENDTO'
        ];

        if (intent.action && dangerousActions.includes(intent.action)) {
          warnings.push({
            field: `steps[${i}].action.intent.action`,
            message: `Intent action may have security implications: ${intent.action}`,
            code: 'DANGEROUS_INTENT_ACTION',
            severity: 'warning',
            category: 'security',
            stepIndex: i,
            suggestions: [
              'Ensure action is necessary and safe',
              'Implement proper error handling',
              'Consider user confirmation for dangerous actions'
            ]
          });
        }
      }
    }
  }

  // ============================================================================
  // Integration Validation
  // ============================================================================

  /**
   * Validate flow integration with graph states
   *
   * @param flow - Flow definition to validate
   * @param context - Validation context
   * @returns Integration validation result
   */
  private async validateIntegration(
    flow: FlowDefinition,
    context: FlowValidationContext
  ): Promise<ValidationResult> {
    const errors: EnhancedValidationError[] = [];
    const warnings: EnhancedValidationWarning[] = [];

    // Validate graph state compatibility
    await this.validateGraphStateCompatibility(flow, errors, warnings, context);

    // Validate package compatibility
    await this.validatePackageCompatibility(flow, errors, warnings, context);

    // Validate flow path validity
    await this.validateFlowPathValidity(flow, errors, warnings, context);

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate graph state compatibility
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateGraphStateCompatibility(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    const availableStates = context.availableStates || await this.getAvailableStates(flow.packageName);

    if (availableStates.length === 0) {
      warnings.push({
        field: 'flow.integration',
        message: 'No graph states available for validation',
        code: 'NO_GRAPH_STATES',
        severity: 'warning',
        category: 'integration',
        suggestions: [
          'Ensure graph discovery has been run for the target package',
          'Verify package name is correct',
          'Consider running state capture for the target app'
        ]
      });
      return;
    }

    // Validate that entry point can match available states
    const entryMatches = await this.countMatchingStates(flow.entryPoint, availableStates);
    if (entryMatches === 0) {
      errors.push({
        field: 'flow.entryPoint',
        message: 'Entry point does not match any available graph states',
        code: 'ENTRY_POINT_NO_MATCH',
        severity: 'error',
        category: 'integration',
        suggestions: [
          'Update entry point criteria to match available states',
          'Run graph discovery for current app state',
          'Verify package compatibility'
        ]
      });
    } else if (entryMatches < availableStates.length * 0.1) {
      warnings.push({
        field: 'flow.entryPoint',
        message: `Entry point matches very few states (${entryMatches}/${availableStates.length})`,
        code: 'ENTRY_POINT_FEW_MATCHES',
        severity: 'warning',
        category: 'integration',
        value: entryMatches,
        suggestions: [
          'Consider broadening entry point criteria',
          'Verify if matching states are appropriate',
          'Check if graph discovery is complete'
        ]
      });
    }

    // Validate that step predicates can match available states
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      // Check preconditions
      for (const precondition of step.preconditions) {
        const matches = await this.countMatchingStates(precondition, availableStates);
        if (matches === 0) {
          warnings.push({
            field: `steps[${i}].preconditions`,
            message: `Step precondition does not match any available states`,
            code: 'PRECONDITION_NO_MATCH',
            severity: 'warning',
            category: 'integration',
            stepIndex: i,
            suggestions: [
              'Update precondition criteria',
              'Verify graph contains expected states',
              'Consider more general matching criteria'
            ]
          });
        }
      }

      // Check expected state
      if (step.expectedState) {
        const matches = await this.countMatchingStates(step.expectedState, availableStates);
        if (matches === 0) {
          warnings.push({
            field: `steps[${i}].expectedState`,
            message: `Step expected state does not match any available states`,
            code: 'EXPECTED_STATE_NO_MATCH',
            severity: 'warning',
            category: 'integration',
            stepIndex: i,
            suggestions: [
              'Update expected state criteria',
              'Verify action leads to expected state',
              'Consider removing expected state if uncertain'
            ]
          });
        }
      }
    }

    // Validate exit point if present
    if (flow.exitPoint) {
      const exitMatches = await this.countMatchingStates(flow.exitPoint, availableStates);
      if (exitMatches === 0) {
        warnings.push({
          field: 'flow.exitPoint',
          message: 'Exit point does not match any available states',
          code: 'EXIT_POINT_NO_MATCH',
          severity: 'warning',
          category: 'integration',
          suggestions: [
            'Update exit point criteria',
            'Verify flow can reach exit state',
            'Consider removing exit point if not needed'
          ]
        });
      }
    }
  }

  /**
   * Validate package compatibility
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validatePackageCompatibility(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    // Check if package is in available packages list
    if (context.availablePackages && context.availablePackages.length > 0) {
      if (!context.availablePackages.includes(flow.packageName)) {
        errors.push({
          field: 'flow.packageName',
          message: `Package not found in available packages: ${flow.packageName}`,
          code: 'PACKAGE_NOT_AVAILABLE',
          severity: 'error',
          category: 'integration',
          suggestions: [
            'Verify package name is correct',
            'Ensure app is installed',
            'Update available packages list'
          ]
        });
      }
    }

    // Validate package name format
    if (!flow.packageName.match(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/)) {
      errors.push({
        field: 'flow.packageName',
        message: 'Invalid package name format',
        code: 'INVALID_PACKAGE_FORMAT',
        severity: 'error',
        category: 'integration',
        suggestions: [
          'Use standard Java package naming',
          'Format: com.company.app',
          'Use only lowercase letters, numbers, and dots'
        ]
      });
    }

    // Check for common system packages that may not be suitable
    const systemPackages = [
      'android',
      'com.android',
      'com.google.android',
      'com.android.systemui'
    ];

    if (systemPackages.some(sysPkg => flow.packageName.startsWith(sysPkg))) {
      warnings.push({
        field: 'flow.packageName',
        message: 'Flow targets system package',
        code: 'SYSTEM_PACKAGE_TARGET',
        severity: 'warning',
        category: 'integration',
        suggestions: [
          'Ensure system package targeting is intentional',
          'Consider compatibility across Android versions',
          'Handle potential system restrictions'
        ]
      });
    }
  }

  /**
   * Validate flow path validity
   *
   * @param flow - Flow definition to validate
   * @param errors - Errors array to populate
   * @param warnings - Warnings array to populate
   * @param context - Validation context
   */
  private async validateFlowPathValidity(
    flow: FlowDefinition,
    errors: EnhancedValidationError[],
    warnings: EnhancedValidationWarning[],
    context: FlowValidationContext
  ): Promise<void> {
    const availableStates = context.availableStates || await this.getAvailableStates(flow.packageName);

    if (availableStates.length === 0) return;

    // Build state transition graph from available states
    const stateGraph = this.buildStateTransitionGraph(availableStates);

    // Simulate flow execution to validate path
    const pathValidation = await this.simulateFlowPath(flow, stateGraph, context);

    if (!pathValidation.valid) {
      errors.push({
        field: 'flow.path',
        message: `Flow path validation failed: ${pathValidation.reason}`,
        code: 'INVALID_FLOW_PATH',
        severity: 'error',
        category: 'integration',
        suggestions: pathValidation.suggestions || [
          'Review flow step sequence',
          'Verify state transitions are possible',
          'Check predicate consistency'
        ],
        relatedIssues: pathValidation.failedSteps?.map(stepId => `step:${stepId}`)
      });
    } else if (pathValidation.confidence < (context.confidenceThreshold || DEFAULT_CONFIDENCE_THRESHOLD)) {
      warnings.push({
        field: 'flow.path',
        message: `Flow path has low confidence: ${pathValidation.confidence.toFixed(2)}`,
        code: 'LOW_CONFIDENCE_PATH',
        severity: 'warning',
        category: 'integration',
        value: pathValidation.confidence,
        suggestions: [
          'Review uncertain transitions',
          'Add more specific predicates',
          'Consider alternative flow paths'
        ]
      });
    }

    // Check for disconnected components in flow path
    const disconnectedComponents = this.findDisconnectedFlowComponents(flow, stateGraph);
    if (disconnectedComponents.length > 0) {
      warnings.push({
        field: 'flow.path',
        message: `Flow has disconnected components: ${disconnectedComponents.join(', ')}`,
        code: 'DISCONNECTED_COMPONENTS',
        severity: 'warning',
        category: 'integration',
        suggestions: [
          'Review flow structure for connectivity',
          'Add bridging steps between components',
          'Consider splitting into separate flows'
        ],
        relatedIssues: disconnectedComponents.map(comp => `component:${comp}`)
      });
    }
  }

  // ============================================================================
  // Predicate Resolution Methods
  // ============================================================================

  /**
   * Resolve predicates to known graph states
   *
   * @param flow - Flow definition
   * @param context - Validation context
   * @returns Array of predicate resolution results
   */
  private async resolvePredicates(
    flow: FlowDefinition,
    context: FlowValidationContext
  ): Promise<Array<{
    predicate: IStatePredicate;
    resolved: boolean;
    confidence: number;
    matchingStates: StateRecord[];
    resolutionTime: number;
  }>> {
    const startTime = performance.now();
    const availableStates = context.availableStates || await this.getAvailableStates(flow.packageName);
    const results = [];

    // Resolve entry point
    const entryResult = await this.resolvePredicate(flow.entryPoint, availableStates, context);
    results.push({
      predicate: flow.entryPoint,
      ...entryResult,
      resolutionTime: performance.now() - startTime
    });

    // Resolve exit point if present
    if (flow.exitPoint) {
      const exitResult = await this.resolvePredicate(flow.exitPoint, availableStates, context);
      results.push({
        predicate: flow.exitPoint,
        ...exitResult,
        resolutionTime: performance.now() - startTime
      });
    }

    // Resolve step preconditions and expected states
    for (const step of flow.steps) {
      for (const precondition of step.preconditions) {
        const result = await this.resolvePredicate(precondition, availableStates, context);
        results.push({
          predicate: precondition,
          ...result,
          resolutionTime: performance.now() - startTime
        });
      }

      if (step.expectedState) {
        const result = await this.resolvePredicate(step.expectedState, availableStates, context);
        results.push({
          predicate: step.expectedState,
          ...result,
          resolutionTime: performance.now() - startTime
        });
      }
    }

    return results;
  }

  /**
   * Resolve a single predicate against available states
   *
   * @param predicate - Predicate to resolve
   * @param availableStates - Available states to match against
   * @param context - Validation context
   * @returns Resolution result
   */
  private async resolvePredicate(
    predicate: StatePredicate | IStatePredicate,
    availableStates: StateRecord[],
    context: FlowValidationContext
  ): Promise<{
    resolved: boolean;
    confidence: number;
    matchingStates: StateRecord[];
  }> {
    // Check cache first
    if (context.enableCaching !== false) {
      const cacheKey = this.generatePredicateCacheKey(predicate, availableStates);
      const cached = this.predicateCache.get(cacheKey);
      if (cached && (Date.now() - cached.timestamp) < PREDICATE_CACHE_TTL) {
        return cached.resolution;
      }
    }

    const predicateInstance = predicate instanceof StatePredicate
      ? predicate
      : new StatePredicate(predicate);

    const matchingStates: StateRecord[] = [];
    let totalConfidence = 0;

    // Match against available states
    for (const state of availableStates) {
      const result = predicateInstance.evaluate(state, {
        enableDebug: false,
        minConfidence: context.confidenceThreshold || DEFAULT_CONFIDENCE_THRESHOLD
      });

      if (result.matched) {
        matchingStates.push(state);
        totalConfidence += result.confidence;
      }
    }

    const resolved = matchingStates.length > 0;
    const confidence = resolved ? totalConfidence / matchingStates.length : 0;

    const resolution = { resolved, confidence, matchingStates };

    // Cache the result
    if (context.enableCaching !== false) {
      const cacheKey = this.generatePredicateCacheKey(predicate, availableStates);
      this.predicateCache.set(cacheKey, {
        resolution,
        timestamp: Date.now(),
        predicateHash: hashObject(predicate)
      });
    }

    return resolution;
  }

  /**
   * Count how many states match a predicate
   *
   * @param predicate - Predicate to check
   * @param availableStates - Available states
   * @returns Number of matching states
   */
  private async countMatchingStates(
    predicate: StatePredicate | IStatePredicate,
    availableStates: StateRecord[]
  ): Promise<number> {
    const resolution = await this.resolvePredicate(predicate, availableStates, {});
    return resolution.matchingStates.length;
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  /**
   * Analyze flow characteristics
   *
   * @param flow - Flow definition
   * @param categoryResults - Validation category results
   * @returns Flow analysis results
   */
  private analyzeFlow(
    flow: FlowDefinition,
    categoryResults: any
  ): ComprehensiveValidationResult['analysis'] {
    const stepCount = flow.steps.length;
    const criticalSteps = flow.steps.filter(step => step.critical).length;
    const conditionalSteps = flow.steps.filter(step => step.preconditions.length > 1).length;

    let totalComplexity = 0;
    for (const step of flow.steps) {
      totalComplexity += this.calculateStepComplexity(step);
    }
    const averageStepComplexity = stepCount > 0 ? totalComplexity / stepCount : 0;

    const estimatedDuration = this.estimateExecutionTime(flow);

    const riskFactors = this.identifyRiskFactors(flow, categoryResults);
    const suggestions = this.generateSuggestions(flow, categoryResults, riskFactors);

    return {
      stepCount,
      criticalSteps,
      conditionalSteps,
      averageStepComplexity,
      estimatedDuration,
      riskFactors,
      suggestions
    };
  }

  /**
   * Calculate performance impact
   *
   * @param validationTime - Time taken for validation
   * @param flow - Flow definition
   * @returns Performance impact level
   */
  private calculatePerformanceImpact(
    validationTime: number,
    flow: FlowDefinition
  ): 'low' | 'medium' | 'high' {
    const stateCount = flow.steps.length * 2; // Estimate states based on steps

    if (stateCount <= 50 && validationTime <= PERFORMANCE_THRESHOLDS.FAST_VALIDATION) {
      return 'low';
    } else if (stateCount <= 200 && validationTime <= PERFORMANCE_THRESHOLDS.MEDIUM_VALIDATION) {
      return 'medium';
    } else {
      return 'high';
    }
  }

  /**
   * Calculate reliability score
   *
   * @param categoryResults - Validation category results
   * @returns Reliability score (0-1)
   */
  private calculateReliability(categoryResults: any): number {
    let totalScore = 0;
    let categoryCount = 0;

    for (const [category, result] of Object.entries(categoryResults)) {
      const isValid = (result as ValidationResult).isValid;
      totalScore += isValid ? 1 : 0;
      categoryCount++;
    }

    return categoryCount > 0 ? totalScore / categoryCount : 0;
  }

  /**
   * Calculate step hash for duplicate detection
   *
   * @param step - Flow step
   * @returns Step hash
   */
  private calculateStepHash(step: FlowStep): string {
    const data = {
      action: step.action,
      preconditions: step.preconditions.map(p => p.toObject()),
      expectedState: step.expectedState?.toObject(),
      timeout: step.timeout,
      critical: step.critical
    };
    return hashObject(data);
  }

  /**
   * Detect circular dependencies in flow
   *
   * @param flow - Flow definition
   * @returns Array of cycles
   */
  private detectCircularDependencies(flow: FlowDefinition): string[][] {
    const cycles: string[][] = [];
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    const stepMap = new Map(flow.steps.map(step => [step.id, step]));

    function dfs(stepId: string, path: string[]): boolean {
      if (recursionStack.has(stepId)) {
        // Cycle detected
        const cycleStart = path.indexOf(stepId);
        cycles.push([...path.slice(cycleStart), stepId]);
        return true;
      }

      if (visited.has(stepId)) {
        return false;
      }

      visited.add(stepId);
      recursionStack.add(stepId);
      path.push(stepId);

      const step = stepMap.get(stepId);
      if (step && step.expectedState) {
        // Find steps that can follow this one
        for (const nextStep of flow.steps) {
          if (nextStep.preconditions.some(precondition =>
            this.canPredicateTransition(step.expectedState!, precondition)
          )) {
            if (dfs(nextStep.id, [...path])) {
              return true;
            }
          }
        }
      }

      recursionStack.delete(stepId);
      return false;
    }

    for (const step of flow.steps) {
      if (!visited.has(step.id)) {
        dfs(step.id, []);
      }
    }

    return cycles;
  }

  /**
   * Find unreachable steps
   *
   * @param flow - Flow definition
   * @returns Array of unreachable step IDs
   */
  private findUnreachableSteps(flow: FlowDefinition): string[] {
    const reachableSteps = new Set<string>();
    const queue = ['entry'];

    // BFS from entry point
    while (queue.length > 0) {
      const current = queue.shift()!;

      if (current === 'entry') {
        // Find steps matching entry point
        for (const step of flow.steps) {
          if (step.preconditions.some(precondition =>
            this.canPredicateTransition(flow.entryPoint, precondition)
          )) {
            if (!reachableSteps.has(step.id)) {
              reachableSteps.add(step.id);
              queue.push(step.id);
            }
          }
        }
      } else {
        // Find next steps
        const currentStep = flow.steps.find(s => s.id === current);
        if (currentStep?.expectedState) {
          for (const nextStep of flow.steps) {
            if (nextStep.preconditions.some(precondition =>
              this.canPredicateTransition(currentStep.expectedState!, precondition)
            )) {
              if (!reachableSteps.has(nextStep.id)) {
                reachableSteps.add(nextStep.id);
                queue.push(nextStep.id);
              }
            }
          }
        }
      }
    }

    return flow.steps
      .filter(step => !reachableSteps.has(step.id))
      .map(step => step.id);
  }

  /**
   * Detect potential infinite loops
   *
   * @param flow - Flow definition
   * @returns Array of potential loops
   */
  private detectPotentialInfiniteLoops(flow: FlowDefinition): string[][] {
    const loops: string[][] = [];
    const visited = new Map<string, number>();

    for (const step of flow.steps) {
      const path: string[] = [];

      const findLoop = (currentStep: FlowStep, depth: number): boolean => {
        if (depth > 10) return false; // Prevent excessive recursion

        if (visited.has(currentStep.id)) {
          const previousDepth = visited.get(currentStep.id)!;
          if (depth - previousDepth > 2) {
            // Found a potential loop
            const loopStart = path.findIndex(s => s === currentStep.id);
            if (loopStart >= 0) {
              loops.push([...path.slice(loopStart), currentStep.id]);
            }
            return true;
          }
          return false;
        }

        visited.set(currentStep.id, depth);
        path.push(currentStep.id);

        if (currentStep.expectedState) {
          for (const nextStep of flow.steps) {
            if (nextStep.preconditions.some(precondition =>
              this.canPredicateTransition(currentStep.expectedState!, precondition)
            )) {
              if (findLoop(nextStep, depth + 1)) {
                return true;
              }
            }
          }
        }

        path.pop();
        return false;
      };

      findLoop(step, 0);
    }

    return loops;
  }

  /**
   * Check if a predicate can transition to another
   *
   * @param fromPredicate - Source predicate
   * @param toPredicate - Target predicate
   * @returns True if transition is possible
   */
  private canPredicateTransition(
    fromPredicate: StatePredicate | IStatePredicate,
    toPredicate: StatePredicate | IStatePredicate
  ): boolean {
    // Simplified transition logic
    // In a real implementation, this would be more sophisticated

    const from = fromPredicate instanceof StatePredicate ? fromPredicate : new StatePredicate(fromPredicate);
    const to = toPredicate instanceof StatePredicate ? toPredicate : new StatePredicate(toPredicate);

    // Exact state ID match
    if (from.type === 'exact' && to.type === 'exact' &&
        from.stateId && to.stateId && from.stateId === to.stateId) {
      return true;
    }

    // Activity match
    if (from.activity && to.activity && from.activity === to.activity) {
      return true;
    }

    // Text content overlap
    if (from.containsText && to.containsText) {
      const hasCommonText = from.containsText.some(text1 =>
        to.containsText!.some(text2 =>
          text1.toLowerCase() === text2.toLowerCase()
        )
      );
      if (hasCommonText) return true;
    }

    return false;
  }

  /**
   * Find redundant steps
   *
   * @param flow - Flow definition
   * @returns Array of redundant step groups
   */
  private findRedundantSteps(flow: FlowDefinition): string[][] {
    const redundantGroups: string[][] = [];
    const processed = new Set<string>();

    for (let i = 0; i < flow.steps.length; i++) {
      if (processed.has(flow.steps[i].id)) continue;

      const similarSteps: string[] = [flow.steps[i].id];

      for (let j = i + 1; j < flow.steps.length; j++) {
        if (processed.has(flow.steps[j].id)) continue;

        const similarity = this.calculateStepSimilarity(flow.steps[i], flow.steps[j]);
        if (similarity > 0.9) {
          similarSteps.push(flow.steps[j].id);
          processed.add(flow.steps[j].id);
        }
      }

      if (similarSteps.length > 1) {
        redundantGroups.push(similarSteps);
        processed.add(flow.steps[i].id);
      }
    }

    return redundantGroups;
  }

  /**
   * Find conflicting preconditions
   *
   * @param flow - Flow definition
   * @returns Array of conflicts
   */
  private findConflictingPreconditions(flow: FlowDefinition): Array<{
    stepIds: string[];
    conflictType: string;
  }> {
    const conflicts: Array<{ stepIds: string[]; conflictType: string }> = [];

    // Check for steps with mutually exclusive preconditions
    for (let i = 0; i < flow.steps.length; i++) {
      for (let j = i + 1; j < flow.steps.length; j++) {
        const step1 = flow.steps[i];
        const step2 = flow.steps[j];

        // Check for contradictory activity requirements
        const conflictingActivities = step1.preconditions.some(p1 =>
          p1.activity && step2.preconditions.some(p2 =>
            p2.activity && p1.activity !== p2.activity
          )
        );

        if (conflictingActivities) {
          conflicts.push({
            stepIds: [step1.id, step2.id],
            conflictType: 'conflicting_activities'
          });
        }
      }
    }

    return conflicts;
  }

  /**
   * Calculate step similarity
   *
   * @param step1 - First step
   * @param step2 - Second step
   * @returns Similarity score (0-1)
   */
  private calculateStepSimilarity(step1: FlowStep, step2: FlowStep): number {
    let similarity = 0;
    let factors = 0;

    // Action similarity
    if (JSON.stringify(step1.action) === JSON.stringify(step2.action)) {
      similarity += 1;
    }
    factors++;

    // Preconditions similarity
    if (step1.preconditions.length === step2.preconditions.length) {
      const preconditionsMatch = step1.preconditions.every(p1 =>
        step2.preconditions.some(p2 =>
          JSON.stringify(p1.toObject()) === JSON.stringify(p2.toObject())
        )
      );
      if (preconditionsMatch) similarity += 1;
    }
    factors++;

    // Expected state similarity
    if (step1.expectedState && step2.expectedState) {
      if (JSON.stringify(step1.expectedState.toObject()) ===
          JSON.stringify(step2.expectedState.toObject())) {
        similarity += 1;
      }
    } else if (!step1.expectedState && !step2.expectedState) {
      similarity += 1;
    }
    factors++;

    // Other properties
    if (step1.timeout === step2.timeout) similarity += 1;
    if (step1.critical === step2.critical) similarity += 1;
    factors += 2;

    return factors > 0 ? similarity / factors : 0;
  }

  /**
   * Identify high-risk steps
   *
   * @param flow - Flow definition
   * @returns Array of high-risk steps
   */
  private identifyHighRiskSteps(flow: FlowDefinition): Array<{
    stepIndex: number;
    step: FlowStep;
    riskFactors: string[];
  }> {
    const highRiskSteps: Array<{ stepIndex: number; step: FlowStep; riskFactors: string[] }> = [];

    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];
      const riskFactors: string[] = [];

      // No preconditions
      if (step.preconditions.length === 0) {
        riskFactors.push('no_preconditions');
      }

      // No expected state
      if (!step.expectedState) {
        riskFactors.push('no_expected_state');
      }

      // Complex action
      if (['intent', 'swipe'].includes(step.action.type)) {
        riskFactors.push('complex_action');
      }

      // No target selector
      if (['tap', 'type', 'long_press'].includes(step.action.type) && !step.action.target) {
        riskFactors.push('no_target_selector');
      }

      // High timeout
      if (step.timeout > 60) {
        riskFactors.push('high_timeout');
      }

      // Critical but lacking validation
      if (step.critical && (!step.expectedState || step.preconditions.length === 0)) {
        riskFactors.push('critical_without_validation');
      }

      if (riskFactors.length >= 2) {
        highRiskSteps.push({ stepIndex: i, step, riskFactors });
      }
    }

    return highRiskSteps;
  }

  /**
   * Find complex predicates
   *
   * @param flow - Flow definition
   * @returns Array of complex predicates
   */
  private findComplexPredicates(flow: FlowDefinition): Array<{
    stepIndex: number;
    predicate: StatePredicate | IStatePredicate;
    complexity: number;
  }> {
    const complexPredicates: Array<{ stepIndex: number; predicate: StatePredicate | IStatePredicate; complexity: number }> = [];

    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      // Check preconditions
      for (const precondition of step.preconditions) {
        const complexity = this.calculatePredicateComplexity(precondition);
        if (complexity > 0.5) {
          complexPredicates.push({ stepIndex: i, predicate: precondition, complexity });
        }
      }

      // Check expected state
      if (step.expectedState) {
        const complexity = this.calculatePredicateComplexity(step.expectedState);
        if (complexity > 0.5) {
          complexPredicates.push({ stepIndex: i, predicate: step.expectedState, complexity });
        }
      }
    }

    return complexPredicates;
  }

  /**
   * Calculate predicate complexity
   *
   * @param predicate - State predicate
   * @returns Complexity score (0-1)
   */
  private calculatePredicateComplexity(predicate: StatePredicate | IStatePredicate): number {
    let complexity = 0;

    // Base complexity by type
    switch (predicate.type) {
      case 'exact':
        complexity += 0.1;
        break;
      case 'contains':
        complexity += 0.3;
        break;
      case 'matches':
        complexity += 0.7;
        break;
      case 'fuzzy':
        complexity += 0.5;
        break;
    }

    // Add complexity for multiple criteria
    if (predicate.containsText && predicate.containsText.length > 1) {
      complexity += 0.1 * (predicate.containsText.length - 1);
    }

    if (predicate.hasSelectors && predicate.hasSelectors.length > 1) {
      complexity += 0.1 * (predicate.hasSelectors.length - 1);
    }

    if (predicate.matches) {
      const matchCount = [
        predicate.matches.activity ? 1 : 0,
        predicate.matches.text ? 1 : 0,
        predicate.matches.selectors ? 1 : 0
      ].reduce((sum, count) => sum + count, 0);

      if (matchCount > 1) {
        complexity += 0.1 * (matchCount - 1);
      }
    }

    return Math.min(complexity, 1.0);
  }

  /**
   * Calculate step complexity
   *
   * @param step - Flow step
   * @returns Complexity score (0-10)
   */
  private calculateStepComplexity(step: FlowStep): number {
    let complexity = 1;

    // Action complexity
    switch (step.action.type) {
      case 'back':
        complexity += 0;
        break;
      case 'tap':
        complexity += 1;
        break;
      case 'type':
        complexity += 2;
        break;
      case 'swipe':
        complexity += 3;
        break;
      case 'long_press':
        complexity += 2;
        break;
      case 'intent':
        complexity += 4;
        break;
    }

    // Precondition complexity
    complexity += step.preconditions.length * 0.5;

    // Expected state complexity
    if (step.expectedState) {
      complexity += 1;
    }

    return Math.min(complexity, 10);
  }

  /**
   * Estimate execution time
   *
   * @param flow - Flow definition
   * @returns Estimated time in milliseconds
   */
  private estimateExecutionTime(flow: FlowDefinition): number {
    let totalTime = 0;

    for (const step of flow.steps) {
      // Base time for different action types
      const baseTimes: Record<string, number> = {
        'back': 1000,
        'tap': 2000,
        'type': 3000,
        'swipe': 2000,
        'long_press': 4000,
        'intent': 3000
      };

      totalTime += baseTimes[step.action.type] || 2000;

      // Add time for preconditions
      totalTime += step.preconditions.length * 500;

      // Add timeout as maximum time
      totalTime = Math.min(totalTime, step.timeout * 1000);

      // Add buffer time
      totalTime *= 1.2;
    }

    return totalTime;
  }

  /**
   * Estimate memory usage
   *
   * @param flow - Flow definition
   * @returns Estimated memory usage in MB
   */
  private estimateMemoryUsage(flow: FlowDefinition): number {
    // Base memory for flow execution
    let memoryUsage = 10; // 10MB base

    // Add memory for each step
    memoryUsage += flow.steps.length * 2; // 2MB per step

    // Add memory for complex predicates
    for (const step of flow.steps) {
      for (const precondition of step.preconditions) {
        memoryUsage += this.calculatePredicateComplexity(precondition) * 5;
      }
    }

    return Math.round(memoryUsage);
  }

  /**
   * Calculate timeout variance
   *
   * @param flow - Flow definition
   * @returns Variance score (0-1)
   */
  private calculateTimeoutVariance(flow: FlowDefinition): number {
    if (flow.steps.length === 0) return 0;

    const timeouts = flow.steps.map(step => step.timeout);
    const mean = timeouts.reduce((sum, timeout) => sum + timeout, 0) / timeouts.length;

    const variance = timeouts.reduce((sum, timeout) => {
      return sum + Math.pow(timeout - mean, 2);
    }, 0) / timeouts.length;

    return Math.min(variance / (mean * mean), 1);
  }

  /**
   * Identify required permissions
   *
   * @param flow - Flow definition
   * @returns Array of required permissions
   */
  private identifyRequiredPermissions(flow: FlowDefinition): string[] {
    const permissions = new Set<string>();

    for (const step of flow.steps) {
      switch (step.action.type) {
        case 'tap':
        case 'type':
        case 'swipe':
        case 'long_press':
          permissions.add('android.permission.INTERNET'); // For UI interaction
          break;
        case 'intent':
          permissions.add('android.permission.INTERNET');

          if (step.action.intent?.action?.includes('CALL')) {
            permissions.add('android.permission.CALL_PHONE');
          }
          if (step.action.intent?.action?.includes('CAMERA')) {
            permissions.add('android.permission.CAMERA');
          }
          if (step.action.intent?.action?.includes('LOCATION')) {
            permissions.add('android.permission.ACCESS_FINE_LOCATION');
          }
          break;
      }
    }

    return Array.from(permissions);
  }

  /**
   * Identify risk factors
   *
   * @param flow - Flow definition
   * @param categoryResults - Validation results
   * @returns Array of risk factors
   */
  private identifyRiskFactors(flow: FlowDefinition, categoryResults: any): string[] {
    const riskFactors: string[] = [];

    // Structural risks
    if (!categoryResults.structural.isValid) {
      riskFactors.push('structural_errors');
    }

    // Semantic risks
    if (!categoryResults.semantic.isValid) {
      riskFactors.push('semantic_errors');
    }

    // Execution risks
    if (!categoryResults.execution.isValid) {
      riskFactors.push('execution_errors');
    }

    // Security risks
    if (!categoryResults.security.isValid) {
      riskFactors.push('security_errors');
    }

    // Complexity risks
    if (flow.steps.length > 20) {
      riskFactors.push('high_complexity');
    }

    // Performance risks
    const estimatedTime = this.estimateExecutionTime(flow);
    if (estimatedTime > 60000) {
      riskFactors.push('long_execution_time');
    }

    // Reliability risks
    const stepsWithoutValidation = flow.steps.filter(step =>
      !step.expectedState || step.preconditions.length === 0
    );
    if (stepsWithoutValidation.length > flow.steps.length * 0.5) {
      riskFactors.push('low_reliability');
    }

    return riskFactors;
  }

  /**
   * Generate improvement suggestions
   *
   * @param flow - Flow definition
   * @param categoryResults - Validation results
   * @param riskFactors - Identified risk factors
   * @returns Array of suggestions
   */
  private generateSuggestions(
    flow: FlowDefinition,
    categoryResults: any,
    riskFactors: string[]
  ): string[] {
    const suggestions: string[] = [];

    // General suggestions based on validation results
    if (categoryResults.structural.errors.length > 0) {
      suggestions.push('Fix structural errors before attempting execution');
    }

    if (categoryResults.semantic.errors.length > 0) {
      suggestions.push('Review flow logic and predicate definitions');
    }

    if (categoryResults.execution.errors.length > 0) {
      suggestions.push('Address execution feasibility issues');
    }

    if (categoryResults.security.errors.length > 0) {
      suggestions.push('Resolve security concerns before deployment');
    }

    // Suggestions based on risk factors
    if (riskFactors.includes('high_complexity')) {
      suggestions.push('Consider breaking flow into smaller, focused flows');
    }

    if (riskFactors.includes('long_execution_time')) {
      suggestions.push('Optimize step timeouts and consider parallel execution where possible');
    }

    if (riskFactors.includes('low_reliability')) {
      suggestions.push('Add more preconditions and expected state validations');
    }

    // Specific suggestions based on flow characteristics
    const criticalStepsWithoutValidation = flow.steps.filter(step =>
      step.critical && (!step.expectedState || step.preconditions.length === 0)
    );

    if (criticalStepsWithoutValidation.length > 0) {
      suggestions.push('Add proper validation to critical steps');
    }

    const stepsWithoutTargets = flow.steps.filter(step =>
      ['tap', 'type', 'long_press'].includes(step.action.type) && !step.action.target
    );

    if (stepsWithoutTargets.length > 0) {
      suggestions.push('Add target selectors to improve step reliability');
    }

    return suggestions;
  }

  /**
   * Validate selector availability
   *
   * @param selector - Target selector
   * @param packageName - Target package
   * @param context - Validation context
   * @returns Availability result
   */
  private async validateSelectorAvailability(
    selector: any,
    packageName: string,
    context: FlowValidationContext
  ): Promise<{
    available: boolean;
    confidence: number;
    matchingStates: StateRecord[];
  }> {
    const availableStates = context.availableStates || await this.getAvailableStates(packageName);
    const matchingStates: StateRecord[] = [];

    for (const state of availableStates) {
      const hasMatchingSelector = state.selectors.some(stateSelector => {
        if (selector.rid && stateSelector.rid === selector.rid) return true;
        if (selector.text && stateSelector.text?.includes(selector.text)) return true;
        if (selector.desc && stateSelector.desc?.includes(selector.desc)) return true;
        if (selector.cls && stateSelector.cls?.includes(selector.cls)) return true;
        return false;
      });

      if (hasMatchingSelector) {
        matchingStates.push(state);
      }
    }

    const available = matchingStates.length > 0;
    const confidence = available ? matchingStates.length / availableStates.length : 0;

    return { available, confidence, matchingStates };
  }

  /**
   * Get available states for a package
   *
   * @param packageName - Package name
   * @returns Array of available states
   */
  private async getAvailableStates(packageName: string): Promise<StateRecord[]> {
    try {
      const graph = await this.graphService.getGraph();
      return graph.states.filter(state => state.package === packageName);
    } catch (error) {
      console.warn(`Failed to load graph for package ${packageName}:`, error);
      return [];
    }
  }

  /**
   * Build state transition graph
   *
   * @param states - Available states
   * @returns State transition graph
   */
  private buildStateTransitionGraph(states: StateRecord[]): Map<string, string[]> {
    const graph = new Map<string, string[]>();

    // Initialize graph with all states
    for (const state of states) {
      graph.set(state.id, []);
    }

    // Add transitions (simplified - would use actual transition data)
    for (let i = 0; i < states.length - 1; i++) {
      const currentState = states[i];
      const nextState = states[i + 1];

      // Add transition if activities are different or if there's significant UI change
      if (currentState.activity !== nextState.activity) {
        graph.get(currentState.id)?.push(nextState.id);
      }
    }

    return graph;
  }

  /**
   * Simulate flow path execution
   *
   * @param flow - Flow definition
   * @param stateGraph - State transition graph
   * @param context - Validation context
   * @returns Path validation result
   */
  private async simulateFlowPath(
    flow: FlowDefinition,
    stateGraph: Map<string, string[]>,
    context: FlowValidationContext
  ): Promise<{
    valid: boolean;
    reason?: string;
    confidence: number;
    suggestions?: string[];
    failedSteps?: string[];
  }> {
    // Simplified path simulation
    // In a real implementation, this would be more sophisticated

    let totalConfidence = 0;
    let stepCount = 0;
    const failedSteps: string[] = [];

    for (const step of flow.steps) {
      stepCount++;

      // Check if preconditions can be satisfied
      let stepConfidence = 0;
      for (const precondition of step.preconditions) {
        // Simplified confidence calculation
        stepConfidence += 0.7; // Assume 70% confidence per precondition
      }

      if (step.preconditions.length > 0) {
        stepConfidence /= step.preconditions.length;
      } else {
        stepConfidence = 0.5; // Low confidence for steps without preconditions
      }

      totalConfidence += stepConfidence;

      if (stepConfidence < (context.confidenceThreshold || DEFAULT_CONFIDENCE_THRESHOLD)) {
        failedSteps.push(step.id);
      }
    }

    const averageConfidence = stepCount > 0 ? totalConfidence / stepCount : 0;
    const valid = failedSteps.length === 0;

    return {
      valid,
      confidence: averageConfidence,
      failedSteps: valid ? undefined : failedSteps,
      reason: valid ? undefined : `Some steps have low confidence: ${failedSteps.join(', ')}`,
      suggestions: valid ? undefined : [
        'Add more specific preconditions',
        'Verify state transitions are possible',
        'Review predicate consistency'
      ]
    };
  }

  /**
   * Find disconnected flow components
   *
   * @param flow - Flow definition
   * @param stateGraph - State transition graph
   * @returns Array of disconnected component names
   */
  private findDisconnectedFlowComponents(
    flow: FlowDefinition,
    stateGraph: Map<string, string[]>
  ): string[] {
    // Simplified disconnected component detection
    // In a real implementation, this would analyze the actual flow graph structure

    const components: string[] = [];
    const visited = new Set<string>();

    for (const step of flow.steps) {
      if (!visited.has(step.id)) {
        // Find connected component
        const component = this.findConnectedComponent(step.id, flow, visited);
        if (component.length === 1) {
          components.push(step.id);
        }
      }
    }

    return components;
  }

  /**
   * Find connected component for a step
   *
   * @param stepId - Starting step ID
   * @param flow - Flow definition
   * @param visited - Visited steps set
   * @returns Array of connected step IDs
   */
  private findConnectedComponent(
    stepId: string,
    flow: FlowDefinition,
    visited: Set<string>
  ): string[] {
    const component: string[] = [];
    const queue = [stepId];

    while (queue.length > 0) {
      const current = queue.shift()!;

      if (visited.has(current)) continue;
      visited.add(current);
      component.push(current);

      const currentStep = flow.steps.find(s => s.id === current);
      if (!currentStep) continue;

      // Find connected steps
      for (const otherStep of flow.steps) {
        if (this.areStepsConnected(currentStep, otherStep) && !visited.has(otherStep.id)) {
          queue.push(otherStep.id);
        }
      }
    }

    return component;
  }

  /**
   * Check if two steps are connected
   *
   * @param step1 - First step
   * @param step2 - Second step
   * @returns True if steps are connected
   */
  private areStepsConnected(step1: FlowStep, step2: FlowStep): boolean {
    // Check if step1's expected state matches step2's preconditions
    if (step1.expectedState) {
      return step2.preconditions.some(precondition =>
        this.canPredicateTransition(step1.expectedState!, precondition)
      );
    }

    // Check if step2's expected state matches step1's preconditions
    if (step2.expectedState) {
      return step1.preconditions.some(precondition =>
        this.canPredicateTransition(step2.expectedState!, precondition)
      );
    }

    return false;
  }

  // ============================================================================
  // Cache Management
  // ============================================================================

  /**
   * Get cached validation result
   *
   * @param flow - Flow definition
   * @param context - Validation context
   * @returns Cached result or null
   */
  private getCachedValidation(
    flow: FlowDefinition,
    context: FlowValidationContext
  ): ComprehensiveValidationResult | null {
    const flowHash = flow.calculateHash();
    const contextHash = hashObject(context);
    const cacheKey = `${flowHash}:${contextHash}`;

    const cached = this.validationCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < VALIDATION_CACHE_TTL) {
      return cached.result;
    }

    return null;
  }

  /**
   * Cache validation result
   *
   * @param flow - Flow definition
   * @param context - Validation context
   * @param result - Validation result
   */
  private cacheValidation(
    flow: FlowDefinition,
    context: FlowValidationContext,
    result: ComprehensiveValidationResult
  ): void {
    const flowHash = flow.calculateHash();
    const contextHash = hashObject(context);
    const cacheKey = `${flowHash}:${contextHash}`;

    this.validationCache.set(cacheKey, {
      result,
      timestamp: Date.now(),
      flowHash,
      contextHash
    });

    // Limit cache size
    if (this.validationCache.size > 100) {
      this.cleanupCache();
    }
  }

  /**
   * Generate predicate cache key
   *
   * @param predicate - State predicate
   * @param availableStates - Available states
   * @returns Cache key
   */
  private generatePredicateCacheKey(
    predicate: StatePredicate | IStatePredicate,
    availableStates: StateRecord[]
  ): string {
    const predicateHash = hashObject(predicate);
    const statesHash = hashObject(availableStates.map(s => s.id));
    return `${predicateHash}:${statesHash}`;
  }

  /**
   * Cleanup expired cache entries
   */
  private cleanupCache(): void {
    const now = Date.now();

    // Cleanup validation cache
    for (const [key, entry] of this.validationCache.entries()) {
      if (now - entry.timestamp > VALIDATION_CACHE_TTL) {
        this.validationCache.delete(key);
      }
    }

    // Cleanup predicate cache
    for (const [key, entry] of this.predicateCache.entries()) {
      if (now - entry.timestamp > PREDICATE_CACHE_TTL) {
        this.predicateCache.delete(key);
      }
    }
  }

  /**
   * Update validation metrics
   *
   * @param validationTime - Time taken for validation
   */
  private updateMetrics(validationTime: number): void {
    this.metrics.totalValidations++;

    // Update running average
    const totalValidations = this.metrics.totalValidations;
    const currentAverage = this.metrics.averageValidationTime;
    this.metrics.averageValidationTime =
      (currentAverage * (totalValidations - 1) + validationTime) / totalValidations;
  }

  // ============================================================================
  // Public API Methods
  // ============================================================================

  /**
   * Get validation metrics
   *
   * @returns Validation metrics
   */
  public getMetrics(): {
    totalValidations: number;
    cacheHits: number;
    cacheHitRate: number;
    averageValidationTime: number;
    validationsByCategory: Record<string, number>;
  } {
    return {
      ...this.metrics,
      cacheHitRate: this.metrics.totalValidations > 0
        ? this.metrics.cacheHits / this.metrics.totalValidations
        : 0
    };
  }

  /**
   * Clear all caches
   */
  public clearCache(): void {
    this.validationCache.clear();
    this.predicateCache.clear();
    this.emit('cache-cleared');
  }

  /**
   * Reset metrics
   */
  public resetMetrics(): void {
    this.metrics = {
      totalValidations: 0,
      cacheHits: 0,
      averageValidationTime: 0,
      validationsByCategory: {
        structural: 0,
        semantic: 0,
        execution: 0,
        security: 0,
        integration: 0
      }
    };
    this.emit('metrics-reset');
  }

  /**
   * Create FlowDefinition from existing data
   */
  private static fromExisting(data: IFlowDefinition): FlowDefinition {
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

    return flow;
  }
}

// ============================================================================
// Exports
// ============================================================================

export default FlowValidator;