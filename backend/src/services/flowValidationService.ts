/**
 * Flow Validation Service
 *
 * Comprehensive validation of flow definitions, preconditions, and execution readiness.
 * Ensures flow completeness and provides actionable feedback for flow authors.
 */

import { FlowDefinition, FlowStep, StatePredicate, StateRecord, UIGraph } from '../types/graph';
import { SemanticSelector, matchSemanticSelector } from '../utils/semanticSelectors';

/**
 * Validation result with detailed feedback
 */
export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  suggestions: ValidationSuggestion[];
  completeness: {
    score: number; // 0-100
    missing: string[];
    incomplete: string[];
  };
  execution: {
    readiness: 'ready' | 'partial' | 'not_ready';
    blockers: string[];
    risks: string[];
  };
}

/**
 * Validation error with severity and context
 */
export interface ValidationError {
  type: 'critical' | 'error' | 'warning';
  code: string;
  message: string;
  field?: string;
  stepIndex?: number;
  details?: any;
  fix?: string;
}

/**
 * Validation warning for potential issues
 */
export interface ValidationWarning {
  code: string;
  message: string;
  stepIndex?: number;
  details?: any;
  recommendation?: string;
}

/**
 * Improvement suggestions
 */
export interface ValidationSuggestion {
  type: 'enhancement' | 'best_practice' | 'robustness';
  message: string;
  stepIndex?: number;
  implementation?: string;
}

/**
 * Flow validation options
 */
export interface FlowValidationOptions {
  /** Check semantic selector validity */
  validateSemanticSelectors: boolean;

  /** Verify target states exist in graph */
  verifyTargetStates: boolean;

  /** Check action feasibility */
  validateActions: boolean;

  /** Analyze flow complexity and performance */
  analyzeComplexity: boolean;

  /** Suggest improvements */
  provideSuggestions: boolean;

  /** Strict validation mode */
  strict: boolean;
}

/**
 * Flow Validation Service
 */
export class FlowValidationService {
  constructor(
    private graphService: any,
    private stateService: any
  ) {}

  /**
   * Comprehensive flow validation
   */
  async validateFlow(
    flow: FlowDefinition,
    graph?: UIGraph,
    options: Partial<FlowValidationOptions> = {}
  ): Promise<ValidationResult> {
    const opts: FlowValidationOptions = {
      validateSemanticSelectors: true,
      verifyTargetStates: true,
      validateActions: true,
      analyzeComplexity: true,
      provideSuggestions: true,
      strict: false,
      ...options
    };

    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];
    const suggestions: ValidationSuggestion[] = [];

    // Basic structure validation
    this.validateBasicStructure(flow, errors);

    // Entry point validation
    await this.validateEntryPoint(flow, graph, errors, warnings);

    // Steps validation
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];
      await this.validateStep(step, i, graph, errors, warnings, suggestions, opts);
    }

    // Flow-level validation
    await this.validateFlowStructure(flow, graph, errors, warnings, suggestions, opts);

    // Complexity and performance analysis
    if (opts.analyzeComplexity) {
      this.analyzeComplexity(flow, warnings, suggestions);
    }

    // Calculate completeness score
    const completeness = this.calculateCompleteness(flow, errors, warnings);

    // Determine execution readiness
    const execution = this.assessExecutionReadiness(errors, warnings, flow);

    const isValid = errors.filter(e => e.type !== 'warning').length === 0;

    return {
      isValid,
      errors,
      warnings,
      suggestions,
      completeness,
      execution
    };
  }

  /**
   * Validate basic flow structure
   */
  private validateBasicStructure(flow: FlowDefinition, errors: ValidationError[]): void {
    // Required fields
    if (!flow.name || flow.name.trim().length === 0) {
      errors.push({
        type: 'critical',
        code: 'MISSING_NAME',
        message: 'Flow name is required',
        field: 'name',
        fix: 'Provide a descriptive name for the flow'
      });
    }

    if (!flow.packageName || flow.packageName.trim().length === 0) {
      errors.push({
        type: 'critical',
        code: 'MISSING_PACKAGE',
        message: 'Package name is required',
        field: 'packageName',
        fix: 'Specify the target Android package name'
      });
    }

    if (!flow.steps || flow.steps.length === 0) {
      errors.push({
        type: 'critical',
        code: 'NO_STEPS',
        message: 'Flow must have at least one step',
        field: 'steps',
        fix: 'Add at least one action step to the flow'
      });
    }

    if (!flow.entryPoint) {
      errors.push({
        type: 'critical',
        code: 'NO_ENTRY_POINT',
        message: 'Flow must have an entry point defined',
        field: 'entryPoint',
        fix: 'Define the starting state conditions for the flow'
      });
    }

    // Version validation
    if (!flow.version || !this.isValidVersion(flow.version)) {
      errors.push({
        type: 'error',
        code: 'INVALID_VERSION',
        message: 'Invalid version format (should be semantic version like 1.0.0)',
        field: 'version',
        fix: 'Use semantic versioning (e.g., 1.0.0, 1.1.0, 2.0.0)'
      });
    }
  }

  /**
   * Validate entry point
   */
  private async validateEntryPoint(
    flow: FlowDefinition,
    graph: UIGraph | undefined,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): Promise<void> {
    if (!flow.entryPoint) return;

    const entryPoint = flow.entryPoint;

    // Validate entry point predicate
    const predicateErrors = this.validateStatePredicate(entryPoint, 'entryPoint');
    errors.push(...predicateErrors);

    // Check if entry point exists in graph
    if (graph && entryPoint.type === 'exact' && entryPoint.stateId) {
      const stateExists = graph.states.some(s => s.id === entryPoint.stateId);
      if (!stateExists) {
        errors.push({
          type: 'error',
          code: 'ENTRY_STATE_NOT_FOUND',
          message: `Entry point state not found in graph: ${entryPoint.stateId.substring(0, 8)}...`,
          field: 'entryPoint.stateId',
          fix: 'Update entry point to use an existing state or create a new state capture'
        });
      }
    }

    // Check entry point specificity
    if (entryPoint.type === 'contains' && (!entryPoint.containsText || entryPoint.containsText.length === 0)) {
      errors.push({
        type: 'error',
        code: 'ENTRY_TOO_GENERIC',
        message: 'Entry point contains predicate is too generic',
        field: 'entryPoint.containsText',
        fix: 'Add specific text content to match for the entry point'
      });
    }
  }

  /**
   * Validate individual step
   */
  private async validateStep(
    step: FlowStep,
    stepIndex: number,
    graph: UIGraph | undefined,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[],
    options: FlowValidationOptions
  ): Promise<void> {
    // Step name validation
    if (!step.name || step.name.trim().length === 0) {
      errors.push({
        type: 'error',
        code: 'MISSING_STEP_NAME',
        message: `Step ${stepIndex + 1} is missing a name`,
        stepIndex,
        field: 'name',
        fix: 'Provide a descriptive name for this step'
      });
    }

    // Action validation
    if (options.validateActions) {
      await this.validateAction(step.action, stepIndex, errors, warnings);
    }

    // Preconditions validation
    for (let i = 0; i < step.preconditions.length; i++) {
      const precondition = step.preconditions[i];
      const predicateErrors = this.validateStatePredicate(precondition, `steps[${stepIndex}].preconditions[${i}]`);
      errors.push(...predicateErrors.map(e => ({ ...e, stepIndex })));

      // Check precondition specificity
      if (precondition.type === 'contains' && (!precondition.containsText || precondition.containsText.length === 0)) {
        warnings.push({
          code: 'VAGUE_PRECONDITION',
          message: `Step ${stepIndex + 1} has a vague precondition that might match too many states`,
          stepIndex,
          recommendation: 'Add more specific text or state conditions to the precondition'
        });
      }
    }

    // Expected state validation
    if (step.expectedState) {
      const predicateErrors = this.validateStatePredicate(step.expectedState, `steps[${stepIndex}].expectedState`);
      errors.push(...predicateErrors.map(e => ({ ...e, stepIndex })));

      // Check if expected state exists in graph
      if (graph && step.expectedState.type === 'exact' && step.expectedState.stateId) {
        const stateExists = graph.states.some(s => s.id === step.expectedState!.stateId);
        if (!stateExists) {
          warnings.push({
            code: 'EXPECTED_STATE_NOT_FOUND',
            message: `Expected state for step ${stepIndex + 1} not found in graph`,
            stepIndex,
            recommendation: 'Capture the expected state or update the expected state predicate'
          });
        }
      }
    }

    // Timeout validation
    if (step.timeout && (step.timeout < 1000 || step.timeout > 60000)) {
      warnings.push({
        code: 'UNUSUAL_TIMEOUT',
        message: `Step ${stepIndex + 1} has an unusual timeout: ${step.timeout}ms`,
        stepIndex,
        recommendation: 'Consider using a timeout between 1-60 seconds for most actions'
      });
    }

    // Critical step validation
    if (step.critical && !step.expectedState) {
      warnings.push({
        code: 'CRITICAL_NO_VERIFICATION',
        message: `Step ${stepIndex + 1} is marked as critical but has no expected state verification`,
        stepIndex,
        recommendation: 'Add an expected state to verify critical step completion'
      });
    }

    // Semantic selector validation
    if (options.validateSemanticSelectors && step.action.semanticSelector) {
      this.validateSemanticSelector(step.action.semanticSelector, stepIndex, errors, warnings);
    }
  }

  /**
   * Validate action configuration
   */
  private async validateAction(
    action: any,
    stepIndex: number,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): Promise<void> {
    switch (action.type) {
      case 'tap':
      case 'long_press':
        if (!action.target && !action.semanticSelector) {
          errors.push({
            type: 'error',
            code: 'MISSING_TARGET',
            message: `Step ${stepIndex + 1} ${action.type} action requires a target`,
            stepIndex,
            field: 'action.target',
            fix: 'Specify the target element using coordinates, selector, or semantic selector'
          });
        }
        break;

      case 'type':
        if (!action.text) {
          errors.push({
            type: 'error',
            code: 'MISSING_TEXT',
            message: `Step ${stepIndex + 1} type action requires text to type`,
            stepIndex,
            field: 'action.text',
            fix: 'Specify the text to be typed into the input field'
          });
        }
        if (!action.target && !action.semanticSelector) {
          errors.push({
            type: 'error',
            code: 'MISSING_INPUT_TARGET',
            message: `Step ${stepIndex + 1} type action requires an input field target`,
            stepIndex,
            field: 'action.target',
            fix: 'Specify the target input field'
          });
        }
        break;

      case 'swipe':
        if (!action.swipe) {
          errors.push({
            type: 'error',
            code: 'MISSING_SWIPE_CONFIG',
            message: `Step ${stepIndex + 1} swipe action requires swipe configuration`,
            stepIndex,
            field: 'action.swipe',
            fix: 'Specify swipe direction and distance'
          });
        } else {
          if (!action.swipe.direction || !['up', 'down', 'left', 'right'].includes(action.swipe.direction)) {
            errors.push({
              type: 'error',
              code: 'INVALID_SWIPE_DIRECTION',
              message: `Step ${stepIndex + 1} has invalid swipe direction`,
              stepIndex,
              field: 'action.swipe.direction',
              fix: 'Use one of: up, down, left, right'
            });
          }
          if (!action.swipe.distance || action.swipe.distance < 10) {
            warnings.push({
              code: 'SHORT_SWIPE_DISTANCE',
              message: `Step ${stepIndex + 1} has a very short swipe distance`,
              stepIndex,
              recommendation: 'Use a distance of at least 50 pixels for reliable swipe detection'
            });
          }
        }
        break;

      case 'intent':
        if (!action.intent || !action.intent.action) {
          errors.push({
            type: 'error',
            code: 'MISSING_INTENT_ACTION',
            message: `Step ${stepIndex + 1} intent action requires intent configuration`,
            stepIndex,
            field: 'action.intent',
            fix: 'Specify the intent action and optionally package/component'
          });
        }
        break;
    }
  }

  /**
   * Validate state predicate
   */
  private validateStatePredicate(predicate: StatePredicate, field: string): ValidationError[] {
    const errors: ValidationError[] = [];

    if (!predicate.type) {
      errors.push({
        type: 'error',
        code: 'MISSING_PREDICATE_TYPE',
        message: 'State predicate is missing type',
        field,
        fix: 'Specify predicate type: exact, contains, matches, or fuzzy'
      });
      return errors;
    }

    switch (predicate.type) {
      case 'exact':
        if (!predicate.stateId) {
          errors.push({
            type: 'error',
            code: 'MISSING_STATE_ID',
            message: 'Exact predicate requires a state ID',
            field: `${field}.stateId`,
            fix: 'Specify the exact state ID to match'
          });
        }
        break;

      case 'contains':
        if (!predicate.containsText || predicate.containsText.length === 0) {
          errors.push({
            type: 'error',
            code: 'MISSING_CONTAINS_TEXT',
            message: 'Contains predicate requires text to match',
            field: `${field}.containsText`,
            fix: 'Specify text content that should be present in the state'
          });
        }
        break;

      case 'matches':
        if (!predicate.matches) {
          errors.push({
            type: 'error',
            code: 'MISSING_MATCHES_PATTERN',
            message: 'Matches predicate requires pattern configuration',
            field: `${field}.matches`,
            fix: 'Specify activity, text, or selector patterns to match'
          });
        }
        break;

      case 'fuzzy':
        if (predicate.fuzzyThreshold === undefined || predicate.fuzzyThreshold < 0 || predicate.fuzzyThreshold > 1) {
          errors.push({
            type: 'error',
            code: 'INVALID_FUZZY_THRESHOLD',
            message: 'Fuzzy predicate requires a valid threshold (0-1)',
            field: `${field}.fuzzyThreshold`,
            fix: 'Specify a similarity threshold between 0 and 1'
          });
        }
        break;
    }

    return errors;
  }

  /**
   * Validate semantic selector
   */
  private validateSemanticSelector(
    semanticSelector: any,
    stepIndex: number,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): void {
    if (!semanticSelector.semanticType && !semanticSelector.purpose) {
      warnings.push({
        code: 'VAGUE_SEMANTIC_SELECTOR',
        message: `Step ${stepIndex + 1} semantic selector lacks specific type or purpose`,
        stepIndex,
        recommendation: 'Define semantic type and purpose for better element matching'
      });
    }

    if (semanticSelector.confidence !== undefined && (semanticSelector.confidence < 0 || semanticSelector.confidence > 1)) {
      errors.push({
        type: 'error',
        code: 'INVALID_SEMANTIC_CONFIDENCE',
        message: `Step ${stepIndex + 1} has invalid semantic selector confidence`,
        stepIndex,
        field: 'action.semanticSelector.confidence',
        fix: 'Confidence must be between 0 and 1'
      });
    }
  }

  /**
   * Validate overall flow structure
   */
  private async validateFlowStructure(
    flow: FlowDefinition,
    graph: UIGraph | undefined,
    errors: ValidationError[],
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[],
    options: FlowValidationOptions
  ): Promise<void> {
    // Check for duplicate step names
    const stepNames = flow.steps.map(s => s.name).filter(Boolean);
    const duplicates = stepNames.filter((name, index) => stepNames.indexOf(name) !== index);
    if (duplicates.length > 0) {
      warnings.push({
        code: 'DUPLICATE_STEP_NAMES',
        message: `Flow has duplicate step names: ${duplicates.join(', ')}`,
        recommendation: 'Use unique names for each step to avoid confusion'
      });
    }

    // Check flow complexity
    if (flow.steps.length > 20) {
      warnings.push({
        code: 'COMPLEX_FLOW',
        message: `Flow has ${flow.steps.length} steps, which may be difficult to maintain`,
        recommendation: 'Consider breaking complex flows into smaller, reusable sub-flows'
      });
    }

    // Check for missing descriptions
    const stepsWithoutDescription = flow.steps.filter(s => !s.description).length;
    if (stepsWithoutDescription > flow.steps.length * 0.5) {
      suggestions.push({
        type: 'best_practice',
        message: 'Add descriptions to steps for better documentation',
        implementation: 'Fill in the description field for each step to explain what it does'
      });
    }

    // Check for missing exit point
    if (!flow.exitPoint && flow.steps.length > 1) {
      suggestions.push({
        type: 'enhancement',
        message: 'Consider adding an exit point to verify flow completion',
        implementation: 'Define expected final state conditions for the flow'
      });
    }

    // Verify state transitions are possible
    if (graph && options.verifyTargetStates) {
      await this.verifyStateTransitions(flow, graph, warnings);
    }
  }

  /**
   * Verify state transitions exist in graph
   */
  private async verifyStateTransitions(
    flow: FlowDefinition,
    graph: UIGraph,
    warnings: ValidationWarning[]
  ): Promise<void> {
    for (let i = 0; i < flow.steps.length; i++) {
      const step = flow.steps[i];

      // Check expected states
      if (step.expectedState && step.expectedState.type === 'exact' && step.expectedState.stateId) {
        const stateExists = graph.states.some(s => s.id === step.expectedState!.stateId);
        if (!stateExists) {
          warnings.push({
            code: 'UNVERIFIABLE_EXPECTED_STATE',
            message: `Step ${i + 1} expected state not found in current graph`,
            recommendation: 'Capture additional states or use more flexible expected state conditions'
          });
        }
      }

      // Check preconditions
      for (const precondition of step.preconditions) {
        if (precondition.type === 'exact' && precondition.stateId) {
          const stateExists = graph.states.some(s => s.id === precondition.stateId);
          if (!stateExists) {
            warnings.push({
              code: 'UNVERIFIABLE_PRECONDITION',
              message: `Step ${i + 1} precondition state not found in current graph`,
              recommendation: 'Update preconditions to use existing states or capture additional states'
            });
          }
        }
      }
    }
  }

  /**
   * Analyze flow complexity
   */
  private analyzeComplexity(
    flow: FlowDefinition,
    warnings: ValidationWarning[],
    suggestions: ValidationSuggestion[]
  ): void {
    // Calculate complexity score
    let complexityScore = 0;
    complexityScore += flow.steps.length * 2;
    complexityScore += flow.steps.filter(s => s.preconditions.length > 0).length * 3;
    complexityScore += flow.steps.filter(s => s.expectedState).length * 2;
    complexityScore += flow.steps.filter(s => s.critical).length * 1;

    // Update flow metadata
    flow.metadata.complexity = Math.round(complexityScore);

    if (complexityScore > 50) {
      warnings.push({
        code: 'HIGH_COMPLEXITY',
        message: `Flow has high complexity score (${complexityScore})`,
        recommendation: 'Consider simplifying the flow or breaking it into smaller flows'
      });
    }

    // Suggest improvements for high complexity
    if (complexityScore > 30) {
      suggestions.push({
        type: 'best_practice',
        message: 'Consider adding more detailed step descriptions for complex flows',
        implementation: 'Document each step\'s purpose and expected outcomes'
      });
    }
  }

  /**
   * Calculate completeness score
   */
  private calculateCompleteness(
    flow: FlowDefinition,
    errors: ValidationError[],
    warnings: ValidationWarning[]
  ): ValidationResult['completeness'] {
    let score = 100;
    const missing: string[] = [];
    const incomplete: string[] = [];

    // Deduct points for errors
    score -= errors.filter(e => e.type === 'critical').length * 20;
    score -= errors.filter(e => e.type === 'error').length * 10;

    // Deduct points for warnings
    score -= warnings.length * 5;

    // Check missing elements
    if (!flow.description) {
      score -= 5;
      missing.push('description');
    }

    const stepsWithoutDescription = flow.steps.filter(s => !s.description).length;
    if (stepsWithoutDescription > 0) {
      score -= stepsWithoutDescription * 2;
      incomplete.push(`${stepsWithoutDescription} step descriptions`);
    }

    const stepsWithoutExpectedState = flow.steps.filter(s => !s.expectedState).length;
    if (stepsWithoutExpectedState > 0) {
      score -= stepsWithoutExpectedState;
      incomplete.push(`${stepsWithoutExpectedState} step verifications`);
    }

    if (!flow.exitPoint) {
      score -= 5;
      missing.push('exit point');
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      missing,
      incomplete
    };
  }

  /**
   * Assess execution readiness
   */
  private assessExecutionReadiness(
    errors: ValidationError[],
    warnings: ValidationWarning[],
    flow: FlowDefinition
  ): ValidationResult['execution'] {
    const blockers = errors
      .filter(e => e.type === 'critical')
      .map(e => e.message);

    const risks = [
      ...errors.filter(e => e.type === 'error').map(e => e.message),
      ...warnings.map(w => w.message)
    ];

    let readiness: 'ready' | 'partial' | 'not_ready';
    if (blockers.length > 0) {
      readiness = 'not_ready';
    } else if (risks.length > 0) {
      readiness = 'partial';
    } else {
      readiness = 'ready';
    }

    return {
      readiness,
      blockers,
      risks
    };
  }

  /**
   * Validate semantic version format
   */
  private isValidVersion(version: string): boolean {
    const semanticVersionRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9-]+)?(\+[a-zA-Z0-9-]+)?$/;
    return semanticVersionRegex.test(version);
  }

  /**
   * Quick validation for flow editor
   */
  quickValidate(flow: FlowDefinition): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!flow.name || flow.name.trim().length === 0) {
      errors.push('Flow name is required');
    }

    if (!flow.steps || flow.steps.length === 0) {
      errors.push('Flow must have at least one step');
    } else {
      flow.steps.forEach((step, index) => {
        if (!step.name || step.name.trim().length === 0) {
          errors.push(`Step ${index + 1} name is required`);
        }

        if (!step.action.type) {
          errors.push(`Step ${index + 1} action type is required`);
        }

        if (step.action.type === 'tap' && !step.action.target && !step.action.semanticSelector) {
          errors.push(`Step ${index + 1} tap action requires a target`);
        }

        if (step.action.type === 'type' && (!step.action.text || (!step.action.target && !step.action.semanticSelector))) {
          errors.push(`Step ${index + 1} type action requires text and target`);
        }
      });
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }
}