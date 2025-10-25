/**
 * AutoApp UI Map & Intelligent Flow Engine - State Predicate Model
 *
 * State predicate entity for flexible state matching and evaluation.
 * Supports exact, contains, matches, and fuzzy matching strategies with
 * confidence scoring and performance optimization.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md and task T043 requirements.
 */

import {
  StatePredicate as IStatePredicate,
  PredicateType,
  ValidationResult,
  ValidationError,
  ValidationWarning,
  State as IState,
  Selector as ISelector
} from '../types/models';

import { calculateTextSimilarity, calculateJaccardSimilarity } from '../utils/hash';

// ============================================================================
// Configuration and Constants
// ============================================================================

/** Default fuzzy matching threshold */
const DEFAULT_FUZZY_THRESHOLD = 0.8;

/** Minimum fuzzy matching threshold */
const MIN_FUZZY_THRESHOLD = 0.1;

/** Maximum fuzzy matching threshold */
const MAX_FUZZY_THRESHOLD = 1.0;

/** State predicate schema version */
const STATE_PREDICATE_SCHEMA_VERSION = '1.0.0';

/** Default confidence score for successful matches */
const DEFAULT_MATCH_CONFIDENCE = 1.0;

/** Minimum confidence score for valid matches */
const MIN_MATCH_CONFIDENCE = 0.0;

/** Maximum confidence score for matches */
const MAX_MATCH_CONFIDENCE = 1.0;

/** Maximum number of predicates to evaluate in batch before optimization */
const BATCH_EVALUATION_THRESHOLD = 100;

// ============================================================================
// Predicate Evaluation Result
// ============================================================================

/**
 * Result of predicate evaluation with detailed scoring
 */
export interface PredicateEvaluationResult {
  /** Whether the predicate matched */
  matched: boolean;

  /** Confidence score for the match (0-1) */
  confidence: number;

  /** Individual factor scores */
  factors: {
    stateId?: number;
    activity?: number;
    textContent?: number;
    selectors?: number;
  };

  /** Matched patterns or criteria */
  matchedCriteria: string[];

  /** Evaluation duration in milliseconds */
  duration: number;

  /** Detailed debug information */
  debug?: {
    stateIdMatch?: boolean;
    activityMatch?: boolean;
    textMatches?: string[];
    selectorMatches?: string[];
    fuzzyDetails?: {
      similarityScore: number;
      threshold: number;
      comparedElements: string[];
    };
  };

  /** Performance metrics */
  performance?: {
    cacheHit?: boolean;
    optimized?: boolean;
    batchIndex?: number;
  };
}

// ============================================================================
// Predicate Comparison Result
// ============================================================================

/**
 * Result of predicate similarity comparison
 */
export interface PredicateComparisonResult {
  /** Similarity score (0-1) */
  similarity: number;

  /** Matching factors */
  factors: {
    predicateType: boolean;
    stateId: boolean;
    activity: boolean;
    textPatterns: boolean;
    selectors: boolean;
  };

  /** Differences between predicates */
  differences: string[];

  /** Recommended action */
  recommendation: 'identical' | 'similar' | 'different';
}

// ============================================================================
// Batch Evaluation Context
// ============================================================================

/**
 * Context for batch predicate evaluation with optimization
 */
export interface BatchEvaluationContext {
  /** Array of states to evaluate against */
  states: IState[];

  /** Array of predicates to evaluate */
  predicates: IStatePredicate[];

  /** Evaluation options */
  options: {
    /** Enable caching for repeated evaluations */
    enableCaching?: boolean;

    /** Enable performance optimizations */
    enableOptimizations?: boolean;

    /** Minimum confidence threshold */
    minConfidence?: number;

    /** Enable detailed debug output */
    enableDebug?: boolean;

    /** Progress callback for large batches */
    onProgress?: (completed: number, total: number) => void;
  };
}

// ============================================================================
// State Predicate Entity Class
// ============================================================================

/**
 * State predicate entity for flexible state matching
 *
 * This class provides comprehensive state matching capabilities with multiple
 * strategies, confidence scoring, and performance optimization for large-scale
 * flow execution scenarios.
 */
export class StatePredicate implements IStatePredicate {
  // ========================================================================
  // Core Properties
  // ========================================================================

  /** Matching strategy type */
  public readonly type: PredicateType;

  /** Direct state reference for exact matching */
  public readonly stateId?: string;

  /** Activity name constraint */
  public readonly activity?: string;

  /** Required text fragments */
  public readonly containsText?: string[];

  /** Regular expression patterns */
  public readonly matches?: {
    activity?: string;
    text?: string;
    selectors?: string;
  };

  /** Fuzzy matching threshold */
  public readonly fuzzyThreshold: number;

  /** Sub-selector hints */
  public readonly hasSelectors?: Array<{
    rid?: string;
    text?: string;
    desc?: string;
  }>;

  /** Schema version */
  public readonly version: string = STATE_PREDICATE_SCHEMA_VERSION;

  // ========================================================================
  // Private State
  // ========================================================================

  /** Cached compiled regex patterns */
  private _compiledPatterns?: {
    activity?: RegExp;
    text?: RegExp;
    selectors?: RegExp;
  };

  /** Validation cache */
  private _validationCache?: ValidationResult;

  /** Performance statistics */
  private _performanceStats = {
    evaluationCount: 0,
    totalDuration: 0,
    cacheHits: 0,
    averageConfidence: 0
  };

  // ========================================================================
  // Constructor
  // ========================================================================

  /**
   * Create a new StatePredicate instance
   *
   * @param data - Predicate data
   */
  constructor(data: IStatePredicate) {
    // Validate predicate type
    this.validatePredicateType(data.type);
    this.type = data.type;

    // Set optional properties
    this.stateId = data.stateId;
    this.activity = data.activity;
    this.containsText = data.containsText;
    this.matches = data.matches;
    this.hasSelectors = data.hasSelectors;

    // Validate and set fuzzy threshold
    this.fuzzyThreshold = this.normalizeFuzzyThreshold(data.fuzzyThreshold);

    // Compile regex patterns if provided
    if (this.matches) {
      this._compiledPatterns = this.compileRegexPatterns(this.matches);
    }

    // Validate the complete predicate
    this.validate();
  }

  // ========================================================================
  // Static Factory Methods
  // ========================================================================

  /**
   * Create an exact match predicate for a specific state
   *
   * @param stateId - State identifier to match exactly
   * @returns New StatePredicate instance
   */
  static exactState(stateId: string): StatePredicate {
    return new StatePredicate({
      type: 'exact',
      stateId
    });
  }

  /**
   * Create an activity-based predicate
   *
   * @param activity - Activity name to match
   * @param type - Matching type (default: exact)
   * @returns New StatePredicate instance
   */
  static activity(activity: string, type: PredicateType = 'exact'): StatePredicate {
    return new StatePredicate({
      type,
      activity
    });
  }

  /**
   * Create a text content predicate
   *
   * @param textFragments - Text fragments that must be present
   * @param type - Matching type (default: contains)
   * @returns New StatePredicate instance
   */
  static textContent(textFragments: string[], type: PredicateType = 'contains'): StatePredicate {
    return new StatePredicate({
      type,
      containsText: textFragments
    });
  }

  /**
   * Create a regex pattern predicate
   *
   * @param patterns - Regex patterns for matching
   * @returns New StatePredicate instance
   */
  static regex(patterns: {
    activity?: string;
    text?: string;
    selectors?: string;
  }): StatePredicate {
    return new StatePredicate({
      type: 'matches',
      matches: patterns
    });
  }

  /**
   * Create a fuzzy matching predicate
   *
   * @param criteria - Matching criteria
   * @param threshold - Fuzzy matching threshold
   * @returns New StatePredicate instance
   */
  static fuzzy(
    criteria: {
      activity?: string;
      containsText?: string[];
      hasSelectors?: Array<{ rid?: string; text?: string; desc?: string }>;
    },
    threshold: number = DEFAULT_FUZZY_THRESHOLD
  ): StatePredicate {
    return new StatePredicate({
      type: 'fuzzy',
      ...criteria,
      fuzzyThreshold: threshold
    });
  }

  /**
   * Create a selector-based predicate
   *
   * @param selectors - Selectors that must be present
   * @param type - Matching type (default: contains)
   * @returns New StatePredicate instance
   */
  static selectors(
    selectors: Array<{ rid?: string; text?: string; desc?: string }>,
    type: PredicateType = 'contains'
  ): StatePredicate {
    return new StatePredicate({
      type,
      hasSelectors: selectors
    });
  }

  // ========================================================================
  // Evaluation Methods
  // ========================================================================

  /**
   * Evaluate this predicate against a state
   *
   * @param state - State to evaluate against
   * @param options - Evaluation options
   * @returns Detailed evaluation result
   */
  public evaluate(
    state: IState,
    options: {
      enableDebug?: boolean;
      minConfidence?: number;
    } = {}
  ): PredicateEvaluationResult {
    const startTime = performance.now();
    const minConfidence = options.minConfidence ?? MIN_MATCH_CONFIDENCE;

    try {
      const result = this.performEvaluation(state, options.enableDebug);
      result.duration = performance.now() - startTime;

      // Update performance statistics
      this.updatePerformanceStats(result);

      // Apply minimum confidence threshold
      result.matched = result.matched && result.confidence >= minConfidence;

      return result;
    } catch (error) {
      return {
        matched: false,
        confidence: 0.0,
        factors: {},
        matchedCriteria: [],
        duration: performance.now() - startTime
      };
    }
  }

  /**
   * Perform the actual predicate evaluation
   *
   * @param state - State to evaluate
   * @param enableDebug - Enable debug output
   * @returns Evaluation result
   */
  private performEvaluation(state: IState, enableDebug?: boolean): PredicateEvaluationResult {
    const result: PredicateEvaluationResult = {
      matched: false,
      confidence: 0.0,
      factors: {},
      matchedCriteria: [],
      duration: 0,
      debug: enableDebug ? {} : undefined
    };

    switch (this.type) {
      case 'exact':
        return this.evaluateExactMatch(state, result);
      case 'contains':
        return this.evaluateContainsMatch(state, result);
      case 'matches':
        return this.evaluateRegexMatch(state, result);
      case 'fuzzy':
        return this.evaluateFuzzyMatch(state, result);
      default:
        throw new Error(`Unsupported predicate type: ${this.type}`);
    }
  }

  /**
   * Evaluate exact match predicate
   *
   * @param state - State to evaluate
   * @param result - Result object to update
   * @returns Evaluation result
   */
  private evaluateExactMatch(state: IState, result: PredicateEvaluationResult): PredicateEvaluationResult {
    if (this.stateId) {
      result.factors.stateId = state.id === this.stateId ? 1.0 : 0.0;
      if (result.debug) {
        result.debug.stateIdMatch = state.id === this.stateId;
      }

      if (state.id === this.stateId) {
        result.matched = true;
        result.confidence = 1.0;
        result.matchedCriteria.push('stateId');
      }
    }

    // If no stateId specified, fall back to exact activity matching
    if (!this.stateId && this.activity) {
      result.factors.activity = state.activity === this.activity ? 1.0 : 0.0;
      if (state.activity === this.activity) {
        result.matched = true;
        result.confidence = 1.0;
        result.matchedCriteria.push('activity');
      }
    }

    return result;
  }

  /**
   * Evaluate contains match predicate
   *
   * @param state - State to evaluate
   * @param result - Result object to update
   * @returns Evaluation result
   */
  private evaluateContainsMatch(state: IState, result: PredicateEvaluationResult): PredicateEvaluationResult {
    let totalScore = 0;
    let factorCount = 0;

    // Check activity match
    if (this.activity) {
      const activityScore = state.activity.includes(this.activity) ? 1.0 : 0.0;
      result.factors.activity = activityScore;
      totalScore += activityScore;
      factorCount++;

      if (activityScore > 0) {
        result.matchedCriteria.push('activity');
      }
    }

    // Check text content matches
    if (this.containsText && this.containsText.length > 0) {
      const stateText = state.visibleText || [];
      const matchingTexts = this.containsText.filter(text =>
        stateText.some(stateTextItem =>
          stateTextItem.toLowerCase().includes(text.toLowerCase())
        )
      );

      const textScore = matchingTexts.length / this.containsText.length;
      result.factors.textContent = textScore;
      totalScore += textScore;
      factorCount++;

      if (textScore > 0) {
        result.matchedCriteria.push('text');
        if (result.debug) {
          result.debug.textMatches = matchingTexts;
        }
      }
    }

    // Check selector matches
    if (this.hasSelectors && this.hasSelectors.length > 0) {
      const matchingSelectors = this.hasSelectors.filter(predicateSelector =>
        state.selectors.some(stateSelector =>
          this.matchesSelector(stateSelector, predicateSelector)
        )
      );

      const selectorScore = matchingSelectors.length / this.hasSelectors.length;
      result.factors.selectors = selectorScore;
      totalScore += selectorScore;
      factorCount++;

      if (selectorScore > 0) {
        result.matchedCriteria.push('selectors');
        if (result.debug) {
          result.debug.selectorMatches = matchingSelectors.map(s =>
            s.rid || s.text || s.desc || 'unknown'
          );
        }
      }
    }

    // Calculate overall confidence
    result.confidence = factorCount > 0 ? totalScore / factorCount : 0.0;
    result.matched = result.confidence > 0;

    return result;
  }

  /**
   * Evaluate regex match predicate
   *
   * @param state - State to evaluate
   * @param result - Result object to update
   * @returns Evaluation result
   */
  private evaluateRegexMatch(state: IState, result: PredicateEvaluationResult): PredicateEvaluationResult {
    if (!this._compiledPatterns) {
      throw new Error('Regex patterns not compiled');
    }

    let totalScore = 0;
    let factorCount = 0;

    // Check activity regex
    if (this._compiledPatterns.activity) {
      const activityScore = this._compiledPatterns.activity.test(state.activity) ? 1.0 : 0.0;
      result.factors.activity = activityScore;
      totalScore += activityScore;
      factorCount++;

      if (activityScore > 0) {
        result.matchedCriteria.push('activity');
      }
    }

    // Check text regex
    if (this._compiledPatterns.text && state.visibleText) {
      const textMatches = state.visibleText.filter(text =>
        this._compiledPatterns!.text!.test(text)
      );

      const textScore = textMatches.length > 0 ? 1.0 : 0.0;
      result.factors.textContent = textScore;
      totalScore += textScore;
      factorCount++;

      if (textScore > 0) {
        result.matchedCriteria.push('text');
        if (result.debug) {
          result.debug.textMatches = textMatches;
        }
      }
    }

    // Check selectors regex
    if (this._compiledPatterns.selectors && state.selectors) {
      const selectorMatches = state.selectors.filter(selector =>
        this._compiledPatterns!.selectors!.test(JSON.stringify(selector))
      );

      const selectorScore = selectorMatches.length > 0 ? 1.0 : 0.0;
      result.factors.selectors = selectorScore;
      totalScore += selectorScore;
      factorCount++;

      if (selectorScore > 0) {
        result.matchedCriteria.push('selectors');
        if (result.debug) {
          result.debug.selectorMatches = selectorMatches.map(s =>
            s.rid || s.text || s.desc || 'unknown'
          );
        }
      }
    }

    // Calculate overall confidence
    result.confidence = factorCount > 0 ? totalScore / factorCount : 0.0;
    result.matched = result.confidence > 0;

    return result;
  }

  /**
   * Evaluate fuzzy match predicate
   *
   * @param state - State to evaluate
   * @param result - Result object to update
   * @returns Evaluation result
   */
  private evaluateFuzzyMatch(state: IState, result: PredicateEvaluationResult): PredicateEvaluationResult {
    let totalScore = 0;
    let factorCount = 0;
    const comparedElements: string[] = [];

    // Fuzzy activity matching
    if (this.activity) {
      const activitySimilarity = this.calculateStringSimilarity(state.activity, this.activity);
      result.factors.activity = activitySimilarity;
      totalScore += activitySimilarity;
      factorCount++;
      comparedElements.push(`activity: ${activitySimilarity.toFixed(3)}`);

      if (activitySimilarity >= this.fuzzyThreshold) {
        result.matchedCriteria.push('activity');
      }
    }

    // Fuzzy text matching
    if (this.containsText && this.containsText.length > 0 && state.visibleText) {
      const textSimilarities = this.containsText.map(predicateText => {
        const bestMatch = state.visibleText!.reduce((best, stateText) => {
          const similarity = this.calculateStringSimilarity(
            stateText.toLowerCase(),
            predicateText.toLowerCase()
          );
          return similarity > best.similarity ? { text: stateText, similarity } : best;
        }, { text: '', similarity: 0 });

        return bestMatch.similarity;
      });

      const avgTextSimilarity = textSimilarities.reduce((sum, sim) => sum + sim, 0) / textSimilarities.length;
      result.factors.textContent = avgTextSimilarity;
      totalScore += avgTextSimilarity;
      factorCount++;
      comparedElements.push(`text: ${avgTextSimilarity.toFixed(3)}`);

      if (avgTextSimilarity >= this.fuzzyThreshold) {
        result.matchedCriteria.push('text');
      }
    }

    // Fuzzy selector matching
    if (this.hasSelectors && this.hasSelectors.length > 0) {
      const selectorSimilarities = this.hasSelectors.map(predicateSelector => {
        const bestMatch = state.selectors.reduce((best, stateSelector) => {
          const similarity = this.calculateSelectorSimilarity(stateSelector, predicateSelector);
          return similarity > best.similarity ? { selector: stateSelector, similarity } : best;
        }, { selector: null as ISelector | null, similarity: 0 });

        return bestMatch.similarity;
      });

      const avgSelectorSimilarity = selectorSimilarities.reduce((sum, sim) => sum + sim, 0) / selectorSimilarities.length;
      result.factors.selectors = avgSelectorSimilarity;
      totalScore += avgSelectorSimilarity;
      factorCount++;
      comparedElements.push(`selectors: ${avgSelectorSimilarity.toFixed(3)}`);

      if (avgSelectorSimilarity >= this.fuzzyThreshold) {
        result.matchedCriteria.push('selectors');
      }
    }

    // Calculate overall confidence
    result.confidence = factorCount > 0 ? totalScore / factorCount : 0.0;
    result.matched = result.confidence >= this.fuzzyThreshold;

    if (result.debug) {
      result.debug.fuzzyDetails = {
        similarityScore: result.confidence,
        threshold: this.fuzzyThreshold,
        comparedElements
      };
    }

    return result;
  }

  // ========================================================================
  // Utility Methods
  // ========================================================================

  /**
   * Check if a state selector matches a predicate selector
   *
   * @param stateSelector - Selector from the state
   * @param predicateSelector - Selector from the predicate
   * @returns True if selectors match
   */
  private matchesSelector(
    stateSelector: ISelector,
    predicateSelector: { rid?: string; text?: string; desc?: string }
  ): boolean {
    if (predicateSelector.rid && stateSelector.rid !== predicateSelector.rid) {
      return false;
    }
    if (predicateSelector.text && stateSelector.text !== predicateSelector.text) {
      return false;
    }
    if (predicateSelector.desc && stateSelector.desc !== predicateSelector.desc) {
      return false;
    }
    return true;
  }

  /**
   * Calculate string similarity using Jaccard similarity on character n-grams
   *
   * @param str1 - First string
   * @param str2 - Second string
   * @returns Similarity score (0-1)
   */
  private calculateStringSimilarity(str1: string, str2: string): number {
    if (str1 === str2) return 1.0;
    if (!str1 || !str2) return 0.0;

    // Use character bigrams for similarity
    const getBigrams = (str: string): Set<string> => {
      const bigrams = new Set<string>();
      for (let i = 0; i < str.length - 1; i++) {
        bigrams.add(str.substring(i, i + 2).toLowerCase());
      }
      return bigrams;
    };

    const bigrams1 = getBigrams(str1);
    const bigrams2 = getBigrams(str2);

    const intersection = new Set([...bigrams1].filter(x => bigrams2.has(x)));
    const union = new Set([...bigrams1, ...bigrams2]);

    return union.size > 0 ? intersection.size / union.size : 0.0;
  }

  /**
   * Calculate selector similarity
   *
   * @param selector1 - First selector
   * @param selector2 - Second selector
   * @returns Similarity score (0-1)
   */
  private calculateSelectorSimilarity(
    selector1: ISelector,
    selector2: { rid?: string; text?: string; desc?: string }
  ): number {
    let matches = 0;
    let total = 0;

    if (selector2.rid) {
      total++;
      if (selector1.rid === selector2.rid) matches++;
    }

    if (selector2.text) {
      total++;
      if (selector1.text === selector2.text) matches++;
      else if (selector1.text && selector2.text) {
        matches += this.calculateStringSimilarity(selector1.text, selector2.text);
      }
    }

    if (selector2.desc) {
      total++;
      if (selector1.desc === selector2.desc) matches++;
      else if (selector1.desc && selector2.desc) {
        matches += this.calculateStringSimilarity(selector1.desc, selector2.desc);
      }
    }

    return total > 0 ? matches / total : 0.0;
  }

  /**
   * Compile regex patterns for efficient matching
   *
   * @param patterns - Patterns to compile
   * @returns Compiled regex patterns
   */
  private compileRegexPatterns(patterns: {
    activity?: string;
    text?: string;
    selectors?: string;
  }): {
    activity?: RegExp;
    text?: RegExp;
    selectors?: RegExp;
  } {
    const compiled: any = {};

    try {
      if (patterns.activity) {
        compiled.activity = new RegExp(patterns.activity, 'i');
      }
      if (patterns.text) {
        compiled.text = new RegExp(patterns.text, 'i');
      }
      if (patterns.selectors) {
        compiled.selectors = new RegExp(patterns.selectors, 'i');
      }
    } catch (error) {
      throw new Error(`Invalid regex pattern: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    return compiled;
  }

  // ========================================================================
  // Validation Methods
  // ========================================================================

  /**
   * Validate predicate type
   *
   * @param type - Predicate type to validate
   * @throws Error if type is invalid
   */
  private validatePredicateType(type: PredicateType): void {
    const validTypes: PredicateType[] = ['exact', 'contains', 'matches', 'fuzzy'];
    if (!validTypes.includes(type)) {
      throw new Error(`Invalid predicate type: ${type}. Must be one of: ${validTypes.join(', ')}`);
    }
  }

  /**
   * Normalize fuzzy threshold to valid range
   *
   * @param threshold - Threshold to normalize
   * @returns Normalized threshold
   */
  private normalizeFuzzyThreshold(threshold?: number): number {
    if (threshold === undefined || threshold === null) {
      return DEFAULT_FUZZY_THRESHOLD;
    }

    if (typeof threshold !== 'number') {
      throw new Error('Fuzzy threshold must be a number');
    }

    return Math.max(MIN_FUZZY_THRESHOLD, Math.min(MAX_FUZZY_THRESHOLD, threshold));
  }

  
  /**
   * Validate predicate and return detailed result
   *
   * @returns Validation result
   */
  public validate(): ValidationResult {
    if (this._validationCache) {
      return this._validationCache;
    }

    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    try {
      // Basic structure validation
      if (!this.type) {
        errors.push({
          field: 'type',
          message: 'Predicate type is required',
          code: 'MISSING_TYPE',
          severity: 'error'
        });
      }

      // Type-specific validation
      if (this.type === 'exact' && !this.stateId && !this.activity) {
        errors.push({
          field: 'exact',
          message: 'Exact match predicate must specify either stateId or activity',
          code: 'INVALID_EXACT_MATCH',
          severity: 'error'
        });
      }

      if (this.type === 'contains' &&
          !this.activity &&
          (!this.containsText || this.containsText.length === 0) &&
          (!this.hasSelectors || this.hasSelectors.length === 0)) {
        errors.push({
          field: 'contains',
          message: 'Contains match predicate must specify activity, containsText, or hasSelectors',
          code: 'INVALID_CONTAINS_MATCH',
          severity: 'error'
        });
      }

      // Warnings
      if (this.type === 'fuzzy' && this.fuzzyThreshold < 0.5) {
        warnings.push({
          field: 'fuzzyThreshold',
          message: 'Low fuzzy threshold may result in many false positives',
          code: 'LOW_FUZZY_THRESHOLD',
          value: this.fuzzyThreshold,
          severity: 'warning'
        });
      }

      if (this.type === 'exact' && this.stateId && this.activity) {
        warnings.push({
          field: 'criteria',
          message: 'Exact match with both stateId and activity - stateId will take precedence',
          code: 'REDUNDANT_CRITERIA',
          severity: 'warning'
        });
      }

    } catch (error) {
      errors.push({
        field: 'predicate',
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

    this._validationCache = result;
    return result;
  }

  // ========================================================================
  // Performance Methods
  // ========================================================================

  /**
   * Update performance statistics
   *
   * @param result - Evaluation result
   */
  private updatePerformanceStats(result: PredicateEvaluationResult): void {
    this._performanceStats.evaluationCount++;
    this._performanceStats.totalDuration += result.duration;

    // Update running average confidence
    const totalConfidence = this._performanceStats.averageConfidence * (this._performanceStats.evaluationCount - 1);
    this._performanceStats.averageConfidence = (totalConfidence + result.confidence) / this._performanceStats.evaluationCount;
  }

  /**
   * Get performance statistics
   *
   * @returns Performance statistics
   */
  public getPerformanceStats(): {
    evaluationCount: number;
    totalDuration: number;
    averageDuration: number;
    averageConfidence: number;
    cacheHits: number;
  } {
    return {
      ...this._performanceStats,
      averageDuration: this._performanceStats.evaluationCount > 0
        ? this._performanceStats.totalDuration / this._performanceStats.evaluationCount
        : 0
    };
  }

  /**
   * Reset performance statistics
   */
  public resetPerformanceStats(): void {
    this._performanceStats = {
      evaluationCount: 0,
      totalDuration: 0,
      cacheHits: 0,
      averageConfidence: 0
    };
  }

  // ========================================================================
  // Utility Methods
  // ========================================================================

  /**
   * Check if this predicate is equivalent to another
   *
   * @param other - Other predicate to compare
   * @returns True if predicates are equivalent
   */
  public isEquivalentTo(other: StatePredicate | IStatePredicate): boolean {
    if (!(other instanceof StatePredicate)) {
      other = new StatePredicate(other);
    }

    // Compare all relevant fields
    return (
      this.type === other.type &&
      this.stateId === other.stateId &&
      this.activity === other.activity &&
      JSON.stringify(this.containsText) === JSON.stringify(other.containsText) &&
      JSON.stringify(this.matches) === JSON.stringify(other.matches) &&
      this.fuzzyThreshold === other.fuzzyThreshold &&
      JSON.stringify(this.hasSelectors) === JSON.stringify(other.hasSelectors)
    );
  }

  /**
   * Calculate similarity with another predicate
   *
   * @param other - Other predicate to compare
   * @returns Comparison result
   */
  public compareWith(other: StatePredicate | IStatePredicate): PredicateComparisonResult {
    if (!(other instanceof StatePredicate)) {
      other = new StatePredicate(other);
    }

    const factors = {
      predicateType: this.type === other.type,
      stateId: this.stateId === other.stateId,
      activity: this.activity === other.activity,
      textPatterns: JSON.stringify(this.containsText) === JSON.stringify(other.containsText),
      selectors: JSON.stringify(this.hasSelectors) === JSON.stringify(other.hasSelectors)
    };

    const matchingFactors = Object.values(factors).filter(Boolean).length;
    const totalFactors = Object.keys(factors).length;
    const similarity = matchingFactors / totalFactors;

    const differences: string[] = [];
    if (!factors.predicateType) differences.push('predicate type');
    if (!factors.stateId) differences.push('state ID');
    if (!factors.activity) differences.push('activity');
    if (!factors.textPatterns) differences.push('text patterns');
    if (!factors.selectors) differences.push('selectors');

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
   * Convert predicate to JSON string
   *
   * @returns JSON representation
   */
  public toJSON(): string {
    return JSON.stringify(this.toObject(), null, 2);
  }

  /**
   * Convert predicate to plain object
   *
   * @returns Plain object representation
   */
  public toObject(): IStatePredicate {
    return {
      type: this.type,
      stateId: this.stateId,
      activity: this.activity,
      containsText: this.containsText,
      matches: this.matches,
      fuzzyThreshold: this.fuzzyThreshold,
      hasSelectors: this.hasSelectors
    };
  }

  /**
   * Get a human-readable description of the predicate
   *
   * @returns Description string
   */
  public getDescription(): string {
    const parts: string[] = [];

    parts.push(`Type: ${this.type}`);

    if (this.stateId) {
      parts.push(`State ID: ${this.stateId}`);
    }

    if (this.activity) {
      parts.push(`Activity: ${this.activity}`);
    }

    if (this.containsText && this.containsText.length > 0) {
      parts.push(`Contains text: [${this.containsText.join(', ')}]`);
    }

    if (this.matches) {
      const patterns = [];
      if (this.matches.activity) patterns.push(`activity:/${this.matches.activity}/`);
      if (this.matches.text) patterns.push(`text:/${this.matches.text}/`);
      if (this.matches.selectors) patterns.push(`selectors:/${this.matches.selectors}/`);
      if (patterns.length > 0) parts.push(`Matches: ${patterns.join(', ')}`);
    }

    if (this.hasSelectors && this.hasSelectors.length > 0) {
      const selectorDescs = this.hasSelectors.map(s =>
        s.rid || s.text || s.desc || 'unknown'
      );
      parts.push(`Has selectors: [${selectorDescs.join(', ')}]`);
    }

    if (this.type === 'fuzzy') {
      parts.push(`Threshold: ${this.fuzzyThreshold}`);
    }

    return parts.join(' | ');
  }

  /**
   * Create a copy of this predicate
   *
   * @returns New StatePredicate instance
   */
  public clone(): StatePredicate {
    return new StatePredicate(this.toObject());
  }
}

// ============================================================================
// Batch Evaluation Utilities
// ============================================================================

/**
 * Utility class for batch predicate evaluation with optimization
 */
export class StatePredicateBatchEvaluator {
  /**
   * Evaluate multiple predicates against multiple states efficiently
   *
   * @param context - Batch evaluation context
   * @returns Array of evaluation results
   */
  static evaluateBatch(context: BatchEvaluationContext): PredicateEvaluationResult[][] {
    const { states, predicates, options } = context;
    const results: PredicateEvaluationResult[][] = [];

    // Create predicate instances for evaluation
    const predicateInstances = predicates.map(p =>
      p instanceof StatePredicate ? p : new StatePredicate(p)
    );

    // Initialize optimization structures
    const cache = options.enableCaching ? new Map<string, PredicateEvaluationResult>() : null;

    for (let i = 0; i < states.length; i++) {
      const state = states[i];
      const stateResults: PredicateEvaluationResult[] = [];

      for (let j = 0; j < predicateInstances.length; j++) {
        const predicate = predicateInstances[j];

        // Check cache first
        let result: PredicateEvaluationResult | undefined;
        if (cache) {
          const cacheKey = `${state.id}:${predicate.type}:${JSON.stringify(predicate.toObject())}`;
          result = cache.get(cacheKey);
          if (result) {
            result.performance = { ...result.performance, cacheHit: true };
          }
        }

        // Evaluate if not cached
        if (!result) {
          result = predicate.evaluate(state, {
            enableDebug: options.enableDebug,
            minConfidence: options.minConfidence
          });

          if (cache) {
            const cacheKey = `${state.id}:${predicate.type}:${JSON.stringify(predicate.toObject())}`;
            cache.set(cacheKey, { ...result });
          }
        }

        stateResults.push(result);
      }

      results.push(stateResults);

      // Progress callback
      if (options.onProgress) {
        options.onProgress(i + 1, states.length);
      }
    }

    return results;
  }

  /**
   * Find best matching state for each predicate
   *
   * @param context - Batch evaluation context
   * @returns Array of best matches per predicate
   */
  static findBestMatches(context: BatchEvaluationContext): Array<{
    predicate: IStatePredicate;
    bestState: IState | null;
    bestResult: PredicateEvaluationResult;
  }> {
    const results = this.evaluateBatch(context);
    const matches: Array<{
      predicate: IStatePredicate;
      bestState: IState | null;
      bestResult: PredicateEvaluationResult;
    }> = [];

    for (let j = 0; j < context.predicates.length; j++) {
      const predicate = context.predicates[j];
      let bestResult: PredicateEvaluationResult = {
        matched: false,
        confidence: 0.0,
        factors: {},
        matchedCriteria: [],
        duration: 0
      };
      let bestState: IState | null = null;

      for (let i = 0; i < context.states.length; i++) {
        const result = results[i][j];
        if (result.confidence > bestResult.confidence &&
            result.confidence >= (context.options.minConfidence || 0)) {
          bestResult = result;
          bestState = context.states[i];
        }
      }

      matches.push({
        predicate,
        bestState,
        bestResult
      });
    }

    return matches;
  }

  /**
   * Filter states by predicates with minimum confidence
   *
   * @param states - States to filter
   * @param predicates - Predicates to match against
   * @param minConfidence - Minimum confidence threshold
   * @returns Filtered states with their matches
   */
  static filterStatesByPredicates(
    states: IState[],
    predicates: IStatePredicate[],
    minConfidence: number = 0.5
  ): Array<{
    state: IState;
    matches: Array<{
      predicate: IStatePredicate;
      result: PredicateEvaluationResult;
    }>;
  }> {
    const context: BatchEvaluationContext = {
      states,
      predicates,
      options: {
        minConfidence,
        enableCaching: true,
        enableOptimizations: true
      }
    };

    const results = this.evaluateBatch(context);
    const filtered: Array<{
      state: IState;
      matches: Array<{
        predicate: IStatePredicate;
        result: PredicateEvaluationResult;
      }>;
    }> = [];

    for (let i = 0; i < states.length; i++) {
      const state = states[i];
      const stateResults = results[i];
      const matches = stateResults
        .map((result, j) => ({
          predicate: predicates[j],
          result
        }))
        .filter(({ result }) => result.matched && result.confidence >= minConfidence);

      if (matches.length > 0) {
        filtered.push({ state, matches });
      }
    }

    return filtered;
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Factory functions for creating common state predicates
 */
export const StatePredicateFactory = {
  /** Create exact state match predicate */
  exactState: StatePredicate.exactState,

  /** Create activity match predicate */
  activity: StatePredicate.activity,

  /** Create text content predicate */
  textContent: StatePredicate.textContent,

  /** Create regex match predicate */
  regex: StatePredicate.regex,

  /** Create fuzzy match predicate */
  fuzzy: StatePredicate.fuzzy,

  /** Create selector predicate */
  selectors: StatePredicate.selectors,

  /**
   * Create a comprehensive predicate combining multiple criteria
   *
   * @param criteria - Multiple matching criteria
   * @param type - Primary matching type
   * @returns Combined predicate
   */
  combined(
    criteria: {
      stateId?: string;
      activity?: string;
      containsText?: string[];
      hasSelectors?: Array<{ rid?: string; text?: string; desc?: string }>;
      fuzzyThreshold?: number;
    },
    type: PredicateType = 'contains'
  ): StatePredicate {
    return new StatePredicate({
      type,
      ...criteria
    });
  },

  /**
   * Create a predicate from a simple description string
   *
   * @param description - Human-readable description
   * @returns Parsed predicate
   */
  fromDescription(description: string): StatePredicate {
    // Simple parsing for common patterns
    const lowerDesc = description.toLowerCase();

    // Activity patterns
    if (lowerDesc.includes('activity:') || lowerDesc.includes('screen:')) {
      const match = description.match(/(?:activity|screen):\s*(\S+)/i);
      if (match) {
        return StatePredicate.activity(match[1], 'contains');
      }
    }

    // Text patterns
    if (lowerDesc.includes('text:') || lowerDesc.includes('contains:')) {
      const match = description.match(/(?:text|contains):\s*["']([^"']+)["']/i);
      if (match) {
        return StatePredicate.textContent([match[1]], 'contains');
      }
    }

    // State ID patterns
    if (lowerDesc.includes('state:') || lowerDesc.includes('id:')) {
      const match = description.match(/(?:state|id):\s*([a-f0-9-]+)/i);
      if (match) {
        return StatePredicate.exactState(match[1]);
      }
    }

    // Default to fuzzy text matching
    const textWords = description.split(/\s+/).filter(word => word.length > 2);
    if (textWords.length > 0) {
      return StatePredicate.fuzzy({
        containsText: textWords
      }, 0.7);
    }

    throw new Error(`Cannot parse predicate from description: ${description}`);
  }
};

// ============================================================================
// Exports
// ============================================================================

export default StatePredicate;