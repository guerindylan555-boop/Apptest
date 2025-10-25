/**
 * AutoApp UI Map & Intelligent Flow Engine - State Deduplication Service (T025)
 *
 * High-performance state deduplication service implementing digest-based matching for UI states.
 * Provides fuzzy matching with configurable similarity thresholds, intelligent merging strategies,
 * activity-based grouping, and comprehensive performance monitoring.
 *
 * Features:
 * - SHA-256 digest-based state matching
 * - Fuzzy matching with configurable similarity thresholds (95% accuracy target)
 * - Intelligent merging strategies for similar states
 * - Activity-based grouping and deduplication
 * - Selector normalization and comparison
 * - Performance metrics and monitoring
 * - Batch deduplication operations
 * - Comprehensive error handling and logging
 *
 * Based on specs/001-ui-map-flow-engine/ and task T025 requirements.
 */

import { createHash } from 'crypto';
import { State, SelectorUtils } from '../models/state';
import {
  State as IState,
  Selector as ISelector,
  ValidationResult,
  ValidationError,
  StateError
} from '../types/models';
import {
  hashObject,
  calculateJaccardSimilarity,
  calculateTextSimilarity,
  calculateStateSimilarity,
  shouldMergeStates,
  isValidSHA256
} from '../utils/hash';
import { LogLevel, LogContext, PerformanceTimer, ServiceLogger, logger } from './logger';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Deduplication configuration interface
 */
export interface DeduplicationConfig {
  /** Similarity threshold for fuzzy matching (0-1) */
  similarityThreshold: number;

  /** Selector weight in similarity calculation */
  selectorWeight: number;

  /** Text weight in similarity calculation */
  textWeight: number;

  /** Minimum selector importance for matching */
  minSelectorImportance: number;

  /** Enable activity-based grouping */
  enableActivityGrouping: boolean;

  /** Batch processing size */
  batchSize: number;

  /** Performance monitoring enabled */
  enablePerformanceMonitoring: boolean;

  /** Logging level */
  logLevel: LogLevel;

  /** Maximum states to process in single batch */
  maxBatchSize: number;
}

/**
 * Deduplication result interface
 */
export interface DeduplicationResult {
  /** Total states processed */
  totalStates: number;

  /** Number of duplicates found */
  duplicatesFound: number;

  /** Number of states merged */
  statesMerged: number;

  /** Number of unique states remaining */
  uniqueStates: number;

  /** Processing time in milliseconds */
  processingTime: number;

  /** Similarity scores distribution */
  similarityDistribution: {
    exact: number;
    high: number;      // 0.9 - 1.0
    medium: number;    // 0.7 - 0.9
    low: number;       // 0.5 - 0.7
    none: number;      // < 0.5
  };

  /** Merge conflicts encountered */
  mergeConflicts: number;

  /** Errors encountered */
  errors: Array<{
    stateId: string;
    error: string;
    code: string;
  }>;
}

/**
 * Merge strategy interface
 */
export interface MergeStrategy {
  /** Strategy name */
  name: string;

  /** Strategy description */
  description: string;

  /** Merge function */
  merge: (states: State[]) => State;
}

/**
 * State comparison result interface
 */
export interface StateComparison {
  /** First state ID */
  state1Id: string;

  /** Second state ID */
  state2Id: string;

  /** Overall similarity score */
  similarity: number;

  /** Selector similarity score */
  selectorSimilarity: number;

  /** Text similarity score */
  textSimilarity: number;

  /** Whether states should be merged */
  shouldMerge: boolean;

  /** Merge confidence */
  confidence: number;

  /** Comparison details */
  details: {
    commonSelectors: string[];
    uniqueSelectors1: string[];
    uniqueSelectors2: string[];
    commonText: string[];
    uniqueText1: string[];
    uniqueText2: string[];
  };
}

/**
 * Performance metrics interface
 */
export interface PerformanceMetrics {
  /** Operation name */
  operation: string;

  /** Start timestamp */
  startTime: Date;

  /** End timestamp */
  endTime: Date;

  /** Duration in milliseconds */
  duration: number;

  /** States processed per second */
  throughput: number;

  /** Memory usage in bytes */
  memoryUsage: number;

  /** Cache hit rate */
  cacheHitRate: number;

  /** Additional metrics */
  additionalMetrics: Record<string, number>;
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error class for deduplication operations
 */
export class StateDeduplicationError extends Error {
  public readonly code: string;
  public readonly stateId?: string;
  public readonly timestamp: string;

  constructor(message: string, code: string, stateId?: string) {
    super(message);
    this.name = 'StateDeduplicationError';
    this.code = code;
    this.stateId = stateId;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Error class for merge conflicts
 */
export class MergeConflictError extends StateDeduplicationError {
  public readonly conflictingStates: string[];
  public readonly conflictReason: string;

  constructor(message: string, conflictingStates: string[], conflictReason: string) {
    super(message, 'MERGE_CONFLICT');
    this.name = 'MergeConflictError';
    this.conflictingStates = conflictingStates;
    this.conflictReason = conflictReason;
  }
}

// ============================================================================
// State Deduplication Service
// ============================================================================

/**
 * Main state deduplication service class
 */
export class StateDeduplicationService {
  private config: DeduplicationConfig;
  private logger: ServiceLogger;
  private metrics: Map<string, PerformanceMetrics> = new Map();
  private selectorCache: Map<string, string> = new Map();
  private digestCache: Map<string, string> = new Map();

  /**
   * Creates a new StateDeduplicationService instance
   *
   * @param config - Deduplication configuration
   */
  constructor(config?: Partial<DeduplicationConfig>) {
    this.config = {
      similarityThreshold: 0.95,
      selectorWeight: 0.7,
      textWeight: 0.3,
      minSelectorImportance: 0.3,
      enableActivityGrouping: true,
      batchSize: 100,
      enablePerformanceMonitoring: true,
      logLevel: 'info',
      maxBatchSize: 1000,
      ...config
    };

    this.logger = logger.createServiceLogger('state-dedup');

    this.logger.info('service_initialized', 'StateDeduplicationService initialized', undefined, {
      config: this.config
    });
  }

  // ============================================================================
  // Public API Methods
  // ============================================================================

  /**
   * Deduplicates a single state against a collection of existing states
   *
   * @param state - State to deduplicate
   * @param existingStates - Collection of existing states to check against
   * @returns Deduplication result with merge decisions
   */
  public async deduplicateState(
    state: State | IState,
    existingStates: (State | IState)[]
  ): Promise<{
    isDuplicate: boolean;
    matchedState?: State | IState;
    similarity?: number;
    mergeCandidate?: State;
  }> {
    const timer = this.startPerformanceTimer('deduplicateState');

    try {
      this.logger.debug('Starting state deduplication', {
        stateId: state.id,
        package: state.package,
        activity: state.activity,
        existingStatesCount: existingStates.length
      });

      // Convert to State instance if needed
      const stateObj = state // State is an interface, not a class;

      // Calculate state digest if not present
      if (!stateObj.digest || !isValidSHA256(stateObj.digest)) {
        stateObj.digest = this.calculateStateDigest(stateObj);
        this.logger.debug('Calculated missing digest', {
          stateId: stateObj.id,
          digest: stateObj.digest
        });
      }

      // Check for exact digest matches first (fast path)
      const exactMatch = existingStates.find(existing =>
        existing.digest === stateObj.digest
      );

      if (exactMatch) {
        this.logger.info('Found exact digest match', {
          stateId: stateObj.id,
          matchedStateId: exactMatch.id,
          digest: stateObj.digest
        });

        timer.end({ result: 'exact_match' });
        return {
          isDuplicate: true,
          matchedState: exactMatch,
          similarity: 1.0
        };
      }

      // Filter states by package and activity if activity grouping is enabled
      let candidates = existingStates;
      if (this.config.enableActivityGrouping) {
        candidates = existingStates.filter(existing =>
          existing.package === stateObj.package &&
          existing.activity === stateObj.activity
        );

        this.logger.debug('Filtered candidates by activity', {
          originalCount: existingStates.length,
          filteredCount: candidates.length,
          package: stateObj.package,
          activity: stateObj.activity
        });
      }

      // Perform similarity matching
      let bestMatch: State | IState | undefined;
      let bestSimilarity = 0;
      let bestComparison: StateComparison | undefined;

      for (const candidate of candidates) {
        const comparison = await this.compareStates(stateObj, candidate);

        if (comparison.similarity > bestSimilarity) {
          bestSimilarity = comparison.similarity;
          bestMatch = candidate;
          bestComparison = comparison;
        }

        // Early exit if we find a very high similarity match
        if (bestSimilarity >= this.config.similarityThreshold) {
          break;
        }
      }

      const isDuplicate = bestSimilarity >= this.config.similarityThreshold;
      let mergeCandidate: State | undefined;

      if (isDuplicate && bestMatch) {
        // Create merge candidate if similarity is high enough
        if (bestSimilarity >= this.config.similarityThreshold * 0.9) {
          try {
            mergeCandidate = await this.mergeStates([stateObj, bestMatch]);
            this.logger.debug('Created merge candidate', {
              stateId: stateObj.id,
              matchedStateId: bestMatch.id,
              similarity: bestSimilarity
            });
          } catch (error) {
            this.logger.warn('Failed to create merge candidate', {
              stateId: stateObj.id,
              matchedStateId: bestMatch.id,
              error: error instanceof Error ? error.message : 'Unknown error'
            });
          }
        }
      }

      timer.end({
        result: isDuplicate ? 'duplicate_found' : 'unique_state',
        similarity: bestSimilarity,
        candidatesChecked: candidates.length
      });

      this.logger.info('State deduplication completed', {
        stateId: stateObj.id,
        isDuplicate,
        similarity: bestSimilarity,
        matchedStateId: bestMatch?.id
      });

      return {
        isDuplicate,
        matchedState: bestMatch,
        similarity: bestSimilarity,
        mergeCandidate
      };

    } catch (error) {
      this.logger.error('State deduplication failed', {
        stateId: state.id,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      });

      timer.end({ result: 'error' });
      throw new StateDeduplicationError(
        `Deduplication failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'DEDUPLICATION_FAILED',
        state.id
      );
    }
  }

  /**
   * Deduplicates a batch of states
   *
   * @param states - Array of states to deduplicate
   * @returns Deduplication result with metrics
   */
  public async deduplicateBatch(states: (State | IState)[]): Promise<DeduplicationResult> {
    const timer = this.startPerformanceTimer('deduplicateBatch');
    const startTime = Date.now();

    this.logger.info('Starting batch deduplication', {
      totalStates: states.length,
      batchSize: this.config.batchSize
    });

    const result: DeduplicationResult = {
      totalStates: states.length,
      duplicatesFound: 0,
      statesMerged: 0,
      uniqueStates: 0,
      processingTime: 0,
      similarityDistribution: {
        exact: 0,
        high: 0,
        medium: 0,
        low: 0,
        none: 0
      },
      mergeConflicts: 0,
      errors: []
    };

    try {
      // Convert all states to State instances
      const stateObjects = states.map(state =>
        state // State is an interface, not a class
      );

      // Group by activity if enabled
      let groups = [stateObjects];
      if (this.config.enableActivityGrouping) {
        const groupMap = new Map<string, State[]>();

        for (const state of stateObjects) {
          const key = `${state.package}:${state.activity}`;
          if (!groupMap.has(key)) {
            groupMap.set(key, []);
          }
          groupMap.get(key)!.push(state);
        }

        groups = Array.from(groupMap.values());

        this.logger.debug('Grouped states by activity', {
          totalGroups: groups.length,
          groupSizes: groups.map(g => g.length)
        });
      }

      // Process each group
      const uniqueStates: State[] = [];
      const processedDigests = new Set<string>();

      for (const group of groups) {
        const groupResult = await this.deduplicateGroup(group, processedDigests);

        // Update result metrics
        result.duplicatesFound += groupResult.duplicatesFound;
        result.statesMerged += groupResult.statesMerged;
        result.mergeConflicts += groupResult.mergeConflicts;
        result.errors.push(...groupResult.errors);

        // Update similarity distribution
        Object.keys(result.similarityDistribution).forEach(key => {
          result.similarityDistribution[key as keyof typeof result.similarityDistribution] +=
            groupResult.similarityDistribution[key as keyof typeof groupResult.similarityDistribution];
        });

        uniqueStates.push(...groupResult.uniqueStates);
      }

      result.uniqueStates = uniqueStates.length;
      result.processingTime = Date.now() - startTime;

      // Calculate throughput
      const throughput = (states.length / result.processingTime) * 1000;

      this.logger.info('Batch deduplication completed', {
        totalStates: result.totalStates,
        uniqueStates: result.uniqueStates,
        duplicatesFound: result.duplicatesFound,
        statesMerged: result.statesMerged,
        processingTime: result.processingTime,
        throughput: `${throughput.toFixed(2)} states/sec`,
        mergeConflicts: result.mergeConflicts,
        errors: result.errors.length
      });

      timer.end({
        totalStates: result.totalStates,
        uniqueStates: result.uniqueStates,
        throughput
      });

      return result;

    } catch (error) {
      this.logger.error('Batch deduplication failed', {
        totalStates: states.length,
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined
      });

      result.processingTime = Date.now() - startTime;
      result.errors.push({
        stateId: 'batch',
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'BATCH_DEDUPLICATION_FAILED'
      });

      timer.end({ result: 'error' });
      throw new StateDeduplicationError(
        `Batch deduplication failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'BATCH_DEDUPLICATION_FAILED'
      );
    }
  }

  /**
   * Compares two states and returns detailed similarity analysis
   *
   * @param state1 - First state to compare
   * @param state2 - Second state to compare
   * @returns Detailed comparison result
   */
  public async compareStates(
    state1: State | IState,
    state2: State | IState
  ): Promise<StateComparison> {
    const timer = this.startPerformanceTimer('compareStates');

    try {
      // Convert to State instances if needed
      const s1 = state1 // State is an interface, not a class;
      const s2 = state2 // State is an interface, not a class;

      // Quick check for different packages/activities
      if (s1.package !== s2.package || s1.activity !== s2.activity) {
        const result: StateComparison = {
          state1Id: s1.id,
          state2Id: s2.id,
          similarity: 0,
          selectorSimilarity: 0,
          textSimilarity: 0,
          shouldMerge: false,
          confidence: 1.0,
          details: {
            commonSelectors: [],
            uniqueSelectors1: [],
            uniqueSelectors2: [],
            commonText: [],
            uniqueText1: [],
            uniqueText2: []
          }
        };

        timer.end({ result: 'different_package_activity' });
        return result;
      }

      // Check for exact digest match
      if (s1.digest === s2.digest && isValidSHA256(s1.digest)) {
        const result: StateComparison = {
          state1Id: s1.id,
          state2Id: s2.id,
          similarity: 1.0,
          selectorSimilarity: 1.0,
          textSimilarity: 1.0,
          shouldMerge: true,
          confidence: 1.0,
          details: {
            commonSelectors: s1.selectors.map(sel => SelectorUtils.getSelectorKey(sel)),
            uniqueSelectors1: [],
            uniqueSelectors2: [],
            commonText: s1.visibleText || [],
            uniqueText1: [],
            uniqueText2: []
          }
        };

        timer.end({ result: 'exact_match' });
        return result;
      }

      // Calculate selector similarity
      const selectorSimilarity = calculateJaccardSimilarity(s1.selectors, s2.selectors);

      // Calculate text similarity
      const textSimilarity = calculateTextSimilarity(
        s1.visibleText || [],
        s2.visibleText || []
      );

      // Calculate overall similarity
      const similarity = (this.config.selectorWeight * selectorSimilarity) +
                        (this.config.textWeight * textSimilarity);

      // Determine if states should be merged
      const shouldMerge = similarity >= this.config.similarityThreshold;

      // Calculate confidence based on similarity and state quality
      const confidence = this.calculateMergeConfidence(s1, s2, similarity);

      // Find common and unique elements
      const details = this.analyzeStateDifferences(s1, s2);

      const result: StateComparison = {
        state1Id: s1.id,
        state2Id: s2.id,
        similarity,
        selectorSimilarity,
        textSimilarity,
        shouldMerge,
        confidence,
        details
      };

      timer.end({
        similarity,
        shouldMerge,
        confidence
      });

      return result;

    } catch (error) {
      this.logger.error('State comparison failed', {
        state1Id: state1.id,
        state2Id: state2.id,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      timer.end({ result: 'error' });
      throw new StateDeduplicationError(
        `State comparison failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'COMPARISON_FAILED'
      );
    }
  }

  /**
   * Merges multiple states into a single representative state
   *
   * @param states - Array of states to merge
   * @param strategy - Merge strategy to use (default: 'comprehensive')
   * @returns Merged state
   */
  public async mergeStates(
    states: (State | IState)[],
    strategy: 'comprehensive' | 'latest' | 'most_selectors' | 'most_interactive' = 'comprehensive'
  ): Promise<State> {
    const timer = this.startPerformanceTimer('mergeStates');

    try {
      if (states.length === 0) {
        throw new StateDeduplicationError('No states provided for merging', 'NO_STATES');
      }

      if (states.length === 1) {
        const state = states[0] // State is an interface, not a class;
        timer.end({ result: 'single_state' });
        return state;
      }

      this.logger.info('Starting state merge', {
        stateCount: states.length,
        strategy,
        stateIds: states.map(s => s.id)
      });

      // Convert all to State instances
      const stateObjects = states.map(state =>
        state // State is an interface, not a class
      );

      // Verify all states are from the same package/activity
      const firstState = stateObjects[0];
      const allSamePackage = stateObjects.every(s => s.package === firstState.package);
      const allSameActivity = stateObjects.every(s => s.activity === firstState.activity);

      if (!allSamePackage || !allSameActivity) {
        throw new MergeConflictError(
          'Cannot merge states from different packages or activities',
          stateObjects.map(s => s.id),
          `Package/activity mismatch: ${[...new Set(stateObjects.map(s => `${s.package}:${s.activity}`))].join(', ')}`
        );
      }

      // Apply merge strategy
      const mergeStrategy = this.getMergeStrategy(strategy);
      const mergedState = mergeStrategy.merge(stateObjects);

      // Recalculate digest for merged state
      mergedState.digest = this.calculateStateDigest(mergedState);

      this.logger.info('State merge completed', {
        mergedStateId: mergedState.id,
        originalStateCount: states.length,
        finalSelectorCount: mergedState.selectors.length,
        strategy
      });

      timer.end({
        result: 'merged',
        originalCount: states.length,
        finalSelectorCount: mergedState.selectors.length
      });

      return mergedState;

    } catch (error) {
      this.logger.error('State merge failed', {
        stateCount: states.length,
        strategy,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      timer.end({ result: 'error' });

      if (error instanceof MergeConflictError) {
        throw error;
      }

      throw new StateDeduplicationError(
        `State merge failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'MERGE_FAILED'
      );
    }
  }

  /**
   * Finds potential duplicate states in a collection
   *
   * @param states - Array of states to analyze
   * @returns Array of duplicate state groups
   */
  public async findDuplicates(states: (State | IState)[]): Promise<(State | IState)[][]> {
    const timer = this.startPerformanceTimer('findDuplicates');

    try {
      this.logger.info('Finding duplicate states', {
        totalStates: states.length
      });

      const groups = new Map<string, (State | IState)[]>();

      // Group by exact digest first
      for (const state of states) {
        const digest = state.digest;
        if (!groups.has(digest)) {
          groups.set(digest, []);
        }
        groups.get(digest)!.push(state);
      }

      // Find exact duplicates
      const exactDuplicates = Array.from(groups.values()).filter(group => group.length > 1);

      // For groups with only one state, check for fuzzy matches
      const fuzzyGroups = new Map<string, (State | IState)[]>();
      const processed = new Set<string>();

      for (const [digest, group] of groups) {
        if (group.length > 1 || processed.has(digest)) {
          continue;
        }

        const state = group[0];
        const similarStates: (State | IState)[] = [state];

        // Check against other groups for fuzzy matches
        for (const [otherDigest, otherGroup] of groups) {
          if (otherDigest === digest || processed.has(otherDigest)) {
            continue;
          }

          const otherState = otherGroup[0];
          const comparison = await this.compareStates(state, otherState);

          if (comparison.shouldMerge) {
            similarStates.push(otherState);
            processed.add(otherDigest);
          }
        }

        if (similarStates.length > 1) {
          const groupKey = similarStates.map(s => s.id).sort().join('|');
          fuzzyGroups.set(groupKey, similarStates);
        }

        processed.add(digest);
      }

      const allDuplicates = [...exactDuplicates, ...Array.from(fuzzyGroups.values())];

      this.logger.info('Duplicate analysis completed', {
        totalStates: states.length,
        exactDuplicateGroups: exactDuplicates.length,
        fuzzyDuplicateGroups: fuzzyGroups.size,
        totalDuplicateGroups: allDuplicates.length,
        totalDuplicates: allDuplicates.reduce((sum, group) => sum + group.length, 0)
      });

      timer.end({
        exactDuplicates: exactDuplicates.length,
        fuzzyDuplicates: fuzzyGroups.size,
        totalGroups: allDuplicates.length
      });

      return allDuplicates;

    } catch (error) {
      this.logger.error('Duplicate finding failed', {
        totalStates: states.length,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      timer.end({ result: 'error' });
      throw new StateDeduplicationError(
        `Duplicate finding failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'DUPLICATE_FINDING_FAILED'
      );
    }
  }

  /**
   * Gets performance metrics for deduplication operations
   *
   * @returns Array of performance metrics
   */
  public getPerformanceMetrics(): PerformanceMetrics[] {
    return Array.from(this.metrics.values());
  }

  /**
   * Clears performance metrics and caches
   */
  public clearCaches(): void {
    this.metrics.clear();
    this.selectorCache.clear();
    this.digestCache.clear();

    this.logger.info('Caches cleared');
  }

  /**
   * Updates deduplication configuration
   *
   * @param newConfig - Partial configuration to update
   */
  public updateConfig(newConfig: Partial<DeduplicationConfig>): void {
    this.config = { ...this.config, ...newConfig };

    this.logger.info('Configuration updated', {
      newConfig,
      currentConfig: this.config
    });
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Deduplicates a group of states from the same package/activity
   *
   * @param states - Group of states to deduplicate
   * @param processedDigests - Set of already processed digests
   * @returns Deduplication result for the group
   */
  private async deduplicateGroup(
    states: State[],
    processedDigests: Set<string>
  ): Promise<{
    duplicatesFound: number;
    statesMerged: number;
    mergeConflicts: number;
    errors: Array<{ stateId: string; error: string; code: string }>;
    similarityDistribution: DeduplicationResult['similarityDistribution'];
    uniqueStates: State[];
  }> {
    const result = {
      duplicatesFound: 0,
      statesMerged: 0,
      mergeConflicts: 0,
      errors: [] as Array<{ stateId: string; error: string; code: string }>,
      similarityDistribution: {
        exact: 0,
        high: 0,
        medium: 0,
        low: 0,
        none: 0
      },
      uniqueStates: [] as State[]
    };

    const uniqueStates = new Map<string, State>();

    for (const state of states) {
      try {
        // Skip if already processed
        if (processedDigests.has(state.digest)) {
          result.duplicatesFound++;
          continue;
        }

        // Check for similar states in current group
        let foundSimilar = false;

        for (const [digest, existingState] of uniqueStates) {
          const comparison = await this.compareStates(state, existingState);

          // Update similarity distribution
          if (comparison.similarity === 1.0) {
            result.similarityDistribution.exact++;
          } else if (comparison.similarity >= 0.9) {
            result.similarityDistribution.high++;
          } else if (comparison.similarity >= 0.7) {
            result.similarityDistribution.medium++;
          } else if (comparison.similarity >= 0.5) {
            result.similarityDistribution.low++;
          } else {
            result.similarityDistribution.none++;
          }

          if (comparison.shouldMerge) {
            try {
              // Merge the states
              const mergedState = await this.mergeStates([state, existingState]);

              // Replace the existing state with the merged one
              uniqueStates.delete(digest);
              uniqueStates.set(mergedState.digest, mergedState);

              result.duplicatesFound++;
              result.statesMerged++;
              foundSimilar = true;

              break;
            } catch (error) {
              if (error instanceof MergeConflictError) {
                result.mergeConflicts++;
                this.logger.warn('Merge conflict encountered', {
                  state1Id: state.id,
                  state2Id: existingState.id,
                  reason: error.conflictReason
                });
              } else {
                result.errors.push({
                  stateId: state.id,
                  error: error instanceof Error ? error.message : 'Unknown error',
                  code: 'MERGE_ERROR'
                });
              }
            }
          }
        }

        if (!foundSimilar) {
          uniqueStates.set(state.digest, state);
          processedDigests.add(state.digest);
        }

      } catch (error) {
        result.errors.push({
          stateId: state.id,
          error: error instanceof Error ? error.message : 'Unknown error',
          code: 'PROCESSING_ERROR'
        });

        this.logger.error('Error processing state', {
          stateId: state.id,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    result.uniqueStates = Array.from(uniqueStates.values());
    return result;
  }

  /**
   * Calculates state digest using SHA-256
   *
   * @param state - State to calculate digest for
   * @returns SHA-256 digest
   */
  private calculateStateDigest(state: State): string {
    // Check cache first
    const cacheKey = `${state.package}:${state.activity}:${state.selectors.length}`;
    if (this.digestCache.has(cacheKey)) {
      const cachedDigest = this.digestCache.get(cacheKey)!;

      // Verify cache is still valid
      const currentData = {
        package: state.package,
        activity: state.activity,
        selectors: state.selectors.map(s => SelectorUtils.getSelectorKey(s)).sort(),
        visibleText: (state.visibleText || []).sort()
      };

      const currentHash = hashObject(currentData);
      if (currentHash === cachedDigest) {
        return cachedDigest;
      }
    }

    // Create canonical representation
    const canonicalData = {
      package: state.package,
      activity: state.activity,
      selectors: state.selectors
        .map(selector => SelectorUtils.normalizeSelector(selector))
        .sort((a, b) => {
          const keyA = SelectorUtils.getSelectorKey(a);
          const keyB = SelectorUtils.getSelectorKey(b);
          return keyA.localeCompare(keyB);
        }),
      visibleText: (state.visibleText || [])
        .filter(text => text && text.trim().length > 0)
        .map(text => text.trim().toLowerCase())
        .sort()
    };

    const digest = hashObject(canonicalData);

    // Update cache
    this.digestCache.set(cacheKey, digest);

    return digest;
  }

  /**
   * Analyzes differences between two states
   *
   * @param state1 - First state
   * @param state2 - Second state
   * @returns Detailed difference analysis
   */
  private analyzeStateDifferences(
    state1: State,
    state2: State
  ): StateComparison['details'] {
    // Get selector keys for comparison
    const selectors1 = new Set(state1.selectors.map(s => SelectorUtils.getSelectorKey(s)));
    const selectors2 = new Set(state2.selectors.map(s => SelectorUtils.getSelectorKey(s)));

    const commonSelectors = [...selectors1].filter(key => selectors2.has(key));
    const uniqueSelectors1 = [...selectors1].filter(key => !selectors2.has(key));
    const uniqueSelectors2 = [...selectors2].filter(key => !selectors1.has(key));

    // Get text for comparison
    const text1 = new Set((state1.visibleText || []).map(t => t.toLowerCase().trim()));
    const text2 = new Set((state2.visibleText || []).map(t => t.toLowerCase().trim()));

    const commonText = [...text1].filter(text => text2.has(text));
    const uniqueText1 = [...text1].filter(text => !text2.has(text));
    const uniqueText2 = [...text2].filter(text => !text1.has(text));

    return {
      commonSelectors,
      uniqueSelectors1,
      uniqueSelectors2,
      commonText,
      uniqueText1,
      uniqueText2
    };
  }

  /**
   * Calculates merge confidence based on state quality and similarity
   *
   * @param state1 - First state
   * @param state2 - Second state
   * @param similarity - Similarity score
   * @returns Confidence score (0-1)
   */
  private calculateMergeConfidence(state1: State, state2: State, similarity: number): number {
    let confidence = similarity;

    // Boost confidence for states with similar selector counts
    const selectorCountDiff = Math.abs(state1.selectors.length - state2.selectors.length);
    const maxSelectors = Math.max(state1.selectors.length, state2.selectors.length);
    if (maxSelectors > 0) {
      const selectorSimilarity = 1 - (selectorCountDiff / maxSelectors);
      confidence = (confidence + selectorSimilarity) / 2;
    }

    // Boost confidence for states with similar metadata
    const metadataSimilarity = this.calculateMetadataSimilarity(state1.metadata, state2.metadata);
    confidence = (confidence * 0.8) + (metadataSimilarity * 0.2);

    // Reduce confidence for states with very different element counts
    const elementCountDiff = Math.abs(state1.metadata.elementCount - state2.metadata.elementCount);
    const maxElements = Math.max(state1.metadata.elementCount, state2.metadata.elementCount);
    if (maxElements > 0 && elementCountDiff / maxElements > 0.3) {
      confidence *= 0.9;
    }

    return Math.min(Math.max(confidence, 0), 1);
  }

  /**
   * Calculates similarity between state metadata
   *
   * @param metadata1 - First metadata
   * @param metadata2 - Second metadata
   * @returns Similarity score (0-1)
   */
  private calculateMetadataSimilarity(
    metadata1: State['metadata'],
    metadata2: State['metadata']
  ): number {
    let similarity = 0;
    let factors = 0;

    // Capture method
    if (metadata1.captureMethod === metadata2.captureMethod) {
      similarity += 1;
    }
    factors++;

    // Capture duration (within 50% tolerance)
    const avgDuration = (metadata1.captureDuration + metadata2.captureDuration) / 2;
    if (avgDuration > 0) {
      const durationDiff = Math.abs(metadata1.captureDuration - metadata2.captureDuration);
      const durationSimilarity = Math.max(0, 1 - (durationDiff / avgDuration));
      similarity += durationSimilarity;
    }
    factors++;

    // Element count (within 30% tolerance)
    const avgElements = (metadata1.elementCount + metadata2.elementCount) / 2;
    if (avgElements > 0) {
      const elementDiff = Math.abs(metadata1.elementCount - metadata2.elementCount);
      const elementSimilarity = Math.max(0, 1 - (elementDiff / avgElements));
      similarity += elementSimilarity;
    }
    factors++;

    // Hierarchy depth
    const avgDepth = (metadata1.hierarchyDepth + metadata2.hierarchyDepth) / 2;
    if (avgDepth > 0) {
      const depthDiff = Math.abs(metadata1.hierarchyDepth - metadata2.hierarchyDepth);
      const depthSimilarity = Math.max(0, 1 - (depthDiff / avgDepth));
      similarity += depthSimilarity;
    }
    factors++;

    return factors > 0 ? similarity / factors : 0;
  }

  /**
   * Gets merge strategy by name
   *
   * @param strategy - Strategy name
   * @returns Merge strategy implementation
   */
  private getMergeStrategy(strategy: string): MergeStrategy {
    const strategies: Record<string, MergeStrategy> = {
      comprehensive: {
        name: 'comprehensive',
        description: 'Merges all unique selectors and text from all states',
        merge: (states: State[]) => {
          const baseState = states[0];
          const allSelectors = new Map<string, ISelector>();
          const allText = new Set<string>();
          const allTags = new Set<string>();

          // Collect all unique selectors
          for (const state of states) {
            for (const selector of state.selectors) {
              const key = SelectorUtils.getSelectorKey(selector);
              if (!allSelectors.has(key)) {
                allSelectors.set(key, selector);
              }
            }

            // Collect all text
            if (state.visibleText) {
              for (const text of state.visibleText) {
                allText.add(text);
              }
            }

            // Collect all tags
            if (state.tags) {
              for (const tag of state.tags) {
                allTags.add(tag);
              }
            }
          }

          // Create merged state
          const mergedData = baseState.toObject();
          mergedData.selectors = Array.from(allSelectors.values());
          mergedData.visibleText = Array.from(allText).sort();
          mergedData.tags = Array.from(allTags);
          mergedData.metadata = {
            ...baseState.metadata,
            elementCount: Math.max(...states.map(s => s.metadata.elementCount)),
            hierarchyDepth: Math.max(...states.map(s => s.metadata.hierarchyDepth))
          };

          return State.fromExisting(mergedData);
        }
      },

      latest: {
        name: 'latest',
        description: 'Uses the most recently updated state as the base',
        merge: (states: State[]) => {
          return states.reduce((latest, current) =>
            current.updatedAt > latest.updatedAt ? current : latest
          );
        }
      },

      most_selectors: {
        name: 'most_selectors',
        description: 'Uses the state with the most selectors as the base',
        merge: (states: State[]) => {
          return states.reduce((most, current) =>
            current.selectors.length > most.selectors.length ? current : most
          );
        }
      },

      most_interactive: {
        name: 'most_interactive',
        description: 'Uses the state with the most interactive elements as the base',
        merge: (states: State[]) => {
          return states.reduce((most, current) => {
            const mostInteractive = most.getInteractiveSelectors().length;
            const currentInteractive = current.getInteractiveSelectors().length;
            return currentInteractive > mostInteractive ? current : most;
          });
        }
      }
    };

    return strategies[strategy] || strategies.comprehensive;
  }

  /**
   * Starts a performance timer for monitoring
   *
   * @param operation - Operation name
   * @returns Performance timer
   */
  private startPerformanceTimer(operation: string): PerformanceTimer {
    if (!this.config.enablePerformanceMonitoring) {
      return {
        startTime: Date.now(),
        operation,
        end: () => 0
      };
    }

    return logger.startTimer(operation, undefined, {
      service: 'state-dedup',
      operation
    });
  }
}

// ============================================================================
// Default Exports and Utilities
// ============================================================================

/**
 * Default deduplication service instance
 */
export const defaultDeduplicationService = new StateDeduplicationService();

/**
 * Convenience function for deduplicating a single state
 *
 * @param state - State to deduplicate
 * @param existingStates - Existing states to check against
 * @returns Deduplication result
 */
export async function deduplicateState(
  state: State | IState,
  existingStates: (State | IState)[]
) {
  return defaultDeduplicationService.deduplicateState(state, existingStates);
}

/**
 * Convenience function for deduplicating a batch of states
 *
 * @param states - States to deduplicate
 * @returns Deduplication result
 */
export async function deduplicateBatch(states: (State | IState)[]) {
  return defaultDeduplicationService.deduplicateBatch(states);
}

/**
 * Convenience function for finding duplicate states
 *
 * @param states - States to analyze
 * @returns Array of duplicate groups
 */
export async function findDuplicates(states: (State | IState)[]) {
  return defaultDeduplicationService.findDuplicates(states);
}

export default StateDeduplicationService;