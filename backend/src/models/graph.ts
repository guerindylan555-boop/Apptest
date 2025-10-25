/**
 * UI Graph (UTG) Entity Model
 *
 * Comprehensive UI state transition graph management for the AutoApp Discovery system.
 * This class provides complete functionality for creating, managing, and validating
 * UI state graphs with version control, statistics, and integrity checks.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md
 */

import { randomUUID } from 'crypto';
import {
  UIGraph as IUIGraph,
  State as IState,
  Transition as ITransition,
  Action,
  Selector,
  CaptureMethod,
  ModelError,
  StateError,
  TransitionError,
  ValidationError,
  ValidationResult
} from '../types/models';
import {
  generateStateId,
  generateDigest,
  generateTransitionId,
  generateFileChecksum,
  isValidSHA256
} from '../utils/hash';
import { logger } from '../services/logger';
import { getEnvironmentConfig } from '../config/environment';

// ============================================================================
// Configuration and Constants
// ============================================================================

/** Maximum number of states allowed in a graph */
const MAX_STATES = 500;

/** Maximum number of transitions allowed in a graph */
const MAX_TRANSITIONS = 2000;

/** Default similarity threshold for state deduplication */
const DEFAULT_SIMILARITY_THRESHOLD = 0.9;

/** Graph schema version */
const GRAPH_SCHEMA_VERSION = '1.0.0';

// ============================================================================
// Custom Error Classes
// ============================================================================

/**
 * Graph-specific error class
 */
export class GraphError extends ModelError {
  constructor(
    message: string,
    code: string,
    details?: {
      graphId?: string;
      packageName?: string;
      constraint?: string;
      [key: string]: any;
    }
  ) {
    super(message, code, details);
    this.name = 'GraphError';
  }
}

/**
 * Graph validation error class
 */
export class GraphValidationError extends GraphError {
  constructor(
    message: string,
    validationErrors: ValidationError[],
    details?: any
  ) {
    super(message, 'GRAPH_VALIDATION_ERROR', {
      ...details,
      validationErrors
    });
    this.name = 'GraphValidationError';
  }
}

// ============================================================================
// Graph Creation Options
// ============================================================================

export interface CreateGraphOptions {
  /** Initial metadata for the graph */
  metadata?: Partial<IUIGraph['metadata']>;

  /** Custom graph limits */
  limits?: {
    maxStates?: number;
    maxTransitions?: number;
  };

  /** Validation settings */
  validation?: {
    strictMode?: boolean;
    deduplicationThreshold?: number;
  };
}

export interface AddStateOptions {
  /** Skip deduplication checking */
  skipDeduplication?: boolean;

  /** Force add even if similar state exists */
  force?: boolean;

  /** Custom similarity threshold */
  similarityThreshold?: number;
}

export interface AddTransitionOptions {
  /** Validate that both states exist */
  validateStates?: boolean;

  /** Skip duplicate transition checking */
  skipDuplicateCheck?: boolean;

  /** Additional metadata for the transition */
  metadata?: Partial<ITransition>;
}

export interface MergeGraphOptions {
  /** Conflict resolution strategy */
  conflictResolution?: 'keep' | 'overwrite' | 'merge';

  /** Validation mode during merge */
  validation?: 'strict' | 'lenient' | 'skip';

  /** Merge metadata */
  mergeMetadata?: {
    mergedBy?: string;
    reason?: string;
  };
}

// ============================================================================
// Graph Statistics Interface
// ============================================================================

export interface GraphStatistics {
  /** Total number of states */
  stateCount: number;

  /** Total number of transitions */
  transitionCount: number;

  /** Average degree (transitions per state) */
  averageDegree: number;

  /** Number of isolated states (no incoming/outgoing transitions) */
  isolatedStates: number;

  /** Number of connected components */
  connectedComponents: number;

  /** Graph density (actual / possible transitions) */
  density: number;

  /** States with highest degree */
  hubStates: Array<{
    stateId: string;
    degree: number;
    inDegree: number;
    outDegree: number;
  }>;

  /** Last capture timestamp */
  lastCapture?: string;

  /** Capture performance metrics */
  captureMetrics: {
    totalCaptureTime: number;
    averageCaptureTime: number;
    totalSessions: number;
  };
}

// ============================================================================
// Main UIGraph Class
// ============================================================================

/**
 * UI Graph (UTG) Entity - Central data structure for UI state management
 */
export class UIGraph implements IUIGraph {
  // ============================================================================
  // Core Properties
  // ============================================================================

  /** Schema version */
  public readonly version: string = GRAPH_SCHEMA_VERSION;

  /** Graph lifecycle timestamps */
  public createdAt: string;
  public updatedAt: string;

  /** Target Android package */
  public packageName: string;

  /** Captured nodes */
  public states: IState[];

  /** Directed edges */
  public transitions: ITransition[];

  /** Derived statistics */
  public stats: IUIGraph['stats'];

  /** Capture metadata */
  public metadata: IUIGraph['metadata'];

  // ============================================================================
  // Internal State
  // ============================================================================

  /** Internal state lookup for O(1) access */
  private _stateMap: Map<string, IState> = new Map();

  /** Internal transition lookup for O(1) access */
  private _transitionMap: Map<string, ITransition> = new Map();

  /** Adjacency list for graph traversal */
  private _adjacencyList: Map<string, Set<string>> = new Map();

  /** Reverse adjacency list for incoming edge lookup */
  private _reverseAdjacencyList: Map<string, Set<string>> = new Map();

  /** Graph limits */
  private _limits: {
    maxStates: number;
    maxTransitions: number;
  };

  /** Validation settings */
  private _validation: {
    strictMode: boolean;
    deduplicationThreshold: number;
  };

  // ============================================================================
  // Constructor and Initialization
  // ============================================================================

  /**
   * Create a new UIGraph instance
   */
  constructor(packageName: string, options: CreateGraphOptions = {}) {
    // Validate package name
    if (!packageName || typeof packageName !== 'string' || packageName.trim().length === 0) {
      throw new GraphError(
        'Package name is required and must be a non-empty string',
        'INVALID_PACKAGE_NAME',
        { packageName }
      );
    }

    this.packageName = packageName.trim();
    this.states = [];
    this.transitions = [];
    this.createdAt = new Date().toISOString();
    this.updatedAt = this.createdAt;

    // Initialize limits
    this._limits = {
      maxStates: options.limits?.maxStates ?? MAX_STATES,
      maxTransitions: options.limits?.maxTransitions ?? MAX_TRANSITIONS
    };

    // Initialize validation settings
    this._validation = {
      strictMode: options.validation?.strictMode ?? false,
      deduplicationThreshold: options.validation?.deduplicationThreshold ?? DEFAULT_SIMILARITY_THRESHOLD
    };

    // Initialize statistics
    this.stats = {
      stateCount: 0,
      transitionCount: 0,
      averageDegree: 0,
      isolatedStates: 0,
      lastCapture: undefined
    };

    // Initialize metadata
    const config = getEnvironmentConfig();
    this.metadata = {
      captureTool: 'UIAutomator2',
      androidVersion: config?.adb?.androidVersion,
      appVersion: undefined,
      deviceInfo: config?.adb?.deviceId,
      totalCaptureTime: 0,
      totalSessions: 0,
      ...options.metadata
    };

    // Log graph creation
    logger.info('UIGraph created', {
      service: 'UIGraph',
      event: 'graph_created',
      graphId: this.id,
      packageName: this.packageName,
      limits: this._limits,
      validation: this._validation
    });
  }

  // ============================================================================
  // Property Accessors
  // ============================================================================

  /**
   * Get a unique identifier for this graph
   */
  public get id(): string {
    // Generate deterministic ID from package name and creation time
    const input = `${this.packageName}:${this.createdAt}`;
    return generateStateId(this.packageName, 'UIGraph', generateFileChecksum(input));
  }

  /**
   * Get current graph size limits
   */
  public get limits() {
    return { ...this._limits };
  }

  /**
   * Get current validation settings
   */
  public get validation() {
    return { ...this._validation };
  }

  /**
   * Get graph density (ratio of actual to possible transitions)
   */
  public get density(): number {
    if (this.states.length <= 1) {
      return 0;
    }

    const maxPossibleTransitions = this.states.length * (this.states.length - 1);
    return this.transitions.length / maxPossibleTransitions;
  }

  // ============================================================================
  // State Management Operations
  // ============================================================================

  /**
   * Add a new state to the graph with deduplication checking
   */
  public addState(stateData: Omit<IState, 'id' | 'createdAt' | 'updatedAt'>, options: AddStateOptions = {}): IState {
    const {
      skipDeduplication = false,
      force = false,
      similarityThreshold = this._validation.deduplicationThreshold
    } = options;

    // Check graph size limit
    if (this.states.length >= this._limits.maxStates) {
      throw new GraphError(
        `Maximum number of states (${this._limits.maxStates}) reached`,
        'MAX_STATES_EXCEEDED',
        {
          currentCount: this.states.length,
          maxStates: this._limits.maxStates,
          packageName: this.packageName
        }
      );
    }

    // Validate package name matches
    if (stateData.package !== this.packageName) {
      throw new GraphError(
        `State package name '${stateData.package}' does not match graph package name '${this.packageName}'`,
        'PACKAGE_NAME_MISMATCH',
        {
          statePackage: stateData.package,
          graphPackage: this.packageName
        }
      );
    }

    // Check for duplicate or similar states
    if (!skipDeduplication && !force) {
      const existingState = this.findSimilarState(stateData, similarityThreshold);
      if (existingState) {
        logger.debug('Found similar state, returning existing', {
          service: 'UIGraph',
          event: 'state_deduplication',
          existingStateId: existingState.id,
          similarity: this.calculateStateSimilarity(stateData, existingState)
        });
        return existingState;
      }
    }

    // Generate state ID
    const stateId = generateStateId(stateData.package, stateData.activity, stateData.digest);

    // Create state object
    const timestamp = new Date().toISOString();
    const state: IState = {
      id: stateId,
      ...stateData,
      createdAt: timestamp,
      updatedAt: timestamp
    };

    // Add to internal structures
    this.states.push(state);
    this._stateMap.set(stateId, state);
    this._adjacencyList.set(stateId, new Set());
    this._reverseAdjacencyList.set(stateId, new Set());

    // Update metadata and statistics
    this.updatedAt = timestamp;
    this.updateStatistics();

    // Log state addition
    logger.info('State added to graph', {
      service: 'UIGraph',
      event: 'state_added',
      graphId: this.id,
      stateId: state.id,
      activity: state.activity,
      totalStates: this.states.length
    });

    return state;
  }

  /**
   * Remove a state from the graph and clean up associated transitions
   */
  public removeState(stateId: string): boolean {
    const state = this._stateMap.get(stateId);
    if (!state) {
      return false;
    }

    // Remove all associated transitions
    const transitionsToRemove = this.transitions.filter(
      t => t.from === stateId || t.to === stateId
    );

    for (const transition of transitionsToRemove) {
      this.removeTransition(transition.id);
    }

    // Remove from arrays and maps
    this.states = this.states.filter(s => s.id !== stateId);
    this._stateMap.delete(stateId);
    this._adjacencyList.delete(stateId);
    this._reverseAdjacencyList.delete(stateId);

    // Update metadata and statistics
    this.updatedAt = new Date().toISOString();
    this.updateStatistics();

    // Log state removal
    logger.info('State removed from graph', {
      service: 'UIGraph',
      event: 'state_removed',
      graphId: this.id,
      stateId,
      removedTransitions: transitionsToRemove.length,
      totalStates: this.states.length
    });

    return true;
  }

  /**
   * Get a state by ID
   */
  public getState(stateId: string): IState | undefined {
    return this._stateMap.get(stateId);
  }

  /**
   * Get all states for a specific activity
   */
  public getStatesByActivity(activity: string): IState[] {
    return this.states.filter(state => state.activity === activity);
  }

  /**
   * Find states matching a predicate
   */
  public findStates(predicate: (state: IState) => boolean): IState[] {
    return this.states.filter(predicate);
  }

  /**
   * Find a state similar to the provided state data
   */
  public findSimilarState(stateData: Omit<IState, 'id' | 'createdAt' | 'updatedAt'>, threshold: number = this._validation.deduplicationThreshold): IState | null {
    for (const state of this.states) {
      if (state.package === stateData.package &&
          state.activity === stateData.activity &&
          state.digest === stateData.digest) {
        return state; // Exact match
      }
    }

    // Check for similarity if no exact match
    if (threshold < 1.0) {
      for (const state of this.states) {
        const similarity = this.calculateStateSimilarity(stateData, state);
        if (similarity >= threshold) {
          return state;
        }
      }
    }

    return null;
  }

  // ============================================================================
  // Transition Management Operations
  // ============================================================================

  /**
   * Add a new transition to the graph
   */
  public addTransition(
    fromStateId: string,
    toStateId: string,
    action: Action,
    options: AddTransitionOptions = {}
  ): ITransition {
    const {
      validateStates = true,
      skipDuplicateCheck = false,
      metadata = {}
    } = options;

    // Check graph size limit
    if (this.transitions.length >= this._limits.maxTransitions) {
      throw new GraphError(
        `Maximum number of transitions (${this._limits.maxTransitions}) reached`,
        'MAX_TRANSITIONS_EXCEEDED',
        {
          currentCount: this.transitions.length,
          maxTransitions: this._limits.maxTransitions,
          packageName: this.packageName
        }
      );
    }

    // Validate states exist
    if (validateStates) {
      if (!this._stateMap.has(fromStateId)) {
        throw new TransitionError(
          `Source state '${fromStateId}' not found in graph`,
          'SOURCE_STATE_NOT_FOUND',
          { fromStateId, graphId: this.id }
        );
      }
      if (!this._stateMap.has(toStateId)) {
        throw new TransitionError(
          `Destination state '${toStateId}' not found in graph`,
          'DESTINATION_STATE_NOT_FOUND',
          { toStateId, graphId: this.id }
        );
      }
    }

    // Check for duplicate transitions
    if (!skipDuplicateCheck) {
      const existingTransition = this.findTransition(fromStateId, toStateId, action);
      if (existingTransition) {
        logger.debug('Found existing transition, returning existing', {
          service: 'UIGraph',
          event: 'transition_deduplication',
          existingTransitionId: existingTransition.id,
          fromStateId,
          toStateId
        });
        return existingTransition;
      }
    }

    // Validate action
    this.validateAction(action);

    // Generate transition ID
    const actionString = JSON.stringify(action);
    const transitionId = generateTransitionId(fromStateId, toStateId, actionString);

    // Create transition object
    const timestamp = new Date().toISOString();
    const transition: ITransition = {
      id: transitionId,
      from: fromStateId,
      to: toStateId,
      action,
      createdAt: timestamp,
      ...metadata
    };

    // Add to internal structures
    this.transitions.push(transition);
    this._transitionMap.set(transitionId, transition);

    // Update adjacency lists
    if (!this._adjacencyList.has(fromStateId)) {
      this._adjacencyList.set(fromStateId, new Set());
    }
    this._adjacencyList.get(fromStateId)!.add(toStateId);

    if (!this._reverseAdjacencyList.has(toStateId)) {
      this._reverseAdjacencyList.set(toStateId, new Set());
    }
    this._reverseAdjacencyList.get(toStateId)!.add(fromStateId);

    // Update metadata and statistics
    this.updatedAt = timestamp;
    this.updateStatistics();

    // Log transition addition
    logger.info('Transition added to graph', {
      service: 'UIGraph',
      event: 'transition_added',
      graphId: this.id,
      transitionId: transition.id,
      fromStateId,
      toStateId,
      actionType: action.type,
      totalTransitions: this.transitions.length
    });

    return transition;
  }

  /**
   * Remove a transition from the graph
   */
  public removeTransition(transitionId: string): boolean {
    const transition = this._transitionMap.get(transitionId);
    if (!transition) {
      return false;
    }

    // Remove from arrays and maps
    this.transitions = this.transitions.filter(t => t.id !== transitionId);
    this._transitionMap.delete(transitionId);

    // Update adjacency lists
    const fromSet = this._adjacencyList.get(transition.from);
    if (fromSet) {
      fromSet.delete(transition.to);
      if (fromSet.size === 0) {
        this._adjacencyList.delete(transition.from);
      }
    }

    const toSet = this._reverseAdjacencyList.get(transition.to);
    if (toSet) {
      toSet.delete(transition.from);
      if (toSet.size === 0) {
        this._reverseAdjacencyList.delete(transition.to);
      }
    }

    // Update metadata and statistics
    this.updatedAt = new Date().toISOString();
    this.updateStatistics();

    // Log transition removal
    logger.info('Transition removed from graph', {
      service: 'UIGraph',
      event: 'transition_removed',
      graphId: this.id,
      transitionId,
      fromStateId: transition.from,
      toStateId: transition.to,
      totalTransitions: this.transitions.length
    });

    return true;
  }

  /**
   * Get a transition by ID
   */
  public getTransition(transitionId: string): ITransition | undefined {
    return this._transitionMap.get(transitionId);
  }

  /**
   * Find transitions between two states
   */
  public findTransitions(fromStateId: string, toStateId?: string): ITransition[] {
    if (toStateId) {
      return this.transitions.filter(t => t.from === fromStateId && t.to === toStateId);
    }
    return this.transitions.filter(t => t.from === fromStateId);
  }

  /**
   * Find a specific transition matching the action
   */
  public findTransition(fromStateId: string, toStateId: string, action: Action): ITransition | null {
    const actionString = JSON.stringify(action);
    return this.transitions.find(t =>
      t.from === fromStateId &&
      t.to === toStateId &&
      JSON.stringify(t.action) === actionString
    ) || null;
  }

  // ============================================================================
  // Graph Operations
  // ============================================================================

  /**
   * Merge another graph into this one
   */
  public mergeGraph(otherGraph: IUIGraph, options: MergeGraphOptions = {}): {
    addedStates: number;
    addedTransitions: number;
    conflicts: string[];
  } {
    const {
      conflictResolution = 'merge',
      validation = 'lenient',
      mergeMetadata = {}
    } = options;

    const result = {
      addedStates: 0,
      addedTransitions: 0,
      conflicts: [] as string[]
    };

    // Validate package name compatibility
    if (otherGraph.packageName !== this.packageName) {
      throw new GraphError(
        `Cannot merge graphs with different package names: '${this.packageName}' vs '${otherGraph.packageName}'`,
        'PACKAGE_NAME_MISMATCH',
        {
          sourcePackage: this.packageName,
          targetPackage: otherGraph.packageName
        }
      );
    }

    logger.info('Starting graph merge', {
      service: 'UIGraph',
      event: 'graph_merge_started',
      graphId: this.id,
      otherGraphId: otherGraph.version,
      otherStates: otherGraph.states.length,
      otherTransitions: otherGraph.transitions.length,
      conflictResolution
    });

    // Merge states
    for (const otherState of otherGraph.states) {
      try {
        const existingState = this.findSimilarState(otherState);
        if (existingState) {
          if (conflictResolution === 'overwrite') {
            this.removeState(existingState.id);
            this.addState(otherState, { force: true });
            result.addedStates++;
            result.conflicts.push(`State ${existingState.id} overwritten`);
          } else if (conflictResolution === 'merge') {
            // Merge metadata and tags
            existingState.tags = [...new Set([...(existingState.tags || []), ...(otherState.tags || [])])];
            existingState.updatedAt = new Date().toISOString();
            result.conflicts.push(`State ${existingState.id} metadata merged`);
          }
          // 'keep' strategy: do nothing
        } else {
          this.addState(otherState, { force: true });
          result.addedStates++;
        }
      } catch (error) {
        if (validation === 'strict') {
          throw error;
        }
        result.conflicts.push(`State merge failed: ${error.message}`);
      }
    }

    // Merge transitions
    for (const otherTransition of otherGraph.transitions) {
      try {
        const existingTransition = this.findTransition(
          otherTransition.from,
          otherTransition.to,
          otherTransition.action
        );

        if (!existingTransition) {
          this.addTransition(
            otherTransition.from,
            otherTransition.to,
            otherTransition.action,
            {
              validateStates: false, // States should already exist
              skipDuplicateCheck: true,
              metadata: otherTransition
            }
          );
          result.addedTransitions++;
        } else {
          result.conflicts.push(`Transition ${existingTransition.id} already exists`);
        }
      } catch (error) {
        if (validation === 'strict') {
          throw error;
        }
        result.conflicts.push(`Transition merge failed: ${error.message}`);
      }
    }

    // Update metadata
    this.metadata.totalCaptureTime += otherGraph.metadata.totalCaptureTime;
    this.metadata.totalSessions += otherGraph.metadata.totalSessions;
    this.updatedAt = new Date().toISOString();

    logger.info('Graph merge completed', {
      service: 'UIGraph',
      event: 'graph_merge_completed',
      graphId: this.id,
      result
    });

    return result;
  }

  // ============================================================================
  // Graph Traversal and Analysis
  // ============================================================================

  /**
   * Find all reachable states from a given state
   */
  public getReachableStates(startStateId: string, maxDepth: number = 10): Set<string> {
    const visited = new Set<string>();
    const queue: Array<{ stateId: string; depth: number }> = [{ stateId: startStateId, depth: 0 }];

    while (queue.length > 0) {
      const { stateId, depth } = queue.shift()!;

      if (visited.has(stateId) || depth >= maxDepth) {
        continue;
      }

      visited.add(stateId);

      const neighbors = this._adjacencyList.get(stateId);
      if (neighbors) {
        for (const neighborId of neighbors) {
          if (!visited.has(neighborId)) {
            queue.push({ stateId: neighborId, depth: depth + 1 });
          }
        }
      }
    }

    return visited;
  }

  /**
   * Find the shortest path between two states
   */
  public findShortestPath(fromStateId: string, toStateId: string): string[] | null {
    if (fromStateId === toStateId) {
      return [fromStateId];
    }

    const visited = new Set<string>();
    const queue: Array<{ stateId: string; path: string[] }> = [{
      stateId: fromStateId,
      path: [fromStateId]
    }];

    while (queue.length > 0) {
      const { stateId, path } = queue.shift()!;

      if (visited.has(stateId)) {
        continue;
      }

      visited.add(stateId);

      const neighbors = this._adjacencyList.get(stateId);
      if (neighbors) {
        for (const neighborId of neighbors) {
          if (neighborId === toStateId) {
            return [...path, neighborId];
          }

          if (!visited.has(neighborId)) {
            queue.push({
              stateId: neighborId,
              path: [...path, neighborId]
            });
          }
        }
      }
    }

    return null;
  }

  /**
   * Find all cycles in the graph
   */
  public findCycles(): string[][] {
    const cycles: string[][] = [];
    const visited = new Set<string>();
    const recursionStack = new Set<string>();
    const path: string[] = [];

    const dfs = (stateId: string): boolean => {
      visited.add(stateId);
      recursionStack.add(stateId);
      path.push(stateId);

      const neighbors = this._adjacencyList.get(stateId);
      if (neighbors) {
        for (const neighborId of neighbors) {
          if (!visited.has(neighborId)) {
            if (dfs(neighborId)) {
              return true;
            }
          } else if (recursionStack.has(neighborId)) {
            // Found a cycle
            const cycleStart = path.indexOf(neighborId);
            cycles.push([...path.slice(cycleStart), neighborId]);
          }
        }
      }

      recursionStack.delete(stateId);
      path.pop();
      return false;
    };

    for (const stateId of this.states.map(s => s.id)) {
      if (!visited.has(stateId)) {
        dfs(stateId);
      }
    }

    return cycles;
  }

  /**
   * Get connected components in the graph
   */
  public getConnectedComponents(): string[][] {
    const visited = new Set<string>();
    const components: string[][] = [];

    for (const state of this.states) {
      if (!visited.has(state.id)) {
        const component = Array.from(this.getReachableStates(state.id));
        components.push(component);
        component.forEach(id => visited.add(id));
      }
    }

    return components;
  }

  // ============================================================================
  // Statistics and Monitoring
  // ============================================================================

  /**
   * Calculate comprehensive graph statistics
   */
  public calculateStatistics(): GraphStatistics {
    const stateCount = this.states.length;
    const transitionCount = this.transitions.length;

    // Calculate degrees
    const inDegrees = new Map<string, number>();
    const outDegrees = new Map<string, number>();

    // Initialize degrees
    for (const state of this.states) {
      inDegrees.set(state.id, 0);
      outDegrees.set(state.id, 0);
    }

    // Count degrees
    for (const transition of this.transitions) {
      outDegrees.set(transition.from, (outDegrees.get(transition.from) || 0) + 1);
      inDegrees.set(transition.to, (inDegrees.get(transition.to) || 0) + 1);
    }

    // Calculate average degree
    const totalDegree = Array.from(inDegrees.values()).reduce((sum, deg) => sum + deg, 0);
    const averageDegree = stateCount > 0 ? totalDegree / stateCount : 0;

    // Find isolated states
    let isolatedStates = 0;
    for (const state of this.states) {
      if ((inDegrees.get(state.id) || 0) === 0 && (outDegrees.get(state.id) || 0) === 0) {
        isolatedStates++;
      }
    }

    // Find hub states (highest degree)
    const hubStates = Array.from(this.states.map(state => ({
      stateId: state.id,
      degree: (inDegrees.get(state.id) || 0) + (outDegrees.get(state.id) || 0),
      inDegree: inDegrees.get(state.id) || 0,
      outDegree: outDegrees.get(state.id) || 0
    })))
    .sort((a, b) => b.degree - a.degree)
    .slice(0, 10); // Top 10 hub states

    // Connected components
    const connectedComponents = this.getConnectedComponents().length;

    // Density
    const maxPossibleTransitions = stateCount * Math.max(0, stateCount - 1);
    const density = maxPossibleTransitions > 0 ? transitionCount / maxPossibleTransitions : 0;

    // Last capture timestamp
    const lastCapture = this.states
      .map(s => s.updatedAt)
      .sort()
      .pop();

    // Capture metrics
    const captureMetrics = {
      totalCaptureTime: this.metadata.totalCaptureTime,
      averageCaptureTime: stateCount > 0 ? this.metadata.totalCaptureTime / stateCount : 0,
      totalSessions: this.metadata.totalSessions
    };

    return {
      stateCount,
      transitionCount,
      averageDegree,
      isolatedStates,
      connectedComponents,
      density,
      hubStates,
      lastCapture,
      captureMetrics
    };
  }

  /**
   * Update internal statistics
   */
  private updateStatistics(): void {
    const stats = this.calculateStatistics();
    this.stats = {
      stateCount: stats.stateCount,
      transitionCount: stats.transitionCount,
      averageDegree: stats.averageDegree,
      isolatedStates: stats.isolatedStates,
      lastCapture: stats.lastCapture
    };
  }

  // ============================================================================
  // Validation and Integrity Checks
  // ============================================================================

  /**
   * Validate the graph for structural integrity
   */
  public validateGraph(): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Check size limits
    if (this.states.length > this._limits.maxStates) {
      errors.push({
        field: 'states',
        message: `State count (${this.states.length}) exceeds maximum (${this._limits.maxStates})`,
        code: 'MAX_STATES_EXCEEDED',
        value: this.states.length,
        severity: 'error'
      });
    }

    if (this.transitions.length > this._limits.maxTransitions) {
      errors.push({
        field: 'transitions',
        message: `Transition count (${this.transitions.length}) exceeds maximum (${this._limits.maxTransitions})`,
        code: 'MAX_TRANSITIONS_EXCEEDED',
        value: this.transitions.length,
        severity: 'error'
      });
    }

    // Check state references in transitions
    for (const transition of this.transitions) {
      if (!this._stateMap.has(transition.from)) {
        errors.push({
          field: 'transitions',
          message: `Transition references non-existent source state: ${transition.from}`,
          code: 'SOURCE_STATE_NOT_FOUND',
          value: transition.from,
          severity: 'error'
        });
      }

      if (!this._stateMap.has(transition.to)) {
        errors.push({
          field: 'transitions',
          message: `Transition references non-existent destination state: ${transition.to}`,
          code: 'DESTINATION_STATE_NOT_FOUND',
          value: transition.to,
          severity: 'error'
        });
      }
    }

    // Check for duplicate state IDs
    const stateIds = this.states.map(s => s.id);
    const duplicateStateIds = stateIds.filter((id, index) => stateIds.indexOf(id) !== index);
    if (duplicateStateIds.length > 0) {
      errors.push({
        field: 'states',
        message: `Duplicate state IDs found: ${duplicateStateIds.join(', ')}`,
        code: 'DUPLICATE_STATE_IDS',
        value: duplicateStateIds,
        severity: 'error'
      });
    }

    // Check for duplicate transition IDs
    const transitionIds = this.transitions.map(t => t.id);
    const duplicateTransitionIds = transitionIds.filter((id, index) => transitionIds.indexOf(id) !== index);
    if (duplicateTransitionIds.length > 0) {
      errors.push({
        field: 'transitions',
        message: `Duplicate transition IDs found: ${duplicateTransitionIds.join(', ')}`,
        code: 'DUPLICATE_TRANSITION_IDS',
        value: duplicateTransitionIds,
        severity: 'error'
      });
    }

    // Check for isolated states (warning)
    const isolatedStates = this.states.filter(state => {
      const hasIncoming = this.transitions.some(t => t.to === state.id);
      const hasOutgoing = this.transitions.some(t => t.from === state.id);
      return !hasIncoming && !hasOutgoing;
    });

    if (isolatedStates.length > 0) {
      warnings.push({
        field: 'states',
        message: `${isolatedStates.length} isolated states found (no incoming or outgoing transitions)`,
        code: 'ISOLATED_STATES',
        value: isolatedStates.map(s => s.id),
        severity: 'warning'
      });
    }

    // Validate state digests
    for (const state of this.states) {
      if (!isValidSHA256(state.digest)) {
        errors.push({
          field: 'states',
          message: `Invalid state digest format: ${state.digest}`,
          code: 'INVALID_DIGEST',
          value: state.digest,
          severity: 'error'
        });
      }
    }

    // Check package name consistency
    for (const state of this.states) {
      if (state.package !== this.packageName) {
        errors.push({
          field: 'states',
          message: `State package name '${state.package}' does not match graph package name '${this.packageName}'`,
          code: 'PACKAGE_NAME_MISMATCH',
          value: state.package,
          severity: 'error'
        });
      }
    }

    // Validate timestamps
    const now = new Date();
    const createdAt = new Date(this.createdAt);
    const updatedAt = new Date(this.updatedAt);

    if (createdAt > now) {
      errors.push({
        field: 'createdAt',
        message: 'Creation timestamp is in the future',
        code: 'INVALID_TIMESTAMP',
        value: this.createdAt,
        severity: 'error'
      });
    }

    if (updatedAt > now) {
      errors.push({
        field: 'updatedAt',
        message: 'Update timestamp is in the future',
        code: 'INVALID_TIMESTAMP',
        value: this.updatedAt,
        severity: 'error'
      });
    }

    if (updatedAt < createdAt) {
      errors.push({
        field: 'updatedAt',
        message: 'Update timestamp is before creation timestamp',
        code: 'INVALID_TIMESTAMP_ORDER',
        value: this.updatedAt,
        severity: 'error'
      });
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate an action object
   */
  private validateAction(action: Action): void {
    if (!action.type) {
      throw new TransitionError(
        'Action type is required',
        'MISSING_ACTION_TYPE',
        { action }
      );
    }

    const validTypes = ['tap', 'type', 'swipe', 'back', 'intent', 'long_press'];
    if (!validTypes.includes(action.type)) {
      throw new TransitionError(
        `Invalid action type: ${action.type}. Valid types: ${validTypes.join(', ')}`,
        'INVALID_ACTION_TYPE',
        { action, validTypes }
      );
    }

    // Type-specific validation
    switch (action.type) {
      case 'type':
        if (!action.text) {
          throw new TransitionError(
            'Text is required for type actions',
            'MISSING_ACTION_TEXT',
            { action }
          );
        }
        break;
      case 'swipe':
        if (!action.swipe) {
          throw new TransitionError(
            'Swipe configuration is required for swipe actions',
            'MISSING_SWIPE_CONFIG',
            { action }
          );
        }
        if (!['up', 'down', 'left', 'right'].includes(action.swipe.direction)) {
          throw new TransitionError(
            `Invalid swipe direction: ${action.swipe.direction}`,
            'INVALID_SWIPE_DIRECTION',
            { action }
          );
        }
        if (typeof action.swipe.distance !== 'number' || action.swipe.distance < 0 || action.swipe.distance > 1) {
          throw new TransitionError(
            'Swipe distance must be a number between 0 and 1',
            'INVALID_SWIPE_DISTANCE',
            { action }
          );
        }
        break;
    }
  }

  /**
   * Calculate similarity between two states
   */
  private calculateStateSimilarity(
    state1: Omit<IState, 'id' | 'createdAt' | 'updatedAt'>,
    state2: IState,
    selectorWeight: number = 0.7,
    textWeight: number = 0.3
  ): number {
    // Different packages or activities = 0 similarity
    if (state1.package !== state2.package || state1.activity !== state2.activity) {
      return 0.0;
    }

    // Identical digests = 1.0 similarity
    if (state1.digest === state2.digest) {
      return 1.0;
    }

    // Simple selector similarity (could be enhanced)
    const selectorSimilarity = this.calculateSelectorSimilarity(state1.selectors, state2.selectors);

    // Simple text similarity
    const textSimilarity = this.calculateTextSimilarity(state1.visibleText || [], state2.visibleText || []);

    return (selectorWeight * selectorSimilarity) + (textWeight * textSimilarity);
  }

  /**
   * Calculate similarity between selector arrays
   */
  private calculateSelectorSimilarity(selectors1: Selector[], selectors2: Selector[]): number {
    if (selectors1.length === 0 && selectors2.length === 0) {
      return 1.0;
    }

    if (selectors1.length === 0 || selectors2.length === 0) {
      return 0.0;
    }

    const normalizeSelector = (selector: Selector): string => {
      const parts = [];
      if (selector.rid) parts.push(`rid:${selector.rid}`);
      if (selector.desc) parts.push(`desc:${selector.desc}`);
      if (selector.text) parts.push(`text:${selector.text}`);
      if (selector.cls) parts.push(`cls:${selector.cls}`);
      if (selector.bounds) parts.push(`bounds:${selector.bounds.join(',')}`);
      return parts.join('|');
    };

    const set1 = new Set(selectors1.map(normalizeSelector));
    const set2 = new Set(selectors2.map(normalizeSelector));

    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return intersection.size / union.size;
  }

  /**
   * Calculate similarity between text arrays
   */
  private calculateTextSimilarity(text1: string[], text2: string[]): number {
    if (text1.length === 0 && text2.length === 0) {
      return 1.0;
    }

    if (text1.length === 0 || text2.length === 0) {
      return 0.0;
    }

    const normalize = (text: string[]) =>
      text
        .filter(t => t && t.trim().length > 0)
        .map(t => t.trim().toLowerCase())
        .sort();

    const set1 = new Set(normalize(text1));
    const set2 = new Set(normalize(text2));

    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return intersection.size / union.size;
  }

  // ============================================================================
  // Export and Serialization
  // ============================================================================

  /**
   * Convert graph to plain object for serialization
   */
  public toJSON(): IUIGraph {
    // Update statistics before export
    this.updateStatistics();

    return {
      version: this.version,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      packageName: this.packageName,
      states: [...this.states],
      transitions: [...this.transitions],
      stats: { ...this.stats },
      metadata: { ...this.metadata }
    };
  }

  /**
   * Create UIGraph from plain object
   */
  public static fromJSON(data: IUIGraph): UIGraph {
    const graph = Object.create(UIGraph.prototype);
    Object.assign(graph, {
      version: data.version,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
      packageName: data.packageName,
      states: [...data.states],
      transitions: [...data.transitions],
      stats: { ...data.stats },
      metadata: { ...data.metadata },
      _stateMap: new Map(data.states.map(s => [s.id, s])),
      _transitionMap: new Map(data.transitions.map(t => [t.id, t])),
      _adjacencyList: (() => {
        const adj = new Map<string, Set<string>>();
        for (const transition of data.transitions) {
          if (!adj.has(transition.from)) {
            adj.set(transition.from, new Set());
          }
          adj.get(transition.from)!.add(transition.to);
        }
        return adj;
      })(),
      _reverseAdjacencyList: (() => {
        const rev = new Map<string, Set<string>>();
        for (const transition of data.transitions) {
          if (!rev.has(transition.to)) {
            rev.set(transition.to, new Set());
          }
          rev.get(transition.to)!.add(transition.from);
        }
        return rev;
      })(),
      _limits: {
        maxStates: MAX_STATES,
        maxTransitions: MAX_TRANSITIONS
      },
      _validation: {
        strictMode: false,
        deduplicationThreshold: DEFAULT_SIMILARITY_THRESHOLD
      }
    });

    return graph;
  }

  /**
   * Generate visualization data for the graph
   */
  public generateVisualizationData(): {
    nodes: Array<{
      id: string;
      label: string;
      activity: string;
      package: string;
      x?: number;
      y?: number;
      degree: number;
      isolated: boolean;
    }>;
    edges: Array<{
      id: string;
      source: string;
      target: string;
      action: string;
      confidence?: number;
    }>;
    statistics: GraphStatistics;
  } {
    const statistics = this.calculateStatistics();
    const inDegrees = new Map<string, number>();
    const outDegrees = new Map<string, number>();

    // Calculate degrees
    for (const state of this.states) {
      inDegrees.set(state.id, 0);
      outDegrees.set(state.id, 0);
    }

    for (const transition of this.transitions) {
      outDegrees.set(transition.from, (outDegrees.get(transition.from) || 0) + 1);
      inDegrees.set(transition.to, (inDegrees.get(transition.to) || 0) + 1);
    }

    const nodes = this.states.map(state => ({
      id: state.id,
      label: state.activity.split('.').pop() || state.activity,
      activity: state.activity,
      package: state.package,
      degree: (inDegrees.get(state.id) || 0) + (outDegrees.get(state.id) || 0),
      isolated: (inDegrees.get(state.id) || 0) === 0 && (outDegrees.get(state.id) || 0) === 0
    }));

    const edges = this.transitions.map(transition => ({
      id: transition.id,
      source: transition.from,
      target: transition.to,
      action: transition.action.type,
      confidence: transition.confidence
    }));

    return {
      nodes,
      edges,
      statistics
    };
  }

  // ============================================================================
  // Cleanup and Maintenance
  // ============================================================================

  /**
   * Remove unreachable states from the graph
   */
  public pruneUnreachableStates(keepStates: string[] = []): {
    removedStates: number;
    removedTransitions: number;
  } {
    const result = {
      removedStates: 0,
      removedTransitions: 0
    };

    // If no states to keep, find all reachable states from any state
    if (keepStates.length === 0 && this.states.length > 0) {
      keepStates = [this.states[0].id];
    }

    const reachableStates = new Set<string>();
    for (const stateId of keepStates) {
      const reachable = this.getReachableStates(stateId);
      reachable.forEach(id => reachableStates.add(id));
    }

    // Remove unreachable states
    const statesToRemove = this.states.filter(s => !reachableStates.has(s.id));
    for (const state of statesToRemove) {
      const removed = this.removeState(state.id);
      if (removed) {
        result.removedStates++;
        result.removedTransitions += this.transitions.filter(t =>
          t.from === state.id || t.to === state.id
        ).length;
      }
    }

    logger.info('Graph pruning completed', {
      service: 'UIGraph',
      event: 'graph_pruned',
      graphId: this.id,
      result
    });

    return result;
  }

  /**
   * Optimize graph structure and remove redundant elements
   */
  public optimizeGraph(): {
    removedTransitions: number;
    mergedStates: number;
    optimizations: string[];
  } {
    const result = {
      removedTransitions: 0,
      mergedStates: 0,
      optimizations: [] as string[]
    };

    // Remove duplicate transitions
    const uniqueTransitions = new Map<string, ITransition>();
    const duplicateTransitionIds: string[] = [];

    for (const transition of this.transitions) {
      const key = `${transition.from}:${transition.to}:${JSON.stringify(transition.action)}`;
      if (!uniqueTransitions.has(key)) {
        uniqueTransitions.set(key, transition);
      } else {
        duplicateTransitionIds.push(transition.id);
      }
    }

    for (const transitionId of duplicateTransitionIds) {
      if (this.removeTransition(transitionId)) {
        result.removedTransitions++;
      }
    }

    if (result.removedTransitions > 0) {
      result.optimizations.push(`Removed ${result.removedTransitions} duplicate transitions`);
    }

    // Merge very similar states (high threshold)
    const statesToRemove = new Set<string>();
    const mergedStatePairs: Array<{ from: string; to: string }> = [];

    for (let i = 0; i < this.states.length; i++) {
      for (let j = i + 1; j < this.states.length; j++) {
        const state1 = this.states[i];
        const state2 = this.states[j];

        if (statesToRemove.has(state1.id) || statesToRemove.has(state2.id)) {
          continue;
        }

        const similarity = this.calculateStateSimilarity(state1, state2);
        if (similarity >= 0.98) { // Very high threshold for merging
          // Keep the newer state, migrate transitions
          const newerState = new Date(state1.updatedAt) > new Date(state2.updatedAt) ? state1 : state2;
          const olderState = newerState === state1 ? state2 : state1;

          // Migrate transitions from older state to newer state
          const transitionsToMigrate = this.transitions.filter(t =>
            t.from === olderState.id || t.to === olderState.id
          );

          for (const transition of transitionsToMigrate) {
            // Create new transition with updated state references
            const newFrom = transition.from === olderState.id ? newerState.id : transition.from;
            const newTo = transition.to === olderState.id ? newerState.id : transition.to;

            if (newFrom !== newTo) { // Avoid self-loops
              this.addTransition(newFrom, newTo, transition.action, {
                validateStates: false,
                skipDuplicateCheck: true,
                metadata: transition
              });
            }
          }

          statesToRemove.add(olderState.id);
          mergedStatePairs.push({ from: olderState.id, to: newerState.id });
        }
      }
    }

    // Remove merged states
    for (const stateId of statesToRemove) {
      if (this.removeState(stateId)) {
        result.mergedStates++;
      }
    }

    if (result.mergedStates > 0) {
      result.optimizations.push(`Merged ${result.mergedStates} similar states`);
    }

    // Remove isolated states (optional optimization)
    const isolatedStates = this.states.filter(state => {
      const hasIncoming = this.transitions.some(t => t.to === state.id);
      const hasOutgoing = this.transitions.some(t => t.from === state.id);
      return !hasIncoming && !hasOutgoing;
    });

    for (const state of isolatedStates) {
      this.removeState(state.id);
      result.mergedStates++;
    }

    if (isolatedStates.length > 0) {
      result.optimizations.push(`Removed ${isolatedStates.length} isolated states`);
    }

    logger.info('Graph optimization completed', {
      service: 'UIGraph',
      event: 'graph_optimized',
      graphId: this.id,
      result
    });

    return result;
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Get graph summary information
   */
  public getSummary(): {
    id: string;
    packageName: string;
    version: string;
    stateCount: number;
    transitionCount: number;
    createdAt: string;
    updatedAt: string;
    size: string;
  } {
    return {
      id: this.id,
      packageName: this.packageName,
      version: this.version,
      stateCount: this.states.length,
      transitionCount: this.transitions.length,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      size: `${JSON.stringify(this.toJSON()).length} bytes`
    };
  }

  /**
   * Clone the graph
   */
  public clone(): UIGraph {
    return UIGraph.fromJSON(this.toJSON());
  }

  /**
   * Clear all states and transitions from the graph
   */
  public clear(): void {
    this.states = [];
    this.transitions = [];
    this._stateMap.clear();
    this._transitionMap.clear();
    this._adjacencyList.clear();
    this._reverseAdjacencyList.clear();
    this.updatedAt = new Date().toISOString();
    this.updateStatistics();

    logger.info('Graph cleared', {
      service: 'UIGraph',
      event: 'graph_cleared',
      graphId: this.id
    });
  }
}

// ============================================================================
// Export Types and Utilities
// ============================================================================

export type {
  CreateGraphOptions,
  AddStateOptions,
  AddTransitionOptions,
  MergeGraphOptions,
  GraphStatistics
};

export {
  GraphError,
  GraphValidationError
};

// ============================================================================
// Usage Examples
// ============================================================================

/**
 * Example usage of the UIGraph class:
 *
 * ```typescript
 * import { UIGraph } from './models/graph';
 *
 * // Create a new graph for an app
 * const graph = new UIGraph('com.example.app', {
 *   metadata: {
 *     captureTool: 'UIAutomator2',
 *     androidVersion: '13',
 *     deviceInfo: 'Pixel_6_Pro'
 *   }
 * });
 *
 * // Add states to the graph
 * const homeState = graph.addState({
 *   package: 'com.example.app',
 *   activity: 'com.example.app.MainActivity',
 *   digest: 'abc123...',
 *   selectors: [{ rid: 'btn_settings', text: 'Settings' }],
 *   visibleText: ['Welcome', 'Settings', 'Profile'],
 *   metadata: {
 *     captureMethod: 'adb',
 *     captureDuration: 150,
 *     elementCount: 15,
 *     hierarchyDepth: 5
 *   }
 * });
 *
 * const settingsState = graph.addState({
 *   package: 'com.example.app',
 *   activity: 'com.example.app.SettingsActivity',
 *   digest: 'def456...',
 *   selectors: [{ rid: 'btn_back', text: 'Back' }],
 *   visibleText: ['Settings', 'Back', 'General'],
 *   metadata: {
 *     captureMethod: 'adb',
 *     captureDuration: 120,
 *     elementCount: 10,
 *     hierarchyDepth: 4
 *   }
 * });
 *
 * // Add transitions between states
 * const transition = graph.addTransition(
 *   homeState.id,
 *   settingsState.id,
 *   { type: 'tap', target: { rid: 'btn_settings' } }
 * );
 *
 * // Validate the graph
 * const validation = graph.validateGraph();
 * if (!validation.isValid) {
 *   console.error('Graph validation errors:', validation.errors);
 * }
 *
 * // Calculate statistics
 * const stats = graph.calculateStatistics();
 * console.log('Graph statistics:', stats);
 *
 * // Find shortest path between states
 * const path = graph.findShortestPath(homeState.id, settingsState.id);
 * console.log('Shortest path:', path);
 *
 * // Export for storage
 * const serialized = graph.toJSON();
 *
 * // Generate visualization data
 * const vizData = graph.generateVisualizationData();
 * ```
 */