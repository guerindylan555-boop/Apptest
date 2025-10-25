/**
 * Graph Management Service
 *
 * UI graph operations, state management, and deduplication.
 * Handles persistent storage and graph statistics.
 */

import { promises as fs } from 'fs';
import path from 'path';
import {
  UIGraph,
  StateRecord,
  TransitionRecord,
  MergeStatesRequest,
  MergeStatesResponse,
  SnapshotResponse
} from '../types/graph';
import {
  calculateStateSimilarity,
  shouldMergeStates,
  isValidSHA256,
  generateTransitionId
} from '../utils/hash';
import { getGraphConfig } from '../config/discovery';
import { v4 as uuidv4 } from 'uuid';

export class GraphService {
  private config = getGraphConfig();
  private graph: UIGraph | null = null;
  private lastModified: Date | null = null;

  /**
   * Load graph from disk
   */
  async loadGraph(): Promise<UIGraph> {
    try {
      const content = await fs.readFile(this.config.graphPath, 'utf-8');
      this.graph = JSON.parse(content);
      this.lastModified = new Date();

      // Validate loaded graph
      this.validateGraph(this.graph);

      return this.graph;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        // Graph file doesn't exist, create new one
        this.graph = await this.createNewGraph();
        return this.graph;
      }
      throw new Error(`Failed to load graph: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Save graph to disk
   */
  async saveGraph(): Promise<void> {
    if (!this.graph) {
      throw new Error('No graph to save');
    }

    try {
      // Update metadata
      this.graph.updatedAt = new Date().toISOString();
      this.updateGraphStats();

      // Ensure directory exists
      await fs.mkdir(path.dirname(this.config.graphPath), { recursive: true });

      // Atomic write: write to temp file first, then rename
      const tempPath = `${this.config.graphPath}.tmp`;
      await fs.writeFile(tempPath, JSON.stringify(this.graph, null, 2));
      await fs.rename(tempPath, this.config.graphPath);

      this.lastModified = new Date();
    } catch (error) {
      throw new Error(`Failed to save graph: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get current graph (load if needed)
   */
  async getGraph(): Promise<UIGraph> {
    if (!this.graph) {
      return await this.loadGraph();
    }
    return this.graph;
  }

  /**
   * Add state to graph with deduplication
   */
  async addState(state: StateRecord): Promise<SnapshotResponse> {
    const graph = await this.getGraph();

    // Check for duplicate states
    const existingState = this.findDuplicateState(graph, state);
    if (existingState) {
      // Merge with existing state
      await this.mergeStates(existingState.id, state.id);
      return {
        state: existingState,
        merged: true,
        mergedInto: existingState.id
      };
    }

    // Add new state
    graph.states.push(state);
    await this.saveGraph();

    return {
      state,
      merged: false
    };
  }

  /**
   * Find state by ID
   */
  async getState(stateId: string): Promise<StateRecord | null> {
    const graph = await this.getGraph();
    return graph.states.find(state => state.id === stateId) || null;
  }

  /**
   * Find duplicate state based on similarity
   */
  private findDuplicateState(graph: UIGraph, state: StateRecord): StateRecord | null {
    const threshold = this.config.mergeThreshold;

    for (const existingState of graph.states) {
      if (shouldMergeStates(state, existingState, threshold)) {
        return existingState;
      }
    }

    return null;
  }

  /**
   * Add transition to graph
   */
  async addTransition(
    fromStateId: string,
    toStateId: string,
    action: any,
    evidence?: any
  ): Promise<TransitionRecord> {
    const graph = await this.getGraph();

    // Validate states exist
    const fromState = graph.states.find(s => s.id === fromStateId);
    const toState = graph.states.find(s => s.id === toStateId);

    if (!fromState) {
      throw new Error(`Source state not found: ${fromStateId}`);
    }
    if (!toState) {
      throw new Error(`Target state not found: ${toStateId}`);
    }

    // Create transition record
    const transition: TransitionRecord = {
      id: generateTransitionId(fromStateId, toStateId, JSON.stringify(action)),
      from: fromStateId,
      to: toStateId,
      action,
      evidence,
      createdAt: new Date().toISOString()
    };

    // Check for duplicate transitions
    const existingTransition = graph.transitions.find(t => t.id === transition.id);
    if (existingTransition) {
      return existingTransition;
    }

    graph.transitions.push(transition);
    await this.saveGraph();

    return transition;
  }

  /**
   * Merge two states
   */
  async mergeStates(sourceId: string, targetId: string): Promise<MergeStatesResponse> {
    const graph = await this.getGraph();

    const sourceState = graph.states.find(s => s.id === sourceId);
    const targetState = graph.states.find(s => s.id === targetId);

    if (!sourceState) {
      throw new Error(`Source state not found: ${sourceId}`);
    }
    if (!targetState) {
      throw new Error(`Target state not found: ${targetId}`);
    }

    if (sourceId === targetId) {
      throw new Error('Cannot merge state with itself');
    }

    const updatedTransitions: string[] = [];
    const removedTransitions: string[] = [];

    // Update all transitions that point to source state
    graph.transitions.forEach(transition => {
      if (transition.from === sourceId) {
        transition.from = targetId;
        transition.id = generateTransitionId(
          targetId,
          transition.to,
          JSON.stringify(transition.action)
        );
        updatedTransitions.push(transition.id);
      }
      if (transition.to === sourceId) {
        transition.to = targetId;
        transition.id = generateTransitionId(
          transition.from,
          targetId,
          JSON.stringify(transition.action)
        );
        updatedTransitions.push(transition.id);
      }
    });

    // Remove self-loops created by merge
    const originalLength = graph.transitions.length;
    graph.transitions = graph.transitions.filter(t => t.from !== t.to);
    const removedCount = originalLength - graph.transitions.length;

    // Remove source state
    const originalStatesLength = graph.states.length;
    graph.states = graph.states.filter(s => s.id !== sourceId);
    const removedStates = originalStatesLength - graph.states.length;

    await this.saveGraph();

    return {
      success: true,
      mergedCount: removedStates,
      updatedTransitions,
      removedTransitions: graph.transitions.slice(-removedCount).map(t => t.id)
    };
  }

  /**
   * Get states by activity
   */
  async getStatesByActivity(activity: string): Promise<StateRecord[]> {
    const graph = await this.getGraph();
    return graph.states.filter(state => state.activity === activity);
  }

  /**
   * Get transitions from state
   */
  async getTransitionsFrom(stateId: string): Promise<TransitionRecord[]> {
    const graph = await this.getGraph();
    return graph.transitions.filter(transition => transition.from === stateId);
  }

  /**
   * Get transitions to state
   */
  async getTransitionsTo(stateId: string): Promise<TransitionRecord[]> {
    const graph = await this.getGraph();
    return graph.transitions.filter(transition => transition.to === stateId);
  }

  /**
   * Detect current state based on UI snapshot
   */
  async detectCurrentState(
    packageName: string,
    activity: string,
    selectors: any[],
    visibleText: string[]
  ): Promise<{
    state?: StateRecord;
    confidence: number;
    candidates: Array<{ state: StateRecord; similarity: number }>;
  }> {
    const graph = await this.getGraph();
    const candidates: Array<{ state: StateRecord; similarity: number }> = [];

    // Find potential matches
    for (const state of graph.states) {
      if (state.package === packageName && state.activity === activity) {
        const similarity = calculateStateSimilarity(
          {
            ...state,
            selectors,
            visibleText,
            package: packageName,
            activity,
            digest: '' // Not needed for similarity calculation
          } as StateRecord,
          state
        );

        if (similarity > 0.5) { // Only consider reasonable matches
          candidates.push({ state, similarity });
        }
      }
    }

    // Sort by similarity (highest first)
    candidates.sort((a, b) => b.similarity - a.similarity);

    const bestMatch = candidates[0];
    const confidence = bestMatch?.similarity || 0;

    return {
      state: confidence > 0.8 ? bestMatch?.state : undefined,
      confidence,
      candidates
    };
  }

  /**
   * Get graph statistics
   */
  async getStats(): Promise<UIGraph['stats']> {
    const graph = await this.getGraph();
    return graph.stats;
  }

  /**
   * Validate graph structure
   */
  private validateGraph(graph: UIGraph): void {
    if (!graph.version) {
      throw new Error('Graph missing version');
    }

    if (!graph.packageName) {
      throw new Error('Graph missing package name');
    }

    if (!Array.isArray(graph.states)) {
      throw new Error('Graph states must be an array');
    }

    if (!Array.isArray(graph.transitions)) {
      throw new Error('Graph transitions must be an array');
    }

    // Validate state IDs
    for (const state of graph.states) {
      if (!isValidSHA256(state.id)) {
        throw new Error(`Invalid state ID: ${state.id}`);
      }
    }

    // Validate transition references
    const stateIds = new Set(graph.states.map(s => s.id));
    for (const transition of graph.transitions) {
      if (!stateIds.has(transition.from)) {
        throw new Error(`Transition references non-existent state: ${transition.from}`);
      }
      if (!stateIds.has(transition.to)) {
        throw new Error(`Transition references non-existent state: ${transition.to}`);
      }
    }
  }

  /**
   * Update graph statistics
   */
  private updateGraphStats(): void {
    if (!this.graph) return;

    const stateCount = this.graph.states.length;
    const transitionCount = this.graph.transitions.length;

    // Calculate average degree (average number of transitions per state)
    let averageDegree = 0;
    if (stateCount > 0) {
      const totalDegree = this.graph.transitions.reduce((sum: number, t) => {
        return sum + 1; // Each transition contributes 1 to degree
      }, 0);
      averageDegree = totalDegree / stateCount;
    }

    // Count isolated states (states with no transitions)
    const statesWithTransitions = new Set([
      ...this.graph.transitions.map(t => t.from),
      ...this.graph.transitions.map(t => t.to)
    ]);
    const isolatedStates = stateCount - statesWithTransitions.size;

    this.graph.stats = {
      stateCount,
      transitionCount,
      averageDegree: Math.round(averageDegree * 100) / 100,
      isolatedStates,
      lastCapture: this.graph.states
        .map(s => s.updatedAt)
        .sort()
        .pop() || undefined
    };
  }

  /**
   * Create new empty graph
   */
  private async createNewGraph(): Promise<UIGraph> {
    const now = new Date().toISOString();

    const graph: UIGraph = {
      version: '1.0.0',
      createdAt: now,
      updatedAt: now,
      packageName: 'unknown', // Will be updated when first state is captured
      states: [],
      transitions: [],
      stats: {
        stateCount: 0,
        transitionCount: 0,
        averageDegree: 0,
        isolatedStates: 0
      },
      metadata: {
        captureTool: 'AutoApp Discovery v1.0',
        totalCaptureTime: 0,
        totalSessions: 0
      }
    };

    this.graph = graph;
    await this.saveGraph();

    return graph;
  }

  /**
   * Clear graph (for testing/reset)
   */
  async clearGraph(): Promise<void> {
    this.graph = await this.createNewGraph();
  }

  /**
   * Export graph as JSON string
   */
  async exportGraph(): Promise<string> {
    const graph = await this.getGraph();
    return JSON.stringify(graph, null, 2);
  }

  /**
   * Import graph from JSON string
   */
  async importGraph(jsonData: string): Promise<UIGraph> {
    try {
      const graph = JSON.parse(jsonData) as UIGraph;
      this.validateGraph(graph);

      this.graph = graph;
      await this.saveGraph();

      return graph;
    } catch (error) {
      throw new Error(`Failed to import graph: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

/**
 * Create singleton instance
 */
export const graphService = new GraphService();