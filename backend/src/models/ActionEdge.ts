/**
 * ActionEdge Entity
 *
 * Represents an action/transition between screen nodes with
 * execution details, guards, and confidence tracking.
 */

import { v4 as uuidv4 } from 'uuid';
import { ExtendedActionEdge } from '../types/graph';
import { SelectorCandidateEntity } from './SelectorCandidate';

export interface ActionEdgeOptions {
  fromNodeId: string;
  toNodeId?: string | null;
  action: {
    kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    delayMs?: number;
    intent?: {
      action: string;
      package?: string;
      component?: string;
    };
  };
  guard?: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  notes?: string;
  createdBy?: string;
  startStateConstraint?: string;
}

export class ActionEdgeEntity implements ExtendedActionEdge {
  id: string;
  fromNodeId: string;
  toNodeId?: string;
  action: {
    kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    delayMs?: number;
    intent?: {
      action: string;
      package?: string;
      component?: string;
    };
  };
  guard: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  notes: string;
  createdAt: string;
  createdBy: string;
  confidence: number;
  startStateConstraint?: string;

  // Extended fields for execution tracking
  lastExecutedAt?: string;
  executionCount: number = 0;
  successCount: number = 0;
  failureCount: number = 0;
  lastResult?: 'success' | 'failure';

  constructor(options: ActionEdgeOptions) {
    this.id = options.fromNodeId ? `${options.fromNodeId}-${uuidv4().substring(0, 8)}` : uuidv4();
    this.fromNodeId = options.fromNodeId;
    this.toNodeId = options.toNodeId || undefined;
    this.action = { ...options.action };
    this.guard = options.guard || {};
    this.notes = options.notes || '';
    this.createdAt = new Date().toISOString();
    this.createdBy = options.createdBy || 'system';
    this.confidence = 0.8; // Default confidence for new edges
    this.startStateConstraint = options.startStateConstraint;

    this.validate();
  }

  /**
   * Create edge with destination node
   */
  static withDestination(
    fromNodeId: string,
    toNodeId: string,
    action: ActionEdgeOptions['action'],
    options: Omit<ActionEdgeOptions, 'fromNodeId' | 'toNodeId' | 'action'> = {}
  ): ActionEdgeEntity {
    return new ActionEdgeEntity({
      fromNodeId,
      toNodeId,
      action,
      ...options
    });
  }

  /**
   * Create edge without destination (for capture workflow)
   */
  static withoutDestination(
    fromNodeId: string,
    action: ActionEdgeOptions['action'],
    options: Omit<ActionEdgeOptions, 'fromNodeId' | 'action'> = {}
  ): ActionEdgeEntity {
    return new ActionEdgeEntity({
      fromNodeId,
      toNodeId: undefined,
      action,
      ...options
    });
  }

  /**
   * Validate edge configuration
   */
  private validate(): void {
    const errors: string[] = [];

    if (!this.fromNodeId) {
      errors.push('Source node ID is required');
    }

    if (!this.action) {
      errors.push('Action is required');
    }

    if (this.action) {
      const { kind, selectorId, text } = this.action;

      // Validate action-specific requirements
      switch (kind) {
        case 'tap':
          if (!selectorId && !text) {
            errors.push('tap action must specify selectorId or text');
          }
          break;

        case 'type':
          if (!text) {
            errors.push('type action must specify text');
          }
          break;

        case 'wait':
          if (!this.action.delayMs || this.action.delayMs <= 0) {
            errors.push('wait action must specify positive delayMs');
          }
          break;

        case 'back':
          if (selectorId || text) {
            errors.push('back action should not specify selectorId or text');
          }
          break;

        case 'intent':
          // Intent actions may require additional validation based on use case
          break;
      }
    }

    // Validate guard conditions
    if (this.guard?.mustMatchSignatureHash && this.guard?.requiredTexts?.length === 0) {
      // This is actually valid - signature hash match can be sufficient
    }

    if (errors.length > 0) {
      throw new Error(`Invalid action edge: ${errors.join(', ')}`);
    }
  }

  /**
   * Update destination node ID
   */
  setDestinationNode(toNodeId: string): void {
    this.toNodeId = toNodeId;
  }

  /**
   * Clear destination node (edge becomes incomplete)
   */
  clearDestinationNode(): void {
    this.toNodeId = undefined;
  }

  /**
   * Check if edge has a complete destination
   */
  hasDestination(): boolean {
    return this.toNodeId !== undefined;
  }

  /**
   * Check if edge is executable (has destination)
   */
  isExecutable(): boolean {
    return this.hasDestination();
  }

  /**
   * Check if edge references a specific selector
   */
  referencesSelector(selectorId: string): boolean {
    return this.action.selectorId === selectorId;
  }

  /**
   * Check if edge references a specific node
   */
  referencesNode(nodeId: string): boolean {
    return this.fromNodeId === nodeId || this.toNodeId === nodeId;
  }

  /**
   * Update action parameters
   */
  updateAction(action: Partial<ActionEdgeOptions['action']>): void {
    this.action = { ...this.action, ...action };
    this.validate();
  }

  /**
   * Update guard conditions
   */
  updateGuard(guard: ActionEdgeOptions['guard']): void {
    this.guard = { ...this.guard, ...guard };
  }

  /**
   * Update notes
   */
  updateNotes(notes: string): void {
    this.notes = notes;
  }

  /**
   * Record execution result
   */
  recordExecution(success: boolean, durationMs?: number): void {
    this.lastExecutedAt = new Date().toISOString();
    this.executionCount++;
    this.lastResult = success ? 'success' : 'failure';

    if (success) {
      this.successCount++;
      // Gradually increase confidence on success
      this.confidence = Math.min(1.0, this.confidence + 0.05);
    } else {
      this.failureCount++;
      // Decrease confidence more aggressively on failure
      this.confidence = Math.max(0.1, this.confidence - 0.1);
    }

    // Store execution metadata if duration provided
    if (durationMs !== undefined) {
      this.lastExecutionDurationMs = durationMs;
    }
  }

  // Extended field for tracking execution duration
  private lastExecutionDurationMs?: number;

  /**
   * Get execution success rate
   */
  getSuccessRate(): number {
    if (this.executionCount === 0) return 0;
    return (this.successCount / this.executionCount) * 100;
  }

  /**
   * Check if edge is considered reliable for automation
   */
  isReliable(): boolean {
    return this.confidence >= 0.6 && this.getSuccessRate() >= 70;
  }

  /**
   * Check if edge is considered risky
   */
  isRisky(): boolean {
    return this.confidence < 0.4 || this.getSuccessRate() < 50;
  }

  /**
   * Get risk level
   */
  getRiskLevel(): 'low' | 'medium' | 'high' {
    if (this.isReliable()) return 'low';
    if (this.isRisky()) return 'high';
    return 'medium';
  }

  /**
   * Get action description for logging
   */
  getActionDescription(): string {
    const { kind, selectorId, text, delayMs, keycode } = this.action;
    const target = selectorId || text || delayMs || keycode || 'system';

    switch (kind) {
      case 'tap':
        return `Tap on: ${target}`;
      case 'type':
        return `Type: "${text}" into: ${target}`;
      case 'wait':
        return `Wait: ${delayMs}ms`;
      case 'back':
        return 'Go back';
      case 'intent':
        return `Intent: ${target}`;
      default:
        return `${kind}: ${target}`;
    }
  }

  /**
   * Check if edge applies to a specific start state
   */
  appliesToStartState(startStateId: string): boolean {
    if (!this.startStateConstraint) {
      return true; // No constraint means applies to all states
    }
    return this.startStateConstraint === startStateId;
  }

  /**
   * Set start state constraint
   */
  setStartStateConstraint(startStateId: string): void {
    this.startStateConstraint = startStateId;
  }

  /**
   * Clear start state constraint
   */
  clearStartStateConstraint(): void {
    this.startStateConstraint = undefined;
  }

  /**
   * Check if edge has guard conditions
   */
  hasGuards(): boolean {
    return !!(this.guard?.mustMatchSignatureHash || this.guard?.requiredTexts?.length);
  }

  /**
   * Check if guard conditions would match given characteristics
   */
  guardsMatch(characteristics: {
    signatureHash?: string;
    texts?: string[];
  }): boolean {
    if (!this.hasGuards()) return true;

    // Check signature hash requirement
    if (this.guard?.mustMatchSignatureHash) {
      if (characteristics.signatureHash !== this.guard.mustMatchSignatureHash) {
        return false;
      }
    }

    // Check required texts
    if (this.guard?.requiredTexts && this.guard.requiredTexts.length > 0) {
      if (!characteristics.texts || characteristics.texts.length === 0) {
        return false;
      }

      const hasAllRequiredTexts = this.guard.requiredTexts.every(requiredText =>
        characteristics.texts!.some(text =>
          text.toLowerCase().includes(requiredText.toLowerCase())
        )
      );

      if (!hasAllRequiredTexts) {
        return false;
      }
    }

    return true;
  }

  /**
   * Get edge summary information
   */
  getSummary(): {
    id: string;
    fromNodeId: string;
    toNodeId?: string;
    action: string;
    confidence: number;
    successRate: number;
    riskLevel: string;
    executionCount: number;
    hasDestination: boolean;
    hasGuards: boolean;
  } {
    return {
      id: this.id,
      fromNodeId: this.fromNodeId,
      toNodeId: this.toNodeId || undefined,
      action: this.getActionDescription(),
      confidence: Math.round(this.confidence * 100),
      successRate: Math.round(this.getSuccessRate()),
      riskLevel: this.getRiskLevel(),
      executionCount: this.executionCount,
      hasDestination: this.hasDestination(),
      hasGuards: this.hasGuards()
    };
  }

  /**
   * Get execution statistics
   */
  getExecutionStats(): {
    totalExecutions: number;
    successfulExecutions: number;
    failedExecutions: number;
    successRate: number;
    averageConfidence: number;
    lastExecutedAt?: string;
    lastResult?: string;
  } {
    return {
      totalExecutions: this.executionCount,
      successfulExecutions: this.successCount,
      failedExecutions: this.failureCount,
      successRate: Math.round(this.getSuccessRate()),
      averageConfidence: Math.round(this.confidence * 100),
      lastExecutedAt: this.lastExecutedAt,
      lastResult: this.lastResult
    };
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): ExtendedActionEdge {
    return {
      id: this.id,
      fromNodeId: this.fromNodeId,
      toNodeId: this.toNodeId,
      action: { ...this.action },
      guard: { ...this.guard },
      notes: this.notes,
      createdAt: this.createdAt,
      createdBy: this.createdBy,
      confidence: this.confidence,
      startStateConstraint: this.startStateConstraint
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: ExtendedActionEdge): ActionEdgeEntity {
    const entity = Object.create(ActionEdgeEntity.prototype);
    Object.assign(entity, data);

    // Initialize extended fields
    entity.lastExecutedAt = undefined;
    entity.executionCount = 0;
    entity.successCount = 0;
    entity.failureCount = 0;
    entity.lastResult = undefined;

    return entity;
  }

  /**
   * Find edges from a specific node
   */
  static findFromNode(edges: ActionEdgeEntity[], fromNodeId: string): ActionEdgeEntity[] {
    return edges.filter(edge => edge.fromNodeId === fromNodeId);
  }

  /**
   * Find edges to a specific node
   */
  static findToNode(edges: ActionEdgeEntity[], toNodeId: string): ActionEdgeEntity[] {
    return edges.filter(edge => edge.toNodeId === toNodeId);
  }

  /**
   * Find edges that reference a specific selector
   */
  static findReferencingSelector(edges: ActionEdgeEntity[], selectorId: string): ActionEdgeEntity[] {
    return edges.filter(edge => edge.referencesSelector(selectorId));
  }

  /**
   * Get executable edges (those with destinations)
   */
  static getExecutableEdges(edges: ActionEdgeEntity[]): ActionEdgeEntity[] {
    return edges.filter(edge => edge.isExecutable());
  }

  /**
   * Get reliable edges (high confidence and success rate)
   */
  static getReliableEdges(edges: ActionEdgeEntity[]): ActionEdgeEntity[] {
    return edges.filter(edge => edge.isReliable());
  }

  /**
   * Get risky edges that need attention
   */
  static getRiskyEdges(edges: ActionEdgeEntity[]): ActionEdgeEntity[] {
    return edges.filter(edge => edge.isRisky());
  }
}