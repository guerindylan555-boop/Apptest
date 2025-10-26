/**
 * FlowStep Entity
 *
 * Represents individual steps in a flow definition with support for
 * edge references, inline actions, guards, and retry policies.
 */

import { v4 as uuidv4 } from 'uuid';
import { FlowStep } from '../types/uiGraph';

export interface FlowStepOptions {
  kind: 'edgeRef' | 'inline';
  edgeId?: string;
  inlineAction?: {
    action: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    waitMs?: number;
  };
  guard?: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  retryPolicy?: {
    maxAttempts: number;
    delayMs: number;
  };
  expectNodeId?: string;
}

export class FlowStepEntity implements FlowStep {
  id: string; // Internal ID for tracking
  kind: 'edgeRef' | 'inline';
  edgeId?: string;
  inlineAction?: {
    action: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    waitMs?: number;
  };
  guard?: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  retryPolicy?: {
    maxAttempts: number;
    delayMs: number;
  };
  expectNodeId?: string;

  constructor(options: FlowStepOptions) {
    this.id = uuidv4();
    this.kind = options.kind;
    this.edgeId = options.edgeId;
    this.inlineAction = options.inlineAction;
    this.guard = options.guard;
    this.retryPolicy = options.retryPolicy || { maxAttempts: 1, delayMs: 1000 };
    this.expectNodeId = options.expectNodeId;

    this.validate();
  }

  /**
   * Create an edge reference step
   */
  static createEdgeRef(
    edgeId: string,
    options: {
      guard?: FlowStepOptions['guard'];
      retryPolicy?: FlowStepOptions['retryPolicy'];
      expectNodeId?: string;
    } = {}
  ): FlowStepEntity {
    return new FlowStepEntity({
      kind: 'edgeRef',
      edgeId,
      guard: options.guard,
      retryPolicy: options.retryPolicy,
      expectNodeId: options.expectNodeId
    });
  }

  /**
   * Create an inline action step
   */
  static createInlineAction(
    action: {
      action: 'tap' | 'type' | 'wait' | 'back' | 'intent';
      selectorId?: string;
      text?: string;
      keycode?: number;
      waitMs?: number;
    },
    options: {
      guard?: FlowStepOptions['guard'];
      retryPolicy?: FlowStepOptions['retryPolicy'];
      expectNodeId?: string;
    } = {}
  ): FlowStepEntity {
    return new FlowStepEntity({
      kind: 'inline',
      inlineAction: action,
      guard: options.guard,
      retryPolicy: options.retryPolicy,
      expectNodeId: options.expectNodeId
    });
  }

  /**
   * Validate step configuration
   */
  private validate(): void {
    const errors: string[] = [];

    if (this.kind === 'edgeRef' && !this.edgeId) {
      errors.push('edgeRef steps must specify edgeId');
    }

    if (this.kind === 'inline' && !this.inlineAction) {
      errors.push('inline steps must specify inlineAction');
    }

    if (this.inlineAction) {
      const action = this.inlineAction.action;

      // Validate action-specific requirements
      switch (action) {
        case 'type':
          if (!this.inlineAction.text && !this.inlineAction.selectorId) {
            errors.push('type action must specify text or selectorId');
          }
          break;

        case 'tap':
          if (!this.inlineAction.selectorId && !this.inlineAction.text) {
            errors.push('tap action must specify selectorId or text');
          }
          break;

        case 'wait':
          if (!this.inlineAction.waitMs) {
            errors.push('wait action must specify waitMs');
          }
          break;

        case 'back':
          if (this.inlineAction.selectorId || this.inlineAction.text) {
            errors.push('back action should not specify selectorId or text');
          }
          break;

        case 'intent':
          // Intent actions are platform-specific and may require additional validation
          break;
      }
    }

    // Validate retry policy
    if (this.retryPolicy) {
      if (this.retryPolicy.maxAttempts < 1) {
        errors.push('retryPolicy maxAttempts must be at least 1');
      }

      if (this.retryPolicy.delayMs < 0) {
        errors.push('retryPolicy delayMs cannot be negative');
      }
    }

    if (errors.length > 0) {
      throw new Error(`Invalid flow step: ${errors.join(', ')}`);
    }
  }

  /**
   * Check if this step has a guard condition
   */
  hasGuard(): boolean {
    return !!(this.guard?.mustMatchSignatureHash || this.guard?.requiredTexts?.length);
  }

  /**
   * Check if this step expects a specific node
   */
  hasExpectedNode(): boolean {
    return !!this.expectNodeId;
  }

  /**
   * Check if this step has retry configuration
   */
  hasRetryPolicy(): boolean {
    return !!(this.retryPolicy && (this.retryPolicy.maxAttempts > 1 || this.retryPolicy.delayMs > 0));
  }

  /**
   * Get the action description for logging
   */
  getActionDescription(): string {
    if (this.kind === 'edgeRef') {
      return `Execute edge: ${this.edgeId}`;
    }

    if (this.inlineAction) {
      const action = this.inlineAction.action;
      const target = this.inlineAction.selectorId || this.inlineAction.text || this.inlineAction.waitMs || 'system';

      switch (action) {
        case 'tap':
          return `Tap on: ${target}`;
        case 'type':
          return `Type text: "${this.inlineAction.text}" into: ${target}`;
        case 'wait':
          return `Wait for: ${this.inlineAction.waitMs}ms`;
        case 'back':
          return 'Go back';
        case 'intent':
          return `Execute intent: ${target}`;
        default:
          return `${action}: ${target}`;
      }
    }

    return 'Unknown action';
  }

  /**
   * Check if this step references a specific edge
   */
  referencesEdge(edgeId: string): boolean {
    return this.kind === 'edgeRef' && this.edgeId === edgeId;
  }

  /**
   * Check if this step references a specific selector
   */
  referencesSelector(selectorId: string): boolean {
    return this.inlineAction?.selectorId === selectorId;
  }

  /**
   * Update the retry policy
   */
  updateRetryPolicy(maxAttempts: number, delayMs: number): void {
    this.retryPolicy = {
      maxAttempts: Math.max(1, maxAttempts),
      delayMs: Math.max(0, delayMs)
    };
  }

  /**
   * Add or update guard conditions
   */
  updateGuard(guard: FlowStepOptions['guard']): void {
    this.guard = guard;
  }

  /**
   * Set expected node
   */
  setExpectedNode(nodeId: string): void {
    this.expectNodeId = nodeId;
  }

  /**
   * Clear expected node
   */
  clearExpectedNode(): void {
    this.expectNodeId = undefined;
  }

  /**
   * Check if the step is properly configured for execution
   */
  isExecutable(): boolean {
    try {
      this.validate();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): FlowStep {
    const result: FlowStep = {
      kind: this.kind
    };

    if (this.edgeId) {
      result.edgeId = this.edgeId;
    }

    if (this.inlineAction) {
      result.inlineAction = { ...this.inlineAction };
    }

    if (this.guard) {
      result.guard = { ...this.guard };
    }

    if (this.retryPolicy) {
      result.retryPolicy = { ...this.retryPolicy };
    }

    if (this.expectNodeId) {
      result.expectNodeId = this.expectNodeId;
    }

    return result;
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: FlowStep): FlowStepEntity {
    const entity = Object.create(FlowStepEntity.prototype);
    Object.assign(entity, data);
    entity.id = uuidv4(); // Generate new ID for tracking
    return entity;
  }

  /**
   * Create array of steps from JSON data
   */
  static fromJSONArray(data: FlowStep[]): FlowStepEntity[] {
    return data.map(step => FlowStepEntity.fromJSON(step));
  }

  /**
   * Find steps that reference a specific edge
   */
  static findStepsReferencingEdge(steps: FlowStepEntity[], edgeId: string): FlowStepEntity[] {
    return steps.filter(step => step.referencesEdge(edgeId));
  }

  /**
   * Find steps that reference a specific selector
   */
  static findStepsReferencingSelector(steps: FlowStepEntity[], selectorId: string): FlowStepEntity[] {
    return steps.filter(step => step.referencesSelector(selectorId));
  }

  /**
   * Validate a sequence of steps for consistency
   */
  static validateStepSequence(steps: FlowStepEntity[]): string[] {
    const errors: string[] = [];

    if (steps.length === 0) {
      errors.push('Flow must have at least one step');
      return errors;
    }

    // Check for executable steps
    const nonExecutableSteps = steps.filter(step => !step.isExecutable());
    if (nonExecutableSteps.length > 0) {
      errors.push(`${nonExecutableSteps.length} steps are not executable`);
    }

    // Check for duplicate expected nodes (might indicate logic issues)
    const expectedNodes = steps.filter(step => step.hasExpectedNode()).map(step => step.expectNodeId);
    const duplicateExpectedNodes = expectedNodes.filter((node, index) => expectedNodes.indexOf(node) !== index);
    if (duplicateExpectedNodes.length > 0) {
      errors.push(`Duplicate expected nodes detected: ${[...new Set(duplicateExpectedNodes)].join(', ')}`);
    }

    return errors;
  }
}