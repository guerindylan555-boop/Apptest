/**
 * FlowDefinition Entity
 *
 * Represents declarative flow definitions with variables,
 * preconditions, steps, postconditions, and recovery rules.
 */

import { v4 as uuidv4 } from 'uuid';
import { FlowDefinition } from '../types/uiGraph';
import { FlowStepEntity } from './FlowStep';
import { ActionEdgeEntity } from './ActionEdge';

export interface FlowVariableOptions {
  name: string;
  description: string;
  type: 'string' | 'number' | 'boolean';
  required: boolean;
  prompt: string;
  defaultValue?: string | number | boolean;
}

export interface FlowDefinitionOptions {
  name: string;
  description: string;
  version?: string;
  variables?: FlowVariableOptions[];
  precondition: {
    nodeId?: string;
    query?: {
      activity?: string;
      requiredTexts?: string[];
    };
  };
  steps: FlowStepEntity[];
  postcondition: {
    nodeId?: string;
    query?: {
      activity?: string;
      requiredTexts?: string[];
    };
  };
  recovery: Array<{
    trigger: 'unexpected_node' | 'system_dialog' | 'timeout';
    allowedActions: ('back' | 'dismiss' | 'reopen' | 'relogin' | 'wait' | 'retry')[];
  }>;
  metadata?: {
    owner?: string;
    lastUpdatedAt?: string;
    validationStatus?: 'draft' | 'validated' | 'deprecated';
    notes?: string;
  };
}

export class FlowDefinitionEntity implements FlowDefinition {
  id: string;
  name: string;
  description: string;
  version: string;
  variables: Array<{
    name: string;
    description: string;
    type: 'string' | 'number' | 'boolean';
    required: boolean;
    prompt: string;
    defaultValue?: string | number | boolean;
  }>;
  precondition: {
    nodeId?: string;
    query?: {
      activity?: string;
      requiredTexts?: string[];
    };
  };
  steps: FlowStepEntity[];
  postcondition: {
    nodeId?: string;
    query?: {
      activity?: string;
      requiredTexts?: string[];
    };
  };
  recovery: Array<{
    trigger: 'unexpected_node' | 'system_dialog' | 'timeout';
    allowedActions: ('back' | 'dismiss' | 'reopen' | 'relogin' | 'wait' | 'retry')[];
  }>;
  metadata: {
    owner?: string;
    lastUpdatedAt: string;
    validationStatus: 'draft' | 'validated' | 'deprecated';
    notes?: string;
  };

  // Extended fields for execution tracking
  executionCount: number = 0;
  successCount: number = 0;
  failureCount: number = 0;
  lastExecutedAt?: string;
  lastResult?: 'success' | 'failure';

  constructor(options: FlowDefinitionOptions) {
    this.id = uuidv4();
    this.name = options.name;
    this.description = options.description;
    this.version = options.version || '1.0.0';
    this.variables = options.variables || [];
    this.precondition = options.precondition;
    this.steps = [...options.steps];
    this.postcondition = options.postcondition;
    this.recovery = [...options.recovery];
    this.metadata = {
      owner: options.metadata?.owner || 'unknown',
      lastUpdatedAt: options.metadata?.lastUpdatedAt || new Date().toISOString(),
      validationStatus: options.metadata?.validationStatus || 'draft',
      notes: options.metadata?.notes || ''
    };

    this.validate();
  }

  /**
   * Create flow from YAML data
   */
  static fromYAML(yamlData: any): FlowDefinitionEntity {
    const steps = yamlData.steps ?
      FlowStepEntity.fromJSONArray(yamlData.steps) : [];

    return new FlowDefinitionEntity({
      name: yamlData.name,
      description: yamlData.description,
      version: yamlData.version,
      variables: yamlData.variables || [],
      precondition: yamlData.precondition || {},
      steps,
      postcondition: yamlData.postcondition || {},
      recovery: yamlData.recovery || [],
      metadata: yamlData.metadata || {}
    });
  }

  /**
   * Create basic MaynDrive flows
   */
  static createMaynDriveFlows(): FlowDefinitionEntity[] {
    return [
      new FlowDefinitionEntity({
        name: 'login-home',
        description: 'Login from clean boot and navigate to home screen',
        version: '1.0.0',
        variables: [
          {
            name: 'phone',
            description: 'User phone number for login',
            type: 'string',
            required: true,
            prompt: 'Enter phone number'
          },
          {
            name: 'otp',
            description: 'One-time password for verification',
            type: 'string',
            required: true,
            prompt: 'Enter OTP code'
          }
        ],
        precondition: {
          query: {
            activity: '.*MainActivity.*',
            requiredTexts: ['Login', 'Sign In', 'Get Started']
          }
        },
        steps: [
          // This would be populated with actual steps from edge references
        ],
        postcondition: {
          query: {
            activity: '.*HomeActivity.*',
            requiredTexts: ['Map', 'Home', 'Profile']
          }
        },
        recovery: [
          {
            trigger: 'unexpected_node',
            allowedActions: ['back', 'dismiss', 'reopen']
          },
          {
            trigger: 'system_dialog',
            allowedActions: ['dismiss']
          },
          {
            trigger: 'timeout',
            allowedActions: ['wait', 'retry']
          }
        ],
        metadata: {
          owner: 'system',
          validationStatus: 'draft'
        }
      }),

      new FlowDefinitionEntity({
        name: 'unlock-any-scooter',
        description: 'Unlock any available scooter when not currently renting',
        version: '1.0.0',
        variables: [],
        precondition: {
          query: {
            activity: '.*HomeActivity.*',
            requiredTexts: ['Map', 'Scan', 'Find Scooter']
          }
        },
        steps: [],
        postcondition: {
          query: {
            activity: '.*RideActivity.*',
            requiredTexts: ['End Ride', 'Timer', 'Current Rental']
          }
        },
        recovery: [
          {
            trigger: 'unexpected_node',
            allowedActions: ['back', 'dismiss', 'reopen']
          },
          {
            trigger: 'system_dialog',
            allowedActions: ['dismiss']
          }
        ],
        metadata: {
          owner: 'system',
          validationStatus: 'draft'
        }
      })
    ];
  }

  /**
   * Validate flow configuration
   */
  private validate(): void {
    const errors: string[] = [];

    if (!this.name || this.name.trim().length === 0) {
      errors.push('Flow name is required');
    }

    if (!this.description || this.description.trim().length === 0) {
      errors.push('Flow description is required');
    }

    if (!this.precondition || (!this.precondition.nodeId && !this.precondition.query)) {
      errors.push('Flow must specify precondition (nodeId or query)');
    }

    if (!this.postcondition || (!this.postcondition.nodeId && !this.postcondition.query)) {
      errors.push('Flow must specify postcondition (nodeId or query)');
    }

    if (!this.steps || this.steps.length === 0) {
      errors.push('Flow must have at least one step');
    }

    // Validate step sequence
    const stepErrors = FlowStepEntity.validateStepSequence(this.steps);
    errors.push(...stepErrors);

    // Validate variables
    this.variables.forEach(variable => {
      if (!variable.name || variable.name.trim().length === 0) {
        errors.push(`Variable name is required`);
      }

      if (!variable.description || variable.description.trim().length === 0) {
        errors.push(`Variable description is required for ${variable.name}`);
      }

      if (!variable.prompt || variable.prompt.trim().length === 0) {
        errors.push(`Variable prompt is required for ${variable.name}`);
      }
    });

    // Validate recovery rules
    if (!this.recovery || this.recovery.length === 0) {
      errors.push('Flow must have at least one recovery rule');
    }

    this.recovery.forEach(rule => {
      if (!rule.trigger || !['unexpected_node', 'system_dialog', 'timeout'].includes(rule.trigger)) {
        errors.push(`Invalid recovery trigger: ${rule.trigger}`);
      }

      if (!rule.allowedActions || rule.allowedActions.length === 0) {
        errors.push(`Recovery rule must specify allowed actions`);
      }
    });

    if (errors.length > 0) {
      throw new Error(`Invalid flow definition: ${errors.join(', ')}`);
    }
  }

  /**
   * Add a step to the flow
   */
  addStep(step: FlowStepEntity): void {
    this.steps.push(step);
    this.markUpdated();
  }

  /**
   * Remove a step from the flow
   */
  removeStep(stepId: string): void {
    this.steps = this.steps.filter(step => step.id !== stepId);
    this.markUpdated();
  }

  /**
   * Get steps that reference a specific edge
   */
  getStepsReferencingEdge(edgeId: string): FlowStepEntity[] {
    return this.steps.filter(step => step.referencesEdge(edgeId));
  }

  /**
   * Get steps that reference a specific selector
   */
  getStepsReferencingSelector(selectorId: string): FlowStepEntity[] {
    return this.steps.filter(step => step.referencesSelector(selectorId));
  }

  /**
   * Check if flow references a specific edge
   */
  referencesEdge(edgeId: string): boolean {
    return this.getStepsReferencingEdge(edgeId).length > 0;
  }

  /**
   * Check if flow references a specific selector
   */
  referencesSelector(selectorId: string): boolean {
    return this.getStepsReferencingSelector(selectorId).length > 0;
  }

  /**
   * Add a variable
   */
  addVariable(variable: FlowVariableOptions): void {
    // Check for duplicate names
    if (this.variables.some(v => v.name === variable.name)) {
      throw new Error(`Variable '${variable.name}' already exists`);
    }

    this.variables.push(variable);
    this.markUpdated();
  }

  /**
   * Remove a variable
   */
  removeVariable(name: string): void {
    this.variables = this.variables.filter(v => v.name !== name);
    this.markUpdated();
  }

  /**
   * Get variable by name
   */
  getVariable(name: string): FlowVariableOptions | undefined {
    return this.variables.find(v => v.name === name);
  }

  /**
   * Get required variables
   */
  getRequiredVariables(): FlowVariableOptions[] {
    return this.variables.filter(v => v.required);
  }

  /**
   * Add recovery rule
   */
  addRecoveryRule(rule: {
    trigger: 'unexpected_node' | 'system_dialog' | 'timeout';
    allowedActions: ('back' | 'dismiss' | 'reopen' | 'relogin' | 'wait' | 'retry')[];
  }): void {
    this.recovery.push(rule);
    this.markUpdated();
  }

  /**
   * Remove recovery rule
   */
  removeRecoveryRule(trigger: string): void {
    this.recovery = this.recovery.filter(rule => rule.trigger !== trigger);
    this.markUpdated();
  }

  /**
   * Get recovery rule by trigger
   */
  getRecoveryRule(trigger: string): {
    trigger: 'unexpected_node' | 'system_dialog' | 'timeout';
    allowedActions: ('back' | 'dismiss' | 'reopen' | 'relogin' | 'wait' | 'retry')[];
  } | undefined {
    return this.recovery.find(rule => rule.trigger === trigger);
  }

  /**
   * Validate flow against available edges
   */
  validateAgainstEdges(edges: ActionEdgeEntity[]): string[] {
    const errors: string[] = [];
    const edgeIds = new Set(edges.map(e => e.id));

    // Check if all referenced edges exist
    this.steps.forEach((step, index) => {
      if (step.kind === 'edgeRef' && step.edgeId) {
        if (!edgeIds.has(step.edgeId)) {
          errors.push(`Step ${index + 1} references non-existent edge: ${step.edgeId}`);
        }
      }
    });

    // Check if precondition node exists
    if (this.precondition.nodeId) {
      const hasEdgeToNode = edges.some(e => e.toNodeId === this.precondition.nodeId);
      if (!hasEdgeToNode) {
        errors.push(`Precondition node ${this.precondition.nodeId} is not reachable from any edge`);
      }
    }

    // Check if postcondition node exists
    if (this.postcondition.nodeId) {
      const hasEdgeToNode = edges.some(e => e.toNodeId === this.postcondition.nodeId);
      if (!hasEdgeToNode) {
        errors.push(`Postcondition node ${this.postcondition.nodeId} is not reachable from any edge`);
      }
    }

    return errors;
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
    } else {
      this.failureCount++;
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
   * Mark flow as updated
   */
  private markUpdated(): void {
    this.metadata.lastUpdatedAt = new Date().toISOString();
  }

  /**
   * Update validation status
   */
  setValidationStatus(status: 'draft' | 'validated' | 'deprecated'): void {
    this.metadata.validationStatus = status;
    this.markUpdated();
  }

  /**
   * Update owner
   */
  setOwner(owner: string): void {
    this.metadata.owner = owner;
    this.markUpdated();
  }

  /**
   * Update notes
   */
  setNotes(notes: string): void {
    this.metadata.notes = notes;
    this.markUpdated();
  }

  /**
   * Check if flow is ready for execution
   */
  isReadyForExecution(): boolean {
    return (
      this.steps.length > 0 &&
      this.steps.every(step => step.isExecutable()) &&
      this.precondition.nodeId !== undefined &&
      this.postcondition.nodeId !== undefined &&
      this.metadata.validationStatus === 'validated'
    );
  }

  /**
   * Get flow summary
   */
  getSummary(): {
    id: string;
    name: string;
    description: string;
    version: string;
    stepCount: number;
    variableCount: number;
    validationStatus: string;
    owner?: string;
    lastUpdated: string;
    successRate: number;
    executionCount: number;
    isReady: boolean;
  } {
    return {
      id: this.id,
      name: this.name,
      description: this.description,
      version: this.version,
      stepCount: this.steps.length,
      variableCount: this.variables.length,
      validationStatus: this.metadata.validationStatus,
      owner: this.metadata.owner,
      lastUpdated: this.metadata.lastUpdatedAt,
      successRate: Math.round(this.getSuccessRate()),
      executionCount: this.executionCount,
      isReady: this.isReadyForExecution()
    };
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): FlowDefinition {
    return {
      name: this.name,
      description: this.description,
      version: this.version,
      variables: [...this.variables],
      precondition: { ...this.precondition },
      steps: this.steps.map(step => step.toJSON()),
      postcondition: { ...this.postcondition },
      recovery: [...this.recovery],
      metadata: { ...this.metadata }
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: FlowDefinition): FlowDefinitionEntity {
    const entity = Object.create(FlowDefinitionEntity.prototype);
    Object.assign(entity, data);

    // Reconstruct step entities
    entity.steps = entity.steps.map((step: any) => FlowStepEntity.fromJSON(step));

    // Initialize extended fields
    entity.executionCount = 0;
    entity.successCount = 0;
    entity.failureCount = 0;
    entity.lastExecutedAt = undefined;
    entity.lastResult = undefined;

    return entity;
  }

  /**
   * Find flows by status
   */
  static findByStatus(flows: FlowDefinitionEntity[], status: string): FlowDefinitionEntity[] {
    return flows.filter(flow => flow.metadata.validationStatus === status);
  }

  /**
   * Find ready flows
   */
  static findReadyFlows(flows: FlowDefinitionEntity[]): FlowDefinitionEntity[] {
    return flows.filter(flow => flow.isReadyForExecution());
  }

  /**
   * Find flows referencing edge
   */
  static findReferencingEdge(flows: FlowDefinitionEntity[], edgeId: string): FlowDefinitionEntity[] {
    return flows.filter((flow: FlowDefinitionEntity) => flow.referencesEdge(edgeId));
  }
}