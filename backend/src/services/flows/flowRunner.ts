/**
 * Flow Runner Service
 *
 * Executes flow definitions with state-aware routing, recovery,
 * and re-detection after each action.
 */

import { EventEmitter } from 'events';
import { FlowDefinition, FlowStep, ActionEdge, ScreenNode } from '../../types/uiGraph';
import { StateDetectorService } from '../state-detector/stateDetectorService';
import { GraphStore } from '../ui-graph/graphStore';
import { logger } from '../../utils/logger';

export interface FlowExecutionContext {
  flow: FlowDefinition;
  variables: Record<string, any>;
  startNodeId?: string;
  startTime: Date;
  currentStep?: number;
  currentNode?: ScreenNode;
  detectedStates: Array<{
    step: number;
    nodeId: string;
    timestamp: Date;
    confidence: number;
  }>;
}

export interface FlowExecutionResult {
  success: boolean;
  flowName: string;
  startTime: Date;
  endTime: Date;
  startNodeId?: string;
  endNodeId?: string;
  stepsExecuted: number;
  totalSteps: number;
  error?: string;
  recoveryTriggered?: string;
  finalState: 'completed' | 'failed' | 'recovered' | 'timeout';
  executionLog: Array<{
    timestamp: Date;
    step: number;
    action: string;
    nodeId: string;
    status: 'success' | 'failed' | 'recovered';
    message?: string;
  }>;
}

export interface FlowRunnerConfig {
  stepTimeoutMs: number;
  maxRetries: number;
  retryDelayMs: number;
  detectionTimeoutMs: number;
  enableTelemetry: boolean;
}

export class FlowRunner extends EventEmitter {
  private config: FlowRunnerConfig;
  private detector: StateDetectorService;
  private graphStore: GraphStore;
  private activeExecutions: Map<string, FlowExecutionContext> = new Map();

  constructor(
    detector: StateDetectorService,
    graphStore: GraphStore,
    config: Partial<FlowRunnerConfig> = {}
  ) {
    super();

    this.config = {
      stepTimeoutMs: 30000, // 30 seconds per step
      maxRetries: 3,
      retryDelayMs: 2000, // 2 seconds
      detectionTimeoutMs: 10000, // 10 seconds for detection
      enableTelemetry: true,
      ...config,
    };

    this.detector = detector;
    this.graphStore = graphStore;
  }

  /**
   * Execute a flow with given variables
   */
  async executeFlow(
    flow: FlowDefinition,
    variables: Record<string, any> = {},
    startNodeId?: string
  ): Promise<FlowExecutionResult> {
    const executionId = `${flow.name}-${Date.now()}`;
    const startTime = new Date();

    logger.info(`Starting flow execution: ${flow.name} (ID: ${executionId})`);

    // Initialize execution context
    const context: FlowExecutionContext = {
      flow,
      variables: this.validateAndPrepareVariables(flow, variables),
      startNodeId,
      startTime,
      currentStep: 0,
      detectedStates: [],
    };

    this.activeExecutions.set(executionId, context);

    try {
      // Verify preconditions
      const startNode = await this.verifyPrecondition(flow, context);
      if (!startNode) {
        throw new Error(`Precondition not met: cannot find starting node`);
      }

      context.currentNode = startNode;
      this.emit('stepStart', { executionId, step: 0, nodeId: startNode.id });

      const result: FlowExecutionResult = {
        success: false,
        flowName: flow.name,
        startTime,
        endTime: new Date(),
        startNodeId: startNode.id,
        stepsExecuted: 0,
        totalSteps: flow.steps.length,
        finalState: 'failed',
        executionLog: [],
      };

      // Execute each step
      for (let i = 0; i < flow.steps.length; i++) {
        context.currentStep = i;
        const step = flow.steps[i];

        try {
          await this.executeStep(step, context, result);
          result.stepsExecuted = i + 1;

          // Re-detect state after each action
          const detectedNode = await this.detectCurrentState(context);
          if (detectedNode) {
            context.currentNode = detectedNode;
            context.detectedStates.push({
              step: i,
              nodeId: detectedNode.id,
              timestamp: new Date(),
              confidence: 0, // Would be populated by actual detection
            });
          }

          this.emit('stepComplete', {
            executionId,
            step: i,
            nodeId: context.currentNode?.id,
            success: true,
          });
        } catch (error) {
          // Step failed - try recovery
          const recovered = await this.attemptRecovery(error, step, context, result);
          if (!recovered) {
            result.error = error instanceof Error ? error.message : String(error);
            result.finalState = 'failed';
            break;
          } else {
            result.recoveryTriggered = 'step_failure';
            result.executionLog.push({
              timestamp: new Date(),
              step: i,
              action: 'recovery',
              nodeId: context.currentNode?.id || 'unknown',
              status: 'recovered',
              message: `Recovered from: ${error instanceof Error ? error.message : String(error)}`,
            });
          }
        }
      }

      // Verify postconditions
      if (result.stepsExecuted === flow.steps.length) {
        const postconditionMet = await this.verifyPostcondition(flow, context);
        if (postconditionMet) {
          result.success = true;
          result.finalState = 'completed';
          result.endNodeId = context.currentNode?.id;
        } else {
          result.error = 'Postcondition not met after flow completion';
          result.finalState = 'failed';
        }
      }

      this.emit('flowComplete', { executionId, result });
      return result;

    } catch (error) {
      logger.error(`Flow execution failed: ${error instanceof Error ? error.message : String(error)}`);

      const result: FlowExecutionResult = {
        success: false,
        flowName: flow.name,
        startTime,
        endTime: new Date(),
        startNodeId: context.startNodeId,
        stepsExecuted: context.currentStep || 0,
        totalSteps: flow.steps.length,
        error: error instanceof Error ? error.message : String(error),
        finalState: 'failed',
        executionLog: [{
          timestamp: new Date(),
          step: context.currentStep || 0,
          action: 'flow_execution',
          nodeId: context.currentNode?.id || 'unknown',
          status: 'failed',
          message: error instanceof Error ? error.message : String(error),
        }],
      };

      this.emit('flowError', { executionId, error, result });
      return result;
    } finally {
      this.activeExecutions.delete(executionId);
    }
  }

  /**
   * Execute a single flow step
   */
  private async executeStep(
    step: FlowStep,
    context: FlowExecutionContext,
    result: FlowExecutionResult
  ): Promise<void> {
    const startTime = Date.now();

    try {
      if (step.kind === 'edgeRef') {
        await this.executeEdgeRef(step, context);
      } else if (step.kind === 'inline') {
        await this.executeInlineAction(step, context);
      } else {
        throw new Error(`Unknown step kind: ${step.kind}`);
      }

      // Log successful execution
      result.executionLog.push({
        timestamp: new Date(),
        step: context.currentStep!,
        action: step.kind,
        nodeId: context.currentNode?.id || 'unknown',
        status: 'success',
        message: `Step completed in ${Date.now() - startTime}ms`,
      });

    } catch (error) {
      result.executionLog.push({
        timestamp: new Date(),
        step: context.currentStep!,
        action: step.kind,
        nodeId: context.currentNode?.id || 'unknown',
        status: 'failed',
        message: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Execute an edge reference step
   */
  private async executeEdgeRef(step: FlowStep, context: FlowExecutionContext): Promise<void> {
    if (!step.edgeId) {
      throw new Error('Edge reference step missing edgeId');
    }

    // Load the edge from graph store
    const graph = await this.graphStore.loadLatestGraph();
    const edge = graph.edges.find((e: ActionEdge) => e.id === step.edgeId);

    if (!edge) {
      throw new Error(`Edge not found: ${step.edgeId}`);
    }

    // Verify guard conditions if present
    if (step.guard) {
      const guardMet = await this.verifyGuard(step.guard, context);
      if (!guardMet) {
        throw new Error(`Guard conditions not met for edge ${step.edgeId}`);
      }
    }

    // Execute the edge action
    await this.executeEdgeAction(edge, context);
  }

  /**
   * Execute an inline action step
   */
  private async executeInlineAction(step: FlowStep, context: FlowExecutionContext): Promise<void> {
    if (!step.inlineAction) {
      throw new Error('Inline step missing inlineAction');
    }

    // Verify guard conditions if present
    if (step.guard) {
      const guardMet = await this.verifyGuard(step.guard, context);
      if (!guardMet) {
        throw new Error('Guard conditions not met for inline action');
      }
    }

    // Execute the inline action
    await this.executeInlineActionStep(step.inlineAction, context);
  }

  /**
   * Execute an edge action (this would integrate with the emulator/automation system)
   */
  private async executeEdgeAction(edge: ActionEdge, context: FlowExecutionContext): Promise<void> {
    logger.info(`Executing edge action: ${edge.action.kind} on edge ${edge.id}`);

    // This would integrate with the actual automation system
    // For now, we'll simulate the action
    await this.simulateAction(edge.action, context);
  }

  /**
   * Execute an inline action step
   */
  private async executeInlineActionStep(
    action: any,
    context: FlowExecutionContext
  ): Promise<void> {
    logger.info(`Executing inline action: ${action.action}`);

    // This would integrate with the actual automation system
    // For now, we'll simulate the action
    await this.simulateAction(action, context);
  }

  /**
   * Simulate an action (placeholder for actual automation integration)
   */
  private async simulateAction(action: any, context: FlowExecutionContext): Promise<void> {
    // Simulate action execution time
    const delay = action.delayMs || 1000;
    await new Promise(resolve => setTimeout(resolve, delay));

    // Simulate variable substitution in text actions
    if (action.text) {
      const substituted = this.substituteVariables(action.text, context.variables);
      logger.debug(`Text action with substitution: "${action.text}" -> "${substituted}"`);
    }

    logger.info(`Action simulated: ${action.action}`);
  }

  /**
   * Detect current state after action execution
   */
  private async detectCurrentState(context: FlowExecutionContext): Promise<ScreenNode | null> {
    try {
      // This would trigger an XML dump from the emulator
      // For now, we'll simulate detection
      const dumpPath = `var/captures/temp/dump-${Date.now()}.xml`;

      // Simulate XML dump creation
      await this.createSimulatedDump(dumpPath, context);

      // Run detection
      const result = await this.detector.detectState(dumpPath);

      if (result.selectedNodeId) {
        const graph = await this.graphStore.loadLatestGraph();
        const node = graph.nodes.find((n: ScreenNode) => n.id === result.selectedNodeId);
        return node || null;
      }

      return null;
    } catch (error) {
      logger.error(`State detection failed: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  /**
   * Attempt recovery from a failed step
   */
  private async attemptRecovery(
    error: any,
    step: FlowStep,
    context: FlowExecutionContext,
    result: FlowExecutionResult
  ): Promise<boolean> {
    logger.warn(`Attempting recovery for step ${context.currentStep}: ${error instanceof Error ? error.message : String(error)}`);

    // Determine recovery trigger type
    let triggerType: 'unexpected_node' | 'system_dialog' | 'timeout' | 'step_failure' = 'step_failure';

    if (error instanceof Error) {
      if (error.message.includes('timeout')) triggerType = 'timeout';
      else if (error.message.includes('dialog')) triggerType = 'system_dialog';
      else if (error.message.includes('node')) triggerType = 'unexpected_node';
    }

    // Find matching recovery rules
    const recoveryRules = context.flow.recovery.filter(rule => rule.trigger === triggerType);

    if (recoveryRules.length === 0) {
      logger.error(`No recovery rules found for trigger: ${triggerType}`);
      return false;
    }

    // Try each recovery action
    for (const rule of recoveryRules) {
      for (const action of rule.allowedActions) {
        try {
          const recovered = await this.executeRecoveryAction(action, context);
          if (recovered) {
            logger.info(`Recovery successful using action: ${action}`);
            return true;
          }
        } catch (recoveryError) {
          logger.warn(`Recovery action ${action} failed: ${recoveryError instanceof Error ? recoveryError.message : String(recoveryError)}`);
        }
      }
    }

    logger.error(`All recovery actions failed for trigger: ${triggerType}`);
    return false;
  }

  /**
   * Execute a recovery action
   */
  private async executeRecoveryAction(
    action: string,
    context: FlowExecutionContext
  ): Promise<boolean> {
    switch (action) {
      case 'back':
        // Simulate back button press
        await this.simulateAction({ action: 'back', delayMs: 500 }, context);
        return true;

      case 'dismiss':
        // Simulate dialog dismissal
        await this.simulateAction({ action: 'tap', delayMs: 500 }, context);
        return true;

      case 'reopen':
        // Simulate reopening the app/activity
        await this.simulateAction({ action: 'intent', delayMs: 2000 }, context);
        return true;

      case 'relogin':
        // This would trigger a re-login flow
        logger.info('Re-login recovery not implemented yet');
        return false;

      case 'retry':
        // Just wait and retry the step
        await new Promise(resolve => setTimeout(resolve, this.config.retryDelayMs));
        return true;

      case 'wait':
        // Wait a bit longer
        await new Promise(resolve => setTimeout(resolve, this.config.stepTimeoutMs / 2));
        return true;

      default:
        logger.warn(`Unknown recovery action: ${action}`);
        return false;
    }
  }

  /**
   * Verify flow precondition
   */
  private async verifyPrecondition(
    flow: FlowDefinition,
    context: FlowExecutionContext
  ): Promise<ScreenNode | null> {
    if (flow.precondition.nodeId) {
      const graph = await this.graphStore.loadLatestGraph();
      const node = graph.nodes.find((n: ScreenNode) => n.id === flow.precondition.nodeId);
      return node || null;
    }

    if (flow.precondition.query) {
      // This would run detection and check if it matches the query
      // For now, return the start node if provided
      if (context.startNodeId) {
        const graph = await this.graphStore.loadLatestGraph();
        const node = graph.nodes.find((n: ScreenNode) => n.id === context.startNodeId);
        return node || null;
      }
    }

    return null;
  }

  /**
   * Verify flow postcondition
   */
  private async verifyPostcondition(
    flow: FlowDefinition,
    context: FlowExecutionContext
  ): Promise<boolean> {
    if (flow.postcondition.nodeId) {
      return context.currentNode?.id === flow.postcondition.nodeId;
    }

    if (flow.postcondition.query) {
      // This would check if the current node matches the query
      // For now, just return true if we have a current node
      return !!context.currentNode;
    }

    return false;
  }

  /**
   * Verify guard conditions
   */
  private async verifyGuard(guard: any, context: FlowExecutionContext): Promise<boolean> {
    if (guard.mustMatchSignatureHash && context.currentNode) {
      if (context.currentNode.signature.hash !== guard.mustMatchSignatureHash) {
        return false;
      }
    }

    if (guard.requiredTexts && context.currentNode) {
      const hasAllTexts = guard.requiredTexts.every((text: string) =>
        context.currentNode!.signature.requiredTexts.includes(text)
      );
      if (!hasAllTexts) {
        return false;
      }
    }

    return true;
  }

  /**
   * Validate and prepare flow variables
   */
  private validateAndPrepareVariables(
    flow: FlowDefinition,
    provided: Record<string, any>
  ): Record<string, any> {
    const variables: Record<string, any> = { ...provided };

    for (const variable of flow.variables) {
      if (variable.required && !(variable.name in variables)) {
        throw new Error(`Required variable missing: ${variable.name}`);
      }

      if (variable.name in variables) {
        // Type validation
        if (variable.type === 'number' && typeof variables[variable.name] !== 'number') {
          variables[variable.name] = parseFloat(variables[variable.name]);
          if (isNaN(variables[variable.name])) {
            throw new Error(`Variable ${variable.name} must be a number`);
          }
        }

        if (variable.type === 'boolean' && typeof variables[variable.name] !== 'boolean') {
          variables[variable.name] = variables[variable.name] === 'true';
        }
      }
    }

    return variables;
  }

  /**
   * Substitute variables in text templates
   */
  private substituteVariables(text: string, variables: Record<string, any>): string {
    return text.replace(/\{\{(\w+)\}\}/g, (match, varName) => {
      return variables[varName]?.toString() || match;
    });
  }

  /**
   * Create a simulated XML dump (placeholder)
   */
  private async createSimulatedDump(dumpPath: string, context: FlowExecutionContext): Promise<void> {
    // This would create an actual XML dump from the emulator
    // For now, create a placeholder file
    const xmlContent = `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="com.mayndrive.app:id/main_container" class="android.widget.FrameLayout" />
</hierarchy>`;

    // Ensure directory exists
    await import('fs').then(fs =>
      fs.promises.mkdir(require('path').dirname(dumpPath), { recursive: true })
    );

    await import('fs').then(fs =>
      fs.promises.writeFile(dumpPath, xmlContent, 'utf-8')
    );
  }

  /**
   * Get active execution context
   */
  getActiveExecution(executionId: string): FlowExecutionContext | undefined {
    return this.activeExecutions.get(executionId);
  }

  /**
   * Cancel an active execution
   */
  cancelExecution(executionId: string): boolean {
    const context = this.activeExecutions.get(executionId);
    if (context) {
      this.activeExecutions.delete(executionId);
      this.emit('executionCancelled', { executionId, context });
      return true;
    }
    return false;
  }
}