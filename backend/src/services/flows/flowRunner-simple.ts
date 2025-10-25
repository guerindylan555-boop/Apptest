/**
 * Simplified Flow Runner Service
 *
 * Basic flow execution with placeholder implementations
 * for deployment testing.
 */

import { EventEmitter } from 'events';
import { FlowDefinition } from '../../types/uiGraph';
import { logger } from '../../utils/logger';

export interface FlowExecutionContext {
  flow: FlowDefinition;
  variables: Record<string, any>;
  startNodeId?: string;
  startTime: Date;
  currentStep?: number;
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

export class FlowRunner extends EventEmitter {
  private activeExecutions: Map<string, FlowExecutionContext> = new Map();

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

    const context: FlowExecutionContext = {
      flow,
      variables,
      startNodeId,
      startTime,
      currentStep: 0,
    };

    this.activeExecutions.set(executionId, context);

    try {
      // Simulate flow execution
      const result: FlowExecutionResult = {
        success: true,
        flowName: flow.name,
        startTime,
        endTime: new Date(),
        startNodeId,
        endNodeId: 'mock-end-node',
        stepsExecuted: flow.steps.length,
        totalSteps: flow.steps.length,
        finalState: 'completed',
        executionLog: flow.steps.map((step, index) => ({
          timestamp: new Date(),
          step: index,
          action: step.kind,
          nodeId: 'mock-node',
          status: 'success' as const,
          message: 'Step executed successfully',
        })),
      };

      this.emit('flowComplete', { executionId, result });
      return result;

    } catch (error) {
      logger.error(`Flow execution failed: ${error instanceof Error ? error.message : String(error)}`);

      const result: FlowExecutionResult = {
        success: false,
        flowName: flow.name,
        startTime,
        endTime: new Date(),
        startNodeId,
        stepsExecuted: context.currentStep || 0,
        totalSteps: flow.steps.length,
        error: error instanceof Error ? error.message : 'Unknown error',
        finalState: 'failed',
        executionLog: [{
          timestamp: new Date(),
          step: context.currentStep || 0,
          action: 'flow_execution',
          nodeId: 'unknown',
          status: 'failed',
          message: error instanceof Error ? error.message : 'Unknown error',
        }],
      };

      this.emit('flowError', { executionId, error, result });
      return result;
    } finally {
      this.activeExecutions.delete(executionId);
    }
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