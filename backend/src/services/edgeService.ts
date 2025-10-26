/**
 * Action Edge Creation Service
 *
 * Creates and manages action edges between UI graph nodes.
 * Handles action execution, validation, and destination capture workflow.
 * Integrates with selector extraction and confidence tracking.
 */

import { v4 as uuidv4 } from 'uuid';
import { selectorExtractor } from './selectorExtractor';
import { signatureGenerator } from './signatureGenerator';
import type { ActionEdge, SelectorCandidate, ScreenNode } from '../types/uiGraph';

export interface CreateEdgeRequest {
  /** Source node ID where action originates */
  fromNodeId: string;
  /** Action definition */
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
  /** Optional guard conditions */
  guard?: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  /** Operator notes for LLM understanding */
  notes?: string;
  /** Optional start-state constraint */
  startStateConstraint?: string;
  /** Request execution and destination capture */
  executeAndCapture?: boolean;
}

export interface EdgeCreationResult {
  /** Created edge */
  edge: ActionEdge;
  /** Destination node if captured */
  destinationNode?: ScreenNode;
  /** Execution metadata */
  metadata: {
    executionTime: number;
    success: boolean;
    error?: string;
    screenshotPath?: string;
    xmlPath?: string;
  };
}

export interface ActionExecutionResult {
  /** Whether action executed successfully */
  success: boolean;
  /** Error message if execution failed */
  error?: string;
  /** Time taken for execution */
  executionTime: number;
  /** Screenshot after action (if available) */
  screenshot?: string;
  /** XML dump after action (if available) */
  xmlDump?: string;
  /** Detected destination node (if found) */
  destinationNodeId?: string;
}

export class EdgeService {
  /**
   * Create a new action edge
   */
  async createEdge(request: CreateEdgeRequest): Promise<EdgeCreationResult> {
    const startTime = Date.now();

    try {
      // Step 1: Create edge with basic validation
      const edge = await this.buildEdge(request);

      // Step 2: Execute action and capture destination if requested
      let destinationNode: ScreenNode | undefined;
      let metadata: any = {
        executionTime: 0,
        success: true,
      };

      if (request.executeAndCapture) {
        const executionResult = await this.executeAction(edge);
        metadata = {
          executionTime: executionResult.executionTime,
          success: executionResult.success,
          error: executionResult.error,
          screenshotPath: executionResult.screenshot,
          xmlPath: executionResult.xmlDump,
        };

        // If execution succeeded and we have XML, capture destination node
        if (executionResult.success && executionResult.xmlDump) {
          destinationNode = await this.captureDestinationNode(
            executionResult.xmlDump,
            executionResult.screenshot
          );
        }
      }

      // Step 3: Update edge with destination if captured
      if (destinationNode) {
        edge.toNodeId = destinationNode.id;
      }

      return {
        edge,
        destinationNode,
        metadata,
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;
      return {
        edge: await this.buildEdge(request),
        metadata: {
          executionTime,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      };
    }
  }

  /**
   * Build edge object from request
   */
  private async buildEdge(request: CreateEdgeRequest): Promise<ActionEdge> {
    const edge: ActionEdge = {
      id: uuidv4(),
      fromNodeId: request.fromNodeId,
      toNodeId: null, // Will be set after destination capture
      action: {
        kind: request.action.kind,
        selectorId: request.action.selectorId,
        text: request.action.text,
        keycode: request.action.keycode,
        delayMs: request.action.delayMs || 1000,
        intent: request.action.intent,
      },
      guard: request.guard || {},
      notes: request.notes || '',
      createdAt: new Date().toISOString(),
      createdBy: 'operator', // TODO: Get from auth context
      confidence: 0.8, // Default confidence
      startStateConstraint: request.startStateConstraint,
    };

    // Validate edge structure
    this.validateEdgePublic(edge);

    return edge;
  }

  /**
   * Execute the action defined by an edge
   */
  async executeAction(edge: ActionEdge): Promise<ActionExecutionResult> {
    const startTime = Date.now();

    try {
      // TODO: Integrate with actual ADB/automation framework
      // For now, simulate the execution

      await this.simulateActionExecution(edge);

      const executionTime = Date.now() - startTime;

      // Capture state after action
      const postActionState = await this.capturePostActionState();

      return {
        success: true,
        executionTime,
        screenshot: postActionState.screenshot,
        xmlDump: postActionState.xmlDump,
        destinationNodeId: postActionState.detectedNodeId,
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Action execution failed',
        executionTime,
      };
    }
  }

  /**
   * Simulate action execution (placeholder for real implementation)
   */
  private async simulateActionExecution(edge: ActionEdge): Promise<void> {
    // Simulate execution time based on action type
    const delays = {
      tap: 500,
      type: 1000,
      wait: edge.action.delayMs || 1000,
      back: 300,
      intent: 800,
    };

    const delay = delays[edge.action.kind] || 1000;
    await new Promise(resolve => setTimeout(resolve, delay));

    // Simulate potential failures
    if (Math.random() < 0.05) { // 5% failure rate for simulation
      throw new Error(`Failed to execute ${edge.action.kind} action`);
    }
  }

  /**
   * Capture post-action state for destination detection
   */
  private async capturePostActionState(): Promise<{
    screenshot?: string;
    xmlDump?: string;
    detectedNodeId?: string;
  }> {
    // TODO: Integrate with actual ADB screenshot and UI dump
    // For now, return mock data

    return {
      screenshot: `/tmp/post_action_${Date.now()}.png`,
      xmlDump: this.generateMockXML(),
      detectedNodeId: undefined, // Will be determined by detector
    };
  }

  /**
   * Generate mock XML for simulation
   */
  private generateMockXML(): string {
    return `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy index="0" text="" class="android.widget.FrameLayout"
  content-desc="" checkable="false" checked="false" clickable="false" enabled="true"
  focusable="false" focused="false" long-clickable="false" password="false"
  scrollable="false" selected="false" bounds="[0,0][1080,2340]">
  <node index="0" text="MaynDrive" class="android.widget.TextView"
    resource-id="com.mayndrive.app:id/title" content-desc="" checkable="false"
    checked="false" clickable="true" enabled="true" focusable="true" focused="false"
    long-clickable="false" password="false" scrollable="false" selected="false"
    bounds="[100,80][980,150]" />
</hierarchy>`;
  }

  /**
   * Capture destination node from post-action state
   */
  private async captureDestinationNode(
    xmlDump: string,
    screenshot?: string
  ): Promise<ScreenNode> {
    try {
      // Generate signature for post-action state
      const signatureResult = await signatureGenerator.generateSignature({
        xmlContent: xmlDump,
      });

      // Extract selectors from post-action state
      const selectorResult = await selectorExtractor.extractSelectors({
        xmlContent: xmlDump,
        includeCoordinates: true,
      });

      // Create destination node
      const destinationNode: ScreenNode = {
        id: signatureResult.signature.hash,
        name: `Auto-captured from action ${Date.now()}`,
        signature: signatureResult.signature,
        selectors: selectorResult.selectors,
        hints: ['Auto-captured destination'],
        samples: {
          screenshotPath: screenshot || '',
          xmlPath: `/var/captures/${signatureResult.signature.hash}/ui.xml`,
          metadataPath: `/var/captures/${signatureResult.signature.hash}/metadata.json`,
          checksum: signatureResult.signature.hash,
        },
        metadata: {
          activity: signatureResult.metadata.activity,
          package: signatureResult.metadata.package,
          emulatorBuild: 'emulator-5554',
          captureTimestamp: new Date().toISOString(),
          operatorId: 'system',
        },
        startStateTag: 'other',
        outgoingEdgeIds: [],
        incomingEdgeIds: [],
        status: 'active',
      };

      return destinationNode;
    } catch (error) {
      throw new Error(`Failed to capture destination node: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate edge structure and constraints
   */
  private validateEdge(edge: ActionEdge): void {
    this.validateEdgePublic(edge);
  }

  /**
   * Validate edge structure and constraints (public method)
   */
  validateEdgePublic(edge: ActionEdge): void {
    const errors: string[] = [];

    // Validate source node
    if (!edge.fromNodeId || edge.fromNodeId.trim().length === 0) {
      errors.push('Source node ID is required');
    }

    // Validate action
    if (!edge.action || !edge.action.kind) {
      errors.push('Action kind is required');
    }

    const validKinds = ['tap', 'type', 'wait', 'back', 'intent'];
    if (edge.action.kind && !validKinds.includes(edge.action.kind)) {
      errors.push(`Invalid action kind: ${edge.action.kind}`);
    }

    // Action-specific validation
    if (edge.action.kind === 'type' && !edge.action.text) {
      errors.push('Text is required for type action');
    }

    if (edge.action.kind === 'intent' && !edge.action.intent) {
      errors.push('Intent configuration is required for intent action');
    }

    // Validate guard if provided
    if (edge.guard) {
      if (edge.guard.mustMatchSignatureHash &&
          !/^[a-f0-9]{32}$/.test(edge.guard.mustMatchSignatureHash)) {
        errors.push('Guard signature hash must be a 16-byte hex string');
      }
    }

    // Validate confidence
    if (typeof edge.confidence !== 'number' ||
        edge.confidence < 0 ||
        edge.confidence > 1) {
      errors.push('Confidence must be a number between 0 and 1');
    }

    if (errors.length > 0) {
      throw new Error(`Edge validation failed: ${errors.join(', ')}`);
    }
  }

  /**
   * Update edge confidence based on execution results
   */
  async updateEdgeConfidence(
    edgeId: string,
    executionSuccess: boolean,
    executionTime: number
  ): Promise<void> {
    try {
      // TODO: Load edge from storage and update confidence
      // For now, just log the update
      const confidenceAdjustment = executionSuccess ? 0.1 : -0.2;
      console.log(`Updating edge ${edgeId} confidence by ${confidenceAdjustment} (execution time: ${executionTime}ms)`);
    } catch (error) {
      throw new Error(`Failed to update edge confidence: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Find edges by criteria
   */
  async findEdges(criteria: {
    fromNodeId?: string;
    toNodeId?: string;
    actionKind?: string;
    startStateConstraint?: string;
  }): Promise<ActionEdge[]> {
    // TODO: Implement actual edge lookup from storage
    // For now, return empty array
    return [];
  }

  /**
   * Delete an edge
   */
  async deleteEdge(edgeId: string): Promise<void> {
    try {
      // TODO: Implement actual edge deletion
      // Also need to check if edge is referenced by any flows
      console.log(`Deleting edge ${edgeId}`);
    } catch (error) {
      throw new Error(`Failed to delete edge: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get edge execution statistics
   */
  async getEdgeStatistics(edgeId: string): Promise<{
    totalExecutions: number;
    successRate: number;
    averageExecutionTime: number;
    lastExecutedAt?: string;
  }> {
    // TODO: Implement actual statistics tracking
    return {
      totalExecutions: 0,
      successRate: 0,
      averageExecutionTime: 0,
    };
  }

  /**
   * Create multiple edges in batch
   */
  async createEdgesBatch(requests: CreateEdgeRequest[]): Promise<EdgeCreationResult[]> {
    const results: EdgeCreationResult[] = [];

    for (const request of requests) {
      try {
        const result = await this.createEdge(request);
        results.push(result);
      } catch (error) {
        // Continue with other edges even if one fails
        results.push({
          edge: await this.buildEdge(request),
          metadata: {
            executionTime: 0,
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });
      }
    }

    return results;
  }
}

export const edgeService = new EdgeService();