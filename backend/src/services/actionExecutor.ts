/**
 * Action Executor Service
 *
 * Executes actions defined in ActionEdge entities and captures the resulting state.
 * Integrates with ADB for device control and performs destination capture workflow.
 * Handles action validation, execution timing, and error recovery.
 */

import { ADBUtils } from '../utils/adb';
import { signatureGenerator } from './signatureGenerator';
import { selectorExtractor } from './selectorExtractor';
import { graphStore } from './graphStore';
import { ScreenNodeEntity } from '../models/ScreenNode';
import { ActionEdgeEntity } from '../models/ActionEdge';
import type { ActionEdge, ScreenNode, SelectorCandidate } from '../types/uiGraph';
import type { ExtendedActionEdge } from '../types/graph';

export interface ActionExecutionRequest {
  /** Edge to execute */
  edge: ActionEdge | ExtendedActionEdge;
  /** Optional override for device ID */
  deviceId?: string;
  /** Whether to capture destination node after execution */
  captureDestination?: boolean;
  /** Optional metadata for execution tracking */
  executionContext?: {
    flowId?: string;
    stepId?: string;
    operatorId?: string;
    sessionId?: string;
    attempt?: number;
    maxRetries?: number;
  };
}

export interface ActionExecutionResult {
  /** Execution success status */
  success: boolean;
  /** Error message if execution failed */
  error?: string;
  /** Time taken for execution in milliseconds */
  executionTime: number;
  /** Screenshot path after action (if captured) */
  screenshotPath?: string;
  /** XML dump path after action (if captured) */
  xmlDumpPath?: string;
  /** Detected destination node (if found and captured) */
  destinationNode?: ScreenNode;
  /** Whether destination was automatically detected */
  destinationDetected: boolean;
  /** Execution metadata */
  metadata: {
    deviceId: string;
    executedAt: string;
    actionDescription: string;
    preExecutionState?: string;
    postExecutionState?: string;
    [key: string]: any;
  };
}

export interface ActionValidationResult {
  /** Whether action is valid for execution */
  valid: boolean;
  /** Validation errors if invalid */
  errors: string[];
  /** Warnings for potentially risky actions */
  warnings: string[];
  /** Recommended fixes if available */
  recommendations: string[];
}

export class ActionExecutor {
  private adb: ADBUtils;
  private executionTimeout: number = 30000; // 30 seconds default

  constructor() {
    this.adb = ADBUtils.getInstance();
  }

  /**
   * Validate an action before execution
   */
  async validateAction(edge: ActionEdge | ExtendedActionEdge): Promise<ActionValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];
    const recommendations: string[] = [];

    // Basic edge validation
    if (!edge.id) {
      errors.push('Edge ID is required');
    }

    if (!edge.fromNodeId) {
      errors.push('Source node ID is required');
    }

    if (!edge.action || !edge.action.kind) {
      errors.push('Action kind is required');
    }

    const validKinds = ['tap', 'type', 'wait', 'back', 'intent'];
    if (edge.action.kind && !validKinds.includes(edge.action.kind)) {
      errors.push(`Invalid action kind: ${edge.action.kind}. Valid kinds: ${validKinds.join(', ')}`);
    }

    // Action-specific validation
    switch (edge.action.kind) {
      case 'tap':
        if (!edge.action.selectorId && !edge.action.text) {
          errors.push('tap action must specify selectorId or text');
        } else if (!edge.action.selectorId) {
          warnings.push('tap action without selectorId may be less reliable');
          recommendations.push('Consider adding a selectorId for better reliability');
        }
        break;

      case 'type':
        if (!edge.action.text) {
          errors.push('type action must specify text to type');
        }
        if (!edge.action.selectorId) {
          warnings.push('type action without selectorId will type into currently focused element');
          recommendations.push('Specify selectorId for targeted typing');
        }
        break;

      case 'wait':
        if (!edge.action.delayMs || edge.action.delayMs <= 0) {
          errors.push('wait action must specify positive delayMs');
        } else if (edge.action.delayMs > 60000) {
          warnings.push('wait action longer than 60 seconds may indicate a design issue');
        }
        break;

      case 'back':
        if (edge.action.selectorId || edge.action.text) {
          warnings.push('back action typically should not specify selectorId or text');
          recommendations.push('Remove selectorId and text from back action');
        }
        break;

      case 'intent':
        if (!edge.action.intent || !edge.action.intent.action) {
          errors.push('intent action must specify intent.action');
        }
        break;
    }

    // Edge confidence validation
    if (edge.confidence < 0.5) {
      warnings.push(`Low confidence edge (${Math.round(edge.confidence * 100)}%). Action may fail`);
      recommendations.push('Consider testing the action and updating confidence');
    }

    // Guard validation
    if (edge.guard?.mustMatchSignatureHash) {
      if (!/^[a-f0-9]{32}$/.test(edge.guard.mustMatchSignatureHash)) {
        errors.push('Guard signature hash must be a 16-byte hex string');
      }
    }

    // Start state constraint validation
    if (edge.startStateConstraint) {
      // This would ideally validate against known start state profiles
      warnings.push(`Edge has start state constraint: ${edge.startStateConstraint}`);
      recommendations.push('Ensure current device state matches the constraint');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      recommendations
    };
  }

  /**
   * Execute an action and optionally capture destination
   */
  async executeAction(request: ActionExecutionRequest): Promise<ActionExecutionResult> {
    const startTime = Date.now();
    const deviceId = request.deviceId || this.adb.getEmulatorDeviceId();
    const executedAt = new Date().toISOString();

    // Initialize result structure
    const result: ActionExecutionResult = {
      success: false,
      executionTime: 0,
      destinationDetected: false,
      metadata: {
        deviceId,
        executedAt,
        actionDescription: this.getActionDescription(request.edge),
        ...request.executionContext
      }
    };

    try {
      // Step 1: Validate the action
      const validation = await this.validateAction(request.edge);
      if (!validation.valid) {
        result.error = `Action validation failed: ${validation.errors.join(', ')}`;
        result.executionTime = Date.now() - startTime;
        return result;
      }

      // Step 2: Check device connectivity
      const deviceAvailable = await this.adb.isDeviceConnected(deviceId);
      if (!deviceAvailable) {
        result.error = `Device ${deviceId} is not connected or available`;
        result.executionTime = Date.now() - startTime;
        return result;
      }

      // Step 3: Capture pre-execution state
      const preExecutionState = await this.captureCurrentState(deviceId);
      result.metadata.preExecutionState = preExecutionState.activity;

      // Step 4: Execute the action based on kind
      await this.performAction(request.edge, deviceId);

      // Step 5: Wait for UI to settle (based on action type)
      await this.waitForUiSettle(request.edge);

      // Step 6: Capture post-execution state
      const postExecutionState = await this.captureCurrentState(deviceId);
      result.metadata.postExecutionState = postExecutionState.activity;
      result.screenshotPath = postExecutionState.screenshotPath;
      result.xmlDumpPath = postExecutionState.xmlDumpPath;

      // Step 7: Auto-detect destination node if requested
      if (request.captureDestination && postExecutionState.xmlDumpPath) {
        try {
          const destinationNode = await this.detectDestinationNode(
            postExecutionState.xmlDumpPath,
            postExecutionState.screenshotPath,
            request.executionContext?.operatorId || 'system'
          );

          if (destinationNode) {
            const destinationEntity = ScreenNodeEntity.fromJSON(destinationNode);
            result.destinationNode = destinationNode;
            result.destinationDetected = true;

            // Store the destination node in graph
            await graphStore.addNode(destinationEntity);

            // Update edge with destination
            const edgeEntity = ActionEdgeEntity.fromJSON({ ...request.edge, toNodeId: destinationNode.id });
            await graphStore.addEdge(edgeEntity);
          }
        } catch (detectError) {
          // Destination detection failure doesn't make the action fail
          console.warn(`Failed to detect destination node: ${detectError}`);
        }
      }

      result.success = true;
      result.executionTime = Date.now() - startTime;

      return result;
    } catch (error) {
      result.success = false;
      result.error = error instanceof Error ? error.message : 'Unknown execution error';
      result.executionTime = Date.now() - startTime;
      return result;
    }
  }

  /**
   * Perform the actual action execution based on action kind
   */
  private async performAction(edge: ActionEdge | ExtendedActionEdge, deviceId: string): Promise<void> {
    switch (edge.action.kind) {
      case 'tap':
        await this.performTap(edge, deviceId);
        break;
      case 'type':
        await this.performType(edge, deviceId);
        break;
      case 'wait':
        await this.performWait(edge);
        break;
      case 'back':
        await this.performBack(deviceId);
        break;
      case 'intent':
        await this.performIntent(edge, deviceId);
        break;
      default:
        throw new Error(`Unsupported action kind: ${edge.action.kind}`);
    }
  }

  /**
   * Perform tap action
   */
  private async performTap(edge: ActionEdge | ExtendedActionEdge, deviceId: string): Promise<void> {
    if (edge.action.selectorId) {
      // Tap using selector
      await this.adb.tapBySelector(deviceId, edge.action.selectorId);
    } else if (edge.action.text) {
      // Tap using text
      await this.adb.tapByText(deviceId, edge.action.text);
    } else {
      throw new Error('tap action requires selectorId or text');
    }
  }

  /**
   * Perform type action
   */
  private async performType(edge: ActionEdge | ExtendedActionEdge, deviceId: string): Promise<void> {
    if (!edge.action.text) {
      throw new Error('type action requires text');
    }

    if (edge.action.selectorId) {
      // Type into specific element
      await this.adb.typeIntoSelector(deviceId, edge.action.selectorId, edge.action.text);
    } else {
      // Type into currently focused element
      await this.adb.typeText(deviceId, edge.action.text);
    }
  }

  /**
   * Perform wait action
   */
  private async performWait(edge: ActionEdge | ExtendedActionEdge): Promise<void> {
    const delay = edge.action.delayMs || 1000;
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Perform back action
   */
  private async performBack(deviceId: string): Promise<void> {
    await this.adb.pressKeyByName('KEYCODE_BACK', deviceId);
  }

  /**
   * Perform intent action
   */
  private async performIntent(edge: ActionEdge | ExtendedActionEdge, deviceId: string): Promise<void> {
    if (!edge.action.intent) {
      throw new Error('intent action requires intent configuration');
    }

    await this.adb.startActivity(
      deviceId,
      edge.action.intent.action,
      edge.action.intent.package,
      edge.action.intent.component
    );
  }

  /**
   * Wait for UI to settle after action
   */
  private async waitForUiSettle(edge: ActionEdge | ExtendedActionEdge): Promise<void> {
    // Default settle time based on action type
    const settleTimes = {
      tap: 500,
      type: 300,
      wait: 100, // Already has its own delay
      back: 500,
      intent: 1000
    };

    const settleTime = settleTimes[edge.action.kind] || 500;
    await new Promise(resolve => setTimeout(resolve, settleTime));
  }

  /**
   * Capture current device state
   */
  private async captureCurrentState(deviceId: string): Promise<{
    activity?: string;
    screenshotPath?: string;
    xmlDumpPath?: string;
  }> {
    try {
      const timestamp = Date.now();
      const screenshotPath = `/tmp/capture_${timestamp}.png`;
      const xmlDumpPath = `/tmp/capture_${timestamp}.xml`;

      // Capture screenshot
      await this.adb.takeScreenshot(deviceId, screenshotPath);

      // Capture UI dump
      await this.adb.dumpUI(deviceId, xmlDumpPath);

      // Extract activity information
      const activity = await this.adb.getCurrentActivity(deviceId);

      return {
        activity,
        screenshotPath,
        xmlDumpPath
      };
    } catch (error) {
      console.error('Failed to capture device state:', error);
      return {};
    }
  }

  /**
   * Detect destination node from captured state
   */
  private async detectDestinationNode(
    xmlDumpPath: string,
    screenshotPath?: string,
    operatorId: string = 'system'
  ): Promise<ScreenNode | null> {
    try {
      // Read XML dump
      const xmlContent = await this.readFile(xmlDumpPath);

      // Generate signature
      const signatureResult = await signatureGenerator.generateSignature({
        xmlContent
      });

      // Extract selectors
      const selectorResult = await selectorExtractor.extractSelectors({
        xmlContent,
        includeCoordinates: true
      });

      // Check if node already exists with this signature
      const existingNode = await graphStore.getNode(signatureResult.signature.hash);
      if (existingNode) {
        // Update the existing node with new artifacts if needed
        if (screenshotPath) {
          existingNode.samples.screenshotPath = screenshotPath;
        }
        existingNode.samples.xmlPath = xmlDumpPath;
        existingNode.metadata.captureTimestamp = new Date().toISOString();

        await graphStore.updateNode(existingNode);
        return existingNode;
      }

      // Create new destination node
      const newNode: ScreenNode = {
        id: signatureResult.signature.hash,
        name: `Auto-captured destination ${new Date().toISOString()}`,
        signature: signatureResult.signature,
        selectors: selectorResult.selectors,
        hints: ['Auto-captured from action execution'],
        samples: {
          screenshotPath: screenshotPath || '',
          xmlPath: xmlDumpPath,
          metadataPath: `/var/captures/${signatureResult.signature.hash}/metadata.json`,
          checksum: signatureResult.signature.hash
        },
        metadata: {
          activity: signatureResult.metadata.activity,
          package: signatureResult.metadata.package,
          emulatorBuild: 'emulator-5554',
          captureTimestamp: new Date().toISOString(),
          operatorId
        },
        startStateTag: 'other',
        outgoingEdgeIds: [],
        incomingEdgeIds: [],
        status: 'active'
      };

      return newNode;
    } catch (error) {
      console.error('Failed to detect destination node:', error);
      return null;
    }
  }

  /**
   * Helper to read file content
   */
  private async readFile(filePath: string): Promise<string> {
    const fs = await import('fs/promises');
    return fs.readFile(filePath, 'utf-8');
  }

  /**
   * Get human-readable action description
   */
  private getActionDescription(edge: ActionEdge | ExtendedActionEdge): string {
    const { kind, selectorId, text, delayMs, intent } = edge.action;
    const target = selectorId || text || delayMs || intent?.action || 'system';

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
        return `Intent: ${intent?.action || target}`;
      default:
        return `${kind}: ${target}`;
    }
  }

  /**
   * Execute multiple actions in sequence
   */
  async executeActionsSequential(requests: ActionExecutionRequest[]): Promise<ActionExecutionResult[]> {
    const results: ActionExecutionResult[] = [];

    for (const request of requests) {
      const result = await this.executeAction(request);
      results.push(result);

      // Stop on first failure
      if (!result.success) {
        break;
      }
    }

    return results;
  }

  /**
   * Execute actions with retry logic
   */
  async executeActionWithRetry(
    request: ActionExecutionRequest,
    maxRetries: number = 3,
    retryDelay: number = 1000
  ): Promise<ActionExecutionResult> {
    let lastResult: ActionExecutionResult;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      const result = await this.executeAction({
        ...request,
        executionContext: {
          ...request.executionContext,
          attempt,
          maxRetries
        }
      });

      if (result.success) {
        return result;
      }

      lastResult = result;

      // Don't retry on validation errors
      if (result.error?.includes('validation failed')) {
        break;
      }

      // Wait before retry (except for last attempt)
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, retryDelay * attempt));
      }
    }

    return lastResult || {
      success: false,
      error: 'All retry attempts failed',
      executionTime: 0,
      destinationDetected: false,
      metadata: {
        deviceId: request.deviceId || this.adb.getEmulatorDeviceId(),
        executedAt: new Date().toISOString(),
        actionDescription: this.getActionDescription(request.edge)
      }
    };
  }
}

export const actionExecutor = new ActionExecutor();