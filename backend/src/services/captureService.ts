/**
 * Capture Service
 *
 * Orchestrates the screen capture workflow for UI graph nodes.
 * Integrates with ADB, artifact storage, signature generation, and selector extraction.
 * Handles error recovery, retry logic, and provenance tracking.
 */

import { ADBUtils } from '../utils/adb';
import { signatureGenerator } from './signatureGenerator';
import { selectorExtractor } from './selectorExtractor';
import { artifactStorage } from './artifactStore';
import { graphStore } from './graphStore';
import { actionExecutor } from './actionExecutor';
import { ScreenNodeEntity } from '../models/ScreenNode';
import { ActionEdgeEntity } from '../models/ActionEdge';
import type { ScreenNode, ActionEdge, SelectorCandidate } from '../types/uiGraph';

export interface CaptureRequest {
  /** Node name for human identification */
  name: string;
  /** Optional hints for operators and LLM */
  hints?: string[];
  /** Start state tag for categorization */
  startStateTag?: 'clean' | 'logged_out_home' | 'logged_in_no_rental' | 'logged_in_with_rental' | 'other';
  /** Device ID for multi-device setups */
  deviceId?: string;
  /** Optional operator ID for provenance */
  operatorId?: string;
  /** Capture quality settings */
  quality?: {
    screenshotFormat?: 'png' | 'jpg';
    screenshotQuality?: number;
    includeDeviceMetrics?: boolean;
  };
}

export interface CaptureResult {
  /** Whether capture succeeded */
  success: boolean;
  /** Error message if failed */
  error?: string;
  /** Captured node if successful */
  node?: ScreenNode;
  /** Execution metadata */
  metadata: {
    captureTime: number;
    deviceId: string;
    operatorId: string;
    timestamp: string;
    screenshotPath: string;
    xmlPath: string;
    selectorCount: number;
    artifactSize: number;
  };
}

export interface RetryOptions {
  /** Maximum retry attempts */
  maxAttempts: number;
  /** Delay between retries (ms) */
  retryDelay: number;
  /** Exponential backoff multiplier */
  backoffMultiplier: number;
  /** Whether to retry on specific error types */
  retryOnErrors: string[];
}

export interface ProvenanceData {
  /** Operator who performed the capture */
  operatorId: string;
  /** When the capture was performed */
  timestamp: string;
  /** Device/emulator build information */
  emulatorBuild?: string;
  /** App version and build info */
  appVersion?: string;
  /** System metrics at capture time */
  systemMetrics?: {
    deviceMemory?: number;
    availableStorage?: number;
    cpuUsage?: number;
  };
  /** Capture workflow information */
  workflowInfo?: {
    sessionId?: string;
    previousNodeId?: string;
    actionExecuted?: ActionEdge;
    captureMethod: 'manual' | 'automated';
  };
}

export class CaptureService {
  private adb: ADBUtils;
  private defaultRetryOptions: RetryOptions = {
    maxAttempts: 3,
    retryDelay: 1000,
    backoffMultiplier: 2,
    retryOnErrors: [
      'Device not connected',
      'Failed to capture screenshot',
      'Failed to dump UI',
      'Connection timeout'
    ]
  };

  constructor() {
    this.adb = ADBUtils.getInstance();
  }

  /**
   * Capture screen node with full workflow
   */
  async captureScreen(request: CaptureRequest): Promise<CaptureResult> {
    const startTime = Date.now();
    const deviceId = request.deviceId || this.adb.getEmulatorDeviceId();
    const operatorId = request.operatorId || 'system';
    const timestamp = new Date().toISOString();

    try {
      // Step 1: Validate device connectivity
      const deviceConnected = await this.adb.isDeviceConnected(deviceId);
      if (!deviceConnected) {
        throw new Error(`Device ${deviceId} is not connected`);
      }

      // Step 2: Capture screenshot
      const screenshotPath = await this.captureScreenshotWithRetry(
        deviceId,
        timestamp,
        this.defaultRetryOptions
      );

      // Step 3: Capture UI dump
      const xmlPath = await this.captureUIWithRetry(
        deviceId,
        timestamp,
        this.defaultRetryOptions
      );

      // Step 4: Read XML data for processing
      const xmlData = await this.readFile(xmlPath);

      // Step 5: Generate signature
      const signatureResult = await signatureGenerator.generateSignature({
        xmlContent: xmlData
      });

      // Step 6: Extract selectors
      const selectorResult = await selectorExtractor.extractSelectors({
        xmlContent: xmlData,
        includeCoordinates: true
      });

      // Step 7: Create provenance data
      const provenanceData = await this.createProvenanceData(deviceId, operatorId, request);

      // Step 8: Create artifact bundle
      const artifactBundle = await artifactStorage.storeBundle(
        signatureResult.signature.hash,
        await this.readFileAsBuffer(screenshotPath),
        xmlData,
        provenanceData
      );

      // Step 9: Create screen node
      const node = await this.createScreenNode(
        request.name,
        signatureResult,
        selectorResult.selectors,
        artifactBundle,
        request.hints || [],
        request.startStateTag,
        provenanceData
      );

      // Step 10: Store node in graph
      const nodeEntity = ScreenNodeEntity.fromJSON(node);
      await graphStore.addNode(nodeEntity);

      const captureTime = Date.now() - startTime;

      return {
        success: true,
        node,
        metadata: {
          captureTime,
          deviceId,
          operatorId,
          timestamp,
          screenshotPath,
          xmlPath,
          selectorCount: selectorResult.selectors.length,
          artifactSize: await artifactBundle.getTotalSize()
        }
      };
    } catch (error) {
      const captureTime = Date.now() - startTime;
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown capture error',
        metadata: {
          captureTime,
          deviceId,
          operatorId,
          timestamp,
          screenshotPath: '',
          xmlPath: '',
          selectorCount: 0,
          artifactSize: 0
        }
      };
    }
  }

  /**
   * Capture screenshot with retry logic
   */
  private async captureScreenshotWithRetry(
    deviceId: string,
    timestamp: string,
    retryOptions: RetryOptions
  ): Promise<string> {
    const screenshotPath = `/tmp/capture_${timestamp}.png`;

    for (let attempt = 1; attempt <= retryOptions.maxAttempts; attempt++) {
      try {
        await this.adb.takeScreenshot(deviceId, screenshotPath);
        return screenshotPath;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Screenshot capture failed';

        // Check if this error type should be retried
        const shouldRetry = retryOptions.retryOnErrors.some(retryError =>
          errorMessage.toLowerCase().includes(retryError.toLowerCase())
        );

        if (!shouldRetry || attempt === retryOptions.maxAttempts) {
          throw new Error(`Failed to capture screenshot after ${attempt} attempts: ${errorMessage}`);
        }

        // Wait before retry
        const delay = retryOptions.retryDelay * Math.pow(retryOptions.backoffMultiplier, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw new Error('Screenshot capture failed after all retry attempts');
  }

  /**
   * Capture UI dump with retry logic
   */
  private async captureUIWithRetry(
    deviceId: string,
    timestamp: string,
    retryOptions: RetryOptions
  ): Promise<string> {
    const xmlPath = `/tmp/capture_${timestamp}.xml`;

    for (let attempt = 1; attempt <= retryOptions.maxAttempts; attempt++) {
      try {
        await this.adb.dumpUI(deviceId, xmlPath);
        return xmlPath;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'UI dump failed';

        // Check if this error type should be retried
        const shouldRetry = retryOptions.retryOnErrors.some(retryError =>
          errorMessage.toLowerCase().includes(retryError.toLowerCase())
        );

        if (!shouldRetry || attempt === retryOptions.maxAttempts) {
          throw new Error(`Failed to dump UI after ${attempt} attempts: ${errorMessage}`);
        }

        // Wait before retry
        const delay = retryOptions.retryDelay * Math.pow(retryOptions.backoffMultiplier, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw new Error('UI dump failed after all retry attempts');
  }

  /**
   * Create screen node from capture data
   */
  private async createScreenNode(
    name: string,
    signatureResult: any,
    selectors: SelectorCandidate[],
    artifactBundle: any,
    hints: string[],
    startStateTag?: 'clean' | 'logged_out_home' | 'logged_in_no_rental' | 'logged_in_with_rental' | 'other',
    provenanceData?: ProvenanceData
  ): Promise<ScreenNode> {
    const node: ScreenNode = {
      id: signatureResult.signature.hash,
      name,
      signature: signatureResult.signature,
      selectors,
      hints,
      samples: {
        screenshotPath: artifactBundle.screenshotPath,
        xmlPath: artifactBundle.xmlPath,
        metadataPath: artifactBundle.metadataPath,
        checksum: artifactBundle.checksum
      },
      metadata: {
        activity: signatureResult.metadata.activity,
        package: signatureResult.metadata.package,
        emulatorBuild: provenanceData?.emulatorBuild || 'unknown',
        captureTimestamp: provenanceData?.timestamp || new Date().toISOString(),
        operatorId: provenanceData?.operatorId || 'system'
      },
      startStateTag,
      outgoingEdgeIds: [],
      incomingEdgeIds: [],
      status: 'active'
    };

    return node;
  }

  /**
   * Create provenance data for capture
   */
  private async createProvenanceData(
    deviceId: string,
    operatorId: string,
    request: CaptureRequest
  ): Promise<ProvenanceData> {
    const timestamp = new Date().toISOString();

    try {
      // Get device info
      const deviceInfo = await this.adb.getDeviceInfo(deviceId);
      const appInfo = await this.adb.getCurrentAppInfo(deviceId);

      return {
        operatorId,
        timestamp,
        emulatorBuild: deviceInfo.version,
        appVersion: appInfo?.version,
        systemMetrics: {
          deviceMemory: 0, // TODO: Implement memory query if needed
          availableStorage: 0, // TODO: Implement storage query if needed
          cpuUsage: 0, // TODO: Implement CPU query if needed
        },
        workflowInfo: {
          captureMethod: 'manual'
        }
      };
    } catch (error) {
      console.warn('Failed to get full provenance data:', error);
      return {
        operatorId,
        timestamp,
        emulatorBuild: 'unknown',
        workflowInfo: {
          captureMethod: 'manual'
        }
      };
    }
  }

  /**
   * Capture destination node after action execution
   */
  async captureDestinationAfterAction(
    actionEdge: ActionEdge,
    deviceId?: string,
    operatorId?: string
  ): Promise<CaptureResult> {
    try {
      // Execute the action
      const edgeEntity = ActionEdgeEntity.fromJSON(actionEdge);
      const executionResult = await actionExecutor.executeAction({
        edge: edgeEntity,
        deviceId,
        executionContext: {
          operatorId,
          sessionId: `capture_${Date.now()}`
        }
      });

      if (!executionResult.success) {
        throw new Error(`Action execution failed: ${executionResult.error}`);
      }

      // If a destination node was already detected, return it
      if (executionResult.destinationNode) {
        return {
          success: true,
          node: executionResult.destinationNode,
          metadata: {
            captureTime: executionResult.executionTime,
            deviceId: executionResult.metadata.deviceId,
            operatorId: operatorId || 'system',
            timestamp: executionResult.metadata.executedAt,
            screenshotPath: executionResult.screenshotPath || '',
            xmlPath: executionResult.xmlDumpPath || '',
            selectorCount: executionResult.destinationNode.selectors.length,
            artifactSize: 0
          }
        };
      }

      // Otherwise, perform a fresh capture
      const captureResult = await this.captureScreen({
        name: `Auto-captured from action ${actionEdge.action.kind}`,
        hints: [`Destination of ${actionEdge.action.kind} action`],
        operatorId,
        deviceId,
        startStateTag: 'other'
      });

      // Update the edge with destination node
      if (captureResult.success && captureResult.node) {
        const updatedEdge = { ...actionEdge, toNodeId: captureResult.node.id };
        const edgeEntity = ActionEdgeEntity.fromJSON(updatedEdge);
        await graphStore.addEdge(edgeEntity);
      }

      return captureResult;
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Destination capture failed',
        metadata: {
          captureTime: 0,
          deviceId: deviceId || this.adb.getEmulatorDeviceId(),
          operatorId: operatorId || 'system',
          timestamp: new Date().toISOString(),
          screenshotPath: '',
          xmlPath: '',
          selectorCount: 0,
          artifactSize: 0
        }
      };
    }
  }

  /**
   * Validate captured artifacts
   */
  async validateArtifacts(nodeId: string): Promise<{
    valid: boolean;
    issues: string[];
    checksumValid: boolean;
  }> {
    try {
      const verification = await artifactStorage.verifyBundle(nodeId);

      const issues: string[] = [...verification.issues];

      // Additional validation checks
      const bundle = await artifactStorage.loadBundle(nodeId);
      if (bundle) {
        // Check if bundle size exceeds limits
        if (await artifactStorage.bundleExceedsLimit(nodeId)) {
          issues.push('Artifact bundle exceeds size limit (1MB)');
        }

        // Check if node has sufficient selectors
        const node = await graphStore.getNode(nodeId);
        if (node && node.selectors.length === 0) {
          issues.push('No selectors found for this node');
        }

        // Check if node has reliable selectors
        if (node && !node.selectors.some(s => s.confidence >= 0.6)) {
          issues.push('No reliable selectors (confidence >= 0.6) found');
        }
      }

      return {
        valid: verification.valid && issues.length === 0,
        issues,
        checksumValid: verification.valid
      };
    } catch (error) {
      return {
        valid: false,
        issues: [error instanceof Error ? error.message : 'Validation failed'],
        checksumValid: false
      };
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
   * Helper to read file as buffer
   */
  private async readFileAsBuffer(filePath: string): Promise<Buffer> {
    const fs = await import('fs/promises');
    return fs.readFile(filePath);
  }

  /**
   * Get capture statistics
   */
  async getCaptureStats(): Promise<{
    totalCaptures: number;
    totalSize: number;
    averageSize: number;
    recentCaptures: Array<{
      nodeId: string;
      name: string;
      timestamp: string;
      size: number;
    }>;
  }> {
    const nodeIds = await artifactStorage.listNodeIds();
    const totalCaptures = nodeIds.length;

    let totalSize = 0;
    const recentCaptures = [];

    for (const nodeId of nodeIds.slice(-10)) { // Last 10 captures
      const size = await artifactStorage.getBundleSize(nodeId);
      const bundle = await artifactStorage.loadBundle(nodeId);

      totalSize += size;

      if (bundle) {
        const metadata = await bundle.getMetadata();
        recentCaptures.push({
          nodeId,
          name: `Node ${nodeId.substring(0, 8)}...`,
          timestamp: metadata.lastModified.toISOString(),
          size
        });
      }
    }

    return {
      totalCaptures,
      totalSize,
      averageSize: totalCaptures > 0 ? Math.round(totalSize / totalCaptures) : 0,
      recentCaptures: recentCaptures.reverse()
    };
  }
}

export const captureService = new CaptureService();