/**
 * Capture Controller
 *
 * API endpoints for screen capture and action recording.
 * Handles node capture, action execution, and edge creation workflows.
 */

import { Request, Response } from 'express';
import { edgeService, CreateEdgeRequest, EdgeCreationResult } from '../services/edgeService';
import { nodeCaptureService } from '../services/ui-graph/nodeCaptureService';
import { graphStore } from '../services/ui-graph/graphStore';

export interface CaptureActionRequest {
  /** Source node ID */
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
  /** Operator notes */
  notes?: string;
  /** Start state constraint */
  startStateConstraint?: string;
  /** Whether to execute and capture destination */
  executeAndCapture?: boolean;
}

export interface CaptureActionResponse {
  /** Success status */
  success: boolean;
  /** Created edge */
  edge?: any;
  /** Destination node if captured */
  destinationNode?: any;
  /** Execution metadata */
  metadata?: {
    executionTime: number;
    success: boolean;
    error?: string;
    screenshotPath?: string;
    xmlPath?: string;
  };
  /** Error message if failed */
  error?: string;
}

/**
 * POST /api/captures/action
 * Record an action and optionally execute it to capture destination
 */
export async function captureAction(
  req: Request<{}, CaptureActionResponse, CaptureActionRequest>,
  res: Response<CaptureActionResponse>
): Promise<void> {
  try {
    const { fromNodeId, action, guard, notes, startStateConstraint, executeAndCapture } = req.body;

    // Validate required fields
    if (!fromNodeId) {
      res.status(400).json({
        success: false,
        error: 'Source node ID is required',
      });
      return;
    }

    if (!action || !action.kind) {
      res.status(400).json({
        success: false,
        error: 'Action kind is required',
      });
      return;
    }

    // Verify source node exists
    const sourceNode = await graphStore.getNode(fromNodeId);
    if (!sourceNode) {
      res.status(404).json({
        success: false,
        error: `Source node ${fromNodeId} not found`,
      });
      return;
    }

    // Create edge request
    const edgeRequest: CreateEdgeRequest = {
      fromNodeId,
      action,
      guard,
      notes,
      startStateConstraint,
      executeAndCapture: executeAndCapture || false,
    };

    // Create edge and optionally execute
    const result: EdgeCreationResult = await edgeService.createEdge(edgeRequest);

    // Store edge in graph
    await graphStore.addEdge(result.edge);

    // Store destination node if captured
    if (result.destinationNode) {
      await graphStore.addNode(result.destinationNode);
    }

    // Update source node with new outgoing edge
    // TODO: Implement GraphStore methods
    // await graphStore.addOutgoingEdge(fromNodeId, result.edge.id);

    // Update destination node with incoming edge if captured
    if (result.destinationNode) {
      // await graphStore.addIncomingEdge(result.destinationNode.id, result.edge.id);
    }

    res.status(201).json({
      success: true,
      edge: result.edge,
      destinationNode: result.destinationNode,
      metadata: result.metadata,
    });
  } catch (error) {
    console.error('Failed to capture action:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to capture action',
    });
  }
}

/**
 * POST /api/captures/action/batch
 * Create multiple actions in batch
 */
export interface BatchCaptureActionRequest {
  actions: CaptureActionRequest[];
}

export interface BatchCaptureActionResponse {
  success: boolean;
  results: CaptureActionResponse[];
  error?: string;
}

export async function batchCaptureAction(
  req: Request<{}, BatchCaptureActionResponse, BatchCaptureActionRequest>,
  res: Response<BatchCaptureActionResponse>
): Promise<void> {
  try {
    const { actions } = req.body;

    if (!actions || !Array.isArray(actions) || actions.length === 0) {
      res.status(400).json({
        success: false,
        results: [],
        error: 'Actions array is required and must not be empty',
      });
      return;
    }

    const results: CaptureActionResponse[] = [];

    // Process each action
    for (const actionRequest of actions) {
      try {
        // Mock the request/response pattern for individual actions
        const mockReq = { body: actionRequest } as Request<{}, CaptureActionResponse, CaptureActionRequest>;
        const mockRes: {
          statusCode?: number;
          json: (data: CaptureActionResponse) => CaptureActionResponse;
        } = {
          json: (data: CaptureActionResponse) => data,
        };

        // Execute single action capture - simplified for now
        // TODO: Implement proper batch processing
        const result: CaptureActionResponse = {
          success: true,
          edge: undefined,
          destinationNode: undefined,
        };
        results.push(result);
      } catch (error) {
        results.push({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    const successCount = results.filter(r => r.success).length;

    res.status(successCount === actions.length ? 201 : 207).json({
      success: successCount > 0,
      results,
    });
  } catch (error) {
    console.error('Failed to batch capture actions:', error);
    res.status(500).json({
      success: false,
      results: [],
      error: error instanceof Error ? error.message : 'Failed to batch capture actions',
    });
  }
}

/**
 * GET /api/captures/action/:edgeId
 * Get action details
 */
export interface GetActionResponse {
  success: boolean;
  edge?: any;
  sourceNode?: any;
  destinationNode?: any;
  statistics?: {
    totalExecutions: number;
    successRate: number;
    averageExecutionTime: number;
    lastExecutedAt?: string;
  };
  error?: string;
}

export async function getAction(
  req: Request<{ edgeId: string }, GetActionResponse>,
  res: Response<GetActionResponse>
): Promise<void> {
  try {
    const { edgeId } = req.params;

    if (!edgeId) {
      res.status(400).json({
        success: false,
        error: 'Edge ID is required',
      });
      return;
    }

    // Get edge from graph store
    const edge = await graphStore.getEdge(edgeId);
    if (!edge) {
      res.status(404).json({
        success: false,
        error: `Action edge ${edgeId} not found`,
      });
      return;
    }

    // Get related nodes
    const sourceNode = edge.fromNodeId ? await graphStore.getNode(edge.fromNodeId) : undefined;
    const destinationNode = edge.toNodeId ? await graphStore.getNode(edge.toNodeId) : undefined;

    // Get execution statistics
    const statistics = await edgeService.getEdgeStatistics(edgeId);

    res.json({
      success: true,
      edge,
      sourceNode,
      destinationNode,
      statistics,
    });
  } catch (error) {
    console.error('Failed to get action:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to get action',
    });
  }
}

/**
 * PUT /api/captures/action/:edgeId
 * Update action details
 */
export interface UpdateActionRequest {
  /** Updated action definition */
  action?: {
    kind?: 'tap' | 'type' | 'wait' | 'back' | 'intent';
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
  /** Updated guard conditions */
  guard?: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  /** Updated notes */
  notes?: string;
  /** Updated start state constraint */
  startStateConstraint?: string;
}

export interface UpdateActionResponse {
  success: boolean;
  edge?: any;
  error?: string;
}

export async function updateAction(
  req: Request<{ edgeId: string }, UpdateActionResponse, UpdateActionRequest>,
  res: Response<UpdateActionResponse>
): Promise<void> {
  try {
    const { edgeId } = req.params;
    const updates = req.body;

    if (!edgeId) {
      res.status(400).json({
        success: false,
        error: 'Edge ID is required',
      });
      return;
    }

    // Get existing edge
    const existingEdge = await graphStore.getEdge(edgeId);
    if (!existingEdge) {
      res.status(404).json({
        success: false,
        error: `Action edge ${edgeId} not found`,
      });
      return;
    }

    // Apply updates
    const updatedEdge = {
      ...existingEdge,
      ...updates,
      // Merge nested objects properly
      action: updates.action ? { ...existingEdge.action, ...updates.action } : existingEdge.action,
      guard: updates.guard ? { ...existingEdge.guard, ...updates.guard } : existingEdge.guard,
    };

    // Validate updated edge
    edgeService.validateEdgePublic(updatedEdge);

    // Store updated edge
    // TODO: Implement GraphStore updateEdge method
    // await graphStore.updateEdge(edgeId, updatedEdge);

    res.json({
      success: true,
      edge: updatedEdge,
    });
  } catch (error) {
    console.error('Failed to update action:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to update action',
    });
  }
}

/**
 * DELETE /api/captures/action/:edgeId
 * Delete an action edge
 */
export interface DeleteActionResponse {
  success: boolean;
  error?: string;
}

export async function deleteAction(
  req: Request<{ edgeId: string }, DeleteActionResponse>,
  res: Response<DeleteActionResponse>
): Promise<void> {
  try {
    const { edgeId } = req.params;

    if (!edgeId) {
      res.status(400).json({
        success: false,
        error: 'Edge ID is required',
      });
      return;
    }

    // Check if edge exists
    const edge = await graphStore.getEdge(edgeId);
    if (!edge) {
      res.status(404).json({
        success: false,
        error: `Action edge ${edgeId} not found`,
      });
      return;
    }

    // TODO: Check if edge is referenced by any flows before deletion

    // Remove edge from graph store
    // TODO: Implement GraphStore methods
    // await graphStore.removeEdge(edgeId);

    // Update source node
    if (edge.fromNodeId) {
      // await graphStore.removeOutgoingEdge(edge.fromNodeId, edgeId);
    }

    // Update destination node
    if (edge.toNodeId) {
      // await graphStore.removeIncomingEdge(edge.toNodeId, edgeId);
    }

    res.json({
      success: true,
    });
  } catch (error) {
    console.error('Failed to delete action:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Failed to delete action',
    });
  }
}