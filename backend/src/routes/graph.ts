/**
 * Graph Management Routes
 *
 * API endpoints for UI state discovery, graph management,
 * and transition recording.
 */

import { Router, Request, Response } from 'express';
import { introspectionService } from '../services/introspectService';
import { graphService } from '../services/graphService';
import { FlowService } from '../services/flowService';
import {
  SnapshotRequest,
  SnapshotResponse,
  CreateTransitionRequest,
  MergeStatesRequest,
  CurrentStateResponse,
  StateRecord,
  TransitionRecord,
  MergeStatesResponse,
  UIGraph
} from '../types/graph';
import {
  CreateFlowRequest,
  UpdateFlowRequest,
  ExecuteFlowRequest,
  ValidateFlowRequest,
  ListFlowsRequest,
  GetFlowExecutionRequest,
  FlowDefinition,
  FlowExecutionResult,
  FlowValidationResult
} from '../types/flow';

const router = Router();

// Initialize flow service
const flowService = new FlowService(graphService);

/**
 * POST /api/graph/snapshot - Capture current UI state
 */
router.post('/snapshot', async (req: Request, res: Response) => {
  try {
    const options: SnapshotRequest = req.body || {};

    // Validate request
    if (options.forceScreenshot !== undefined && typeof options.forceScreenshot !== 'boolean') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'forceScreenshot must be a boolean'
      });
    }

    if (options.tags && (!Array.isArray(options.tags) || !options.tags.every(tag => typeof tag === 'string'))) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'tags must be an array of strings'
      });
    }

    // Capture state
    const result = await introspectionService.captureState(options);

    // Add to graph (handles deduplication)
    const graphResult = await graphService.addState(result.state);

    // Log capture event
    await logSessionEvent('state_capture', 'info', `Captured state: ${result.state.activity}`, {
      stateId: result.state.id,
      captureDuration: result.captureTime,
      merged: graphResult.merged,
      elementCount: result.state.selectors.length
    });

    const response: SnapshotResponse = {
      state: graphResult.state,
      merged: graphResult.merged,
      mergedInto: graphResult.mergedInto
    };

    res.status(200).json(response);
  } catch (error) {
    console.error('State capture failed:', error);

    await logSessionEvent('error', 'error', `State capture failed: ${error instanceof Error ? error.message : 'Unknown error'}`);

    res.status(500).json({
      error: 'capture_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/graph - Get complete UI graph
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    const graph = await graphService.getGraph();

    // Add response time header
    res.setHeader('X-Graph-States', graph.states.length.toString());
    res.setHeader('X-Graph-Transitions', graph.transitions.length.toString());

    res.json(graph);
  } catch (error) {
    console.error('Failed to get graph:', error);
    res.status(500).json({
      error: 'graph_retrieval_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/state/current - Get current UI state
 */
router.get('/state/current', async (req: Request, res: Response) => {
  try {
    // Get current UI state via ADB
    const captureResult = await introspectionService.captureState({ skipScreenshot: true });
    const state = captureResult.state;

    // Find best match in graph
    const detection = await graphService.detectCurrentState(
      state.package,
      state.activity,
      state.selectors,
      state.visibleText
    );

    const response: CurrentStateResponse = {
      state: detection.state,
      confidence: detection.confidence,
      candidates: detection.candidates
    };

    res.json(response);
  } catch (error) {
    console.error('Failed to get current state:', error);
    res.status(500).json({
      error: 'current_state_detection_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/state/:stateId - Get specific state
 */
router.get('/state/:stateId', async (req: Request, res: Response) => {
  try {
    const { stateId } = req.params;

    if (!stateId || typeof stateId !== 'string') {
      return res.status(400).json({
        error: 'invalid_state_id',
        message: 'State ID is required and must be a string'
      });
    }

    const state = await graphService.getState(stateId);

    if (!state) {
      return res.status(404).json({
        error: 'state_not_found',
        message: `State not found: ${stateId}`
      });
    }

    res.json(state);
  } catch (error) {
    console.error('Failed to get state:', error);
    res.status(500).json({
      error: 'state_retrieval_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/state/:stateId/screenshot - Get state screenshot
 */
router.get('/state/:stateId/screenshot', async (req: Request, res: Response) => {
  try {
    const { stateId } = req.params;

    if (!stateId || typeof stateId !== 'string') {
      return res.status(400).json({
        error: 'invalid_state_id',
        message: 'State ID is required and must be a string'
      });
    }

    const state = await graphService.getState(stateId);

    if (!state) {
      return res.status(404).json({
        error: 'state_not_found',
        message: `State not found: ${stateId}`
      });
    }

    if (!state.screenshot) {
      return res.status(404).json({
        error: 'screenshot_not_found',
        message: 'State has no associated screenshot'
      });
    }

    const screenshotsDir = process.env.SCREENSHOTS_DIR || '/app/data/screenshots';
    const screenshotPath = `${screenshotsDir}/${state.screenshot}`;

    res.sendFile(screenshotPath, (err) => {
      if (err) {
        console.error('Failed to send screenshot:', err);
        if (!res.headersSent) {
          res.status(404).json({
            error: 'screenshot_file_not_found',
            message: 'Screenshot file not found on disk'
          });
        }
      }
    });
  } catch (error) {
    console.error('Failed to get screenshot:', error);
    res.status(500).json({
      error: 'screenshot_retrieval_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/graph/transition - Create a transition
 */
router.post('/transition', async (req: Request, res: Response) => {
  try {
    const request: CreateTransitionRequest = req.body;

    // Validate request
    if (!request.action) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'action is required'
      });
    }

    if (!request.action.type) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'action.type is required'
      });
    }

    // Get current state if fromStateId not provided
    let fromStateId = request.fromStateId;
    if (!fromStateId) {
      const current = await introspectionService.captureState({ skipScreenshot: true });
      fromStateId = current.state.id;
    }

    // Get target state if toStateId not provided
    let toStateId = request.toStateId;
    if (!toStateId) {
      const current = await introspectionService.captureState({ skipScreenshot: true });
      toStateId = current.state.id;
    }

    // Add evidence if not provided
    const evidence = request.evidence || {};
    if (!evidence.beforeDigest && fromStateId) {
      const fromState = await graphService.getState(fromStateId);
      if (fromState) {
        evidence.beforeDigest = fromState.digest;
      }
    }

    // Create transition
    const transition = await graphService.addTransition(
      fromStateId,
      toStateId,
      request.action,
      {
        ...evidence,
        timestamp: new Date().toISOString()
      }
    );

    // Log transition creation
    await logSessionEvent('transition_create', 'info', `Created transition: ${request.action.type}`, {
      transitionId: transition.id,
      fromStateId,
      toStateId,
      action: request.action
    });

    res.status(201).json(transition);
  } catch (error) {
    console.error('Failed to create transition:', error);

    await logSessionEvent('error', 'error', `Transition creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);

    res.status(500).json({
      error: 'transition_creation_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/graph/merge - Merge two states
 */
router.post('/merge', async (req: Request, res: Response) => {
  try {
    const request: MergeStatesRequest = req.body;

    // Validate request
    if (!request.sourceId || !request.targetId) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'sourceId and targetId are required'
      });
    }

    if (request.sourceId === request.targetId) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Cannot merge state with itself'
      });
    }

    // Merge states
    const result = await graphService.mergeStates(request.sourceId, request.targetId);

    // Log merge operation
    await logSessionEvent('state_merge', 'info', `Merged states: ${request.sourceId} -> ${request.targetId}`, {
      sourceId: request.sourceId,
      targetId: request.targetId,
      mergedCount: result.mergedCount,
      updatedTransitions: result.updatedTransitions.length
    });

    res.json(result);
  } catch (error) {
    console.error('Failed to merge states:', error);

    await logSessionEvent('error', 'error', `State merge failed: ${error instanceof Error ? error.message : 'Unknown error'}`);

    if (error instanceof Error && error.message.includes('not found')) {
      return res.status(404).json({
        error: 'state_not_found',
        message: error.message
      });
    }

    res.status(500).json({
      error: 'state_merge_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/sessions - List capture sessions
 */
router.get('/sessions', async (req: Request, res: Response) => {
  try {
    const sessionsDir = process.env.SESSIONS_DIR || '/app/data/sessions';

    // This is a simplified implementation - in a real system you would
    // scan the sessions directory and return session metadata
    const sessions = [
      {
        id: new Date().toISOString().split('T')[0],
        timestamp: new Date().toISOString(),
        eventCount: 0,
        duration: 0
      }
    ];

    res.json({ sessions });
  } catch (error) {
    console.error('Failed to list sessions:', error);
    res.status(500).json({
      error: 'session_list_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/sessions/:sessionId - Get session events
 */
router.get('/sessions/:sessionId', async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;

    // This is a simplified implementation - in a real system you would
    // read the session file and return the events
    const session = {
      id: sessionId,
      events: []
    };

    res.json(session);
  } catch (error) {
    console.error('Failed to get session:', error);
    res.status(500).json({
      error: 'session_retrieval_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Log session events (helper function)
 */
async function logSessionEvent(
  type: string,
  severity: string,
  message: string,
  data?: Record<string, any>
): Promise<void> {
  try {
    const sessionsDir = process.env.SESSIONS_DIR || '/app/data/sessions';
    const today = new Date().toISOString().split('T')[0];
    const sessionFile = `${sessionsDir}/${today}.jsonl`;

    const event = {
      id: `evt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      type,
      severity,
      message,
      ...(data && { data })
    };

    // Ensure sessions directory exists
    const fs = require('fs').promises;
    await fs.mkdir(sessionsDir, { recursive: true });

    // Append event to session file
    await fs.appendFile(sessionFile, JSON.stringify(event) + '\n');
  } catch (error) {
    console.error('Failed to log session event:', error);
  }
}

/**
 * Performance testing endpoint
 */
router.post('/test/performance', async (req: Request, res: Response) => {
  try {
    const { iterations = 5 } = req.body;

    if (iterations < 1 || iterations > 50) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'iterations must be between 1 and 50'
      });
    }

    const results = await introspectionService.testPerformance(iterations);

    res.json(results);
  } catch (error) {
    console.error('Performance test failed:', error);
    res.status(500).json({
      error: 'performance_test_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Device validation endpoint
 */
router.get('/device/validate', async (req: Request, res: Response) => {
  try {
    const validation = await introspectionService.validateDevice();
    res.json(validation);
  } catch (error) {
    console.error('Device validation failed:', error);
    res.status(500).json({
      error: 'device_validation_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Device information endpoint
 */
router.get('/device/info', async (req: Request, res: Response) => {
  try {
    const info = await introspectionService.getDeviceInfo();
    res.json(info);
  } catch (error) {
    console.error('Failed to get device info:', error);
    res.status(500).json({
      error: 'device_info_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// ============================================================================
// Flow Management Endpoints
// ============================================================================

/**
 * POST /api/flows - Create a new flow
 */
router.post('/flows', async (req: Request, res: Response) => {
  try {
    const request: CreateFlowRequest = req.body;

    // Validate request
    if (!request.flow) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flow is required'
      });
    }

    if (!request.flow.name) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flow.name is required'
      });
    }

    if (!request.flow.packageName) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flow.packageName is required'
      });
    }

    if (!request.flow.steps || !Array.isArray(request.flow.steps)) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flow.steps must be a non-empty array'
      });
    }

    if (!request.flow.entryPoint) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flow.entryPoint is required'
      });
    }

    // Create flow
    const flow = await flowService.createFlow(request);

    // Log flow creation
    await logSessionEvent('flow_create', 'info', `Created flow: ${flow.name}`, {
      flowId: flow.id,
      flowName: flow.name,
      packageName: flow.packageName,
      stepCount: flow.steps.length
    });

    res.status(201).json(flow);
  } catch (error) {
    console.error('Failed to create flow:', error);

    await logSessionEvent('error', 'error', `Flow creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);

    if (error instanceof Error && error.message.includes('validation failed')) {
      return res.status(400).json({
        error: 'flow_validation_failed',
        message: error.message
      });
    }

    res.status(500).json({
      error: 'flow_creation_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/flows - List flows with filtering and pagination
 */
router.get('/flows', async (req: Request, res: Response) => {
  try {
    const request: ListFlowsRequest = {
      filter: {
        package: req.query.package as string,
        tags: req.query.tags ? (req.query.tags as string).split(',') : undefined,
        author: req.query.author as string,
        search: req.query.search as string
      },
      sort: {
        field: (req.query.sortField as any) || 'updatedAt',
        order: (req.query.sortOrder as any) || 'desc'
      },
      pagination: {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 50
      }
    };

    // Validate pagination
    if (request.pagination!.page < 1) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'page must be greater than 0'
      });
    }

    if (request.pagination!.limit < 1 || request.pagination!.limit > 100) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'limit must be between 1 and 100'
      });
    }

    const result = await flowService.listFlows(request);

    res.json({
      flows: result.flows,
      pagination: {
        page: request.pagination!.page,
        limit: request.pagination!.limit,
        total: result.total,
        pages: Math.ceil(result.total / request.pagination!.limit)
      }
    });
  } catch (error) {
    console.error('Failed to list flows:', error);
    res.status(500).json({
      error: 'flow_list_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/flows/:flowId - Get a specific flow
 */
router.get('/flows/:flowId', async (req: Request, res: Response) => {
  try {
    const { flowId } = req.params;

    if (!flowId || typeof flowId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flowId is required and must be a string'
      });
    }

    const flow = await flowService.loadFlow(flowId);

    if (!flow) {
      return res.status(404).json({
        error: 'flow_not_found',
        message: `Flow not found: ${flowId}`
      });
    }

    res.json(flow);
  } catch (error) {
    console.error('Failed to get flow:', error);
    res.status(500).json({
      error: 'flow_retrieval_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * PUT /api/flows/:flowId - Update a flow
 */
router.put('/flows/:flowId', async (req: Request, res: Response) => {
  try {
    const { flowId } = req.params;
    const request: UpdateFlowRequest = {
      flowId,
      flow: req.body,
      mergeStrategy: req.body.mergeStrategy || 'merge'
    };

    if (!flowId || typeof flowId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flowId is required and must be a string'
      });
    }

    if (!request.flow) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flow data is required'
      });
    }

    // Update flow
    const updatedFlow = await flowService.updateFlow(request);

    // Log flow update
    await logSessionEvent('flow_update', 'info', `Updated flow: ${updatedFlow.name}`, {
      flowId: updatedFlow.id,
      flowName: updatedFlow.name,
      version: updatedFlow.version
    });

    res.json(updatedFlow);
  } catch (error) {
    console.error('Failed to update flow:', error);

    await logSessionEvent('error', 'error', `Flow update failed: ${error instanceof Error ? error.message : 'Unknown error'}`);

    if (error instanceof Error && error.message.includes('not found')) {
      return res.status(404).json({
        error: 'flow_not_found',
        message: error.message
      });
    }

    if (error instanceof Error && error.message.includes('validation failed')) {
      return res.status(400).json({
        error: 'flow_validation_failed',
        message: error.message
      });
    }

    res.status(500).json({
      error: 'flow_update_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * DELETE /api/flows/:flowId - Delete a flow
 */
router.delete('/flows/:flowId', async (req: Request, res: Response) => {
  try {
    const { flowId } = req.params;

    if (!flowId || typeof flowId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flowId is required and must be a string'
      });
    }

    // Check if flow exists
    const flow = await flowService.loadFlow(flowId);
    if (!flow) {
      return res.status(404).json({
        error: 'flow_not_found',
        message: `Flow not found: ${flowId}`
      });
    }

    // TODO: Implement flow deletion in FlowService
    // await flowService.deleteFlow(flowId);

    // Log flow deletion
    await logSessionEvent('flow_delete', 'info', `Deleted flow: ${flow.name}`, {
      flowId: flow.id,
      flowName: flow.name
    });

    res.status(204).send();
  } catch (error) {
    console.error('Failed to delete flow:', error);

    await logSessionEvent('error', 'error', `Flow deletion failed: ${error instanceof Error ? error.message : 'Unknown error'}`);

    res.status(500).json({
      error: 'flow_deletion_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/flows/:flowId/execute - Execute a flow
 */
router.post('/flows/:flowId/execute', async (req: Request, res: Response) => {
  try {
    const { flowId } = req.params;
    const request: ExecuteFlowRequest = {
      flowId,
      config: req.body.config || {}
    };

    if (!flowId || typeof flowId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flowId is required and must be a string'
      });
    }

    // Check if flow exists
    const flow = await flowService.loadFlow(flowId);
    if (!flow) {
      return res.status(404).json({
        error: 'flow_not_found',
        message: `Flow not found: ${flowId}`
      });
    }

    // Execute flow
    const executionId = await flowService.executeFlow(request);

    // Log flow execution start
    await logSessionEvent('flow_execute', 'info', `Started flow execution: ${flow.name}`, {
      flowId: flow.id,
      flowName: flow.name,
      executionId,
      config: request.config
    });

    res.status(202).json({
      executionId,
      status: 'started',
      message: 'Flow execution started'
    });
  } catch (error) {
    console.error('Failed to execute flow:', error);

    await logSessionEvent('error', 'error', `Flow execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`);

    if (error instanceof Error && error.message.includes('not found')) {
      return res.status(404).json({
        error: 'flow_not_found',
        message: error.message
      });
    }

    if (error instanceof Error && error.message.includes('Maximum parallel executions')) {
      return res.status(429).json({
        error: 'too_many_executions',
        message: error.message
      });
    }

    res.status(500).json({
      error: 'flow_execution_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/flows/:flowId/executions/:executionId - Get flow execution status
 */
router.get('/flows/:flowId/executions/:executionId', async (req: Request, res: Response) => {
  try {
    const { flowId, executionId } = req.params;

    if (!flowId || typeof flowId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flowId is required and must be a string'
      });
    }

    if (!executionId || typeof executionId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'executionId is required and must be a string'
      });
    }

    const status = flowService.getExecutionStatus(executionId);

    if (!status) {
      return res.status(404).json({
        error: 'execution_not_found',
        message: `Execution not found: ${executionId}`
      });
    }

    res.json({
      executionId: status.executionId,
      flowId: status.flow.id,
      status: status.status,
      currentStep: status.currentStep,
      startedAt: status.startedAt,
      stepHistory: status.stepHistory,
      variables: status.variables
    });
  } catch (error) {
    console.error('Failed to get execution status:', error);
    res.status(500).json({
      error: 'execution_status_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/flows/:flowId/executions/:executionId/result - Get flow execution result
 */
router.get('/flows/:flowId/executions/:executionId/result', async (req: Request, res: Response) => {
  try {
    const { flowId, executionId } = req.params;
    const includeLogs = req.query.includeLogs === 'true';
    const includeStepHistory = req.query.includeStepHistory === 'true';

    if (!flowId || typeof flowId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flowId is required and must be a string'
      });
    }

    if (!executionId || typeof executionId !== 'string') {
      return res.status(400).json({
        error: 'validation_error',
        message: 'executionId is required and must be a string'
      });
    }

    const result = await flowService.getExecutionResult(executionId);

    if (!result) {
      return res.status(404).json({
        error: 'execution_not_found',
        message: `Execution not found: ${executionId}`
      });
    }

    // Filter response based on query parameters
    let response: any = {
      executionId: result.executionId,
      flowId: result.flowId,
      status: result.status,
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      duration: result.duration,
      summary: result.summary
    };

    if (includeStepHistory) {
      response.stepHistory = result.stepHistory;
    }

    if (includeLogs) {
      response.logs = result.logs;
    }

    res.json(response);
  } catch (error) {
    console.error('Failed to get execution result:', error);
    res.status(500).json({
      error: 'execution_result_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/flows/validate - Validate a flow definition
 */
router.post('/flows/validate', async (req: Request, res: Response) => {
  try {
    const request: ValidateFlowRequest = req.body;

    if (!request.flow) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'flow is required'
      });
    }

    // Validate flow
    const result = await flowService.validateFlow(request);

    res.json(result);
  } catch (error) {
    console.error('Failed to validate flow:', error);
    res.status(500).json({
      error: 'flow_validation_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/flows/templates - List available flow templates
 */
router.get('/flows/templates', async (req: Request, res: Response) => {
  try {
    // TODO: Implement flow templates in FlowService
    // const templates = await flowService.getFlowTemplates();

    const templates = [
      {
        id: 'login-template',
        name: 'Login Flow Template',
        description: 'Template for creating login flows',
        category: 'login',
        parameters: [
          {
            name: 'username',
            type: 'string',
            required: true,
            description: 'Username for login'
          },
          {
            name: 'password',
            type: 'string',
            required: true,
            description: 'Password for login'
          }
        ]
      }
    ];

    res.json({ templates });
  } catch (error) {
    console.error('Failed to list flow templates:', error);
    res.status(500).json({
      error: 'flow_templates_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/flows/library - Get flow library summary
 */
router.get('/flows/library', async (req: Request, res: Response) => {
  try {
    const { flows, total } = await flowService.listFlows({ pagination: { page: 1, limit: 1 } });

    const library = {
      version: '1.0.0',
      flows: [], // Would be populated with full flow list if needed
      templates: [], // Would be populated with template list if needed
      categories: [
        {
          name: 'login',
          description: 'Authentication and login flows',
          flowCount: flows.filter(f => f.metadata.tags?.includes('login')).length
        },
        {
          name: 'navigation',
          description: 'UI navigation flows',
          flowCount: flows.filter(f => f.metadata.tags?.includes('navigation')).length
        },
        {
          name: 'form',
          description: 'Form filling and submission flows',
          flowCount: flows.filter(f => f.metadata.tags?.includes('form')).length
        }
      ],
      stats: {
        totalFlows: total,
        totalTemplates: 0,
        totalExecutions: 0, // Would be calculated from execution logs
        averageFlowDuration: 0,
        successRate: 0
      },
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        packageName: 'fr.mayndrive.app',
        version: '1.0.0'
      }
    };

    res.json(library);
  } catch (error) {
    console.error('Failed to get flow library:', error);
    res.status(500).json({
      error: 'flow_library_failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

export default router;