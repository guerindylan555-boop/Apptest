/**
 * Graph Management Routes
 *
 * API endpoints for UI state discovery, graph management,
 * and transition recording.
 */

import { Router, Request, Response } from 'express';
import { introspectionService } from '../services/introspectService';
import { graphService } from '../services/graphService';
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

const router = Router();

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

export default router;