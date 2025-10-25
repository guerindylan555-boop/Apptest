/**
 * Flow API Routes
 *
 * Provides REST endpoints for managing and executing flows
 * including creation, validation, and runtime control.
 */

import express from 'express';
import { FlowRepository } from '../services/flows/flowRepository';
import { FlowRunner } from '../services/flows/flowRunner';
import { StateDetectorService } from '../services/state-detector/stateDetectorService';
import { GraphStore } from '../services/ui-graph/graphStore';
import { logger } from '../utils/logger';

const router = express.Router();

// Initialize services
const graphStore = new GraphStore();
const detector = new StateDetectorService(graphStore);
const flowRunner = new FlowRunner(detector, graphStore);
const flowRepository = new FlowRepository();

// Initialize flow repository
flowRepository.initialize().catch(error => {
  logger.error(`Failed to initialize flow repository: ${error}`);
});

/**
 * GET /flows
 * List all available flows
 */
router.get('/flows', async (req, res) => {
  try {
    const flows = await flowRepository.listFlows();

    res.json({
      success: true,
      data: flows,
    });
  } catch (error) {
    logger.error(`Failed to list flows: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to list flows',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /flows/:name
 * Get a specific flow by name
 */
router.get('/flows/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const flow = await flowRepository.loadFlow(name);

    if (!flow) {
      return res.status(404).json({
        error: 'Flow not found',
        message: `No flow found with name: ${name}`,
      });
    }

    res.json({
      success: true,
      data: flow,
    });
  } catch (error) {
    logger.error(`Failed to get flow: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to get flow',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * POST /flows
 * Create or update a flow
 */
router.post('/flows', async (req, res) => {
  try {
    const flow = req.body;

    // Basic validation
    if (!flow.name || !flow.description || !flow.version) {
      return res.status(400).json({
        error: 'Invalid flow data',
        message: 'Flow must include name, description, and version',
      });
    }

    // Validate flow structure
    const validation = flowRepository.validateFlow(flow);
    if (validation.errors.length > 0) {
      return res.status(400).json({
        error: 'Flow validation failed',
        message: 'Flow contains validation errors',
        details: validation.errors,
      });
    }

    // Update metadata
    flow.metadata = {
      ...flow.metadata,
      lastUpdatedAt: new Date().toISOString(),
      validationStatus: validation.errors.length === 0 ? 'validated' : 'draft',
    };

    await flowRepository.saveFlow(flow);

    res.json({
      success: true,
      data: flow,
      warnings: validation.warnings,
    });

    logger.info(`Flow created/updated: ${flow.name} v${flow.version}`);
  } catch (error) {
    logger.error(`Failed to save flow: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to save flow',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * PUT /flows/:name
 * Update an existing flow
 */
router.put('/flows/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const flow = req.body;

    // Ensure flow name matches URL parameter
    if (flow.name !== name) {
      return res.status(400).json({
        error: 'Flow name mismatch',
        message: 'Flow name in body must match name in URL',
      });
    }

    // Check if flow exists
    const existingFlow = await flowRepository.loadFlow(name);
    if (!existingFlow) {
      return res.status(404).json({
        error: 'Flow not found',
        message: `No flow found with name: ${name}`,
      });
    }

    // Validate flow structure
    const validation = flowRepository.validateFlow(flow);
    if (validation.errors.length > 0) {
      return res.status(400).json({
        error: 'Flow validation failed',
        message: 'Flow contains validation errors',
        details: validation.errors,
      });
    }

    // Update metadata
    flow.metadata = {
      ...flow.metadata,
      lastUpdatedAt: new Date().toISOString(),
      validationStatus: validation.errors.length === 0 ? 'validated' : 'draft',
    };

    await flowRepository.saveFlow(flow);

    res.json({
      success: true,
      data: flow,
      warnings: validation.warnings,
    });

    logger.info(`Flow updated: ${flow.name} v${flow.version}`);
  } catch (error) {
    logger.error(`Failed to update flow: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to update flow',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * DELETE /flows/:name
 * Delete a flow
 */
router.delete('/flows/:name', async (req, res) => {
  try {
    const { name } = req.params;

    await flowRepository.deleteFlow(name);

    res.json({
      success: true,
      message: `Flow ${name} deleted successfully`,
    });

    logger.info(`Flow deleted: ${name}`);
  } catch (error) {
    if (error instanceof Error && error.message.includes('not found')) {
      return res.status(404).json({
        error: 'Flow not found',
        message: error.message,
      });
    }

    logger.error(`Failed to delete flow: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to delete flow',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * POST /flows/:name/validate
 * Validate a flow without saving it
 */
router.post('/flows/:name/validate', async (req, res) => {
  try {
    const { name } = req.params;
    const flow = req.body;

    // Ensure flow name matches URL parameter
    if (flow.name !== name) {
      return res.status(400).json({
        error: 'Flow name mismatch',
        message: 'Flow name in body must match name in URL',
      });
    }

    // Validate flow structure
    const validation = flowRepository.validateFlow(flow);

    res.json({
      success: true,
      data: {
        valid: validation.errors.length === 0,
        errors: validation.errors,
        warnings: validation.warnings,
      },
    });
  } catch (error) {
    logger.error(`Failed to validate flow: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to validate flow',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * POST /flows/:name/run
 * Execute a flow
 */
router.post('/flows/:name/run', async (req, res) => {
  try {
    const { name } = req.params;
    const { variables, startNodeId } = req.body;

    // Load the flow
    const flow = await flowRepository.loadFlow(name);
    if (!flow) {
      return res.status(404).json({
        error: 'Flow not found',
        message: `No flow found with name: ${name}`,
      });
    }

    // Start flow execution (non-blocking)
    const executionPromise = flowRunner.executeFlow(flow, variables || {}, startNodeId);

    // Set up event listeners for this execution
    const executionId = `${name}-${Date.now()}`;

    flowRunner.once('flowComplete', ({ result }: any) => {
      logger.info(`Flow execution completed: ${result.flowName} - ${result.finalState}`);
    });

    flowRunner.once('flowError', ({ error, result }: any) => {
      logger.error(`Flow execution failed: ${result.flowName} - ${error}`);
    });

    // Return execution ID immediately (async execution)
    res.json({
      success: true,
      data: {
        executionId,
        flowName: name,
        status: 'started',
        startTime: new Date().toISOString(),
      },
    });

    // Execute flow in background
    executionPromise.catch(error => {
      logger.error(`Background flow execution failed: ${error instanceof Error ? error.message : String(error)}`);
    });

  } catch (error) {
    logger.error(`Failed to start flow execution: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to start flow execution',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /flows/:name/runs
 * List execution history for a flow
 */
router.get('/flows/:name/runs', async (req, res) => {
  try {
    const { name } = req.params;

    // This would typically query a database for execution history
    // For now, return a placeholder response
    res.json({
      success: true,
      data: {
        flowName: name,
        executions: [], // Would be populated from actual execution logs
      },
    });
  } catch (error) {
    logger.error(`Failed to get flow execution history: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to get execution history',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /flows/:name/runs/:executionId
 * Get details of a specific execution
 */
router.get('/flows/:name/runs/:executionId', async (req, res) => {
  try {
    const { name, executionId } = req.params;

    const execution = flowRunner.getActiveExecution(executionId);

    if (!execution) {
      return res.status(404).json({
        error: 'Execution not found',
        message: `No active execution found with ID: ${executionId}`,
      });
    }

    res.json({
      success: true,
      data: {
        executionId,
        flowName: name,
        startTime: execution.startTime,
        currentStep: execution.currentStep,
        currentNode: execution.currentNode?.id,
        variables: execution.variables,
        detectedStates: execution.detectedStates,
      },
    });
  } catch (error) {
    logger.error(`Failed to get execution details: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to get execution details',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * DELETE /flows/:name/runs/:executionId
 * Cancel an active execution
 */
router.delete('/flows/:name/runs/:executionId', async (req, res) => {
  try {
    const { executionId } = req.params;

    const cancelled = flowRunner.cancelExecution(executionId);

    if (!cancelled) {
      return res.status(404).json({
        error: 'Execution not found',
        message: `No active execution found with ID: ${executionId}`,
      });
    }

    res.json({
      success: true,
      message: `Execution ${executionId} cancelled successfully`,
    });

    logger.info(`Execution cancelled: ${executionId}`);
  } catch (error) {
    logger.error(`Failed to cancel execution: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to cancel execution',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * POST /flows/lint
 * Lint multiple flows at once
 */
router.post('/flows/lint', async (req, res) => {
  try {
    const { flowNames } = req.body;

    if (!flowNames || !Array.isArray(flowNames)) {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'flowNames array is required',
      });
    }

    const results = [];

    for (const name of flowNames) {
      try {
        const flow = await flowRepository.loadFlow(name);
        if (!flow) {
          results.push({
            name,
            found: false,
            valid: false,
            errors: ['Flow not found'],
          });
          continue;
        }

        const validation = flowRepository.validateFlow(flow);
        results.push({
          name,
          found: true,
          valid: validation.errors.length === 0,
          errors: validation.errors,
          warnings: validation.warnings,
        });
      } catch (error) {
        results.push({
          name,
          found: true,
          valid: false,
          errors: [error instanceof Error ? error.message : 'Unknown error'],
        });
      }
    }

    res.json({
      success: true,
      data: results,
    });
  } catch (error) {
    logger.error(`Failed to lint flows: ${error instanceof Error ? error.message : String(error)}`);
    res.status(500).json({
      error: 'Failed to lint flows',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

export default router;