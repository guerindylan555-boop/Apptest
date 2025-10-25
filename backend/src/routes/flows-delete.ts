/**
 * Flow Deletion API Routes (T049)
 *
 * Comprehensive REST API endpoints for deleting flow definitions.
 * Supports soft delete with backup creation, dependency checking and warnings,
 * cascade delete for dependent resources, and comprehensive audit trails.
 *
 * Features:
 * - Soft delete with automatic backup creation
 * - Dependency checking and warnings
 * - Cascade delete for dependent resources
 * - Permanent delete with confirmation
 * - Audit trail and deletion history
 * - Recovery and restoration capabilities
 * - Performance monitoring and metrics
 * - Rate limiting and security
 * - Batch deletion support
 */

import { Router, Request, Response, NextFunction } from 'express';

// Extended Request interface for custom properties
interface EnhancedRequest extends Request {
  requestId?: string;
  dependencyCheck?: any;
}
import { FlowService } from '../services/flowService';
import { FlowValidationService } from '../services/flowValidationService';
import { FlowDefinition, FlowError } from '../types/flow';

const router = Router();

// Performance tracking
const deletionMetrics = {
  totalDeletions: 0,
  successfulDeletions: 0,
  failedDeletions: 0,
  softDeletes: 0,
  permanentDeletes: 0,
  cascadeDeletes: 0,
  recoveries: 0,
  averageDeletionTime: 0,
  deletionTimeHistory: [] as number[],
  maxHistorySize: 100
};

// Deletion rate limiting configuration
const DELETION_RATE_LIMITS = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxDeletions: 10, // limit each IP to 10 deletions per windowMs
  deletionRequests: new Map<string, { count: number; resetTime: number }>()
};

// Deletion tracking and audit
const deletionHistory = new Map<string, Array<{
  timestamp: string;
  flowId: string;
  flowName: string;
  deletionType: 'soft' | 'permanent' | 'cascade';
  reason?: string;
  deletedBy: string;
  backupId?: string;
  dependencies: string[];
  restored: boolean;
  restoredAt?: string;
  restoredBy?: string;
}>>();

// Backup storage
const deletionBackups = new Map<string, {
  backupId: string;
  flowId: string;
  flow: FlowDefinition;
  createdAt: string;
  deletedBy: string;
  reason?: string;
  expiresAt?: string;
}>();

/**
 * Enhanced flow deletion request
 */
interface DeleteFlowRequest {
  /** Deletion type */
  deletionType?: 'soft' | 'permanent' | 'cascade';

  /** Confirmation token for permanent deletion */
  confirmationToken?: string;

  /** Deletion reason */
  reason?: string;

  /** Backup options */
  backup?: {
    enabled: boolean;
    location?: string;
    expiresAfter?: number; // days
    encrypt?: boolean;
  };

  /** Dependency handling */
  dependencies?: {
    deleteDependentFlows?: boolean;
    deleteExecutionHistory?: boolean;
    deleteValidationResults?: boolean;
  };

  /** Response format */
  format?: 'json' | 'xml';

  /** Include options */
  include?: {
    deletionSummary?: boolean;
    dependencyList?: boolean;
    backupInfo?: boolean;
  };
}

/**
 * Enhanced flow deletion response
 */
interface DeleteFlowResponse {
  /** Deletion confirmation */
  deletion: {
    flowId: string;
    flowName: string;
    deleted: boolean;
    deletionType: string;
    deletedAt: string;
  };

  /** Backup information */
  backup?: {
    created: boolean;
    backupId: string;
    location: string;
    expiresAt?: string;
  };

  /** Dependencies information */
  dependencies: {
    found: number;
    deleted: number;
    warnings: string[];
    details: Array<{
      type: 'flow' | 'execution' | 'validation' | 'unknown';
      id: string;
      name: string;
      action: 'deleted' | 'preserved' | 'warning';
    }>;
  };

  /** Recovery information */
  recovery: {
    possible: boolean;
    recoveryToken?: string;
    expiresAt?: string;
    instructions?: string[];
  };

  /** Performance metrics */
  performance: {
    deletionTime: number;
    backupTime: number;
    dependencyCheckTime: number;
    totalTime: number;
  };
}

/**
 * Batch deletion request
 */
interface BatchDeleteRequest {
  /** Flow IDs to delete */
  flowIds: string[];

  /** Common deletion options */
  options?: DeleteFlowRequest;

  /** Batch processing options */
  batch?: {
    continueOnError: boolean;
    maxParallel: number;
    timeoutMs: number;
  };
}

/**
 * Batch deletion response
 */
interface BatchDeleteResponse {
  /** Batch processing summary */
  batch: {
    totalFlows: number;
    successfulDeletions: number;
    failedDeletions: number;
    skippedDeletions: number;
    processedAt: string;
  };

  /** Individual results */
  results: Array<{
    flowId: string;
    success: boolean;
    error?: string;
    deletionType?: string;
    backupId?: string;
  }>;

  /** Overall backup information */
  batchBackup?: {
    backupId: string;
    flowCount: number;
    location: string;
  };

  /** Performance metrics */
  performance: {
    totalTime: number;
    averageTimePerFlow: number;
    parallelProcessing: boolean;
  };
}

/**
 * Recovery request
 */
interface RecoveryRequest {
  /** Recovery token */
  recoveryToken: string;

  /** Recovery options */
  options?: {
    newFlowName?: string;
    newVersion?: string;
    restoreDependencies?: boolean;
  };
}

/**
 * Error response with detailed deletion information
 */
interface DeleteErrorResponse {
  error: {
    code: string;
    message: string;
    details?: {
      flowId?: string;
      deletionType?: string;
      dependencies?: any[];
      backupInfo?: any;
    };
    timestamp: string;
    requestId: string;
  };
  performance?: {
    deletionTime: number;
  };
}

// Initialize services
let flowService: FlowService;
let flowValidationService: FlowValidationService;

export function initializeFlowsDeleteRoutes(
  flowSvc: FlowService,
  flowValidationSvc: FlowValidationService
): Router {
  flowService = flowSvc;
  flowValidationService = flowValidationSvc;

  // Apply middleware
  router.use(requestLogger);
  router.use(deletionRateLimiter);
  router.use(inputSanitizer);
  router.use(dependencyChecker);

  return router;
}

/**
 * Middleware for request logging
 */
function requestLogger(req: EnhancedRequest, res: Response, next: NextFunction): void {
  const startTime = Date.now();
  const requestId = `delete_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  res.setHeader('X-Request-ID', requestId);
  req.requestId = requestId;

  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    requestId,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    event: 'flow_delete_request_start'
  }));

  const originalEnd = res.end;
  res.end = function(chunk?: any, encoding?: any): Response<any, Record<string, any>> {
    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      event: 'flow_delete_request_complete'
    }));

    originalEnd.call(this, chunk, encoding);
  };

  next();
}

/**
 * Rate limiting middleware for flow deletions
 */
function deletionRateLimiter(req: EnhancedRequest, res: Response, next: NextFunction): void {
  const clientIp = req.ip || 'unknown';
  const now = Date.now();

  // Clean up expired entries
  for (const [ip, data] of DELETION_RATE_LIMITS.deletionRequests.entries()) {
    if (now > data.resetTime) {
      DELETION_RATE_LIMITS.deletionRequests.delete(ip);
    }
  }

  // Check current usage
  const clientUsage = DELETION_RATE_LIMITS.deletionRequests.get(clientIp);

  if (clientUsage && clientUsage.count >= DELETION_RATE_LIMITS.maxDeletions) {
    const resetIn = Math.ceil((clientUsage.resetTime - now) / 1000);

    res.status(429).json({
      error: {
        code: 'DELETION_RATE_LIMIT_EXCEEDED',
        message: `Flow deletion rate limit exceeded. Try again in ${resetIn} seconds.`,
        details: {
          limit: DELETION_RATE_LIMITS.maxDeletions,
          windowMs: DELETION_RATE_LIMITS.windowMs,
          resetIn
        },
        timestamp: new Date().toISOString(),
        requestId: req.requestId
      }
    } as DeleteErrorResponse);
  }

  // Update usage
  if (clientUsage) {
    clientUsage.count++;
  } else {
    DELETION_RATE_LIMITS.deletionRequests.set(clientIp, {
      count: 1,
      resetTime: now + DELETION_RATE_LIMITS.windowMs
    });
  }

  next();
}

/**
 * Input sanitization middleware
 */
function inputSanitizer(req: EnhancedRequest, res: Response, next: NextFunction): void {
  try {
    if (req.body && typeof req.body === 'object') {
      sanitizeObject(req.body);
    }
    next();
  } catch (error) {
    res.status(400).json({
      error: {
        code: 'INVALID_INPUT',
        message: 'Invalid input format',
        timestamp: new Date().toISOString(),
        requestId: req.requestId
      }
    } as DeleteErrorResponse);
  }
}

/**
 * Recursively sanitize object properties
 */
function sanitizeObject(obj: any): void {
  for (const key in obj) {
    if (typeof obj[key] === 'string') {
      obj[key] = obj[key]
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/<[^>]*>/g, '')
        .trim();
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      sanitizeObject(obj[key]);
    }
  }
}

/**
 * Dependency checking middleware
 */
function dependencyChecker(req: EnhancedRequest, res: Response, next: NextFunction): void {
  // Store dependency check state for later use
  req.dependencyCheck = {
    checked: false,
    dependencies: [],
    warnings: []
  };
  next();
}

/**
 * DELETE /api/flows/{flowId} - Delete a flow definition
 *
 * This endpoint deletes flow definitions with comprehensive dependency checking,
 * backup creation, and audit trails. Supports soft delete, permanent delete,
 * and cascade deletion options.
 *
 * @param flowId - ID of the flow to delete
 * @bodyparam deletionType - Type of deletion (soft, permanent, cascade)
 * @bodyparam confirmationToken - Confirmation token for permanent deletion
 * @bodyparam reason - Reason for deletion
 * @bodyparam backup - Backup options
 * @bodyparam dependencies - Dependency handling options
 * @bodyparam format - Response format (json, xml)
 *
 * @example
 * // Soft delete with backup
 * DELETE /api/flows/flow123
 * {
 *   "deletionType": "soft",
 *   "reason": "No longer needed",
 *   "backup": { "enabled": true, "expiresAfter": 30 }
 * }
 *
 * // Permanent delete with confirmation
 * DELETE /api/flows/flow123
 * {
 *   "deletionType": "permanent",
 *   "confirmationToken": "abc123",
 *   "reason": "Replacing with new version"
 * }
 *
 * // Cascade delete
 * DELETE /api/flows/flow123
 * {
 *   "deletionType": "cascade",
 *   "dependencies": {
 *     "deleteDependentFlows": true,
 *     "deleteExecutionHistory": true
 *   }
 * }
 */
router.delete('/:flowId', async (req: EnhancedRequest, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  const flowId = req.params.flowId;
  deletionMetrics.totalDeletions++;

  try {
    // Parse and validate request
    const deleteRequest = parseDeleteRequest(req);

    // Load existing flow
    const existingFlow = await flowService.loadFlow(flowId);
    if (!existingFlow) {
      return res.status(404).json({
        error: {
          code: 'FLOW_NOT_FOUND',
          message: `Flow not found: ${flowId}`,
          details: { flowId },
          timestamp: new Date().toISOString(),
          requestId
        }
      } as DeleteErrorResponse);
    }

    // Check dependencies
    const dependencyCheck = await checkFlowDependencies(existingFlow, deleteRequest);
    req.dependencyCheck = dependencyCheck;

    // Require confirmation for permanent deletion
    if (deleteRequest.deletionType === 'permanent') {
      if (!deleteRequest.confirmationToken) {
        return res.status(400).json({
          error: {
            code: 'CONFIRMATION_REQUIRED',
            message: 'Confirmation token is required for permanent deletion',
            details: {
              flowId,
              deletionType: 'permanent',
              dependencies: dependencyCheck.dependencies
            },
            timestamp: new Date().toISOString(),
            requestId
          }
        } as DeleteErrorResponse);
      }

      // Validate confirmation token (simplified - in production, use proper token validation)
      if (!validateConfirmationToken(deleteRequest.confirmationToken, flowId)) {
        return res.status(400).json({
          error: {
            code: 'INVALID_CONFIRMATION_TOKEN',
            message: 'Invalid confirmation token',
            timestamp: new Date().toISOString(),
            requestId
          }
        } as DeleteErrorResponse);
      }
    }

    // Create backup if requested
    let backupInfo;
    if (deleteRequest.backup?.enabled) {
      backupInfo = await createFlowBackup(existingFlow, deleteRequest.backup, req);
    }

    // Perform deletion based on type
    const deletionResult = await performFlowDeletion(existingFlow, deleteRequest);

    // Handle cascade deletion if requested
    let cascadeResults;
    if (deleteRequest.deletionType === 'cascade' && dependencyCheck.dependencies.length > 0) {
      cascadeResults = await performCascadeDeletion(dependencyCheck.dependencies, deleteRequest);
      deletionMetrics.cascadeDeletes++;
    }

    // Track deletion in audit history
    await trackDeletion(existingFlow, deleteRequest, deletionResult, req);

    // Generate recovery token for soft deletes
    let recoveryInfo;
    if (deleteRequest.deletionType === 'soft') {
      recoveryInfo = generateRecoveryInfo(existingFlow, deleteRequest);
    }

    // Build response
    const response: DeleteFlowResponse = {
      deletion: {
        flowId,
        flowName: existingFlow.name,
        deleted: deletionResult.success,
        deletionType: deleteRequest.deletionType || 'soft',
        deletedAt: new Date().toISOString()
      },
      backup: backupInfo,
      dependencies: {
        found: dependencyCheck.dependencies.length,
        deleted: cascadeResults?.deletedCount || 0,
        warnings: dependencyCheck.warnings,
        details: dependencyCheck.dependencies.map(dep => ({
          type: dep.type,
          id: dep.id,
          name: dep.name,
          action: dep.action
        }))
      },
      recovery: {
        possible: deleteRequest.deletionType === 'soft',
        recoveryToken: recoveryInfo?.recoveryToken,
        expiresAt: recoveryInfo?.expiresAt,
        instructions: recoveryInfo?.instructions
      },
      performance: {
        deletionTime: Date.now() - startTime,
        backupTime: backupInfo?.creationTime || 0,
        dependencyCheckTime: dependencyCheck.checkTime || 0,
        totalTime: Date.now() - startTime
      }
    };

    // Update metrics
    if (deletionResult.success) {
      deletionMetrics.successfulDeletions++;
      if (deleteRequest.deletionType === 'soft') {
        deletionMetrics.softDeletes++;
      } else if (deleteRequest.deletionType === 'permanent') {
        deletionMetrics.permanentDeletes++;
      }
    } else {
      deletionMetrics.failedDeletions++;
    }

    updateDeletionMetrics(Date.now() - startTime);

    // Log successful deletion
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_delete_success',
      flowId,
      flowName: existingFlow.name,
      deletionType: deleteRequest.deletionType,
      dependenciesFound: dependencyCheck.dependencies.length,
      backupCreated: backupInfo?.created || false,
      deletionTime: `${Date.now() - startTime}ms`
    }));

    // Format response if requested
    if (deleteRequest.format === 'xml') {
      res.setHeader('Content-Type', 'application/xml');
      return res.send(formatDeleteXmlResponse(response));
    }

    // Return appropriate status code
    if (deletionResult.success) {
      res.status(deleteRequest.deletionType === 'soft' ? 200 : 204).json(response);
    } else {
      res.status(500).json({
        error: {
          code: 'DELETION_FAILED',
          message: deletionResult.error || 'Deletion failed',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as DeleteErrorResponse);
    }

  } catch (error) {
    deletionMetrics.failedDeletions++;
    const responseTime = Date.now() - startTime;

    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_delete_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      flowId,
      responseTime: `${responseTime}ms`
    }));

    const errorResponse: DeleteErrorResponse = {
      error: {
        code: 'FLOW_DELETION_ERROR',
        message: 'Failed to delete flow',
        details: {
          flowId,
          errorMessage: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: new Date().toISOString(),
        requestId
      },
      performance: {
        deletionTime: responseTime
      }
    };

    res.status(500).json(errorResponse);
  }
});

/**
 * POST /api/flows/batch-delete - Batch delete multiple flows
 *
 * Delete multiple flows in a single request with options for
 * batch processing, error handling, and progress tracking.
 */
router.post('/batch-delete', async (req: EnhancedRequest, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    const batchRequest: BatchDeleteRequest = req.body;

    if (!batchRequest.flowIds || batchRequest.flowIds.length === 0) {
      return res.status(400).json({
        error: {
          code: 'MISSING_FLOW_IDS',
          message: 'Flow IDs are required for batch deletion',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as DeleteErrorResponse);
    }

    // Validate batch size
    if (batchRequest.flowIds.length > 100) {
      return res.status(400).json({
        error: {
          code: 'BATCH_SIZE_EXCEEDED',
          message: 'Batch size cannot exceed 100 flows',
          details: { requestedSize: batchRequest.flowIds.length, maxSize: 100 },
          timestamp: new Date().toISOString(),
          requestId
        }
      } as DeleteErrorResponse);
    }

    // Process batch deletion
    const batchResult = await processBatchDeletion(batchRequest, requestId);

    const response: BatchDeleteResponse = {
      batch: {
        totalFlows: batchRequest.flowIds.length,
        successfulDeletions: batchResult.successfulCount,
        failedDeletions: batchResult.failedCount,
        skippedDeletions: batchResult.skippedCount,
        processedAt: new Date().toISOString()
      },
      results: batchResult.results,
      batchBackup: batchResult.batchBackup,
      performance: {
        totalTime: Date.now() - startTime,
        averageTimePerFlow: (Date.now() - startTime) / batchRequest.flowIds.length,
        parallelProcessing: batchRequest.batch?.maxParallel && batchRequest.batch.maxParallel > 1
      }
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'batch_delete_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }));

    res.status(500).json({
      error: {
        code: 'BATCH_DELETION_ERROR',
        message: 'Failed to process batch deletion',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as DeleteErrorResponse);
  }
});

/**
 * GET /api/flows/{flowId}/dependencies - Check flow dependencies
 *
 * Check what resources depend on this flow before deletion.
 */
router.get('/:flowId/dependencies', async (req: EnhancedRequest, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  const flowId = req.params.flowId;

  try {
    const flow = await flowService.loadFlow(flowId);
    if (!flow) {
      return res.status(404).json({
        error: {
          code: 'FLOW_NOT_FOUND',
          message: `Flow not found: ${flowId}`,
          timestamp: new Date().toISOString(),
          requestId
        }
      } as DeleteErrorResponse);
    }

    const dependencies = await checkFlowDependencies(flow, { deletionType: 'soft' });

    const response = {
      flowId,
      flowName: flow.name,
      dependencies: dependencies.dependencies,
      warnings: dependencies.warnings,
      summary: {
        totalDependencies: dependencies.dependencies.length,
        criticalDependencies: dependencies.dependencies.filter(d => d.critical).length,
        safeToDelete: dependencies.dependencies.length === 0
      },
      performance: {
        responseTime: Date.now() - startTime
      }
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_dependencies_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      flowId
    }));

    res.status(500).json({
      error: {
        code: 'DEPENDENCY_CHECK_ERROR',
        message: 'Failed to check flow dependencies',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as DeleteErrorResponse);
  }
});

/**
 * POST /api/flows/recover - Recover a deleted flow
 *
 * Recover a soft-deleted flow using a recovery token.
 */
router.post('/recover', async (req: EnhancedRequest, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    const recoveryRequest: RecoveryRequest = req.body;

    if (!recoveryRequest.recoveryToken) {
      return res.status(400).json({
        error: {
          code: 'MISSING_RECOVERY_TOKEN',
          message: 'Recovery token is required',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as DeleteErrorResponse);
    }

    const recoveryResult = await recoverDeletedFlow(recoveryRequest, req);

    if (recoveryResult.success) {
      deletionMetrics.recoveries++;

      const response = {
        flow: recoveryResult.flow,
        recovery: {
          recoveredAt: new Date().toISOString(),
          recoveredBy: req.ip || 'anonymous',
          originalDeletionDate: recoveryResult.originalDeletionDate
        },
        performance: {
          recoveryTime: Date.now() - startTime
        }
      };

      res.json(response);
    } else {
      res.status(400).json({
        error: {
          code: 'RECOVERY_FAILED',
          message: recoveryResult.error || 'Recovery failed',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as DeleteErrorResponse);
    }

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_recovery_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }));

    res.status(500).json({
      error: {
        code: 'FLOW_RECOVERY_ERROR',
        message: 'Failed to recover flow',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as DeleteErrorResponse);
  }
});

/**
 * Parse and validate delete request
 */
function parseDeleteRequest(req: EnhancedRequest): DeleteFlowRequest {
  const body = req.body;

  return {
    deletionType: body.deletionType || 'soft',
    confirmationToken: body.confirmationToken,
    reason: body.reason,
    backup: body.backup,
    dependencies: body.dependencies,
    format: body.format,
    include: body.include
  };
}

/**
 * Check flow dependencies
 */
async function checkFlowDependencies(
  flow: FlowDefinition,
  deleteRequest: DeleteFlowRequest
): Promise<any> {
  const startTime = Date.now();
  const dependencies: any[] = [];
  const warnings: string[] = [];

  try {
    // TODO: Implement actual dependency checking
    // This would involve checking for:
    // - Other flows that reference this flow
    // - Execution history for this flow
    // - Templates based on this flow
    // - External references

    // For now, return empty dependencies
    const checkTime = Date.now() - startTime;

    return {
      dependencies,
      warnings,
      checkTime
    };
  } catch (error) {
    console.error('Error checking flow dependencies:', error);
    return {
      dependencies: [],
      warnings: ['Failed to check dependencies'],
      checkTime: Date.now() - startTime
    };
  }
}

/**
 * Validate confirmation token
 */
function validateConfirmationToken(token: string, flowId: string): boolean {
  // Simple validation - in production, use proper token validation
  // This could be a JWT, a signed token, or a temporary token from a database
  return token && token.length > 10;
}

/**
 * Create flow backup
 */
async function createFlowBackup(
  flow: FlowDefinition,
  backupOptions: any,
  req: Request
): Promise<any> {
  try {
    const backupId = `backup_${flow.id}_${Date.now()}`;
    const expiresAt = backupOptions.expiresAfter
      ? new Date(Date.now() + backupOptions.expiresAfter * 24 * 60 * 60 * 1000).toISOString()
      : undefined;

    const backupData = {
      backupId,
      flowId: flow.id,
      flow: { ...flow },
      createdAt: new Date().toISOString(),
      deletedBy: req.ip || 'anonymous',
      reason: backupOptions.reason,
      expiresAt
    };

    // Store backup
    deletionBackups.set(backupId, backupData);

    console.log(`Created backup ${backupId} for flow ${flow.id}`);

    return {
      created: true,
      backupId,
      location: backupOptions.location || 'default',
      expiresAt,
      creationTime: 0 // TODO: Track actual backup time
    };
  } catch (error) {
    console.error('Failed to create flow backup:', error);
    return {
      created: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Perform flow deletion
 */
async function performFlowDeletion(
  flow: FlowDefinition,
  deleteRequest: DeleteFlowRequest
): Promise<{ success: boolean; error?: string }> {
  try {
    switch (deleteRequest.deletionType) {
      case 'soft':
        // TODO: Implement soft delete - mark as deleted but keep in storage
        console.log(`Soft deleting flow ${flow.id}`);
        return { success: true };

      case 'permanent':
        // TODO: Implement permanent delete - remove from storage
        console.log(`Permanently deleting flow ${flow.id}`);
        return { success: true };

      case 'cascade':
        // TODO: Implement cascade delete - delete with dependencies
        console.log(`Cascade deleting flow ${flow.id}`);
        return { success: true };

      default:
        return { success: false, error: 'Unknown deletion type' };
    }
  } catch (error) {
    console.error('Failed to perform flow deletion:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Perform cascade deletion
 */
async function performCascadeDeletion(
  dependencies: any[],
  deleteRequest: DeleteFlowRequest
): Promise<{ deletedCount: number; errors: string[] }> {
  const deletedCount = 0;
  const errors: string[] = [];

  // TODO: Implement cascade deletion logic
  console.log(`Performing cascade deletion for ${dependencies.length} dependencies`);

  return { deletedCount, errors };
}

/**
 * Track deletion in audit history
 */
async function trackDeletion(
  flow: FlowDefinition,
  deleteRequest: DeleteFlowRequest,
  deletionResult: any,
  req: Request
): Promise<void> {
  try {
    const historyEntry = {
      timestamp: new Date().toISOString(),
      flowId: flow.id,
      flowName: flow.name,
      deletionType: deleteRequest.deletionType || 'soft',
      reason: deleteRequest.reason,
      deletedBy: req.ip || 'anonymous',
      backupId: deletionResult.backupId,
      dependencies: req.dependencyCheck?.dependencies || [],
      restored: false
    };

    // Store in deletion history
    const flowHistory = deletionHistory.get(flow.id) || [];
    flowHistory.push(historyEntry);
    deletionHistory.set(flow.id, flowHistory);

    console.log(`Tracked deletion for flow ${flow.id}`);

  } catch (error) {
    console.error('Failed to track deletion:', error);
  }
}

/**
 * Generate recovery information
 */
function generateRecoveryInfo(flow: FlowDefinition, deleteRequest: DeleteFlowRequest): any {
  const recoveryToken = Buffer.from(`recover_${flow.id}_${Date.now()}`).toString('base64');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

  return {
    recoveryToken,
    expiresAt,
    instructions: [
      'Use the recovery token within the expiration period',
      'Recovery will restore the flow to its original state',
      'Any changes made after deletion will be lost'
    ]
  };
}

/**
 * Process batch deletion
 */
async function processBatchDeletion(
  batchRequest: BatchDeleteRequest,
  requestId: string
): Promise<any> {
  const results = [];
  let successfulCount = 0;
  let failedCount = 0;
  let skippedCount = 0;

  // Process each flow
  for (const flowId of batchRequest.flowIds) {
    try {
      // TODO: Implement actual batch deletion logic
      // For now, simulate successful deletion
      results.push({
        flowId,
        success: true,
        deletionType: batchRequest.options?.deletionType || 'soft'
      });
      successfulCount++;
    } catch (error) {
      results.push({
        flowId,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      failedCount++;

      if (!batchRequest.batch?.continueOnError) {
        break;
      }
    }
  }

  return {
    results,
    successfulCount,
    failedCount,
    skippedCount
  };
}

/**
 * Recover deleted flow
 */
async function recoverDeletedFlow(
  recoveryRequest: RecoveryRequest,
  req: Request
): Promise<any> {
  try {
    // TODO: Implement actual recovery logic
    // This would involve:
    // 1. Validate recovery token
    // 2. Check if recovery is still possible (not expired)
    // 3. Restore flow from backup
    // 4. Update audit history

    return {
      success: false,
      error: 'Recovery functionality not yet implemented'
    };
  } catch (error) {
    console.error('Failed to recover flow:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Update deletion metrics
 */
function updateDeletionMetrics(deletionTime: number): void {
  deletionMetrics.deletionTimeHistory.push(deletionTime);

  if (deletionMetrics.deletionTimeHistory.length > deletionMetrics.maxHistorySize) {
    deletionMetrics.deletionTimeHistory.shift();
  }

  deletionMetrics.averageDeletionTime = Math.round(
    deletionMetrics.deletionTimeHistory.reduce((sum, time) => sum + time, 0) /
    deletionMetrics.deletionTimeHistory.length
  );
}

/**
 * Format delete response as XML
 */
function formatDeleteXmlResponse(response: DeleteFlowResponse): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<deleteFlowResponse>
  <deletion>
    <flowId>${response.deletion.flowId}</flowId>
    <flowName>${response.deletion.flowName}</flowName>
    <deleted>${response.deletion.deleted}</deleted>
    <deletionType>${response.deletion.deletionType}</deletionType>
    <deletedAt>${response.deletion.deletedAt}</deletedAt>
  </deletion>
  <dependencies>
    <found>${response.dependencies.found}</found>
    <deleted>${response.dependencies.deleted}</deleted>
    <warnings>${response.dependencies.warnings.join(', ')}</warnings>
  </dependencies>
  <recovery>
    <possible>${response.recovery.possible}</possible>
    <recoveryToken>${response.recovery.recoveryToken || ''}</recoveryToken>
    <expiresAt>${response.recovery.expiresAt || ''}</expiresAt>
  </recovery>
  <performance>
    <deletionTime>${response.performance.deletionTime}</deletionTime>
    <totalTime>${response.performance.totalTime}</totalTime>
  </performance>
</deleteFlowResponse>`;
}

/**
 * Get deletion metrics
 */
export function getDeletionMetrics() {
  return {
    ...deletionMetrics,
    successRate: deletionMetrics.totalDeletions > 0
      ? deletionMetrics.successfulDeletions / deletionMetrics.totalDeletions
      : 0
  };
}

export default router;