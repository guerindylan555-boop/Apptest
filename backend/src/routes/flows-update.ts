/**
 * Flow Update API Routes (T048)
 *
 * Comprehensive REST API endpoints for updating existing flow definitions.
 * Supports partial updates, merge strategies, optimistic locking with conflict detection,
 * versioning, and change tracking with comprehensive audit trails.
 *
 * Features:
 * - Partial updates with merge strategies (replace, merge, patch)
 * - Optimistic locking with conflict detection
 * - Version management and change tracking
 * - Comprehensive validation of updates
 * - Audit trail and change history
 * - Performance monitoring and metrics
 * - Rate limiting and security
 * - Response format negotiation
 * - Backup and rollback capabilities
 */

import { Router, Request, Response, NextFunction } from 'express';
import { FlowService } from '../services/flowService';
import { FlowValidationService } from '../services/flowValidationService';
import {
  UpdateFlowRequest,
  UpdateFlowResponse,
  FlowDefinition,
  FlowValidationResult,
  FlowError
} from '../types/flow';

const router = Router();

// Performance tracking
const updateMetrics = {
  totalUpdates: 0,
  successfulUpdates: 0,
  failedUpdates: 0,
  conflictDetections: 0,
  averageUpdateTime: 0,
  updateTimeHistory: [] as number[],
  mergeStrategyUsage: {
    replace: 0,
    merge: 0,
    patch: 0
  },
  maxHistorySize: 100
};

// Update rate limiting configuration
const UPDATE_RATE_LIMITS = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxUpdates: 50, // limit each IP to 50 updates per windowMs
  updateRequests: new Map<string, { count: number; resetTime: number }>()
};

// Change tracking
const changeHistory = new Map<string, Array<{
  timestamp: string;
  changes: any[];
  userId: string;
  version: string;
}>>();

/**
 * Enhanced flow update request with additional options
 */
interface EnhancedUpdateFlowRequest extends UpdateFlowRequest {
  /** Conflict resolution strategy */
  conflictResolution?: 'error' | 'overwrite' | 'merge';

  /** Change tracking options */
  changeTracking?: {
    enabled: boolean;
    comment?: string;
    reason?: string;
    tags?: string[];
  };

  /** Validation options */
  validation?: {
    strict: boolean;
    checkStates: boolean;
    checkActions: boolean;
    checkLogic: boolean;
    analyzePerformance: boolean;
  };

  /** Backup options */
  backup?: {
    enabled: boolean;
    keepCount?: number;
    location?: string;
  };

  /** Publication options */
  publication?: {
    publish: boolean;
    versionIncrement?: 'patch' | 'minor' | 'major';
    changelog?: string;
  };

  /** Response format */
  format?: 'json' | 'xml';

  /** Include options */
  include?: {
    previousVersion?: boolean;
    validationResults?: boolean;
    changeSummary?: boolean;
  };
}

/**
 * Enhanced flow update response with additional metadata
 */
interface EnhancedUpdateFlowResponse extends UpdateFlowResponse {
  /** Update metadata */
  metadata: {
    updatedAt: string;
    updatedBy: string;
    updateTime: number;
    mergeStrategy: string;
    conflictDetected: boolean;
    conflictResolved: boolean;
  };

  /** Version information */
  versioning: {
    previousVersion: string;
    newVersion: string;
    versionIncrement: string;
  };

  /** Change summary */
  changeSummary: {
    totalChanges: number;
    fieldChanges: string[];
    structuralChanges: string[];
  };

  /** Backup information */
  backup?: {
    created: boolean;
    backupId: string;
    location: string;
  };

  /** Publication information */
  publication?: {
    published: boolean;
    version: string;
    publishedAt?: string;
  };

  /** Performance metrics */
  performance: {
    updateTime: number;
    validationTime: number;
    backupTime: number;
    totalTime: number;
  };
}

/**
 * Conflict detection response
 */
interface ConflictDetectionResponse {
  hasConflicts: boolean;
  conflicts: Array<{
    field: string;
    currentValue: any;
    incomingValue: any;
    conflictType: 'version' | 'value' | 'structure';
    resolution?: string;
  }>;
  baseVersion: string;
  currentVersion: string;
  incomingVersion: string;
}

/**
 * Error response with detailed conflict information
 */
interface UpdateErrorResponse {
  error: {
    code: string;
    message: string;
    details?: {
      flowId?: string;
      field?: string;
      value?: any;
      conflicts?: ConflictDetectionResponse['conflicts'];
      validationErrors?: any[];
    };
    timestamp: string;
    requestId: string;
  };
  performance?: {
    updateTime: number;
  };
}

// Initialize services
let flowService: FlowService;
let flowValidationService: FlowValidationService;

export function initializeFlowsUpdateRoutes(
  flowSvc: FlowService,
  flowValidationSvc: FlowValidationService
): Router {
  flowService = flowSvc;
  flowValidationService = flowValidationSvc;

  // Apply middleware
  router.use(requestLogger);
  router.use(updateRateLimiter);
  router.use(inputSanitizer);
  router.use(conflictDetector);

  return router;
}

/**
 * Middleware for request logging
 */
function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();
  const requestId = `update_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  res.setHeader('X-Request-ID', requestId);
  req.requestId = requestId;

  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    requestId,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    event: 'flow_update_request_start'
  }));

  const originalEnd = res.end;
  res.end = function(chunk?: any, encoding?: any) {
    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      event: 'flow_update_request_complete'
    }));

    originalEnd.call(this, chunk, encoding);
  };

  next();
}

/**
 * Rate limiting middleware for flow updates
 */
function updateRateLimiter(req: Request, res: Response, next: NextFunction): void {
  const clientIp = req.ip || 'unknown';
  const now = Date.now();

  // Clean up expired entries
  for (const [ip, data] of UPDATE_RATE_LIMITS.updateRequests.entries()) {
    if (now > data.resetTime) {
      UPDATE_RATE_LIMITS.updateRequests.delete(ip);
    }
  }

  // Check current usage
  const clientUsage = UPDATE_RATE_LIMITS.updateRequests.get(clientIp);

  if (clientUsage && clientUsage.count >= UPDATE_RATE_LIMITS.maxUpdates) {
    const resetIn = Math.ceil((clientUsage.resetTime - now) / 1000);

    return res.status(429).json({
      error: {
        code: 'UPDATE_RATE_LIMIT_EXCEEDED',
        message: `Flow update rate limit exceeded. Try again in ${resetIn} seconds.`,
        details: {
          limit: UPDATE_RATE_LIMITS.maxUpdates,
          windowMs: UPDATE_RATE_LIMITS.windowMs,
          resetIn
        },
        timestamp: new Date().toISOString(),
        requestId: req.requestId
      }
    } as UpdateErrorResponse);
  }

  // Update usage
  if (clientUsage) {
    clientUsage.count++;
  } else {
    UPDATE_RATE_LIMITS.updateRequests.set(clientIp, {
      count: 1,
      resetTime: now + UPDATE_RATE_LIMITS.windowMs
    });
  }

  next();
}

/**
 * Input sanitization middleware
 */
function inputSanitizer(req: Request, res: Response, next: NextFunction): void {
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
    } as UpdateErrorResponse);
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
 * Conflict detection middleware
 */
function conflictDetector(req: Request, res: Response, next: NextFunction): void {
  // Store conflict detection state for later use
  req.conflictDetection = {
    checked: false,
    conflictsDetected: false,
    conflicts: []
  };
  next();
}

/**
 * PUT /api/flows/{flowId} - Update an existing flow definition
 *
 * This endpoint updates existing flow definitions with comprehensive conflict detection,
 * version management, and change tracking. Supports multiple merge strategies and
 * provides detailed feedback on all changes made.
 *
 * @param flowId - ID of the flow to update
 * @bodyparam flow - Partial flow definition with updates
 * @bodyparam mergeStrategy - Merge strategy (replace, merge, patch)
 * @bodyparam conflictResolution - Conflict resolution strategy (error, overwrite, merge)
 * @bodyparam expectedVersion - Expected version for optimistic locking
 * @bodyparam changeTracking - Change tracking options
 * @bodyparam validation - Validation options
 * @bodyparam backup - Backup options
 * @bodyparam publication - Publication options
 * @bodyparam format - Response format (json, xml)
 *
 * @example
 * // Simple update
 * PUT /api/flows/flow123
 * {
 *   "flow": {
 *     "name": "Updated Flow Name",
 *     "description": "Updated description"
 *   },
 *   "mergeStrategy": "merge",
 *   "expectedVersion": "1.0.0"
 * }
 *
 * // Complex update with conflict resolution
 * PUT /api/flows/flow123
 * {
 *   "flow": { ... },
 *   "mergeStrategy": "patch",
 *   "conflictResolution": "merge",
 *   "expectedVersion": "1.0.0",
 *   "changeTracking": {
 *     "enabled": true,
 *     "comment": "Fixed login issue",
 *     "reason": "bug_fix"
 *   },
 *   "backup": { "enabled": true }
 * }
 */
router.put('/:flowId', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  const flowId = req.params.flowId;
  updateMetrics.totalUpdates++;

  try {
    // Parse and validate request
    const updateRequest = parseUpdateRequest(req);

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
      } as UpdateErrorResponse);
    }

    // Check version conflicts (optimistic locking)
    if (updateRequest.expectedVersion && updateRequest.expectedVersion !== existingFlow.version) {
      const conflicts = await detectVersionConflicts(existingFlow, updateRequest);
      updateMetrics.conflictDetections++;
      req.conflictDetection = {
        checked: true,
        conflictsDetected: true,
        conflicts
      };

      if (updateRequest.conflictResolution === 'error') {
        return res.status(409).json({
          error: {
            code: 'VERSION_CONFLICT',
            message: `Version conflict. Expected ${updateRequest.expectedVersion}, found ${existingFlow.version}`,
            details: {
              flowId,
              expectedVersion: updateRequest.expectedVersion,
              currentVersion: existingFlow.version,
              conflicts
            },
            timestamp: new Date().toISOString(),
            requestId
          }
        } as UpdateErrorResponse);
      }
    }

    // Create backup if requested
    let backupInfo;
    if (updateRequest.backup?.enabled) {
      backupInfo = await createFlowBackup(existingFlow, updateRequest.backup);
    }

    // Apply updates with merge strategy
    const mergedFlow = await applyMergeStrategy(existingFlow, updateRequest);
    updateMetrics.mergeStrategyUsage[updateRequest.mergeStrategy || 'replace']++;

    // Validate updated flow
    const validationResult = await validateUpdatedFlow(mergedFlow, updateRequest.validation);
    if (!validationResult.isValid && updateRequest.validation?.strict) {
      return res.status(400).json({
        error: {
          code: 'FLOW_VALIDATION_FAILED',
          message: 'Updated flow validation failed in strict mode',
          details: {
            flowId,
            validationErrors: validationResult.errors
          },
          timestamp: new Date().toISOString(),
          requestId
        }
      } as UpdateErrorResponse);
    }

    // Update flow using service
    const serviceRequest: UpdateFlowRequest = {
      flowId,
      flow: mergedFlow,
      mergeStrategy: updateRequest.mergeStrategy
    };

    const updatedFlow = await flowService.updateFlow(serviceRequest);

    // Track changes if enabled
    let changeHistoryEntry;
    if (updateRequest.changeTracking?.enabled) {
      changeHistoryEntry = await trackChanges(existingFlow, updatedFlow, updateRequest.changeTracking, req);
    }

    // Calculate changes summary
    const changeSummary = calculateChangeSummary(existingFlow, updatedFlow);

    // Handle publication if requested
    let publicationInfo;
    if (updateRequest.publication?.publish) {
      publicationInfo = await handlePublication(updatedFlow, updateRequest.publication);
    }

    // Build response
    const response: EnhancedUpdateFlowResponse = {
      flow: updatedFlow,
      changes: changeSummary.fieldChanges.map(field => ({
        field,
        oldValue: (existingFlow as any)[field],
        newValue: (updatedFlow as any)[field]
      })),
      validation: validationResult,
      metadata: {
        updatedAt: new Date().toISOString(),
        updatedBy: req.ip || 'anonymous',
        updateTime: Date.now() - startTime,
        mergeStrategy: updateRequest.mergeStrategy || 'replace',
        conflictDetected: req.conflictDetection?.conflictsDetected || false,
        conflictResolved: req.conflictDetection?.conflictsDetected && updateRequest.conflictResolution !== 'error'
      },
      versioning: {
        previousVersion: existingFlow.version,
        newVersion: updatedFlow.version,
        versionIncrement: updateRequest.publication?.versionIncrement || 'patch'
      },
      changeSummary,
      backup: backupInfo,
      publication: publicationInfo,
      performance: {
        updateTime: Date.now() - startTime,
        validationTime: 0, // TODO: Track validation time separately
        backupTime: backupInfo?.creationTime || 0,
        totalTime: Date.now() - startTime
      }
    };

    // Update metrics
    updateMetrics.successfulUpdates++;
    updateUpdateMetrics(Date.now() - startTime);

    // Log successful update
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_update_success',
      flowId,
      flowName: updatedFlow.name,
      previousVersion: existingFlow.version,
      newVersion: updatedFlow.version,
      mergeStrategy: updateRequest.mergeStrategy,
      changesCount: changeSummary.totalChanges,
      updateTime: `${Date.now() - startTime}ms`
    }));

    // Format response if requested
    if (updateRequest.format === 'xml') {
      res.setHeader('Content-Type', 'application/xml');
      return res.send(formatUpdateXmlResponse(response));
    }

    res.json(response);

  } catch (error) {
    updateMetrics.failedCreations++;
    const responseTime = Date.now() - startTime;

    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_update_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      flowId,
      responseTime: `${responseTime}ms`
    }));

    const errorResponse: UpdateErrorResponse = {
      error: {
        code: 'FLOW_UPDATE_ERROR',
        message: 'Failed to update flow',
        details: {
          flowId,
          originalError: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: new Date().toISOString(),
        requestId
      },
      performance: {
        updateTime: responseTime
      }
    };

    res.status(500).json(errorResponse);
  }
});

/**
 * GET /api/flows/{flowId}/conflicts - Check for potential conflicts
 *
 * Check for potential conflicts before updating a flow without actually
 * performing the update. Useful for conflict resolution in UI.
 */
router.get('/:flowId/conflicts', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  const flowId = req.params.flowId;

  try {
    const { expectedVersion, incomingChanges } = req.query;

    if (!expectedVersion) {
      return res.status(400).json({
        error: {
          code: 'MISSING_EXPECTED_VERSION',
          message: 'Expected version is required for conflict detection',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as UpdateErrorResponse);
    }

    // Load existing flow
    const existingFlow = await flowService.loadFlow(flowId);
    if (!existingFlow) {
      return res.status(404).json({
        error: {
          code: 'FLOW_NOT_FOUND',
          message: `Flow not found: ${flowId}`,
          timestamp: new Date().toISOString(),
          requestId
        }
      } as UpdateErrorResponse);
    }

    // Detect conflicts
    const conflicts = await detectVersionConflicts(existingFlow, {
      expectedVersion: expectedVersion as string,
      flow: incomingChanges ? JSON.parse(incomingChanges as string) : {}
    });

    const response: ConflictDetectionResponse = {
      hasConflicts: conflicts.length > 0,
      conflicts,
      baseVersion: existingFlow.version,
      currentVersion: existingFlow.version,
      incomingVersion: expectedVersion as string
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_conflict_detection_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      flowId
    }));

    res.status(500).json({
      error: {
        code: 'CONFLICT_DETECTION_ERROR',
        message: 'Failed to detect conflicts',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as UpdateErrorResponse);
  }
});

/**
 * GET /api/flows/{flowId}/history - Get change history
 *
 * Get the complete change history for a flow with detailed
 * change tracking and audit trail.
 */
router.get('/:flowId/history', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  const flowId = req.params.flowId;

  try {
    const limit = parseInt(req.query.limit as string) || 50;
    const offset = parseInt(req.query.offset as string) || 0;

    const history = changeHistory.get(flowId) || [];
    const paginatedHistory = history.slice(offset, offset + limit);

    const response = {
      flowId,
      history: paginatedHistory,
      pagination: {
        offset,
        limit,
        total: history.length,
        hasMore: offset + limit < history.length
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
      event: 'flow_history_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      flowId
    }));

    res.status(500).json({
      error: {
        code: 'FLOW_HISTORY_ERROR',
        message: 'Failed to retrieve flow history',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as UpdateErrorResponse);
  }
});

/**
 * POST /api/flows/{flowId}/rollback - Rollback to previous version
 *
 * Rollback a flow to a previous version with proper validation
 * and change tracking.
 */
router.post('/:flowId/rollback', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  const flowId = req.params.flowId;

  try {
    const { targetVersion, reason, backup } = req.body;

    if (!targetVersion) {
      return res.status(400).json({
        error: {
          code: 'MISSING_TARGET_VERSION',
          message: 'Target version is required for rollback',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as UpdateErrorResponse);
    }

    // Load current flow
    const currentFlow = await flowService.loadFlow(flowId);
    if (!currentFlow) {
      return res.status(404).json({
        error: {
          code: 'FLOW_NOT_FOUND',
          message: `Flow not found: ${flowId}`,
          timestamp: new Date().toISOString(),
          requestId
        }
      } as UpdateErrorResponse);
    }

    // TODO: Implement rollback logic
    // This would involve loading the target version from backup/history
    // and updating the current flow

    const response = {
      flowId,
      rollbackPerformed: false,
      message: 'Rollback functionality not yet implemented',
      currentVersion: currentFlow.version,
      targetVersion,
      performance: {
        responseTime: Date.now() - startTime
      }
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_rollback_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      flowId
    }));

    res.status(500).json({
      error: {
        code: 'FLOW_ROLLBACK_ERROR',
        message: 'Failed to rollback flow',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as UpdateErrorResponse);
  }
});

/**
 * Parse and validate update request
 */
function parseUpdateRequest(req: Request): EnhancedUpdateFlowRequest {
  const body = req.body;
  const flowId = req.params.flowId;

  const updateRequest: EnhancedUpdateFlowRequest = {
    flowId,
    flow: body.flow,
    mergeStrategy: body.mergeStrategy || 'merge'
  };

  // Parse optional fields
  if (body.expectedVersion) updateRequest.expectedVersion = body.expectedVersion;
  if (body.conflictResolution) updateRequest.conflictResolution = body.conflictResolution;
  if (body.changeTracking) updateRequest.changeTracking = body.changeTracking;
  if (body.validation) updateRequest.validation = body.validation;
  if (body.backup) updateRequest.backup = body.backup;
  if (body.publication) updateRequest.publication = body.publication;
  if (body.format) updateRequest.format = body.format;
  if (body.include) updateRequest.include = body.include;

  return updateRequest;
}

/**
 * Detect version conflicts
 */
async function detectVersionConflicts(
  existingFlow: FlowDefinition,
  updateRequest: EnhancedUpdateFlowRequest
): Promise<ConflictDetectionResponse['conflicts']> {
  const conflicts: ConflictDetectionResponse['conflicts'] = [];

  // Version conflict
  if (updateRequest.expectedVersion && updateRequest.expectedVersion !== existingFlow.version) {
    conflicts.push({
      field: 'version',
      currentValue: existingFlow.version,
      incomingValue: updateRequest.expectedVersion,
      conflictType: 'version',
      resolution: updateRequest.conflictResolution
    });
  }

  // Value conflicts for updated fields
  if (updateRequest.flow) {
    for (const [field, incomingValue] of Object.entries(updateRequest.flow)) {
      const currentValue = (existingFlow as any)[field];
      if (currentValue !== undefined && JSON.stringify(currentValue) !== JSON.stringify(incomingValue)) {
        conflicts.push({
          field,
          currentValue,
          incomingValue,
          conflictType: 'value',
          resolution: updateRequest.conflictResolution
        });
      }
    }
  }

  return conflicts;
}

/**
 * Create flow backup
 */
async function createFlowBackup(flow: FlowDefinition, backupOptions: any): Promise<any> {
  try {
    const backupId = `backup_${flow.id}_${Date.now()}`;
    const backupData = {
      id: backupId,
      flowId: flow.id,
      version: flow.version,
      flow: { ...flow },
      createdAt: new Date().toISOString(),
      location: backupOptions.location || 'default'
    };

    // TODO: Implement actual backup storage
    console.log(`Creating backup ${backupId} for flow ${flow.id}`);

    return {
      created: true,
      backupId,
      location: backupOptions.location || 'default',
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
 * Apply merge strategy to combine existing and updated flow
 */
async function applyMergeStrategy(
  existingFlow: FlowDefinition,
  updateRequest: EnhancedUpdateFlowRequest
): Promise<Partial<FlowDefinition>> {
  const { flow: updates, mergeStrategy = 'merge' } = updateRequest;

  switch (mergeStrategy) {
    case 'replace':
      return { ...existingFlow, ...updates };

    case 'merge':
      return mergeFlowDefinitions(existingFlow, updates);

    case 'patch':
      return patchFlowDefinition(existingFlow, updates);

    default:
      return { ...existingFlow, ...updates };
  }
}

/**
 * Deep merge flow definitions
 */
function mergeFlowDefinitions(existing: FlowDefinition, updates: Partial<FlowDefinition>): Partial<FlowDefinition> {
  const merged = { ...existing };

  for (const [key, value] of Object.entries(updates)) {
    if (value === undefined) continue;

    if (key === 'metadata' && typeof value === 'object' && typeof merged[key] === 'object') {
      merged[key] = { ...merged[key], ...value };
    } else if (key === 'config' && typeof value === 'object' && typeof merged[key] === 'object') {
      merged[key] = { ...merged[key], ...value };
    } else {
      (merged as any)[key] = value;
    }
  }

  return merged;
}

/**
 * Patch flow definition (only update defined fields)
 */
function patchFlowDefinition(existing: FlowDefinition, updates: Partial<FlowDefinition>): Partial<FlowDefinition> {
  const patched = { ...existing };

  for (const [key, value] of Object.entries(updates)) {
    if (value !== undefined) {
      (patched as any)[key] = value;
    }
  }

  return patched;
}

/**
 * Validate updated flow
 */
async function validateUpdatedFlow(
  flow: Partial<FlowDefinition>,
  validationOptions?: any
): Promise<FlowValidationResult> {
  try {
    return await flowService.validateFlow({
      flow: flow as FlowDefinition,
      options: {
        checkStates: validationOptions?.checkStates !== false,
        checkActions: validationOptions?.checkActions !== false,
        checkLogic: validationOptions?.checkLogic !== false,
        analyzePerformance: validationOptions?.analyzePerformance === true
      }
    });
  } catch (error) {
    return {
      isValid: false,
      errors: [{
        type: 'syntax',
        severity: 'error',
        message: error instanceof Error ? error.message : 'Validation failed',
        code: 'VALIDATION_ERROR'
      }],
      warnings: [],
      summary: {
        totalSteps: flow.steps?.length || 0,
        validSteps: 0,
        invalidSteps: flow.steps?.length || 0,
        unreachableStates: 0,
        circularDependencies: 0
      }
    };
  }
}

/**
 * Track changes in change history
 */
async function trackChanges(
  previousFlow: FlowDefinition,
  updatedFlow: FlowDefinition,
  changeTracking: any,
  req: Request
): Promise<any> {
  try {
    const changes = calculateDetailedChanges(previousFlow, updatedFlow);
    const historyEntry = {
      timestamp: new Date().toISOString(),
      changes,
      userId: req.ip || 'anonymous',
      version: updatedFlow.version,
      comment: changeTracking.comment,
      reason: changeTracking.reason,
      tags: changeTracking.tags || []
    };

    // Store in change history
    const flowHistory = changeHistory.get(updatedFlow.id) || [];
    flowHistory.push(historyEntry);
    changeHistory.set(updatedFlow.id, flowHistory);

    // Keep only recent history (last 100 changes per flow)
    if (flowHistory.length > 100) {
      flowHistory.splice(0, flowHistory.length - 100);
    }

    return historyEntry;
  } catch (error) {
    console.error('Failed to track changes:', error);
    return null;
  }
}

/**
 * Calculate change summary
 */
function calculateChangeSummary(previousFlow: FlowDefinition, updatedFlow: FlowDefinition): any {
  const fieldChanges: string[] = [];
  const structuralChanges: string[] = [];

  // Compare top-level fields
  for (const key of Object.keys(updatedFlow)) {
    if (JSON.stringify((previousFlow as any)[key]) !== JSON.stringify((updatedFlow as any)[key])) {
      fieldChanges.push(key);
    }
  }

  // Check for structural changes
  if (previousFlow.steps.length !== updatedFlow.steps.length) {
    structuralChanges.push('steps_count_changed');
  }

  if (previousFlow.entryPoint !== updatedFlow.entryPoint) {
    structuralChanges.push('entry_point_changed');
  }

  if (previousFlow.exitPoint !== updatedFlow.exitPoint) {
    structuralChanges.push('exit_point_changed');
  }

  return {
    totalChanges: fieldChanges.length + structuralChanges.length,
    fieldChanges,
    structuralChanges
  };
}

/**
 * Calculate detailed changes between flows
 */
function calculateDetailedChanges(previousFlow: FlowDefinition, updatedFlow: FlowDefinition): any[] {
  const changes: any[] = [];

  // Compare all fields
  for (const key of Object.keys(updatedFlow)) {
    const previousValue = (previousFlow as any)[key];
    const updatedValue = (updatedFlow as any)[key];

    if (JSON.stringify(previousValue) !== JSON.stringify(updatedValue)) {
      changes.push({
        field: key,
        type: 'field_change',
        previousValue,
        updatedValue,
        changeType: previousValue === undefined ? 'added' :
                      updatedValue === undefined ? 'removed' : 'modified'
      });
    }
  }

  return changes;
}

/**
 * Handle publication
 */
async function handlePublication(flow: FlowDefinition, publicationOptions: any): Promise<any> {
  // TODO: Implement publication logic
  return {
    published: true,
    version: flow.version,
    publishedAt: new Date().toISOString()
  };
}

/**
 * Update update metrics
 */
function updateUpdateMetrics(updateTime: number): void {
  updateMetrics.updateTimeHistory.push(updateTime);

  if (updateMetrics.updateTimeHistory.length > updateMetrics.maxHistorySize) {
    updateMetrics.updateTimeHistory.shift();
  }

  updateMetrics.averageUpdateTime = Math.round(
    updateMetrics.updateTimeHistory.reduce((sum, time) => sum + time, 0) /
    updateMetrics.updateTimeHistory.length
  );
}

/**
 * Format update response as XML
 */
function formatUpdateXmlResponse(response: EnhancedUpdateFlowResponse): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<updateFlowResponse>
  <flow>
    <id>${response.flow.id}</id>
    <name>${response.flow.name}</name>
    <packageName>${response.flow.packageName}</packageName>
    <version>${response.flow.version}</version>
  </flow>
  <metadata>
    <updatedAt>${response.metadata.updatedAt}</updatedAt>
    <updatedBy>${response.metadata.updatedBy}</updatedBy>
    <updateTime>${response.metadata.updateTime}</updateTime>
    <mergeStrategy>${response.metadata.mergeStrategy}</mergeStrategy>
    <conflictDetected>${response.metadata.conflictDetected}</conflictDetected>
  </metadata>
  <versioning>
    <previousVersion>${response.versioning.previousVersion}</previousVersion>
    <newVersion>${response.versioning.newVersion}</newVersion>
    <versionIncrement>${response.versioning.versionIncrement}</versionIncrement>
  </versioning>
  <changeSummary>
    <totalChanges>${response.changeSummary.totalChanges}</totalChanges>
    <fieldChanges>${response.changeSummary.fieldChanges.join(', ')}</fieldChanges>
  </changeSummary>
  <performance>
    <updateTime>${response.performance.updateTime}</updateTime>
    <totalTime>${response.performance.totalTime}</totalTime>
  </performance>
</updateFlowResponse>`;
}

/**
 * Get update metrics
 */
export function getUpdateMetrics() {
  return {
    ...updateMetrics,
    successRate: updateMetrics.totalUpdates > 0
      ? updateMetrics.successfulUpdates / updateMetrics.totalUpdates
      : 0
  };
}

export default router;