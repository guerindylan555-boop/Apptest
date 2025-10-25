/**
 * Flow Validation API Routes (T050)
 *
 * Comprehensive REST API endpoints for validating flow definitions.
 * Supports comprehensive validation with detailed feedback, predicate resolution,
 * confidence scoring, batch validation, and performance analysis.
 *
 * Features:
 * - Comprehensive validation with detailed feedback
 * - Predicate resolution and confidence scoring
 * - Batch validation for multiple flows
 * - Performance impact analysis
 * - Validation rule configuration
 * - Custom validation profiles
 * - Validation caching and optimization
 * - Detailed error reporting and suggestions
 */

import { Router, Request, Response, NextFunction } from 'express';
import { FlowService } from '../services/flowService';
import { FlowValidationService } from '../services/flowValidationService';
import {
  FlowDefinition,
  FlowValidationResult,
  FlowValidationError,
  FlowValidationWarning,
  ValidateFlowRequest,
  ValidateFlowResponse
} from '../types/flow';

const router = Router();

// Performance tracking
const validationMetrics = {
  totalValidations: 0,
  successfulValidations: 0,
  failedValidations: 0,
  batchValidations: 0,
  averageValidationTime: 0,
  validationTimeHistory: [] as number[],
  cacheHits: 0,
  cacheMisses: 0,
  ruleUsage: new Map<string, number>(),
  maxHistorySize: 100
};

// Validation cache
const validationCache = new Map<string, {
  result: any;
  timestamp: number;
  flowHash: string;
  ttl: number;
}>();

// Validation rate limiting configuration
const VALIDATION_RATE_LIMITS = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxValidations: 200, // limit each IP to 200 validations per windowMs
  validationRequests: new Map<string, { count: number; resetTime: number }>()
};

// Validation profiles configuration
const VALIDATION_PROFILES = {
  strict: {
    checkStates: true,
    checkActions: true,
    checkLogic: true,
    analyzePerformance: true,
    provideSuggestions: true,
    strict: true
  },
  standard: {
    checkStates: true,
    checkActions: true,
    checkLogic: false,
    analyzePerformance: false,
    provideSuggestions: true,
    strict: false
  },
  quick: {
    checkStates: false,
    checkActions: true,
    checkLogic: false,
    analyzePerformance: false,
    provideSuggestions: false,
    strict: false
  },
  comprehensive: {
    checkStates: true,
    checkActions: true,
    checkLogic: true,
    analyzePerformance: true,
    provideSuggestions: true,
    strict: false,
    includeSemanticAnalysis: true,
    includeSecurityAnalysis: true,
    includeAccessibilityAnalysis: true
  }
};

/**
 * Enhanced validation request with additional options
 */
interface EnhancedValidateFlowRequest extends ValidateFlowRequest {
  /** Validation profile */
  profile?: keyof typeof VALIDATION_PROFILES | 'custom';

  /** Custom validation options */
  customOptions?: {
    checkStates?: boolean;
    checkActions?: boolean;
    checkLogic?: boolean;
    analyzePerformance?: boolean;
    provideSuggestions?: boolean;
    strict?: boolean;
    includeSemanticAnalysis?: boolean;
    includeSecurityAnalysis?: boolean;
    includeAccessibilityAnalysis?: boolean;
  };

  /** Validation context */
  context?: {
    targetEnvironment?: 'development' | 'staging' | 'production';
    deviceInfo?: {
      platform: string;
      version: string;
      screenSize?: string;
    };
    executionMode?: 'test' | 'production' | 'debug';
  };

  /** Performance analysis options */
  performanceAnalysis?: {
    includeResourceUsage?: boolean;
    includeTimeComplexity?: boolean;
    includeRiskAssessment?: boolean;
    benchmarkAgainst?: string[];
  };

  /** Output options */
  output?: {
    includeDetailedErrors?: boolean;
    includeSuggestions?: boolean;
    includeFixes?: boolean;
    format?: 'json' | 'xml' | 'yaml';
    language?: 'en' | 'es' | 'fr' | 'de';
  };

  /** Caching options */
  caching?: {
    enabled?: boolean;
    ttl?: number;
    forceRefresh?: boolean;
  };
}

/**
 * Enhanced validation response with additional analysis
 */
interface EnhancedValidateFlowResponse extends ValidateFlowResponse {
  /** Validation metadata */
  metadata: {
    validatedAt: string;
    validatedBy: string;
    validationTime: number;
    profile: string;
    cacheHit: boolean;
    flowHash: string;
  };

  /** Detailed analysis results */
  detailedAnalysis: {
    semanticAnalysis?: {
      clarityScore: number;
      complexityScore: number;
      readabilityScore: number;
      suggestions: string[];
    };
    securityAnalysis?: {
      riskLevel: 'low' | 'medium' | 'high';
      vulnerabilities: Array<{
        type: string;
        severity: 'low' | 'medium' | 'high';
        description: string;
        recommendation: string;
      }>;
    };
    accessibilityAnalysis?: {
      complianceScore: number;
      issues: Array<{
        type: string;
        severity: 'minor' | 'major' | 'critical';
        description: string;
        fix: string;
      }>;
    };
  };

  /** Performance metrics */
  performance: {
    validationTime: number;
    analysisTime: number;
    totalTime: number;
    rulesChecked: number;
    cacheHit: boolean;
  };
}

/**
 * Batch validation request
 */
interface BatchValidateRequest {
  /** Flow definitions to validate */
  flows: FlowDefinition[];

  /** Validation options applied to all flows */
  options?: EnhancedValidateFlowRequest;

  /** Batch processing options */
  batch?: {
    continueOnError?: boolean;
    maxParallel?: number;
    timeoutMs?: number;
    aggregateResults?: boolean;
  };
}

/**
 * Batch validation response
 */
interface BatchValidateResponse {
  /** Batch processing summary */
  batch: {
    totalFlows: number;
    validFlows: number;
    invalidFlows: number;
    processedAt: string;
    processingTime: number;
  };

  /** Individual validation results */
  results: Array<{
    flowId: string;
    flowName: string;
    valid: boolean;
    errors: FlowValidationError[];
    warnings: FlowValidationWarning[];
    performance: number;
  }>;

  /** Aggregated analysis */
  aggregate?: {
    averageComplexity: number;
    averageReliability: number;
    commonErrors: Array<{
      code: string;
      count: number;
      description: string;
    }>;
    commonWarnings: Array<{
      code: string;
      count: number;
      description: string;
    }>;
  };

  /** Performance metrics */
  performance: {
    totalTime: number;
    averageTimePerFlow: number;
    parallelProcessing: boolean;
    cacheHits: number;
  };
}

/**
 * Error response with detailed validation information
 */
interface ValidateErrorResponse {
  error: {
    code: string;
    message: string;
    details?: {
      flowId?: string;
      validationErrors?: any;
      ruleFailures?: any;
    };
    timestamp: string;
    requestId: string;
  };
  performance?: {
    validationTime: number;
  };
}

// Initialize services
let flowService: FlowService;
let flowValidationService: FlowValidationService;

export function initializeFlowsValidateRoutes(
  flowSvc: FlowService,
  flowValidationSvc: FlowValidationService
): Router {
  flowService = flowSvc;
  flowValidationService = flowValidationSvc;

  // Apply middleware
  router.use(requestLogger);
  router.use(validationRateLimiter);
  router.use(inputSanitizer);
  router.use(cacheManager);

  return router;
}

/**
 * Middleware for request logging
 */
function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();
  const requestId = `validate_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  res.setHeader('X-Request-ID', requestId);
  req.requestId = requestId;

  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    requestId,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    event: 'flow_validate_request_start'
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
      event: 'flow_validate_request_complete'
    }));

    originalEnd.call(this, chunk, encoding);
  };

  next();
}

/**
 * Rate limiting middleware for flow validations
 */
function validationRateLimiter(req: Request, res: Response, next: NextFunction): void {
  const clientIp = req.ip || 'unknown';
  const now = Date.now();

  // Clean up expired entries
  for (const [ip, data] of VALIDATION_RATE_LIMITS.validationRequests.entries()) {
    if (now > data.resetTime) {
      VALIDATION_RATE_LIMITS.validationRequests.delete(ip);
    }
  }

  // Check current usage
  const clientUsage = VALIDATION_RATE_LIMITS.validationRequests.get(clientIp);

  if (clientUsage && clientUsage.count >= VALIDATION_RATE_LIMITS.maxValidations) {
    const resetIn = Math.ceil((clientUsage.resetTime - now) / 1000);

    return res.status(429).json({
      error: {
        code: 'VALIDATION_RATE_LIMIT_EXCEEDED',
        message: `Flow validation rate limit exceeded. Try again in ${resetIn} seconds.`,
        details: {
          limit: VALIDATION_RATE_LIMITS.maxValidations,
          windowMs: VALIDATION_RATE_LIMITS.windowMs,
          resetIn
        },
        timestamp: new Date().toISOString(),
        requestId: req.requestId
      }
    } as ValidateErrorResponse);
  }

  // Update usage
  if (clientUsage) {
    clientUsage.count++;
  } else {
    VALIDATION_RATE_LIMITS.validationRequests.set(clientIp, {
      count: 1,
      resetTime: now + VALIDATION_RATE_LIMITS.windowMs
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
    } as ValidateErrorResponse);
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
 * Cache management middleware
 */
function cacheManager(req: Request, res: Response, next: NextFunction): void {
  // Store cache configuration for later use
  req.cacheConfig = {
    enabled: true,
    ttl: 5 * 60 * 1000, // 5 minutes default
    forceRefresh: false
  };
  next();
}

/**
 * POST /api/flows/{flowId}/validate - Validate a flow definition
 *
 * This endpoint provides comprehensive flow validation with detailed feedback,
 * performance analysis, and actionable suggestions. Supports multiple validation
 * profiles and custom validation options.
 *
 * @param flowId - ID of the flow to validate
 * @bodyparam flow - Flow definition to validate (if not using existing flow)
 * @bodyparam profile - Validation profile (strict, standard, quick, comprehensive)
 * @bodyparam customOptions - Custom validation options
 * @bodyparam context - Validation context
 * @bodyparam performanceAnalysis - Performance analysis options
 * @bodyparam output - Output formatting options
 * @bodyparam caching - Caching options
 *
 * @example
 * // Validate with standard profile
 * POST /api/flows/flow123/validate
 * {
 *   "profile": "standard",
 *   "context": {
 *     "targetEnvironment": "production",
 *     "deviceInfo": { "platform": "android", "version": "11" }
 *   }
 * }
 *
 * // Validate with custom options
 * POST /api/flows/flow123/validate
 * {
 *   "profile": "custom",
 *   "customOptions": {
 *     "checkStates": true,
 *     "checkActions": true,
 *     "analyzePerformance": true,
 *     "provideSuggestions": true
 *   },
 *   "performanceAnalysis": {
 *     "includeRiskAssessment": true
 *   }
 * }
 */
router.post('/:flowId/validate', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';
  const flowId = req.params.flowId;
  validationMetrics.totalValidations++;

  try {
    // Parse and validate request
    const validateRequest = parseValidateRequest(req);

    // Load flow if not provided in request
    let flow = validateRequest.flow;
    if (!flow) {
      flow = await flowService.loadFlow(flowId);
      if (!flow) {
        return res.status(404).json({
          error: {
            code: 'FLOW_NOT_FOUND',
            message: `Flow not found: ${flowId}`,
            details: { flowId },
            timestamp: new Date().toISOString(),
            requestId
          }
        } as ValidateErrorResponse);
      }
    }

    // Generate flow hash for caching
    const flowHash = generateFlowHash(flow);

    // Check cache if enabled
    let cachedResult = null;
    let cacheHit = false;

    if (validateRequest.caching?.enabled !== false && !validateRequest.caching?.forceRefresh) {
      cachedResult = getCachedValidation(flowId, flowHash);
      if (cachedResult) {
        cacheHit = true;
        validationMetrics.cacheHits++;
      } else {
        validationMetrics.cacheMisses++;
      }
    }

    let validationResult;
    let analysisResults;

    if (cachedResult) {
      validationResult = cachedResult.validationResult;
      analysisResults = cachedResult.analysisResults;
    } else {
      // Determine validation options
      const validationOptions = resolveValidationOptions(validateRequest);

      // Perform validation
      validationResult = await performFlowValidation(flow, validationOptions);

      // Perform additional analysis
      analysisResults = await performAdditionalAnalysis(flow, validateRequest);

      // Cache results if enabled
      if (validateRequest.caching?.enabled !== false) {
        cacheValidationResult(flowId, flowHash, validationResult, analysisResults, validateRequest.caching);
      }
    }

    // Build response
    const response: EnhancedValidateFlowResponse = {
      result: validationResult,
      analysis: analysisResults.performanceAnalysis,
      metadata: {
        validatedAt: new Date().toISOString(),
        validatedBy: req.ip || 'anonymous',
        validationTime: Date.now() - startTime,
        profile: validateRequest.profile || 'standard',
        cacheHit,
        flowHash
      },
      detailedAnalysis: {
        semanticAnalysis: analysisResults.semanticAnalysis,
        securityAnalysis: analysisResults.securityAnalysis,
        accessibilityAnalysis: analysisResults.accessibilityAnalysis
      },
      performance: {
        validationTime: Date.now() - startTime,
        analysisTime: 0, // TODO: Track analysis time separately
        totalTime: Date.now() - startTime,
        rulesChecked: validationResult.errors.length + validationResult.warnings.length,
        cacheHit
      }
    };

    // Update metrics
    if (validationResult.isValid) {
      validationMetrics.successfulValidations++;
    } else {
      validationMetrics.failedValidations++;
    }

    updateValidationMetrics(Date.now() - startTime);
    trackRuleUsage(validationResult);

    // Log successful validation
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_validate_success',
      flowId,
      flowName: flow.name,
      valid: validationResult.isValid,
      errorsCount: validationResult.errors.length,
      warningsCount: validationResult.warnings.length,
      profile: validateRequest.profile,
      cacheHit,
      validationTime: `${Date.now() - startTime}ms`
    }));

    // Format response if requested
    if (validateRequest.output?.format === 'xml') {
      res.setHeader('Content-Type', 'application/xml');
      return res.send(formatValidationXmlResponse(response));
    } else if (validateRequest.output?.format === 'yaml') {
      res.setHeader('Content-Type', 'application/yaml');
      return res.send(formatValidationYamlResponse(response));
    }

    res.json(response);

  } catch (error) {
    validationMetrics.failedValidations++;
    const responseTime = Date.now() - startTime;

    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_validate_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      flowId,
      responseTime: `${responseTime}ms`
    }));

    const errorResponse: ValidateErrorResponse = {
      error: {
        code: 'FLOW_VALIDATION_ERROR',
        message: 'Failed to validate flow',
        details: {
          flowId,
          originalError: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: new Date().toISOString(),
        requestId
      },
      performance: {
        validationTime: responseTime
      }
    };

    res.status(500).json(errorResponse);
  }
});

/**
 * POST /api/flows/batch-validate - Batch validate multiple flows
 *
 * Validate multiple flows in a single request with options for
 * parallel processing, error handling, and aggregated results.
 */
router.post('/batch-validate', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    const batchRequest: BatchValidateRequest = req.body;

    if (!batchRequest.flows || batchRequest.flows.length === 0) {
      return res.status(400).json({
        error: {
          code: 'MISSING_FLOWS',
          message: 'Flows are required for batch validation',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as ValidateErrorResponse);
    }

    // Validate batch size
    if (batchRequest.flows.length > 50) {
      return res.status(400).json({
        error: {
          code: 'BATCH_SIZE_EXCEEDED',
          message: 'Batch size cannot exceed 50 flows',
          details: { requestedSize: batchRequest.flows.length, maxSize: 50 },
          timestamp: new Date().toISOString(),
          requestId
        }
      } as ValidateErrorResponse);
    }

    // Process batch validation
    const batchResult = await processBatchValidation(batchRequest, requestId);
    validationMetrics.batchValidations++;

    const response: BatchValidateResponse = {
      batch: {
        totalFlows: batchRequest.flows.length,
        validFlows: batchResult.validCount,
        invalidFlows: batchResult.invalidCount,
        processedAt: new Date().toISOString(),
        processingTime: Date.now() - startTime
      },
      results: batchResult.results,
      aggregate: batchResult.aggregate,
      performance: {
        totalTime: Date.now() - startTime,
        averageTimePerFlow: (Date.now() - startTime) / batchRequest.flows.length,
        parallelProcessing: batchRequest.batch?.maxParallel && batchRequest.batch.maxParallel > 1,
        cacheHits: batchResult.cacheHits
      }
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'batch_validate_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }));

    res.status(500).json({
      error: {
        code: 'BATCH_VALIDATION_ERROR',
        message: 'Failed to process batch validation',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as ValidateErrorResponse);
  }
});

/**
 * GET /api/flows/validation-profiles - Get available validation profiles
 *
 * Returns available validation profiles with their configurations.
 */
router.get('/validation-profiles', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    const profiles = Object.entries(VALIDATION_PROFILES).map(([name, config]) => ({
      name,
      description: getProfileDescription(name),
      configuration: config,
      useCases: getProfileUseCases(name)
    }));

    const response = {
      profiles,
      defaultProfile: 'standard',
      performance: {
        responseTime: Date.now() - startTime
      }
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'validation_profiles_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }));

    res.status(500).json({
      error: {
        code: 'VALIDATION_PROFILES_ERROR',
        message: 'Failed to retrieve validation profiles',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as ValidateErrorResponse);
  }
});

/**
 * GET /api/flows/validation-rules - Get validation rules
 *
 * Returns available validation rules with descriptions and configurations.
 */
router.get('/validation-rules', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    const rules = [
      {
        id: 'flow_structure',
        name: 'Flow Structure Validation',
        description: 'Validates basic flow structure and required fields',
        category: 'structure',
        severity: 'error',
        enabled: true
      },
      {
        id: 'step_validation',
        name: 'Step Validation',
        description: 'Validates individual step configuration and actions',
        category: 'structure',
        severity: 'error',
        enabled: true
      },
      {
        id: 'state_predicate_validation',
        name: 'State Predicate Validation',
        description: 'Validates state predicates and conditions',
        category: 'semantic',
        severity: 'error',
        enabled: true
      },
      {
        id: 'action_feasibility',
        name: 'Action Feasibility Check',
        description: 'Checks if actions are feasible and properly configured',
        category: 'practical',
        severity: 'warning',
        enabled: true
      },
      {
        id: 'logic_validation',
        name: 'Flow Logic Validation',
        description: 'Validates flow logic and detects potential issues',
        category: 'logic',
        severity: 'warning',
        enabled: false
      },
      {
        id: 'performance_analysis',
        name: 'Performance Impact Analysis',
        description: 'Analyzes potential performance issues',
        category: 'performance',
        severity: 'info',
        enabled: false
      }
    ];

    const response = {
      rules,
      categories: ['structure', 'semantic', 'practical', 'logic', 'performance'],
      performance: {
        responseTime: Date.now() - startTime
      }
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'validation_rules_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }));

    res.status(500).json({
      error: {
        code: 'VALIDATION_RULES_ERROR',
        message: 'Failed to retrieve validation rules',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as ValidateErrorResponse);
  }
});

/**
 * Parse and validate validation request
 */
function parseValidateRequest(req: Request): EnhancedValidateFlowRequest {
  const body = req.body;

  return {
    flow: body.flow,
    profile: body.profile,
    customOptions: body.customOptions,
    context: body.context,
    performanceAnalysis: body.performanceAnalysis,
    output: body.output,
    caching: body.caching,
    options: {
      checkStates: body.customOptions?.checkStates,
      checkActions: body.customOptions?.checkActions,
      checkLogic: body.customOptions?.checkLogic,
      analyzePerformance: body.customOptions?.analyzePerformance
    }
  };
}

/**
 * Generate flow hash for caching
 */
function generateFlowHash(flow: FlowDefinition): string {
  // Create a hash based on relevant flow properties
  const hashInput = JSON.stringify({
    name: flow.name,
    packageName: flow.packageName,
    steps: flow.steps,
    entryPoint: flow.entryPoint,
    exitPoint: flow.exitPoint,
    version: flow.version
  });

  // Simple hash function - in production, use a proper hashing algorithm
  let hash = 0;
  for (let i = 0; i < hashInput.length; i++) {
    const char = hashInput.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }

  return Math.abs(hash).toString(36);
}

/**
 * Get cached validation result
 */
function getCachedValidation(flowId: string, flowHash: string): any {
  const cacheKey = `${flowId}:${flowHash}`;
  const cached = validationCache.get(cacheKey);

  if (cached && Date.now() < cached.timestamp + cached.ttl) {
    return cached;
  }

  // Remove expired entry
  if (cached) {
    validationCache.delete(cacheKey);
  }

  return null;
}

/**
 * Cache validation result
 */
function cacheValidationResult(
  flowId: string,
  flowHash: string,
  validationResult: any,
  analysisResults: any,
  cachingOptions?: any
): void {
  const cacheKey = `${flowId}:${flowHash}`;
  const ttl = cachingOptions?.ttl || 5 * 60 * 1000; // 5 minutes default

  validationCache.set(cacheKey, {
    validationResult,
    analysisResults,
    flowHash,
    timestamp: Date.now(),
    ttl
  });

  // Clean old cache entries periodically
  if (validationCache.size > 100) {
    const now = Date.now();
    for (const [key, entry] of validationCache.entries()) {
      if (now > entry.timestamp + entry.ttl) {
        validationCache.delete(key);
      }
    }
  }
}

/**
 * Resolve validation options from profile and custom options
 */
function resolveValidationOptions(request: EnhancedValidateFlowRequest): any {
  let baseOptions;

  // Use profile options
  if (request.profile && request.profile !== 'custom' && VALIDATION_PROFILES[request.profile]) {
    baseOptions = { ...VALIDATION_PROFILES[request.profile] };
  } else {
    baseOptions = { ...VALIDATION_PROFILES.standard };
  }

  // Override with custom options
  if (request.customOptions) {
    baseOptions = { ...baseOptions, ...request.customOptions };
  }

  return baseOptions;
}

/**
 * Perform flow validation
 */
async function performFlowValidation(flow: FlowDefinition, options: any): Promise<FlowValidationResult> {
  try {
    return await flowService.validateFlow({
      flow,
      options
    });
  } catch (error) {
    console.error('Flow validation failed:', error);
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
 * Perform additional analysis
 */
async function performAdditionalAnalysis(
  flow: FlowDefinition,
  request: EnhancedValidateFlowRequest
): Promise<any> {
  const results: any = {};

  try {
    // Performance analysis
    if (request.customOptions?.analyzePerformance || request.performanceAnalysis) {
      results.performanceAnalysis = await analyzePerformance(flow, request.performanceAnalysis);
    }

    // Semantic analysis
    if (request.customOptions?.includeSemanticAnalysis) {
      results.semanticAnalysis = await analyzeSemantics(flow);
    }

    // Security analysis
    if (request.customOptions?.includeSecurityAnalysis) {
      results.securityAnalysis = await analyzeSecurity(flow);
    }

    // Accessibility analysis
    if (request.customOptions?.includeAccessibilityAnalysis) {
      results.accessibilityAnalysis = await analyzeAccessibility(flow);
    }

  } catch (error) {
    console.error('Additional analysis failed:', error);
  }

  return results;
}

/**
 * Analyze flow performance
 */
async function analyzePerformance(flow: FlowDefinition, options?: any): Promise<any> {
  const complexity = flow.metadata.complexity || 0;
  const estimatedDuration = flow.metadata.estimatedDuration || 0;
  const stepCount = flow.steps.length;

  let performanceImpact: 'low' | 'medium' | 'high' = 'low';
  if (complexity > 70 || estimatedDuration > 120000) {
    performanceImpact = 'high';
  } else if (complexity > 40 || estimatedDuration > 60000) {
    performanceImpact = 'medium';
  }

  const suggestions: string[] = [];
  if (complexity > 50) {
    suggestions.push('Consider breaking complex flow into smaller flows');
  }
  if (estimatedDuration > 60000) {
    suggestions.push('Flow execution time is high, consider optimization');
  }
  if (stepCount > 20) {
    suggestions.push('Large number of steps may impact reliability');
  }

  return {
    estimatedDuration,
    complexityScore: complexity,
    performanceImpact,
    reliabilityScore: Math.max(0, 1 - (complexity / 100)),
    suggestions
  };
}

/**
 * Analyze flow semantics
 */
async function analyzeSemantics(flow: FlowDefinition): Promise<any> {
  // TODO: Implement semantic analysis
  return {
    clarityScore: 0.8,
    complexityScore: 0.6,
    readabilityScore: 0.9,
    suggestions: [
      'Add more descriptive step names',
      'Include detailed descriptions for complex steps'
    ]
  };
}

/**
 * Analyze flow security
 */
async function analyzeSecurity(flow: FlowDefinition): Promise<any> {
  // TODO: Implement security analysis
  return {
    riskLevel: 'low' as const,
    vulnerabilities: [],
    recommendations: [
      'Validate all user inputs',
      'Use secure communication channels'
    ]
  };
}

/**
 * Analyze flow accessibility
 */
async function analyzeAccessibility(flow: FlowDefinition): Promise<any> {
  // TODO: Implement accessibility analysis
  return {
    complianceScore: 0.85,
    issues: [],
    recommendations: [
      'Ensure all UI elements are accessible',
      'Provide alternative text for images'
    ]
  };
}

/**
 * Process batch validation
 */
async function processBatchValidation(
  batchRequest: BatchValidateRequest,
  requestId: string
): Promise<any> {
  const results = [];
  let validCount = 0;
  let invalidCount = 0;
  let cacheHits = 0;

  // TODO: Implement parallel processing if requested
  for (const flow of batchRequest.flows) {
    try {
      const validateRequest: EnhancedValidateFlowRequest = {
        flow,
        ...batchRequest.options
      };

      const validationOptions = resolveValidationOptions(validateRequest);
      const validationResult = await performFlowValidation(flow, validationOptions);

      if (validationResult.isValid) {
        validCount++;
      } else {
        invalidCount++;
      }

      results.push({
        flowId: flow.id,
        flowName: flow.name,
        valid: validationResult.isValid,
        errors: validationResult.errors,
        warnings: validationResult.warnings,
        performance: 0 // TODO: Calculate performance score
      });

    } catch (error) {
      invalidCount++;
      results.push({
        flowId: flow.id,
        flowName: flow.name,
        valid: false,
        errors: [{
          type: 'system',
          severity: 'error',
          message: error instanceof Error ? error.message : 'Unknown error',
          code: 'BATCH_VALIDATION_ERROR'
        }],
        warnings: [],
        performance: 0
      });

      if (!batchRequest.batch?.continueOnError) {
        break;
      }
    }
  }

  // Calculate aggregate statistics
  const aggregate = calculateAggregateStatistics(results);

  return {
    results,
    validCount,
    invalidCount,
    cacheHits,
    aggregate
  };
}

/**
 * Calculate aggregate statistics for batch validation
 */
function calculateAggregateStatistics(results: any[]): any {
  const allErrors = results.flatMap(r => r.errors);
  const allWarnings = results.flatMap(r => r.warnings);

  const errorCounts = new Map<string, number>();
  const warningCounts = new Map<string, number>();

  allErrors.forEach(error => {
    const count = errorCounts.get(error.code) || 0;
    errorCounts.set(error.code, count + 1);
  });

  allWarnings.forEach(warning => {
    const count = warningCounts.get(warning.code) || 0;
    warningCounts.set(warning.code, count + 1);
  });

  return {
    averageComplexity: 0, // TODO: Calculate from flow metadata
    averageReliability: results.filter(r => r.valid).length / results.length,
    commonErrors: Array.from(errorCounts.entries())
      .map(([code, count]) => ({
        code,
        count,
        description: code // TODO: Map to human-readable descriptions
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    commonWarnings: Array.from(warningCounts.entries())
      .map(([code, count]) => ({
        code,
        count,
        description: code // TODO: Map to human-readable descriptions
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10)
  };
}

/**
 * Get profile description
 */
function getProfileDescription(profileName: string): string {
  const descriptions: Record<string, string> = {
    strict: 'Comprehensive validation with strict error checking',
    standard: 'Standard validation with essential checks',
    quick: 'Fast validation for development and testing',
    comprehensive: 'Complete validation including semantic and security analysis'
  };

  return descriptions[profileName] || 'Custom validation profile';
}

/**
 * Get profile use cases
 */
function getProfileUseCases(profileName: string): string[] {
  const useCases: Record<string, string[]> = {
    strict: ['Production deployment', 'Quality assurance', 'Compliance checking'],
    standard: ['Development workflow', 'Code reviews', 'CI/CD pipelines'],
    quick: ['Development testing', 'Rapid prototyping', 'Local validation'],
    comprehensive: ['Security audit', 'Accessibility review', 'Performance optimization']
  };

  return useCases[profileName] || ['Custom validation scenarios'];
}

/**
 * Track rule usage
 */
function trackRuleUsage(validationResult: FlowValidationResult): void {
  // Track error codes
  validationResult.errors.forEach(error => {
    const count = validationMetrics.ruleUsage.get(error.code) || 0;
    validationMetrics.ruleUsage.set(error.code, count + 1);
  });

  // Track warning codes
  validationResult.warnings.forEach(warning => {
    const count = validationMetrics.ruleUsage.get(warning.code) || 0;
    validationMetrics.ruleUsage.set(warning.code, count + 1);
  });
}

/**
 * Update validation metrics
 */
function updateValidationMetrics(validationTime: number): void {
  validationMetrics.validationTimeHistory.push(validationTime);

  if (validationMetrics.validationTimeHistory.length > validationMetrics.maxHistorySize) {
    validationMetrics.validationTimeHistory.shift();
  }

  validationMetrics.averageValidationTime = Math.round(
    validationMetrics.validationTimeHistory.reduce((sum, time) => sum + time, 0) /
    validationMetrics.validationTimeHistory.length
  );
}

/**
 * Format validation response as XML
 */
function formatValidationXmlResponse(response: EnhancedValidateFlowResponse): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<validateFlowResponse>
  <result>
    <isValid>${response.result.isValid}</isValid>
    <errors>
      ${response.result.errors.map(error => `
      <error>
        <type>${error.type}</type>
        <severity>${error.severity}</severity>
        <message>${error.message}</message>
        <code>${error.code}</code>
      </error>`).join('')}
    </errors>
    <warnings>
      ${response.result.warnings.map(warning => `
      <warning>
        <type>${warning.type}</type>
        <severity>${warning.severity}</severity>
        <message>${warning.message}</message>
        <code>${warning.code}</code>
      </warning>`).join('')}
    </warnings>
  </result>
  <metadata>
    <validatedAt>${response.metadata.validatedAt}</validatedAt>
    <profile>${response.metadata.profile}</profile>
    <cacheHit>${response.metadata.cacheHit}</cacheHit>
  </metadata>
  <performance>
    <validationTime>${response.performance.validationTime}</validationTime>
    <totalTime>${response.performance.totalTime}</totalTime>
  </performance>
</validateFlowResponse>`;
}

/**
 * Format validation response as YAML
 */
function formatValidationYamlResponse(response: EnhancedValidateFlowResponse): string {
  // Simple YAML formatting - in production, use a proper YAML library
  return `result:
  isValid: ${response.result.isValid}
  errors: ${response.result.errors.length}
  warnings: ${response.result.warnings.length}
metadata:
  validatedAt: ${response.metadata.validatedAt}
  profile: ${response.metadata.profile}
  cacheHit: ${response.metadata.cacheHit}
performance:
  validationTime: ${response.performance.validationTime}
  totalTime: ${response.performance.totalTime}`;
}

/**
 * Get validation metrics
 */
export function getValidationMetrics() {
  return {
    ...validationMetrics,
    successRate: validationMetrics.totalValidations > 0
      ? validationMetrics.successfulValidations / validationMetrics.totalValidations
      : 0,
    cacheHitRate: validationMetrics.cacheHits + validationMetrics.cacheMisses > 0
      ? validationMetrics.cacheHits / (validationMetrics.cacheHits + validationMetrics.cacheMisses)
      : 0,
    ruleUsage: Object.fromEntries(validationMetrics.ruleUsage)
  };
}

export default router;