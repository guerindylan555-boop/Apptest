/**
 * Flow List API Routes (T046)
 *
 * Comprehensive REST API endpoints for flow listing with advanced filtering,
 * pagination, and search capabilities. Provides efficient flow discovery and
 * management with performance optimization and monitoring.
 *
 * Features:
 * - Advanced filtering by package, category, tags, author, status
 * - Flexible sorting by name, created, updated, usage, success-rate
 * - Full-text search across flow metadata
 * - Pagination with configurable limits
 * - Performance monitoring and caching
 * - Rate limiting and security
 * - Comprehensive error handling
 * - Response format negotiation (JSON, XML)
 */

import { Router, Request, Response, NextFunction } from 'express';
import { FlowService } from '../services/flowService';
import { FlowValidationService } from '../services/flowValidationService';
import {
  ListFlowsRequest,
  ListFlowsResponse,
  FlowDefinition,
  FlowError
} from '../types/flow';

const router = Router();

// Extended Request interface for custom properties
interface EnhancedRequest extends Request {
  requestId?: string;
  cacheKey?: string;
}

// Performance tracking
const performanceMetrics = {
  requestCount: 0,
  averageResponseTime: 0,
  responseTimeHistory: [] as number[],
  cacheHits: 0,
  cacheMisses: 0,
  maxHistorySize: 100
};

// Request cache for frequently accessed data
const requestCache = new Map<string, { data: any; timestamp: number; ttl: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Rate limiting configuration
const RATE_LIMITS = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 100, // limit each IP to 100 requests per windowMs
  successfulRequests: new Map<string, { count: number; resetTime: number }>()
};

/**
 * Flow list request interface with extended filtering options
 */
interface FlowListRequest extends ListFlowsRequest {
  /** Extended filter options */
  filter?: {
    /** Package name filter */
    package?: string;

    /** Category filter */
    category?: string;

    /** Tag filter */
    tags?: string[];

    /** Author filter */
    author?: string;

    /** Status filter (active, inactive, draft, published) */
    status?: 'active' | 'inactive' | 'draft' | 'published';

    /** Complexity range filter */
    complexity?: {
      min?: number;
      max?: number;
    };

    /** Success rate range filter */
    successRate?: {
      min?: number;
      max?: number;
    };

    /** Date range filter */
    dateRange?: {
      from?: string;
      to?: string;
    };

    /** Full-text search query */
    search?: string;
  };

  /** Extended sort options */
  sort?: {
    field: 'name' | 'createdAt' | 'updatedAt' | 'successRate' | 'executionCount' | 'complexity' | 'duration';
    order: 'asc' | 'desc';
  };

  /** Response format */
  format?: 'json' | 'xml';

  /** Include options */
  include?: {
    statistics?: boolean;
    executionHistory?: boolean;
    validationResults?: boolean;
  };
}

/**
 * Flow list response with additional metadata
 */
interface FlowListResponse extends ListFlowsResponse {
  /** Performance metrics */
  performance?: {
    responseTime: number;
    cacheHit: boolean;
    totalFlows: number;
    filteredFlows: number;
  };

  /** Available filters */
  availableFilters?: {
    packages: string[];
    authors: string[];
    tags: string[];
    categories: string[];
  };

  /** Search suggestions */
  suggestions?: string[];
}

/**
 * Enhanced error response with context
 */
interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    requestId: string;
  };
  performance?: {
    responseTime: number;
  };
}

/**
 * Middleware for request logging and monitoring
 */
function requestLogger(req: EnhancedRequest, res: Response, next: NextFunction): void {
  const startTime = Date.now();
  const requestId = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  // Attach request ID to response headers
  res.setHeader('X-Request-ID', requestId);
  req.requestId = requestId;

  // Log request start
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    requestId,
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    event: 'flow_list_request_start'
  }));

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk?: any, encoding?: any) {
    const responseTime = Date.now() - startTime;

    // Update performance metrics
    updatePerformanceMetrics(responseTime);

    // Log request completion
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      event: 'flow_list_request_complete'
    }));

    // Add response time header
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    originalEnd.call(this, chunk, encoding);
  };

  next();
}

/**
 * Rate limiting middleware
 */
function rateLimiter(req: EnhancedRequest, res: Response, next: NextFunction): void {
  const clientIp = req.ip || 'unknown';
  const now = Date.now();

  // Clean up expired entries
  for (const [ip, data] of RATE_LIMITS.successfulRequests.entries()) {
    if (now > data.resetTime) {
      RATE_LIMITS.successfulRequests.delete(ip);
    }
  }

  // Check current usage
  const clientUsage = RATE_LIMITS.successfulRequests.get(clientIp);

  if (clientUsage && clientUsage.count >= RATE_LIMITS.maxRequests) {
    const resetIn = Math.ceil((clientUsage.resetTime - now) / 1000);

    return res.status(429).json({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Rate limit exceeded. Try again in ${resetIn} seconds.`,
        details: {
          limit: RATE_LIMITS.maxRequests,
          windowMs: RATE_LIMITS.windowMs,
          resetIn
        },
        timestamp: new Date().toISOString(),
        requestId: req.requestId
      }
    } as ErrorResponse);
  }

  // Update usage
  if (clientUsage) {
    clientUsage.count++;
  } else {
    RATE_LIMITS.successfulRequests.set(clientIp, {
      count: 1,
      resetTime: now + RATE_LIMITS.windowMs
    });
  }

  next();
}

/**
 * Cache middleware for GET requests
 */
function cacheMiddleware(req: EnhancedRequest, res: Response, next: NextFunction): void {
  if (req.method !== 'GET') {
    return next();
  }

  const cacheKey = generateCacheKey(req);
  const cached = requestCache.get(cacheKey);

  if (cached && Date.now() < cached.timestamp + cached.ttl) {
    performanceMetrics.cacheHits++;

    // Add cache headers
    res.setHeader('X-Cache', 'HIT');
    res.setHeader('X-Cache-Age', Math.floor((Date.now() - cached.timestamp) / 1000));

    return res.json(cached.data);
  }

  performanceMetrics.cacheMisses++;
  res.setHeader('X-Cache', 'MISS');

  next();
}

/**
 * Generate cache key from request
 */
function generateCacheKey(req: EnhancedRequest): string {
  const url = req.url;
  const query = JSON.stringify(req.query);
  const headers = JSON.stringify({
    accept: req.get('Accept'),
    'accept-language': req.get('Accept-Language')
  });

  return Buffer.from(`${url}:${query}:${headers}`).toString('base64');
}

/**
 * Update performance metrics
 */
function updatePerformanceMetrics(responseTime: number): void {
  performanceMetrics.requestCount++;
  performanceMetrics.responseTimeHistory.push(responseTime);

  // Keep only last N measurements
  if (performanceMetrics.responseTimeHistory.length > performanceMetrics.maxHistorySize) {
    performanceMetrics.responseTimeHistory.shift();
  }

  // Calculate average
  performanceMetrics.averageResponseTime = Math.round(
    performanceMetrics.responseTimeHistory.reduce((sum, time) => sum + time, 0) /
    performanceMetrics.responseTimeHistory.length
  );
}

/**
 * Store response in cache
 */
function storeInCache(key: string, data: any, ttl: number = CACHE_TTL): void {
  requestCache.set(key, {
    data,
    timestamp: Date.now(),
    ttl
  });

  // Clean old cache entries periodically
  if (requestCache.size > 100) {
    const now = Date.now();
    for (const [cacheKey, entry] of requestCache.entries()) {
      if (now > entry.timestamp + entry.ttl) {
        requestCache.delete(cacheKey);
      }
    }
  }
}

/**
 * Initialize services (to be injected by the main app)
 */
let flowService: FlowService;
let flowValidationService: FlowValidationService;

export function initializeFlowsListRoutes(
  flowSvc: FlowService,
  flowValidationSvc: FlowValidationService
): Router {
  flowService = flowSvc;
  flowValidationService = flowValidationSvc;

  // Apply middleware
  router.use(requestLogger);
  router.use(rateLimiter);
  router.use(cacheMiddleware);

  return router;
}

/**
 * GET /api/flows - List flows with comprehensive filtering and pagination
 *
 * This endpoint provides advanced flow listing capabilities with:
 * - Multi-dimensional filtering (package, tags, author, status, etc.)
 * - Flexible sorting options
 * - Full-text search
 * - Pagination with customizable limits
 * - Performance monitoring and caching
 * - Rate limiting and security
 *
 * @queryparam package - Filter by package name
 * @queryparam category - Filter by flow category
 * @queryparam tags - Filter by tags (comma-separated)
 * @queryparam author - Filter by author
 * @queryparam status - Filter by status (active, inactive, draft, published)
 * @queryparam search - Full-text search query
 * @queryparam sort_by - Sort field (name, createdAt, updatedAt, successRate, executionCount, complexity, duration)
 * @queryparam sort_order - Sort order (asc, desc)
 * @queryparam page - Page number (default: 1)
 * @queryparam limit - Results per page (default: 50, max: 200)
 * @queryparam format - Response format (json, xml)
 * @queryparam include - Include additional data (statistics, executionHistory, validationResults)
 *
 * @example
 * // Get all flows for a specific package
 * GET /api/flows?package=com.example.app
 *
 * // Search flows with pagination
 * GET /api/flows?search=login&page=2&limit=25
 *
 * // Get flows sorted by success rate
 * GET /api/flows?sort_by=successRate&sort_order=desc
 *
 * // Complex filtering
 * GET /api/flows?tags=login,authentication&author=john&status=published
 */
router.get('/', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    // Parse and validate request parameters
    const listRequest = parseListRequest(req);

    // Validate pagination limits
    if (listRequest.pagination && listRequest.pagination.limit > 200) {
      return res.status(400).json({
        error: {
          code: 'INVALID_PAGINATION_LIMIT',
          message: 'Pagination limit cannot exceed 200',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as ErrorResponse);
    }

    // Get flows from service
    const serviceResult = await flowService.listFlows(listRequest);

    // Build response with additional metadata
    const response: FlowListResponse = {
      flows: serviceResult.flows,
      pagination: {
        page: listRequest.pagination?.page || 1,
        limit: listRequest.pagination?.limit || 50,
        total: serviceResult.total,
        pages: Math.ceil(serviceResult.total / (listRequest.pagination?.limit || 50))
      },
      summary: calculateSummary(serviceResult.flows, serviceResult.total),
      performance: {
        responseTime: Date.now() - startTime,
        cacheHit: res.get('X-Cache') === 'HIT',
        totalFlows: serviceResult.total,
        filteredFlows: serviceResult.flows.length
      }
    };

    // Add additional data if requested
    if (listRequest.include?.statistics) {
      response.availableFilters = await getAvailableFilters();
    }

    if (listRequest.include?.validationResults) {
      // Add validation results for each flow
      response.flows = await enrichWithValidationResults(response.flows);
    }

    // Format response if requested
    if (listRequest.format === 'xml') {
      res.setHeader('Content-Type', 'application/xml');
      return res.send(formatXmlResponse(response));
    }

    // Cache successful responses
    const cacheKey = generateCacheKey(req);
    storeInCache(cacheKey, response);

    // Log successful request
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_list_success',
      flowCount: serviceResult.flows.length,
      totalFlows: serviceResult.total,
      responseTime: `${Date.now() - startTime}ms`,
      filter: listRequest.filter,
      sort: listRequest.sort
    }));

    res.json(response);

  } catch (error) {
    const responseTime = Date.now() - startTime;

    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_list_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
      responseTime: `${responseTime}ms`
    }));

    const errorResponse: ErrorResponse = {
      error: {
        code: 'FLOW_LIST_ERROR',
        message: 'Failed to retrieve flows',
        details: {
          originalError: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: new Date().toISOString(),
        requestId
      },
      performance: {
        responseTime
      }
    };

    res.status(500).json(errorResponse);
  }
});

/**
 * GET /api/flows/search - Advanced search with suggestions
 *
 * Enhanced search endpoint with auto-complete suggestions and
 * relevance scoring for better user experience.
 *
 * @queryparam q - Search query
 * @queryparam limit - Maximum number of suggestions (default: 10)
 * @queryparam include_suggestions - Include search suggestions (default: true)
 */
router.get('/search', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    const query = req.query.q as string;
    const limit = parseInt(req.query.limit as string) || 10;
    const includeSuggestions = req.query.include_suggestions !== 'false';

    if (!query || query.trim().length === 0) {
      return res.status(400).json({
        error: {
          code: 'MISSING_SEARCH_QUERY',
          message: 'Search query is required',
          timestamp: new Date().toISOString(),
          requestId
        }
      } as ErrorResponse);
    }

    // Perform search
    const searchRequest: ListFlowsRequest = {
      filter: { search: query.trim() },
      pagination: { page: 1, limit: Math.min(limit, 100) },
      sort: { field: 'name', order: 'asc' }
    };

    const searchResult = await flowService.listFlows(searchRequest);

    // Generate suggestions if requested
    let suggestions: string[] = [];
    if (includeSuggestions) {
      suggestions = await generateSearchSuggestions(query);
    }

    const response = {
      query,
      flows: searchResult.flows,
      total: searchResult.total,
      suggestions,
      performance: {
        responseTime: Date.now() - startTime,
        resultsCount: searchResult.flows.length
      }
    };

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_search_error',
      error: error instanceof Error ? error.message : 'Unknown error',
      query: req.query.q
    }));

    res.status(500).json({
      error: {
        code: 'FLOW_SEARCH_ERROR',
        message: 'Search failed',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as ErrorResponse);
  }
});

/**
 * GET /api/flows/filters - Get available filter options
 *
 * Returns available values for filtering flows, useful for
 * building filter UI components.
 */
router.get('/filters', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    const filters = await getAvailableFilters();

    const response = {
      filters,
      performance: {
        responseTime: Date.now() - startTime
      }
    };

    // Cache filter data longer since it changes less frequently
    const cacheKey = `filters:${requestId}`;
    storeInCache(cacheKey, response, 10 * 60 * 1000); // 10 minutes

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_filters_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }));

    res.status(500).json({
      error: {
        code: 'FLOW_FILTERS_ERROR',
        message: 'Failed to retrieve filters',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as ErrorResponse);
  }
});

/**
 * GET /api/flows/stats - Get flow statistics and metrics
 *
 * Returns comprehensive statistics about flows including
 * usage patterns, success rates, and performance metrics.
 */
router.get('/stats', async (req: Request, res: Response) => {
  const startTime = Date.now();
  const requestId = req.requestId || 'unknown';

  try {
    // Get all flows for statistics
    const allFlowsResult = await flowService.listFlows({
      pagination: { page: 1, limit: 1000 }
    });

    const stats = calculateFlowStatistics(allFlowsResult.flows);

    const response = {
      statistics: stats,
      performance: {
        responseTime: Date.now() - startTime,
        totalFlowsAnalyzed: allFlowsResult.flows.length
      }
    };

    // Cache statistics for a reasonable period
    const cacheKey = `stats:${requestId}`;
    storeInCache(cacheKey, response, 5 * 60 * 1000); // 5 minutes

    res.json(response);

  } catch (error) {
    console.error(JSON.stringify({
      timestamp: new Date().toISOString(),
      requestId,
      event: 'flow_stats_error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }));

    res.status(500).json({
      error: {
        code: 'FLOW_STATS_ERROR',
        message: 'Failed to retrieve statistics',
        timestamp: new Date().toISOString(),
        requestId
      }
    } as ErrorResponse);
  }
});

/**
 * Parse and validate list request from Express request
 */
function parseListRequest(req: EnhancedRequest): FlowListRequest {
  const query = req.query;

  const listRequest: FlowListRequest = {
    filter: {},
    sort: {
      field: 'name',
      order: 'asc'
    },
    pagination: {
      page: 1,
      limit: 50
    }
  };

  // Parse filters
  if (query.package) listRequest.filter!.package = query.package as string;
  if (query.category) listRequest.filter!.category = query.category as string;
  if (query.author) listRequest.filter!.author = query.author as string;
  if (query.status) listRequest.filter!.status = query.status as any;
  if (query.search) listRequest.filter!.search = query.search as string;

  // Parse tags (comma-separated)
  if (query.tags) {
    listRequest.filter!.tags = (query.tags as string).split(',').map(tag => tag.trim());
  }

  // Parse complexity range
  if (query.complexity_min || query.complexity_max) {
    listRequest.filter!.complexity = {
      min: query.complexity_min ? parseInt(query.complexity_min as string) : undefined,
      max: query.complexity_max ? parseInt(query.complexity_max as string) : undefined
    };
  }

  // Parse success rate range
  if (query.success_rate_min || query.success_rate_max) {
    listRequest.filter!.successRate = {
      min: query.success_rate_min ? parseFloat(query.success_rate_min as string) : undefined,
      max: query.success_rate_max ? parseFloat(query.success_rate_max as string) : undefined
    };
  }

  // Parse date range
  if (query.date_from || query.date_to) {
    listRequest.filter!.dateRange = {
      from: query.date_from as string,
      to: query.date_to as string
    };
  }

  // Parse sorting
  if (query.sort_by) {
    const validFields = ['name', 'createdAt', 'updatedAt', 'successRate', 'executionCount', 'complexity', 'duration'];
    if (validFields.includes(query.sort_by as string)) {
      listRequest.sort!.field = query.sort_by as any;
    }
  }

  if (query.sort_order && ['asc', 'desc'].includes(query.sort_order as string)) {
    listRequest.sort!.order = query.sort_order as any;
  }

  // Parse pagination
  if (query.page) {
    const page = parseInt(query.page as string);
    if (page > 0) listRequest.pagination!.page = page;
  }

  if (query.limit) {
    const limit = parseInt(query.limit as string);
    if (limit > 0 && limit <= 200) listRequest.pagination!.limit = limit;
  }

  // Parse format
  if (query.format && ['json', 'xml'].includes(query.format as string)) {
    (listRequest as any).format = query.format;
  }

  // Parse include options
  if (query.include) {
    const includeOptions = (query.include as string).split(',');
    (listRequest as any).include = {
      statistics: includeOptions.includes('statistics'),
      executionHistory: includeOptions.includes('executionHistory'),
      validationResults: includeOptions.includes('validationResults')
    };
  }

  return listRequest;
}

/**
 * Calculate summary statistics for flows
 */
function calculateSummary(flows: FlowDefinition[], total: number) {
  const successRates = flows
    .filter(f => f.metadata.successRate !== undefined)
    .map(f => f.metadata.successRate!);

  const complexities = flows
    .filter(f => f.metadata.complexity !== undefined)
    .map(f => f.metadata.complexity!);

  return {
    totalFlows: total,
    filteredFlows: flows.length,
    averageSuccessRate: successRates.length > 0
      ? successRates.reduce((sum, rate) => sum + rate, 0) / successRates.length
      : 0,
    averageComplexity: complexities.length > 0
      ? complexities.reduce((sum, complexity) => sum + complexity, 0) / complexities.length
      : 0
  };
}

/**
 * Get available filter options from existing flows
 */
async function getAvailableFilters(): Promise<any> {
  try {
    const allFlowsResult = await flowService.listFlows({
      pagination: { page: 1, limit: 1000 }
    });

    const packages = [...new Set(allFlowsResult.flows.map(f => f.packageName))];
    const authors = [...new Set(allFlowsResult.flows
      .map(f => f.metadata.author)
      .filter(Boolean))];
    const tags = [...new Set(allFlowsResult.flows
      .flatMap(f => f.metadata.tags || []))];

    return {
      packages: packages.sort(),
      authors: authors.sort(),
      tags: tags.sort(),
      categories: ['login', 'navigation', 'form', 'search', 'custom'] // TODO: Make dynamic
    };
  } catch (error) {
    console.error('Failed to get available filters:', error);
    return {
      packages: [],
      authors: [],
      tags: [],
      categories: []
    };
  }
}

/**
 * Generate search suggestions based on query
 */
async function generateSearchSuggestions(query: string): Promise<string[]> {
  try {
    const allFlowsResult = await flowService.listFlows({
      pagination: { page: 1, limit: 100 }
    });

    const suggestions = new Set<string>();
    const lowerQuery = query.toLowerCase();

    // Add matching flow names
    allFlowsResult.flows.forEach(flow => {
      if (flow.name.toLowerCase().includes(lowerQuery)) {
        suggestions.add(flow.name);
      }
    });

    // Add matching tags
    allFlowsResult.flows.forEach(flow => {
      flow.metadata.tags?.forEach(tag => {
        if (tag.toLowerCase().includes(lowerQuery)) {
          suggestions.add(tag);
        }
      });
    });

    // Add matching package names
    allFlowsResult.flows.forEach(flow => {
      if (flow.packageName.toLowerCase().includes(lowerQuery)) {
        suggestions.add(flow.packageName);
      }
    });

    return Array.from(suggestions).slice(0, 10);
  } catch (error) {
    console.error('Failed to generate search suggestions:', error);
    return [];
  }
}

/**
 * Enrich flows with validation results
 */
async function enrichWithValidationResults(flows: FlowDefinition[]): Promise<FlowDefinition[]> {
  try {
    // For performance, only validate a subset of flows
    const flowsToValidate = flows.slice(0, 10);

    const enrichedFlows = await Promise.all(
      flowsToValidate.map(async (flow) => {
        try {
          const validation = await flowService.validateFlow({ flow });
          return {
            ...flow,
            validation
          };
        } catch (error) {
          console.error(`Failed to validate flow ${flow.id}:`, error);
          return flow;
        }
      })
    );

    // Combine validated flows with remaining ones
    return [...enrichedFlows, ...flows.slice(10)];
  } catch (error) {
    console.error('Failed to enrich flows with validation results:', error);
    return flows;
  }
}

/**
 * Calculate comprehensive flow statistics
 */
function calculateFlowStatistics(flows: FlowDefinition[]): any {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  const recentFlows = flows.filter(f => new Date(f.metadata.createdAt) > thirtyDaysAgo);
  const publishedFlows = flows.filter(f => f.metadata.tags?.includes('published'));
  const draftFlows = flows.filter(f => f.metadata.tags?.includes('draft'));

  const successRates = flows
    .filter(f => f.metadata.successRate !== undefined)
    .map(f => f.metadata.successRate!);

  const complexities = flows
    .filter(f => f.metadata.complexity !== undefined)
    .map(f => f.metadata.complexity!);

  const executionCounts = flows
    .filter(f => f.metadata.executionCount !== undefined)
    .map(f => f.metadata.executionCount!);

  return {
    overview: {
      totalFlows: flows.length,
      recentFlows: recentFlows.length,
      publishedFlows: publishedFlows.length,
      draftFlows: draftFlows.length
    },
    performance: {
      averageSuccessRate: successRates.length > 0
        ? successRates.reduce((sum, rate) => sum + rate, 0) / successRates.length
        : 0,
      averageComplexity: complexities.length > 0
        ? complexities.reduce((sum, complexity) => sum + complexity, 0) / complexities.length
        : 0,
      totalExecutions: executionCounts.reduce((sum, count) => sum + count, 0)
    },
    distribution: {
      byComplexity: {
        low: complexities.filter(c => c < 20).length,
        medium: complexities.filter(c => c >= 20 && c < 50).length,
        high: complexities.filter(c => c >= 50).length
      },
      bySuccessRate: {
        excellent: successRates.filter(r => r >= 0.9).length,
        good: successRates.filter(r => r >= 0.7 && r < 0.9).length,
        needsImprovement: successRates.filter(r => r < 0.7).length
      }
    }
  };
}

/**
 * Format response as XML
 */
function formatXmlResponse(data: any): string {
  // Simple XML formatter - in production, use a proper XML library
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<flowListResponse>
  <flows>
    ${data.flows.map((flow: any) => `
    <flow>
      <id>${flow.id}</id>
      <name>${flow.name}</name>
      <packageName>${flow.packageName}</packageName>
      <description>${flow.description || ''}</description>
      <version>${flow.version}</version>
      <metadata>
        <createdAt>${flow.metadata.createdAt}</createdAt>
        <updatedAt>${flow.metadata.updatedAt}</updatedAt>
        <author>${flow.metadata.author || ''}</author>
        <complexity>${flow.metadata.complexity || 0}</complexity>
        <successRate>${flow.metadata.successRate || 0}</successRate>
        <executionCount>${flow.metadata.executionCount || 0}</executionCount>
      </metadata>
    </flow>`).join('')}
  </flows>
  <pagination>
    <page>${data.pagination.page}</page>
    <limit>${data.pagination.limit}</limit>
    <total>${data.pagination.total}</total>
    <pages>${data.pagination.pages}</pages>
  </pagination>
  <summary>
    <totalFlows>${data.summary.totalFlows}</totalFlows>
    <filteredFlows>${data.summary.filteredFlows}</filteredFlows>
    <averageSuccessRate>${data.summary.averageSuccessRate}</averageSuccessRate>
    <averageComplexity>${data.summary.averageComplexity}</averageComplexity>
  </summary>
  <performance>
    <responseTime>${data.performance.responseTime}</responseTime>
    <cacheHit>${data.performance.cacheHit}</cacheHit>
  </performance>
</flowListResponse>`;

  return xml;
}

/**
 * Get performance metrics
 */
export function getPerformanceMetrics() {
  return {
    ...performanceMetrics,
    cacheHitRate: performanceMetrics.cacheHits / (performanceMetrics.cacheHits + performanceMetrics.cacheMisses) || 0
  };
}

export default router;