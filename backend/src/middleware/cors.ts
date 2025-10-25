/**
 * CORS Middleware Configuration
 *
 * Comprehensive Cross-Origin Resource Sharing middleware for the AutoApp
 * UI Map & Intelligent Flow Engine system. Supports remote Dockploy domain
 * access, development environments, and configurable security policies.
 *
 * Features:
 * - Remote Dockploy domain support
 * - Development localhost access
 * - Configurable allowed origins
 * - Proper preflight handling
 * - Credential management
 * - Environment-based configuration
 * - Security validation and logging
 *
 * @author AutoApp Team
 * @version 1.0.0
 */

import type { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { createServiceLogger } from '../services/logger';

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

/**
 * CORS configuration interface
 */
export interface CorsConfig {
  /** Allowed origins for cross-origin requests */
  allowedOrigins: string[];

  /** Whether to allow credentials (cookies, authorization headers) */
  credentials: boolean;

  /** Allowed HTTP methods */
  methods: string[];

  /** Allowed headers in requests */
  allowedHeaders: string[];

  /** Exposed headers for clients */
  exposedHeaders: string[];

  /** Preflight cache duration in seconds */
  maxAge: number;

  /** Whether to allow wildcard origins */
  allowWildcard: boolean;

  /** Pre-flight success status code */
  preflightStatus: number;

  /** Whether to log CORS requests */
  logRequests: boolean;

  /** Custom origin validation function */
  originValidator?: (origin: string, req: Request) => boolean;

  /** Development mode settings */
  development: {
    /** Allow wildcard origins in development */
    allowWildcardOrigins: boolean;
    /** Additional development origins */
    additionalOrigins: string[];
    /** Enable permissive logging */
    permissiveLogging: boolean;
  };

  /** Production mode settings */
  production: {
    /** Strict origin validation */
    strictOriginValidation: boolean;
    /** Rate limit for preflight requests */
    preflightRateLimit: number;
    /** Enforce HTTPS */
    enforceHttps: boolean;
  };
}

/**
 * CORS middleware options
 */
export interface CorsMiddlewareOptions {
  /** Custom configuration */
  config?: Partial<CorsConfig>;

  /** Environment override */
  environment?: 'development' | 'production' | 'test';

  /** Additional cors options to merge */
  [key: string]: any;
}

/**
 * CORS request context for logging
 */
export interface CorsRequestContext {
  /** Request origin */
  origin: string | undefined;

  /** Request method */
  method: string;

  /** Request headers */
  headers: Record<string, string>;

  /** User agent */
  userAgent: string;

  /** Request IP */
  ip: string;

  /** Timestamp */
  timestamp: string;

  /** Trace ID for request tracking */
  traceId: string;

  /** Whether request was allowed */
  allowed: boolean;

  /** Reason for decision */
  reason?: string;

  /** Response headers set */
  responseHeaders: Record<string, string>;
}

// =============================================================================
// LOGGER
// =============================================================================

const corsLogger = createServiceLogger('cors-middleware');

// =============================================================================
// CONFIGURATION LOADERS
// =============================================================================

/**
 * Parse comma-separated origins from environment variable
 */
function parseOrigins(envValue: string | undefined): string[] {
  if (!envValue || envValue.trim() === '') {
    return [];
  }

  return envValue
    .split(',')
    .map(origin => origin.trim())
    .filter(origin => origin.length > 0);
}

/**
 * Validate URL format for origins
 */
function validateOrigin(origin: string): boolean {
  if (origin === '*') return true;

  try {
    new URL(origin);
    return true;
  } catch {
    return false;
  }
}

/**
 * Load CORS configuration from environment
 */
export function loadCorsConfig(): CorsConfig {
  const environment = (process.env.NODE_ENV || 'development') as 'development' | 'production' | 'test';
  const isDevelopment = environment === 'development';
  const isProduction = environment === 'production';

  // Default development origins
  const defaultDevelopmentOrigins = [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:3001',
    'http://127.0.0.1:3001',
    'http://localhost:8080',
    'http://127.0.0.1:8080'
  ];

  // Default production origins (Dockploy domains)
  const defaultProductionOrigins = [
    // Add your Dockploy domains here
    'https://app.yourdomain.com',
    'https://autoapp.yourdomain.com'
  ];

  // Parse origins from environment
  const envOrigins = parseOrigins(process.env.CORS_ALLOWED_ORIGINS);
  const additionalOrigins = parseOrigins(process.env.CORS_ADDITIONAL_ORIGINS);

  // Determine allowed origins
  let allowedOrigins: string[] = [];

  if (process.env.CORS_ALLOWED_ORIGINS?.trim() === '*') {
    allowedOrigins = ['*'];
  } else if (envOrigins.length > 0) {
    allowedOrigins = envOrigins.filter(validateOrigin);
  } else {
    allowedOrigins = isDevelopment
      ? [...defaultDevelopmentOrigins, ...additionalOrigins]
      : [...defaultProductionOrigins, ...additionalOrigins];
  }

  // Parse methods
  const methods = process.env.CORS_METHODS
    ? process.env.CORS_METHODS.split(',').map(m => m.trim().toUpperCase())
    : ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

  // Parse headers
  const allowedHeaders = process.env.CORS_ALLOWED_HEADERS
    ? process.env.CORS_ALLOWED_HEADERS.split(',').map(h => h.trim())
    : [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'Accept',
        'Origin',
        'Access-Control-Request-Method',
        'Access-Control-Request-Headers',
        'X-API-Key',
        'X-Trace-ID'
      ];

  const exposedHeaders = process.env.CORS_EXPOSED_HEADERS
    ? process.env.CORS_EXPOSED_HEADERS.split(',').map(h => h.trim())
    : [
        'X-Total-Count',
        'X-Trace-ID',
        'X-Rate-Limit-Limit',
        'X-Rate-Limit-Remaining',
        'X-Rate-Limit-Reset'
      ];

  const config: CorsConfig = {
    allowedOrigins,
    credentials: process.env.CORS_CREDENTIALS !== 'false',
    methods,
    allowedHeaders,
    exposedHeaders,
    maxAge: parseInt(process.env.CORS_MAX_AGE || '86400', 10), // 24 hours
    allowWildcard: process.env.CORS_ALLOW_WILDCARD === 'true',
    preflightStatus: parseInt(process.env.CORS_PREFLIGHT_STATUS || '204', 10),
    logRequests: process.env.CORS_LOG_REQUESTS !== 'false',
    development: {
      allowWildcardOrigins: isDevelopment || process.env.CORS_DEV_ALLOW_WILDCARD === 'true',
      additionalOrigins,
      permissiveLogging: isDevelopment || process.env.CORS_DEV_PERMISSIVE_LOGGING === 'true'
    },
    production: {
      strictOriginValidation: isProduction || process.env.CORS_PROD_STRICT_VALIDATION === 'true',
      preflightRateLimit: parseInt(process.env.CORS_PROD_PREFLIGHT_RATE_LIMIT || '100', 10),
      enforceHttps: isProduction || process.env.CORS_PROD_ENFORCE_HTTPS === 'true'
    }
  };

  corsLogger.info('cors_config_loaded', `CORS configuration loaded for ${environment}`, undefined, {
    environment,
    allowedOriginsCount: allowedOrigins.length,
    allowedOrigins: allowedOrigins.slice(0, 5), // Log first 5 for brevity
    credentials: config.credentials,
    methodsCount: methods.length,
    logRequests: config.logRequests
  });

  return config;
}

// =============================================================================
// ORIGIN VALIDATION
// =============================================================================

/**
 * Check if origin is allowed based on configuration
 */
export function isOriginAllowed(
  origin: string | undefined,
  config: CorsConfig,
  req: Request
): { allowed: boolean; reason?: string } {
  // No origin header - allow for same-origin requests
  if (!origin) {
    return { allowed: true, reason: 'No origin header (same-origin request)' };
  }

  // Wildcard allowed
  if (config.allowWildcard && config.allowedOrigins.includes('*')) {
    if (config.production.enforceHttps && !origin.startsWith('https://') && !origin.startsWith('http://localhost')) {
      return { allowed: false, reason: 'HTTPS required in production' };
    }
    return { allowed: true, reason: 'Wildcard origin allowed' };
  }

  // Custom validator
  if (config.originValidator) {
    try {
      const allowed = config.originValidator(origin, req);
      return {
        allowed,
        reason: allowed ? 'Custom validator allowed' : 'Custom validator rejected'
      };
    } catch (error) {
      corsLogger.error('origin_validator_error', 'Custom origin validator failed', error as Error);
      return { allowed: false, reason: 'Custom validator error' };
    }
  }

  // Exact match
  if (config.allowedOrigins.includes(origin)) {
    return { allowed: true, reason: 'Exact origin match' };
  }

  // Subdomain matching for production
  if (config.production.strictOriginValidation) {
    for (const allowedOrigin of config.allowedOrigins) {
      if (allowedOrigin.startsWith('https://') && origin.startsWith('https://')) {
        const allowedDomain = allowedOrigin.replace('https://', '');
        const requestDomain = origin.replace('https://', '');

        // Allow subdomains
        if (requestDomain.endsWith(`.${allowedDomain}`) || requestDomain === allowedDomain) {
          return { allowed: true, reason: 'Subdomain match' };
        }
      }
    }
  }

  // Development additional origins
  if (config.development.additionalOrigins.includes(origin)) {
    return { allowed: true, reason: 'Development additional origin' };
  }

  // Development wildcard
  if (config.development.allowWildcardOrigins && (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1'))) {
    return { allowed: true, reason: 'Development localhost wildcard' };
  }

  return { allowed: false, reason: 'Origin not in allowed list' };
}

// =============================================================================
// REQUEST LOGGING
// =============================================================================

/**
 * Create CORS request context for logging
 */
function createCorsContext(
  req: Request,
  res: Response,
  allowed: boolean,
  reason?: string
): CorsRequestContext {
  const headers: Record<string, string> = {};

  // Extract relevant headers
  const relevantHeaders = [
    'origin',
    'access-control-request-method',
    'access-control-request-headers',
    'user-agent',
    'referer',
    'accept'
  ];

  relevantHeaders.forEach(header => {
    const value = req.get(header);
    if (value) {
      headers[header] = value;
    }
  });

  // Get response headers
  const responseHeaders: Record<string, string> = {};
  const headerNames = res.getHeaderNames();
  headerNames.forEach(name => {
    const value = res.getHeader(name);
    if (typeof value === 'string') {
      responseHeaders[name] = value;
    }
  });

  return {
    origin: req.get('origin'),
    method: req.method,
    headers,
    userAgent: req.get('user-agent') || 'unknown',
    ip: req.ip || req.connection.remoteAddress || 'unknown',
    timestamp: new Date().toISOString(),
    traceId: req.get('x-trace-id') || corsLogger.generateTraceId(),
    allowed,
    reason,
    responseHeaders
  };
}

/**
 * Log CORS request
 */
function logCorsRequest(context: CorsRequestContext): void {
  const level = context.allowed ? 'info' : 'warn';
  const message = context.allowed
    ? `CORS request allowed: ${context.method} ${context.origin}`
    : `CORS request blocked: ${context.method} ${context.origin}`;

  corsLogger[level]('cors_request', message, context.traceId, {
    origin: context.origin,
    method: context.method,
    userAgent: context.userAgent,
    ip: context.ip,
    allowed: context.allowed,
    reason: context.reason,
    headers: Object.keys(context.headers).length
  });
}

// =============================================================================
// MIDDLEWARE FACTORY
// =============================================================================

/**
 * Create CORS middleware with configuration
 */
export function createCorsMiddleware(options: CorsMiddlewareOptions = {}) {
  const config = { ...loadCorsConfig(), ...options.config };
  const environment = options.environment || (process.env.NODE_ENV as any) || 'development';

  corsLogger.info('cors_middleware_created', 'CORS middleware initialized', undefined, {
    environment,
    allowedOriginsCount: config.allowedOrigins.length,
    credentials: config.credentials,
    logRequests: config.logRequests
  });

  // Create CORS options
  const corsOptions: any = {
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
      // Create a minimal mock request for origin validation
      const mockReq = {
        get: (header: string) => header === 'origin' ? origin : undefined
      } as Request;

      const result = isOriginAllowed(origin, config, mockReq);

      // Log request if enabled
      if (config.logRequests) {
        const context = createCorsContext(
          mockReq,
          {} as Response,
          result.allowed,
          result.reason
        );
        logCorsRequest(context);
      }

      callback(null, result.allowed);
    },

    methods: config.methods,

    allowedHeaders: config.allowedHeaders,

    exposedHeaders: config.exposedHeaders,

    credentials: config.credentials,

    maxAge: config.maxAge,

    optionsSuccessStatus: config.preflightStatus,

    preflightContinue: false,

    ...options // Allow overriding cors options
  };

  // Return the cors middleware with additional logging
  return (req: Request, res: Response, next: NextFunction) => {
    // Add trace ID if not present
    const traceId = req.get('x-trace-id') || corsLogger.generateTraceId();
    req.headers['x-trace-id'] = traceId;

    // Start timer for performance monitoring
    const timer = corsLogger.startTimer('cors_request', traceId, {
      method: req.method,
      origin: req.get('origin'),
      path: req.path
    });

    // Apply CORS middleware
    cors(corsOptions)(req, res, (error) => {
      if (error) {
        corsLogger.error('cors_middleware_error', 'CORS middleware failed', error, traceId, {
          method: req.method,
          origin: req.get('origin'),
          path: req.path
        });
        return next(error);
      }

      // Log successful request
      if (config.logRequests) {
        const context = createCorsContext(req, res, true, 'CORS headers applied');
        logCorsRequest(context);
      }

      timer.end({ success: true });
      next();
    });
  };
}

// =============================================================================
// EXPRESS MIDDLEWARE
// =============================================================================

/**
 * CORS middleware with default configuration
 */
export const corsMiddleware = createCorsMiddleware();

/**
 * Development-specific CORS middleware (more permissive)
 */
export const developmentCorsMiddleware = createCorsMiddleware({
  environment: 'development',
  config: {
    logRequests: true,
    allowWildcard: true,
    credentials: true
  }
});

/**
 * Production-specific CORS middleware (strict)
 */
export const productionCorsMiddleware = createCorsMiddleware({
  environment: 'production',
  config: {
    logRequests: false,
    allowWildcard: false,
    credentials: false
  }
});

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Get current CORS configuration
 */
export function getCorsConfig(): CorsConfig {
  return loadCorsConfig();
}

/**
 * Validate CORS configuration
 */
export function validateCorsConfig(config: CorsConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Validate origins
  if (config.allowedOrigins.length === 0 && !config.allowWildcard) {
    errors.push('No allowed origins configured and wildcard not allowed');
  }

  for (const origin of config.allowedOrigins) {
    if (origin !== '*' && !validateOrigin(origin)) {
      errors.push(`Invalid origin format: ${origin}`);
    }
  }

  // Validate methods
  if (config.methods.length === 0) {
    errors.push('No HTTP methods allowed');
  }

  // Validate max age
  if (config.maxAge < 0 || config.maxAge > 86400) {
    errors.push('Max age must be between 0 and 86400 seconds');
  }

  // Validate preflight status
  if (config.preflightStatus < 200 || config.preflightStatus >= 600) {
    errors.push('Preflight status must be a valid HTTP status code (200-599)');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * CORS health check for monitoring
 */
export function corsHealthCheck(): { healthy: boolean; config: any } {
  const config = loadCorsConfig();
  const validation = validateCorsConfig(config);

  return {
    healthy: validation.valid,
    config: {
      allowedOriginsCount: config.allowedOrigins.length,
      credentials: config.credentials,
      methodsCount: config.methods.length,
      logRequests: config.logRequests,
      environment: process.env.NODE_ENV || 'development'
    }
  };
}

// =============================================================================
// DEFAULT EXPORTS
// =============================================================================

// Export everything that needs to be used by other modules