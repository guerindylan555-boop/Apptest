import { Router } from 'express';
import { corsHealthCheck, getCorsConfig } from '../../middleware/cors';

const router = Router();

/**
 * GET /api/cors/health
 * CORS middleware health check endpoint
 * Returns the current CORS configuration and validation status
 */
router.get('/health', (req, res) => {
  try {
    const health = corsHealthCheck();
    const config = getCorsConfig();

    const response = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      cors: {
        healthy: health.healthy,
        config: {
          environment: process.env.NODE_ENV || 'development',
          allowedOriginsCount: config.allowedOrigins.length,
          allowedOrigins: config.allowedOrigins.slice(0, 10), // Limit to first 10 for brevity
          credentials: config.credentials,
          methodsCount: config.methods.length,
          methods: config.methods,
          allowedHeadersCount: config.allowedHeaders.length,
          maxAge: config.maxAge,
          logRequests: config.logRequests,
          development: {
            allowWildcardOrigins: config.development.allowWildcardOrigins,
            additionalOriginsCount: config.development.additionalOrigins.length
          },
          production: {
            strictOriginValidation: config.production.strictOriginValidation,
            preflightRateLimit: config.production.preflightRateLimit,
            enforceHttps: config.production.enforceHttps
          }
        }
      },
      request: {
        origin: req.get('origin'),
        method: req.method,
        userAgent: req.get('user-agent'),
        ip: req.ip
      }
    };

    res.status(health.healthy ? 200 : 503).json(response);
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to get CORS health status',
      error: (error as Error).message
    });
  }
});

/**
 * GET /api/cors/config
 * Returns current CORS configuration (admin endpoint)
 */
router.get('/config', (req, res) => {
  try {
    const config = getCorsConfig();

    // Sanitize config for response (remove sensitive data if any)
    const sanitizedConfig = {
      allowedOrigins: config.allowedOrigins,
      credentials: config.credentials,
      methods: config.methods,
      allowedHeaders: config.allowedHeaders,
      exposedHeaders: config.exposedHeaders,
      maxAge: config.maxAge,
      allowWildcard: config.allowWildcard,
      preflightStatus: config.preflightStatus,
      logRequests: config.logRequests,
      development: config.development,
      production: config.production
    };

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      config: sanitizedConfig
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to get CORS configuration',
      error: (error as Error).message
    });
  }
});

/**
 * POST /api/cors/test
 * Test CORS configuration with a specific origin
 */
router.post('/test', (req, res) => {
  try {
    const { origin } = req.body;

    if (!origin) {
      return res.status(400).json({
        status: 'error',
        message: 'Origin is required in request body'
      });
    }

    const config = getCorsConfig();

    // Import the validation function
    const { isOriginAllowed } = require('../../middleware/cors');
    const result = isOriginAllowed(origin, config, req);

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      test: {
        origin,
        allowed: result.allowed,
        reason: result.reason
      },
      request: {
        actualOrigin: req.get('origin'),
        method: req.method,
        ip: req.ip
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to test CORS origin',
      error: (error as Error).message
    });
  }
});

export default router;