/**
 * Base REST API Routes
 *
 * Provides the main API router structure and middleware
 * for the MaynDrive UI Mapping backend service.
 */

import { Router } from 'express';
import { Request, Response, NextFunction } from 'express';

// Import route handlers
import { streamUrlHandler } from './routes/streamUrl';
import { healthHandler } from './routes/health';
import { emulatorStartHandler } from './routes/emulatorStart';
import { emulatorStopHandler } from './routes/emulatorStop';
import { emulatorRestartHandler } from './routes/emulatorRestart';
import uiGraphRoutes from './routes/ui-graph';
import stateDetectionRoutes from './state-detection';
import flowsRoutes from './flows';
import capturesRoutes from './routes/captures';
import nodesRoutes from './routes/nodes';

const router = Router();

/**
 * Request validation middleware
 */
export const validateRequest = (schema: any) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // TODO: Add proper validation using zod or similar
      next();
    } catch (error) {
      res.status(400).json({
        error: 'Validation failed',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  };
};

/**
 * Error handling middleware
 */
export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.error(`API Error: ${error.message}`, error);

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV !== 'production';

  res.status(500).json({
    error: 'Internal server error',
    message: isDevelopment ? error.message : 'Something went wrong',
    ...(isDevelopment && { stack: error.stack })
  });
};

/**
 * Authentication middleware (placeholder for future implementation)
 */
export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  // TODO: Implement proper authentication
  // For now, just continue
  next();
};

/**
 * Request logging middleware
 */
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
  });

  next();
};

/**
 * Rate limiting middleware (basic implementation)
 */
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

export const rateLimit = (maxRequests: number = 100, windowMs: number = 60000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const clientIp = req.ip || 'unknown';
    const now = Date.now();
    const windowStart = now - windowMs;

    // Clean up old entries
    for (const [ip, data] of rateLimitStore.entries()) {
      if (data.resetTime < now) {
        rateLimitStore.delete(ip);
      }
    }

    // Get or create client data
    let clientData = rateLimitStore.get(clientIp);
    if (!clientData || clientData.resetTime < now) {
      clientData = { count: 0, resetTime: now + windowMs };
      rateLimitStore.set(clientIp, clientData);
    }

    // Check rate limit
    if (clientData.count >= maxRequests) {
      const resetIn = Math.ceil((clientData.resetTime - now) / 1000);
      res.set('Retry-After', resetIn.toString());
      return res.status(429).json({
        error: 'Too many requests',
        message: `Rate limit exceeded. Try again in ${resetIn} seconds.`
      });
    }

    clientData.count++;
    next();
  };
};

/**
 * Health check endpoint
 */
router.get('/health', healthHandler);

/**
 * Stream URL endpoint
 */
router.get('/stream/url', streamUrlHandler);

/**
 * Emulator management endpoints
 */
router.post('/emulator/start', emulatorStartHandler);
router.post('/emulator/stop', emulatorStopHandler);
router.post('/emulator/restart', emulatorRestartHandler);

/**
 * API root endpoint
 */
router.get('/', (req: Request, res: Response) => {
  res.json({
    name: 'MaynDrive UI Mapping API',
    version: '1.0.0',
    description: 'Backend API for MaynDrive State-Aware UI Mapping system',
    endpoints: {
      health: '/health',
      captures: '/api/captures',
      nodes: '/api/nodes',
      detection: '/api/detect',
      flows: '/api/flows',
      telemetry: '/api/telemetry'
    },
    documentation: '/api/docs'
  });
});

/**
 * API version endpoint
 */
router.get('/version', (req: Request, res: Response) => {
  res.json({
    version: process.env.npm_package_version || '1.0.0',
    buildTime: process.env.BUILD_TIME || new Date().toISOString(),
    gitCommit: process.env.GIT_COMMIT || 'unknown',
    environment: process.env.NODE_ENV || 'development'
  });
});

/**
 * API documentation endpoint (placeholder)
 */
router.get('/docs', (req: Request, res: Response) => {
  res.json({
    title: 'MaynDrive UI Mapping API',
    version: '1.0.0',
    description: 'RESTful API for UI capture, graph management, and flow execution',
    baseUrl: `${req.protocol}://${req.get('host')}/api`,
    endpoints: {
      captures: {
        description: 'Screen capture and action recording',
        methods: ['POST /api/captures/screen', 'POST /api/captures/action']
      },
      nodes: {
        description: 'UI graph node management',
        methods: ['GET /api/nodes/:id', 'PUT /api/nodes/:id', 'DELETE /api/nodes/:id']
      },
      detection: {
        description: 'State detection and matching',
        methods: ['POST /api/detect', 'GET /api/detect/history']
      },
      flows: {
        description: 'Flow definition and execution',
        methods: ['GET /api/flows', 'POST /api/flows/run', 'GET /api/flows/:id']
      },
      telemetry: {
        description: 'Telemetry and analytics data',
        methods: ['GET /api/telemetry/detections', 'GET /api/telemetry/executions']
      }
    }
  });
});

/**
 * Mount API route groups
 */

// Capture and graph management routes (User Story 1)
router.use('/ui-graph', rateLimit(50), uiGraphRoutes);
router.use('/captures', rateLimit(50), capturesRoutes);

// Node management routes (User Story 1)
router.use('/nodes', rateLimit(100), nodesRoutes);

// State detection routes (User Story 2) - temporarily disabled
// router.use('/', stateDetectionRoutes);

// Flow execution routes (User Story 3)
router.use('/flows', rateLimit(20), flowsRoutes);

// Telemetry routes
// router.use('/telemetry', requireAuth, rateLimit(100), telemetryRoutes);

/**
 * Static data endpoints for development
 */
router.get('/static/screens', (req: Request, res: Response) => {
  // Return sample screen data for testing
  res.json({
    screens: [
      {
        id: 'sample-screen-1',
        name: 'Login Screen',
        activity: 'com.mayndrive.LoginActivity',
        status: 'active',
        selectors: [
          { id: 'sel-1', type: 'resource-id', value: 'login_button', confidence: 0.9 },
          { id: 'sel-2', type: 'text', value: 'Login', confidence: 0.7 }
        ]
      }
    ]
  });
});

router.get('/static/flows', (req: Request, res: Response) => {
  // Return sample flow data for testing
  res.json({
    flows: [
      {
        id: 'sample-flow-1',
        name: 'Login Flow',
        description: 'Basic login flow for testing',
        status: 'draft',
        steps: [
          { id: 'step-1', action: 'tap', target: 'login_button', description: 'Tap login button' },
          { id: 'step-2', action: 'type', target: 'email_input', text: '${email}', description: 'Enter email' }
        ]
      }
    ]
  });
});

/**
 * CORS preflight handler
 */
router.use((req: Request, res: Response, next: NextFunction) => {
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.status(200).send();
  } else {
    next();
  }
});

/**
 * 404 handler for unknown API routes
 */
router.use((req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    message: `API endpoint ${req.method} ${req.originalUrl} not found`,
    availableEndpoints: [
      'GET /api/health',
      'GET /api/stream/url',
      'POST /api/emulator/start',
      'POST /api/emulator/stop',
      'POST /api/emulator/restart',
      'GET /api/',
      'GET /api/version',
      'GET /api/docs',
      'GET /api/static/screens',
      'GET /api/static/flows'
    ]
  });
});

export default router;
export { router as apiRouter };