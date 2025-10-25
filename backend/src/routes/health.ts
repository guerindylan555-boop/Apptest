/**
 * Health Check Routes
 *
 * System health monitoring endpoints for the discovery system.
 * Provides /api/healthz endpoint for constitution compliance.
 */

import { Router, Request, Response } from 'express';
import { createADBConnection } from '../utils/adb';
import { getGraphConfig, getConfigSummary } from '../config/discovery';
import { promises as fs } from 'fs';
import path from 'path';

const router = Router();

/**
 * Health check response interface
 */
interface HealthResponse {
  status: 'ok' | 'degraded' | 'error';
  timestamp: string;
  uptime: number;
  version: string;
  services: {
    adb: ServiceHealth;
    graph: ServiceHealth;
    storage: ServiceHealth;
  };
  performance?: {
    captureTime?: number;
    apiResponseTime?: number;
    memoryUsage?: number;
  };
  config?: {
    featureFlags: Record<string, boolean>;
    limits: Record<string, number>;
  };
}

interface ServiceHealth {
  status: 'ok' | 'degraded' | 'error';
  message?: string;
  details?: Record<string, any>;
}

/**
 * Main health check endpoint (/api/healthz)
 */
router.get('/healthz', async (req: Request, res: Response) => {
  try {
    const startTime = Date.now();
    const health: HealthResponse = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      services: {
        adb: await checkADBHealth(),
        graph: await checkGraphHealth(),
        storage: await checkStorageHealth()
      }
    };

    // Determine overall status
    const serviceStatuses = Object.values(health.services);
    const hasErrors = serviceStatuses.some(s => s.status === 'error');
    const hasDegraded = serviceStatuses.some(s => s.status === 'degraded');

    if (hasErrors) {
      health.status = 'error';
      res.status(503);
    } else if (hasDegraded) {
      health.status = 'degraded';
      res.status(200); // Still serve traffic but indicate issues
    }

    // Add performance metrics if requested
    if (req.query.include === 'performance') {
      health.performance = await getPerformanceMetrics();
    }

    // Add configuration summary if requested
    if (req.query.include === 'config') {
      const config = getConfigSummary();
      health.config = {
        featureFlags: config.features,
        limits: config.limits
      };
    }

    // Add response time
    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    res.json(health);
  } catch (error) {
    console.error('Health check failed:', error);

    const errorHealth: HealthResponse = {
      status: 'error',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      services: {
        adb: { status: 'error', message: 'Health check failed' },
        graph: { status: 'error', message: 'Health check failed' },
        storage: { status: 'error', message: 'Health check failed' }
      }
    };

    res.status(503).json(errorHealth);
  }
});

/**
 * Check ADB connection health
 */
async function checkADBHealth(): Promise<ServiceHealth> {
  try {
    const adb = createADBConnection();

    // Check if device is connected
    const isConnected = await adb.isDeviceConnected();
    if (!isConnected) {
      return {
        status: 'error',
        message: 'ADB device not connected',
        details: { serial: process.env.ANDROID_SERIAL || 'emulator-5554' }
      };
    }

    // Check device responsiveness
    const startTime = Date.now();
    const activity = await adb.getCurrentActivity();
    const responseTime = Date.now() - startTime;

    // Get device properties for additional info
    const properties = await adb.getDeviceProperties();

    adb.close();

    // Consider slow responses (>2s) as degraded
    if (responseTime > 2000) {
      return {
        status: 'degraded',
        message: 'ADB response time is slow',
        details: {
          responseTime: `${responseTime}ms`,
          currentActivity: activity,
          androidVersion: properties['ro.build.version.release'],
          deviceModel: properties['ro.product.model']
        }
      };
    }

    return {
      status: 'ok',
      message: 'ADB connection healthy',
      details: {
        responseTime: `${responseTime}ms`,
        currentActivity: activity,
        androidVersion: properties['ro.build.version.release'],
        deviceModel: properties['ro.product.model']
      }
    };
  } catch (error) {
    return {
      status: 'error',
      message: `ADB health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Check graph file health
 */
async function checkGraphHealth(): Promise<ServiceHealth> {
  try {
    const config = getGraphConfig();

    // Check if graph file exists
    try {
      await fs.access(config.graphPath);
    } catch (error) {
      return {
        status: 'ok',
        message: 'Graph file not found (new session)',
        details: { graphPath: config.graphPath }
      };
    }

    // Check graph file size and readability
    const stats = await fs.stat(config.graphPath);
    const fileSize = stats.size;

    // Check if file is too large (>10MB)
    if (fileSize > 10 * 1024 * 1024) {
      return {
        status: 'degraded',
        message: 'Graph file is large',
        details: {
          graphPath: config.graphPath,
          fileSize: `${Math.round(fileSize / 1024 / 1024 * 100) / 100}MB`,
          lastModified: stats.mtime.toISOString()
        }
      };
    }

    // Try to parse graph file
    try {
      const content = await fs.readFile(config.graphPath, 'utf-8');
      const graph = JSON.parse(content);

      // Basic graph validation
      const stateCount = graph.states?.length || 0;
      const transitionCount = graph.transitions?.length || 0;

      // Check if graph is getting large
      if (stateCount > 400 || transitionCount > 1500) {
        return {
          status: 'degraded',
          message: 'Graph is approaching size limits',
          details: {
            stateCount,
            transitionCount,
            maxStates: config.maxStates,
            maxTransitions: config.maxTransitions,
            lastModified: stats.mtime.toISOString()
          }
        };
      }

      return {
        status: 'ok',
        message: 'Graph file healthy',
        details: {
          stateCount,
          transitionCount,
          fileSize: `${Math.round(fileSize / 1024)}KB`,
          version: graph.version,
          lastModified: stats.mtime.toISOString()
        }
      };
    } catch (parseError) {
      return {
        status: 'error',
        message: 'Graph file is corrupted',
        details: {
          graphPath: config.graphPath,
          error: parseError instanceof Error ? parseError.message : 'Parse error'
        }
      };
    }
  } catch (error) {
    return {
      status: 'error',
      message: `Graph health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Check storage health
 */
async function checkStorageHealth(): Promise<ServiceHealth> {
  try {
    const config = getGraphConfig();
    const paths = [
      config.graphPath,
      config.sessionsDir,
      config.screenshotsDir
    ];

    const results: Record<string, any> = {};

    for (const filePath of paths) {
      try {
        if (filePath.endsWith('.json')) {
          // Check file
          const stats = await fs.stat(filePath);
          results[path.basename(filePath)] = {
            status: 'ok',
            size: stats.size,
            lastModified: stats.mtime.toISOString()
          };
        } else {
          // Check directory
          const stats = await fs.stat(filePath);
          const files = await fs.readdir(filePath);
          results[path.basename(filePath)] = {
            status: 'ok',
            type: 'directory',
            fileCount: files.length,
            lastModified: stats.mtime.toISOString()
          };
        }
      } catch (error) {
        // For directories that don't exist, try to create them
        if (!filePath.endsWith('.json')) {
          try {
            await fs.mkdir(filePath, { recursive: true });
            results[path.basename(filePath)] = {
              status: 'ok',
              type: 'directory',
              created: true,
              fileCount: 0
            };
          } catch (createError) {
            results[path.basename(filePath)] = {
              status: 'error',
              error: createError instanceof Error ? createError.message : 'Create failed'
            };
          }
        } else {
          results[path.basename(filePath)] = {
            status: 'error',
            error: error instanceof Error ? error.message : 'Access failed'
          };
        }
      }
    }

    // Check overall storage status
    const hasErrors = Object.values(results).some((r: any) => r.status === 'error');
    const hasIssues = Object.values(results).some((r: any) => r.status !== 'ok');

    if (hasErrors) {
      return {
        status: 'error',
        message: 'Storage access errors detected',
        details: results
      };
    }

    if (hasIssues) {
      return {
        status: 'degraded',
        message: 'Storage issues detected',
        details: results
      };
    }

    return {
      status: 'ok',
      message: 'Storage healthy',
      details: results
    };
  } catch (error) {
    return {
      status: 'error',
      message: `Storage health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
}

/**
 * Get performance metrics
 */
async function getPerformanceMetrics(): Promise<HealthResponse['performance']> {
  try {
    const memUsage = process.memoryUsage();

    return {
      memoryUsage: memUsage.heapUsed,
      // These would be populated by actual performance monitoring
      // captureTime: getAverageCaptureTime(),
      // apiResponseTime: getAverageAPIResponseTime()
    };
  } catch (error) {
    return {
      memoryUsage: 0
    };
  }
}

/**
 * Readiness probe (for Kubernetes/container orchestration)
 */
router.get('/ready', async (req: Request, res: Response) => {
  try {
    const adbHealth = await checkADBHealth();
    const storageHealth = await checkStorageHealth();

    if (adbHealth.status === 'error' || storageHealth.status === 'error') {
      return res.status(503).json({
        status: 'not ready',
        timestamp: new Date().toISOString(),
        services: { adb: adbHealth, storage: storageHealth }
      });
    }

    res.json({
      status: 'ready',
      timestamp: new Date().toISOString(),
      services: { adb: adbHealth, storage: storageHealth }
    });
  } catch (error) {
    res.status(503).json({
      status: 'not ready',
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Liveness probe (for Kubernetes/container orchestration)
 */
router.get('/live', (req: Request, res: Response) => {
  res.json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    pid: process.pid
  });
});

export default router;