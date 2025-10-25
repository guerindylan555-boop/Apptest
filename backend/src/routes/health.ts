/**
 * Health Check Routes
 *
 * System health monitoring endpoints for the discovery system.
 * Provides comprehensive health monitoring with <500ms performance budget
 * in compliance with constitution §10 requirements.
 */

import { Router, Request, Response } from 'express';
import { createADBConnection } from '../utils/adb';
import { getGraphConfig, getConfigSummary } from '../config/discovery';
import { promises as fs } from 'fs';
import path from 'path';
import { webrtcManager } from '../services/webrtc-manager';

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
    webrtc: ServiceHealth;
    graph: ServiceHealth;
    storage: ServiceHealth;
  };
  performance?: {
    captureTime?: number;
    apiResponseTime?: number;
    memoryUsage?: number;
    heapTotal?: number;
    externalMemory?: number;
    rss?: number;
    cpuUser?: number;
    cpuSystem?: number;
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
  responseTime?: string;
}

/**
 * Detailed health response interface
 */
interface DetailedHealthResponse extends HealthResponse {
  system: {
    nodeVersion: string;
    platform: string;
    arch: string;
    memory: {
      total: number;
      free: number;
      used: number;
      usage: number;
    };
    cpu: {
      loadAvg: number[];
    };
  };
  endpoints: {
    adb: ServiceHealth;
    webrtc: ServiceHealth;
    storage: ServiceHealth;
    graph: ServiceHealth;
  };
  configuration: {
    webrtcPublicUrl?: string;
    externalEmulator: boolean;
    enableFrida: boolean;
    logLevel: string;
  };
}

const HEALTH_CHECK_TIMEOUT = 450; // ms, leaving 50ms margin for response overhead

/**
 * Helper function to run health checks with timeout
 */
async function runHealthCheck<T>(check: () => Promise<T>, timeout: number = HEALTH_CHECK_TIMEOUT): Promise<T> {
  return Promise.race([
    check(),
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error('Health check timeout')), timeout)
    )
  ]);
}

/**
 * Main health check endpoint (/api/healthz) - Constitution mandated
 * Performance budget: <500ms total response time
 */
router.get('/healthz', async (req: Request, res: Response) => {
  const startTime = Date.now();

  // Set overall timeout for health check
  const healthTimeout = setTimeout(() => {
    if (!res.headersSent) {
      res.status(503).json({
        status: 'error',
        timestamp: new Date().toISOString(),
        message: 'Health check timeout (>500ms)',
        responseTime: `${Date.now() - startTime}ms`
      });
    }
  }, 500);

  try {
    const health: HealthResponse = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      services: {
        adb: await runHealthCheck(() => checkADBHealth()),
        webrtc: await runHealthCheck(() => checkWebRTCHealth()),
        graph: await runHealthCheck(() => checkGraphHealth()),
        storage: await runHealthCheck(() => checkStorageHealth())
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

    // Add response time header and track performance
    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    // Update performance metrics
    updatePerformanceMetrics(responseTime);

    // Log structured health check result (constitution §10)
    console.log(JSON.stringify({
      service: 'backend',
      event: 'health_check',
      severity: hasErrors ? 'error' : hasDegraded ? 'warn' : 'info',
      responseTime: `${responseTime}ms`,
      status: health.status,
      timestamp: new Date().toISOString()
    }));

    clearTimeout(healthTimeout);
    res.json(health);
  } catch (error) {
    clearTimeout(healthTimeout);

    console.error(JSON.stringify({
      service: 'backend',
      event: 'health_check_error',
      severity: 'error',
      error: error instanceof Error ? error.message : 'Unknown error',
      responseTime: `${Date.now() - startTime}ms`,
      timestamp: new Date().toISOString()
    }));

    const errorHealth: HealthResponse = {
      status: 'error',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      services: {
        adb: { status: 'error', message: 'Health check failed' },
        webrtc: { status: 'error', message: 'Health check failed' },
        graph: { status: 'error', message: 'Health check failed' },
        storage: { status: 'error', message: 'Health check failed' }
      }
    };

    if (!res.headersSent) {
      res.status(503).json(errorHealth);
    }
  }
});

/**
 * Check ADB connection health
 */
async function checkADBHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();
  try {
    const adb = createADBConnection();

    // Check if device is connected
    const isConnected = await adb.isDeviceConnected();
    if (!isConnected) {
      return {
        status: 'error',
        message: 'ADB device not connected',
        responseTime: `${Date.now() - startTime}ms`,
        details: { serial: process.env.ANDROID_SERIAL || 'emulator-5554' }
      };
    }

    // Check device responsiveness
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
        responseTime: `${responseTime}ms`,
        details: {
          currentActivity: activity,
          androidVersion: properties['ro.build.version.release'],
          deviceModel: properties['ro.product.model']
        }
      };
    }

    return {
      status: 'ok',
      message: 'ADB connection healthy',
      responseTime: `${responseTime}ms`,
      details: {
        currentActivity: activity,
        androidVersion: properties['ro.build.version.release'],
        deviceModel: properties['ro.product.model']
      }
    };
  } catch (error) {
    return {
      status: 'error',
      message: `ADB health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      responseTime: `${Date.now() - startTime}ms`
    };
  }
}

/**
 * Check WebRTC connection health
 */
async function checkWebRTCHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();
  try {
    const webrtcConfig = {
      PUBLIC_URL: process.env.EMULATOR_WEBRTC_PUBLIC_URL,
      ICE_SERVERS: process.env.EMULATOR_WEBRTC_ICE_SERVERS,
      GRPC_ENDPOINT: process.env.EMULATOR_GRPC_ENDPOINT
    };

    // Check if WebRTC configuration is set
    if (!webrtcConfig.PUBLIC_URL) {
      return {
        status: 'degraded',
        message: 'WebRTC public URL not configured',
        responseTime: `${Date.now() - startTime}ms`,
        details: { config: webrtcConfig }
      };
    }

    // Check WebRTC manager availability (lightweight check)
    const connectionStatus = webrtcManager.getConnectionState();
    const responseTime = Date.now() - startTime;

    // Check if connection is healthy
    if (connectionStatus === 'connected') {
      return {
        status: 'ok',
        message: 'WebRTC connection healthy',
        responseTime: `${responseTime}ms`,
        details: {
          connectionStatus,
          config: {
            publicUrl: webrtcConfig.PUBLIC_URL,
            hasIceServers: !!webrtcConfig.ICE_SERVERS,
            hasGrpcEndpoint: !!webrtcConfig.GRPC_ENDPOINT
          }
        }
      };
    } else if (connectionStatus === 'connecting' || connectionStatus === 'disconnected') {
      return {
        status: 'degraded',
        message: `WebRTC status: ${connectionStatus}`,
        responseTime: `${responseTime}ms`,
        details: {
          connectionStatus,
          config: {
            publicUrl: webrtcConfig.PUBLIC_URL,
            hasIceServers: !!webrtcConfig.ICE_SERVERS,
            hasGrpcEndpoint: !!webrtcConfig.GRPC_ENDPOINT
          }
        }
      };
    } else {
      return {
        status: 'error',
        message: `WebRTC error state: ${connectionStatus}`,
        responseTime: `${responseTime}ms`,
        details: {
          connectionStatus,
          config: webrtcConfig
        }
      };
    }
  } catch (error) {
    return {
      status: 'error',
      message: `WebRTC health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      responseTime: `${Date.now() - startTime}ms`
    };
  }
}

/**
 * Check graph file health
 */
async function checkGraphHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();
  try {
    const config = getGraphConfig();

    // Check if graph file exists
    try {
      await fs.access(config.graphPath);
    } catch (error) {
      return {
        status: 'ok',
        message: 'Graph file not found (new session)',
        responseTime: `${Date.now() - startTime}ms`,
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
        responseTime: `${Date.now() - startTime}ms`,
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
          responseTime: `${Date.now() - startTime}ms`,
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
        responseTime: `${Date.now() - startTime}ms`,
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
        responseTime: `${Date.now() - startTime}ms`,
        details: {
          graphPath: config.graphPath,
          error: parseError instanceof Error ? parseError.message : 'Parse error'
        }
      };
    }
  } catch (error) {
    return {
      status: 'error',
      message: `Graph health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      responseTime: `${Date.now() - startTime}ms`
    };
  }
}

/**
 * Check storage health
 */
async function checkStorageHealth(): Promise<ServiceHealth> {
  const startTime = Date.now();
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
        responseTime: `${Date.now() - startTime}ms`,
        details: results
      };
    }

    if (hasIssues) {
      return {
        status: 'degraded',
        message: 'Storage issues detected',
        responseTime: `${Date.now() - startTime}ms`,
        details: results
      };
    }

    return {
      status: 'ok',
      message: 'Storage healthy',
      responseTime: `${Date.now() - startTime}ms`,
      details: results
    };
  } catch (error) {
    return {
      status: 'error',
      message: `Storage health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      responseTime: `${Date.now() - startTime}ms`
    };
  }
}

// Performance tracking for response times
const performanceMetrics = {
  averageResponseTime: 0,
  responseTimeHistory: [] as number[],
  maxHistorySize: 100,
  captureTime: 0,
  apiResponseTime: 0
};

/**
 * Update performance metrics with new response time
 */
function updatePerformanceMetrics(responseTime: number): void {
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
 * Get performance metrics
 */
async function getPerformanceMetrics(): Promise<HealthResponse['performance']> {
  try {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();

    return {
      memoryUsage: memUsage.heapUsed,
      apiResponseTime: performanceMetrics.averageResponseTime,
      captureTime: performanceMetrics.captureTime,
      // Additional performance data
      heapTotal: memUsage.heapTotal,
      externalMemory: memUsage.external,
      rss: memUsage.rss,
      cpuUser: cpuUsage.user,
      cpuSystem: cpuUsage.system
    };
  } catch (error) {
    return {
      memoryUsage: 0,
      apiResponseTime: 0,
      captureTime: 0
    };
  }
}

/**
 * Export performance tracking for other modules to use
 */
export function recordResponseTime(responseTime: number): void {
  updatePerformanceMetrics(responseTime);
}

export function getAverageResponseTime(): number {
  return performanceMetrics.averageResponseTime;
}

/**
 * Readiness probe (/api/health/ready) - Container orchestration
 * Checks if service is ready to accept traffic
 */
router.get('/ready', async (req: Request, res: Response) => {
  const startTime = Date.now();
  try {
    const adbHealth = await runHealthCheck(() => checkADBHealth());
    const storageHealth = await runHealthCheck(() => checkStorageHealth());
    const webrtcHealth = await runHealthCheck(() => checkWebRTCHealth());

    const criticalServices = [adbHealth, storageHealth, webrtcHealth];
    const hasErrors = criticalServices.some(s => s.status === 'error');

    if (hasErrors) {
      const responseTime = Date.now() - startTime;
      res.setHeader('X-Response-Time', `${responseTime}ms`);
      return res.status(503).json({
        status: 'not ready',
        timestamp: new Date().toISOString(),
        responseTime: `${responseTime}ms`,
        services: { adb: adbHealth, storage: storageHealth, webrtc: webrtcHealth }
      });
    }

    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);
    res.json({
      status: 'ready',
      timestamp: new Date().toISOString(),
      responseTime: `${responseTime}ms`,
      services: { adb: adbHealth, storage: storageHealth, webrtc: webrtcHealth }
    });
  } catch (error) {
    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);
    res.status(503).json({
      status: 'not ready',
      timestamp: new Date().toISOString(),
      responseTime: `${responseTime}ms`,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * Liveness probe (/api/health/live) - Container orchestration
 * Basic liveness check to determine if container should be restarted
 */
router.get('/live', (req: Request, res: Response) => {
  const responseTime = Date.now();
  res.setHeader('X-Response-Time', `${responseTime}ms`);
  res.json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    responseTime: `${responseTime}ms`,
    uptime: process.uptime(),
    pid: process.pid
  });
});

/**
 * Detailed health check (/api/health/detailed) - Comprehensive health report
 * Provides complete system health information with detailed metrics
 */
router.get('/detailed', async (req: Request, res: Response) => {
  const startTime = Date.now();

  // Set extended timeout for detailed health check (1 second)
  const healthTimeout = setTimeout(() => {
    if (!res.headersSent) {
      res.status(503).json({
        status: 'error',
        timestamp: new Date().toISOString(),
        message: 'Detailed health check timeout (>1000ms)',
        responseTime: `${Date.now() - startTime}ms`
      });
    }
  }, 1000);

  try {
    // Gather all service health information
    const [adbHealth, webrtcHealth, graphHealth, storageHealth] = await Promise.all([
      runHealthCheck(() => checkADBHealth()),
      runHealthCheck(() => checkWebRTCHealth()),
      runHealthCheck(() => checkGraphHealth()),
      runHealthCheck(() => checkStorageHealth())
    ]);

    // Get system information
    const memUsage = process.memoryUsage();
    const systemInfo = {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      memory: {
        total: memUsage.heapTotal,
        free: memUsage.heapTotal - memUsage.heapUsed,
        used: memUsage.heapUsed,
        usage: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100)
      },
      cpu: {
        loadAvg: require('os').loadavg()
      }
    };

    // Get configuration information
    const config = {
      webrtcPublicUrl: process.env.EMULATOR_WEBRTC_PUBLIC_URL,
      externalEmulator: process.env.EXTERNAL_EMULATOR === 'true',
      enableFrida: process.env.ENABLE_FRIDA === 'true',
      logLevel: process.env.LOG_LEVEL || 'info'
    };

    // Determine overall status
    const allServices = [adbHealth, webrtcHealth, graphHealth, storageHealth];
    const hasErrors = allServices.some(s => s.status === 'error');
    const hasDegraded = allServices.some(s => s.status === 'degraded');

    const detailedHealth: DetailedHealthResponse = {
      status: hasErrors ? 'error' : hasDegraded ? 'degraded' : 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      services: {
        adb: adbHealth,
        webrtc: webrtcHealth,
        graph: graphHealth,
        storage: storageHealth
      },
      system: systemInfo,
      endpoints: {
        adb: adbHealth,
        webrtc: webrtcHealth,
        storage: storageHealth,
        graph: graphHealth
      },
      configuration: config,
      performance: await getPerformanceMetrics()
    };

    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    // Log structured detailed health check result
    console.log(JSON.stringify({
      service: 'backend',
      event: 'detailed_health_check',
      severity: hasErrors ? 'error' : hasDegraded ? 'warn' : 'info',
      responseTime: `${responseTime}ms`,
      status: detailedHealth.status,
      timestamp: new Date().toISOString()
    }));

    clearTimeout(healthTimeout);

    // Set appropriate HTTP status
    if (hasErrors) {
      res.status(503);
    } else if (hasDegraded) {
      res.status(200);
    } else {
      res.status(200);
    }

    res.json(detailedHealth);
  } catch (error) {
    clearTimeout(healthTimeout);

    const responseTime = Date.now() - startTime;
    res.setHeader('X-Response-Time', `${responseTime}ms`);

    console.error(JSON.stringify({
      service: 'backend',
      event: 'detailed_health_check_error',
      severity: 'error',
      error: error instanceof Error ? error.message : 'Unknown error',
      responseTime: `${responseTime}ms`,
      timestamp: new Date().toISOString()
    }));

    if (!res.headersSent) {
      res.status(503).json({
        status: 'error',
        timestamp: new Date().toISOString(),
        responseTime: `${responseTime}ms`,
        message: 'Detailed health check failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
});

export default router;