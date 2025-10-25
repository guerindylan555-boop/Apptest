/**
 * Structured Logger Usage Examples
 *
 * This file demonstrates how to use the new structured JSON logging service
 * in accordance with Constitution §10 requirements.
 */

import { createServiceLogger, logger } from './logger';
import { randomUUID } from 'crypto';

// ============================================================================
// Basic Service Logger Usage
// ============================================================================

// Example 1: WebRTC Manager Service
const webrtcLogger = createServiceLogger('webrtc-manager');

export function handleWebRTCConnection(connectionId: string) {
  const traceId = webrtcLogger.generateTraceId();

  webrtcLogger.info('connection_attempt', 'Starting WebRTC connection', traceId, {
    connectionId,
    timestamp: new Date().toISOString()
  });

  const timer = webrtcLogger.startTimer('webrtc_connection', traceId, {
    connectionId
  });

  try {
    // Simulate WebRTC connection logic
    setTimeout(() => {
      const duration = timer.end({
        status: 'connected',
        iceServers: 2
      });

      webrtcLogger.info('connection_established', 'WebRTC connection established successfully', traceId, {
        connectionId,
        duration,
        videoQuality: 'high'
      });
    }, 150);

  } catch (error) {
    timer.end({ status: 'failed', error: error.message });
    webrtcLogger.error('connection_failed', 'WebRTC connection failed', error as Error, traceId, {
      connectionId
    });
  }
}

// ============================================================================
// Performance Monitoring Examples
// ============================================================================

// Example 2: ADB Bridge Service with Performance Monitoring
const adbLogger = createServiceLogger('adb-bridge');

export async function executeADBCommand(command: string, deviceId: string) {
  const traceId = adbLogger.generateTraceId();

  adbLogger.info('adb_command_start', `Executing ADB command: ${command}`, traceId, {
    deviceId,
    command
  });

  const timer = adbLogger.startTimer('adb_command_execution', traceId, {
    command,
    deviceId
  });

  try {
    // Simulate ADB command execution
    await new Promise(resolve => setTimeout(resolve, 200 + Math.random() * 300));

    const duration = timer.end({
      status: 'success',
      outputLength: 1024
    });

    adbLogger.info('adb_command_complete', 'ADB command executed successfully', traceId, {
      command,
      deviceId,
      duration,
      outputSize: 1024
    });

    return { success: true, duration };

  } catch (error) {
    timer.end({ status: 'failed', error: (error as Error).message });
    adbLogger.error('adb_command_failed', 'ADB command execution failed', error as Error, traceId, {
      command,
      deviceId
    });
    return { success: false, error: (error as Error).message };
  }
}

// ============================================================================
// Health Check Implementation
// ============================================================================

// Example 3: UI Capture Service Health Check
const uiCaptureLogger = createServiceLogger('ui-capture');

export async function performHealthCheck() {
  try {
    const timer = uiCaptureLogger.startTimer('health_check');

    // Simulate health check operations
    await Promise.all([
      checkDatabaseConnection(),
      checkFilesystemAccess(),
      checkMemoryUsage()
    ]);

    const duration = timer.end();

    uiCaptureLogger.healthCheck('healthy', {
      database: 'connected',
      filesystem: 'accessible',
      memoryUsage: '45%',
      duration
    });

    return { status: 'healthy', duration };

  } catch (error) {
    uiCaptureLogger.healthCheck('unhealthy', {
      error: (error as Error).message,
      component: 'database'
    });
    return { status: 'unhealthy', error: (error as Error).message };
  }
}

async function checkDatabaseConnection(): Promise<void> {
  // Simulate database check
  await new Promise(resolve => setTimeout(resolve, 50));
}

async function checkFilesystemAccess(): Promise<void> {
  // Simulate filesystem check
  await new Promise(resolve => setTimeout(resolve, 20));
}

async function checkMemoryUsage(): Promise<void> {
  // Simulate memory check
  await new Promise(resolve => setTimeout(resolve, 30));
}

// ============================================================================
// Error Handling and Context Logging
// ============================================================================

// Example 4: Flow Service with Complex Error Context
const flowLogger = createServiceLogger('flow-service');

export interface FlowExecutionContext extends Record<string, unknown> {
  flowId: string;
  stepId: string;
  userId?: string;
  sessionId: string;
  variables: Record<string, unknown>;
}

export async function executeFlowStep(context: FlowExecutionContext) {
  const traceId = flowLogger.generateTraceId();

  flowLogger.info('flow_step_start', 'Executing flow step', traceId, {
    flowId: context.flowId,
    stepId: context.stepId,
    sessionId: context.sessionId,
    variableCount: Object.keys(context.variables).length
  });

  const timer = flowLogger.startTimer('flow_step_execution', traceId, context);

  try {
    // Simulate flow step execution
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));

    // Simulate occasional failure for demonstration
    if (Math.random() < 0.2) {
      throw new Error('Flow step validation failed: Missing required variable "targetElement"');
    }

    const duration = timer.end({
      status: 'success',
      outputVariables: 3
    });

    flowLogger.info('flow_step_complete', 'Flow step executed successfully', traceId, {
      flowId: context.flowId,
      stepId: context.stepId,
      duration,
      outputVariables: 3
    });

    return { success: true, duration };

  } catch (error) {
    const duration = timer.end({
      status: 'failed',
      error: (error as Error).message
    });

    flowLogger.error('flow_step_failed', 'Flow step execution failed', error as Error, traceId, {
      flowId: context.flowId,
      stepId: context.stepId,
      duration,
      context: {
        variableCount: Object.keys(context.variables).length,
        hasUserId: !!context.userId
      }
    });

    return {
      success: false,
      error: (error as Error).message,
      duration
    };
  }
}

// ============================================================================
// Backward Compatibility Examples
// ============================================================================

// Example 5: Using Legacy Logger Interface (for existing code)
export function legacyLogExample() {
  // These methods maintain backward compatibility with existing code
  logger.debug('Debug message for troubleshooting', {
    component: 'auth-service',
    userId: 12345
  });

  logger.info('User authentication successful', {
    userId: 12345,
    method: 'oauth2',
    timestamp: new Date().toISOString()
  });

  logger.warn('Rate limit approaching threshold', {
    userId: 12345,
    currentRate: 95,
    limit: 100,
    window: '1h'
  });

  logger.error('Database connection failed', new Error('Connection timeout after 5000ms'));
}

// ============================================================================
// Request Correlation Examples
// ============================================================================

// Example 6: Request/Operation Correlation Across Services
export class RequestCorrelationExample {
  private traceId: string;

  constructor() {
    this.traceId = logger.generateTraceId();
  }

  async processUserRequest(userId: string, action: string) {
    // Log request start
    logger.info('Processing user request: ' + action, {
      service: 'request-processor',
      event: 'request_start',
      userId,
      action,
      timestamp: new Date().toISOString(),
      trace_id: this.traceId
    });

    try {
      // Step 1: Validate user permissions
      const authTimer = logger.startTimer('user_authorization', this.traceId);
      await this.validateUserPermissions(userId, action);
      authTimer.end({ result: 'authorized' });

      // Step 2: Execute main action using appropriate service logger
      const actionLogger = createServiceLogger('action-processor');
      const actionTimer = actionLogger.startTimer('action_execution', this.traceId);
      const result = await this.executeAction(userId, action);
      actionTimer.end({ result: 'success', outputSize: JSON.stringify(result).length });

      // Log request completion
      logger.info('User request processed successfully', {
        service: 'request-processor',
        event: 'request_complete',
        userId,
        action,
        duration: Date.now(),
        trace_id: this.traceId
      });

      return result;

    } catch (error) {
      logger.error('User request processing failed', {
        service: 'request-processor',
        event: 'request_failed',
        userId,
        action,
        trace_id: this.traceId,
        error: (error as Error).message
      });
      throw error;
    }
  }

  private async validateUserPermissions(userId: string, action: string): Promise<void> {
    // Simulate permission check
    await new Promise(resolve => setTimeout(resolve, 50));
  }

  private async executeAction(userId: string, action: string): Promise<unknown> {
    // Simulate action execution
    await new Promise(resolve => setTimeout(resolve, 200));
    return { success: true, userId, action, timestamp: new Date().toISOString() };
  }
}

// ============================================================================
// Configuration Examples
// ============================================================================

// Example 7: Logger Configuration and Runtime Updates
export function demonstrateLoggerConfiguration() {
  // Get current configuration
  const currentConfig = logger.getConfig();
  console.log('Current logger configuration:', currentConfig);

  // Update configuration at runtime
  logger.updateConfig({
    level: 'debug',
    includeTrace: true,
    format: 'json'
  });

  // Test with new configuration
  const testLogger = createServiceLogger('config-test');
  testLogger.debug('config_test', 'Testing debug level with new configuration', undefined, {
    configUpdated: true,
    timestamp: new Date().toISOString()
  });

  // Reset to original configuration
  logger.updateConfig(currentConfig);
}

// ============================================================================
// Integration with Existing Services
// ============================================================================

// Example 8: Integration Pattern for Existing Service Classes
export abstract class BaseService {
  protected logger: ReturnType<typeof createServiceLogger>;
  protected serviceName: string;

  constructor(serviceName: string) {
    this.serviceName = serviceName;
    this.logger = createServiceLogger(serviceName);
  }

  protected async withPerformanceMonitoring<T>(
    operation: string,
    fn: () => Promise<T>,
    context?: Record<string, unknown>
  ): Promise<T> {
    const traceId = this.logger.generateTraceId();
    const timer = this.logger.startTimer(operation, traceId, context);

    try {
      this.logger.info(`${operation}_start`, `Starting ${operation}`, traceId, context);

      const result = await fn();

      const duration = timer.end({ status: 'success' });
      this.logger.info(`${operation}_complete`, `${operation} completed successfully`, traceId, {
        duration,
        ...context
      });

      return result;

    } catch (error) {
      timer.end({ status: 'failed', error: (error as Error).message });
      this.logger.error(`${operation}_failed`, `${operation} failed`, error as Error, traceId, context);
      throw error;
    }
  }

  protected logHealthCheck(status: 'healthy' | 'unhealthy', details?: Record<string, unknown>): void {
    this.logger.healthCheck(status, {
      serviceName: this.serviceName,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
}

// Example usage of the base service class
export class EnhancedADBService extends BaseService {
  constructor() {
    super('adb-bridge-enhanced');
  }

  async connectToDevice(deviceId: string): Promise<void> {
    return this.withPerformanceMonitoring(
      'device_connection',
      async () => {
        // Simulate device connection logic
        await new Promise(resolve => setTimeout(resolve, 300));
        console.log(`Connected to device: ${deviceId}`);
      },
      { deviceId }
    );
  }

  async performHealthCheck(): Promise<void> {
    return this.withPerformanceMonitoring(
      'service_health_check',
      async () => {
        // Simulate health check logic
        await new Promise(resolve => setTimeout(resolve, 100));
        this.logHealthCheck('healthy', {
          deviceCount: 2,
          lastConnection: new Date().toISOString()
        });
      }
    );
  }
}

// ============================================================================
// Export all example functions for testing
// ============================================================================

export const examples = {
  handleWebRTCConnection,
  executeADBCommand,
  performHealthCheck,
  executeFlowStep,
  legacyLogExample,
  RequestCorrelationExample,
  demonstrateLoggerConfiguration,
  EnhancedADBService
};