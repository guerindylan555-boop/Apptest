/**
 * Structured Logger Tests
 *
 * Test suite for the structured JSON logging service to ensure
 * Constitution §10 compliance and proper functionality.
 */

import {
  logger,
  createServiceLogger,
  StructuredLogger,
  ServiceLogger,
  LogLevel,
  LogFormat,
  LoggerConfig
} from '../logger';
import { existsSync, readFileSync, unlinkSync } from 'fs';
import { resolve } from 'path';

describe('Structured Logger', () => {
  const testLogFile = '/tmp/test-autoapp.log';
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset environment
    process.env = { ...originalEnv };
    process.env.LOG_FILE = 'test-autoapp.log';
    process.env.LOG_DIR = '/tmp';

    // Clean up test log file
    if (existsSync(testLogFile)) {
      unlinkSync(testLogFile);
    }
  });

  afterAll(() => {
    // Restore original environment
    process.env = originalEnv;

    // Clean up test log file
    if (existsSync(testLogFile)) {
      unlinkSync(testLogFile);
    }
  });

  describe('Basic Logging Functionality', () => {
    test('should create service logger', () => {
      const serviceLogger = createServiceLogger('test-service');
      expect(serviceLogger).toBeInstanceOf(ServiceLogger);
    });

    test('should generate trace IDs', () => {
      const traceId1 = logger.generateTraceId();
      const traceId2 = logger.generateTraceId();

      expect(traceId1).toMatch(/^[a-f0-9]{16}$/);
      expect(traceId2).toMatch(/^[a-f0-9]{16}$/);
      expect(traceId1).not.toBe(traceId2);
    });

    test('should create performance timers', () => {
      const timer = logger.startTimer('test-operation', 'test-trace', { context: 'test' });

      expect(timer.startTime).toBeGreaterThan(0);
      expect(timer.operation).toBe('test-operation');
      expect(timer.traceId).toBe('test-trace');
      expect(timer.context).toEqual({ context: 'test' });
      expect(typeof timer.end).toBe('function');
    });

    test('should measure operation duration', async () => {
      const timer = logger.startTimer('duration-test');

      // Wait 50ms
      await new Promise(resolve => setTimeout(resolve, 50));

      const duration = timer.end();

      expect(duration).toBeGreaterThanOrEqual(45); // Allow some variance
      expect(duration).toBeLessThan(100);
    });
  });

  describe('Service Logger Functionality', () => {
    let serviceLogger: ServiceLogger;

    beforeEach(() => {
      serviceLogger = createServiceLogger('test-service');
    });

    test('should log debug messages', () => {
      const traceId = serviceLogger.generateTraceId();
      serviceLogger.debug('test-event', 'Debug message', traceId, { key: 'value' });

      expect(existsSync(testLogFile)).toBe(true);
      const logContent = readFileSync(testLogFile, 'utf8');
      const logEntry = JSON.parse(logContent.trim());

      expect(logEntry.service).toBe('test-service');
      expect(logEntry.event).toBe('test-event');
      expect(logEntry.severity).toBe('debug');
      expect(logEntry.message).toBe('Debug message');
      expect(logEntry.trace_id).toBe(traceId);
      expect(logEntry.key).toBe('value');
    });

    test('should log info messages', () => {
      const traceId = serviceLogger.generateTraceId();
      serviceLogger.info('test-event', 'Info message', traceId, { count: 42 });

      const logContent = readFileSync(testLogFile, 'utf8');
      const logEntry = JSON.parse(logContent.trim());

      expect(logEntry.service).toBe('test-service');
      expect(logEntry.event).toBe('test-event');
      expect(logEntry.severity).toBe('info');
      expect(logEntry.message).toBe('Info message');
      expect(logEntry.count).toBe(42);
    });

    test('should log warning messages', () => {
      const traceId = serviceLogger.generateTraceId();
      serviceLogger.warn('test-event', 'Warning message', traceId, { threshold: 0.9 });

      const logContent = readFileSync(testLogFile, 'utf8');
      const logEntry = JSON.parse(logContent.trim());

      expect(logEntry.service).toBe('test-service');
      expect(logEntry.event).toBe('test-event');
      expect(logEntry.severity).toBe('warn');
      expect(logEntry.message).toBe('Warning message');
      expect(logEntry.threshold).toBe(0.9);
    });

    test('should log error messages with error details', () => {
      const traceId = serviceLogger.generateTraceId();
      const error = new Error('Test error message');
      (error as any).code = 'TEST_ERROR';

      serviceLogger.error('test-event', 'Error occurred', error, traceId, { context: 'test' });

      const logContent = readFileSync(testLogFile, 'utf8');
      const logEntry = JSON.parse(logContent.trim());

      expect(logEntry.service).toBe('test-service');
      expect(logEntry.event).toBe('test-event');
      expect(logEntry.severity).toBe('error');
      expect(logEntry.message).toBe('Error occurred');
      expect(logEntry.error.name).toBe('Error');
      expect(logEntry.error.message).toBe('Test error message');
      expect(logEntry.error.code).toBe('TEST_ERROR');
      expect(logEntry.error.stack).toBeDefined();
      expect(logEntry.context).toBe('test');
    });

    test('should perform health checks', () => {
      serviceLogger.healthCheck('healthy', { metric: 0.95 });

      const logContent = readFileSync(testLogFile, 'utf8');
      const lines = logContent.trim().split('\n');

      // Should have 2 entries: performance timer and health check
      expect(lines).toHaveLength(2);

      const healthLogEntry = JSON.parse(lines[1]);
      expect(healthLogEntry.service).toBe('test-service');
      expect(healthLogEntry.event).toBe('health_check');
      expect(healthLogEntry.severity).toBe('info');
      expect(healthLogEntry.status).toBe('healthy');
      expect(healthLogEntry.metric).toBe(0.95);
      expect(healthLogEntry.duration).toBeGreaterThan(0);
    });
  });

  describe('Configuration', () => {
    test('should load default configuration', () => {
      const config = logger.getConfig();

      expect(config.level).toBe('info');
      expect(config.format).toBe('json');
      expect(config.includeTrace).toBe(true);
      expect(config.enablePerformanceMonitoring).toBe(true);
      expect(config.healthCheckBudget).toBe(500);
    });

    test('should load configuration from environment', () => {
      process.env.LOG_LEVEL = 'debug';
      process.env.LOG_FORMAT = 'text';
      process.env.LOG_INCLUDE_TRACE = 'false';
      process.env.HEALTH_CHECK_BUDGET = '1000';
      process.env.SERVICE_LOG_LEVELS = 'webrtc-manager=warn,adb-bridge=debug';

      // Create new logger instance to test environment loading
      const testLogger = new StructuredLogger();
      const config = testLogger.getConfig();

      expect(config.level).toBe('debug');
      expect(config.format).toBe('text');
      expect(config.includeTrace).toBe(false);
      expect(config.healthCheckBudget).toBe(1000);
      expect(config.serviceLevels?.['webrtc-manager']).toBe('warn');
      expect(config.serviceLevels?.['adb-bridge']).toBe('debug');
    });

    test('should update configuration at runtime', () => {
      logger.updateConfig({
        level: 'debug',
        format: 'text',
        includeTrace: false
      });

      const config = logger.getConfig();
      expect(config.level).toBe('debug');
      expect(config.format).toBe('text');
      expect(config.includeTrace).toBe(false);
    });
  });

  describe('Log Filtering', () => {
    test('should filter debug messages when level is info', () => {
      logger.updateConfig({ level: 'info' });
      const serviceLogger = createServiceLogger('filter-test');

      // Clear any existing log file
      if (existsSync(testLogFile)) {
        unlinkSync(testLogFile);
      }

      serviceLogger.debug('debug-event', 'This should not appear');
      serviceLogger.info('info-event', 'This should appear');

      const logContent = readFileSync(testLogFile, 'utf8');
      const lines = logContent.trim().split('\n');

      // Only info message should appear
      expect(lines).toHaveLength(1);
      const logEntry = JSON.parse(lines[0]);
      expect(logEntry.severity).toBe('info');
    });

    test('should respect service-specific log levels', () => {
      process.env.SERVICE_LOG_LEVELS = 'service-debug=debug,service-info=info';

      const debugLogger = createServiceLogger('service-debug');
      const infoLogger = createServiceLogger('service-info');

      // Clear any existing log file
      if (existsSync(testLogFile)) {
        unlinkSync(testLogFile);
      }

      debugLogger.debug('debug-event', 'Debug message from debug service');
      infoLogger.debug('debug-event', 'Debug message from info service');
      infoLogger.info('info-event', 'Info message from info service');

      const logContent = readFileSync(testLogFile, 'utf8');
      const lines = logContent.trim().split('\n');

      // Should have debug from debug service and info from info service
      expect(lines).toHaveLength(2);

      const entries = lines.map(line => JSON.parse(line));
      expect(entries.some(e => e.service === 'service-debug' && e.severity === 'debug')).toBe(true);
      expect(entries.some(e => e.service === 'service-info' && e.severity === 'info')).toBe(true);
      expect(entries.some(e => e.service === 'service-info' && e.severity === 'debug')).toBe(false);
    });
  });

  describe('Performance Monitoring', () => {
    test('should log performance budget warnings', async () => {
      const serviceLogger = createServiceLogger('performance-test');

      // Set a very low budget to trigger warning
      logger.updateConfig({ healthCheckBudget: 10 });

      const timer = serviceLogger.startTimer('health_check');

      // Wait longer than budget
      await new Promise(resolve => setTimeout(resolve, 50));

      timer.end();

      const logContent = readFileSync(testLogFile, 'utf8');
      const lines = logContent.trim().split('\n');

      // Should have both the duration log and the budget warning
      expect(lines).toHaveLength(2);

      const warningEntry = JSON.parse(lines[1]);
      expect(warningEntry.service).toBe('performance-monitor');
      expect(warningEntry.event).toBe('health_check_budget_exceeded');
      expect(warningEntry.severity).toBe('warn');
      expect(warningEntry.budget).toBe(10);
      expect(warningEntry.duration).toBeGreaterThan(10);
    });
  });

  describe('Format Options', () => {
    test('should format logs as JSON by default', () => {
      const serviceLogger = createServiceLogger('format-test');
      serviceLogger.info('test-event', 'Test message', 'trace-123', { key: 'value' });

      const logContent = readFileSync(testLogFile, 'utf8');
      const logEntry = JSON.parse(logContent.trim());

      expect(logEntry.service).toBe('format-test');
      expect(logEntry.event).toBe('test-event');
      expect(logEntry.message).toBe('Test message');
      expect(logEntry.trace_id).toBe('trace-123');
      expect(logEntry.key).toBe('value');
    });

    test('should format logs as text when configured', () => {
      logger.updateConfig({ format: 'text' });
      const serviceLogger = createServiceLogger('format-test');

      // Clear any existing log file
      if (existsSync(testLogFile)) {
        unlinkSync(testLogFile);
      }

      serviceLogger.info('test-event', 'Test message', 'trace-123');

      const logContent = readFileSync(testLogFile, 'utf8').trim();

      expect(logContent).toContain('[INFO]');
      expect(logContent).toContain('format-test');
      expect(logContent).toContain('test-event');
      expect(logContent).toContain('Test message');
      expect(logContent).toContain('[trace:trace-123]');
      expect(logContent).toMatch(/\(\d+ms\)/); // Duration should be present
    });
  });

  describe('Backward Compatibility', () => {
    test('should maintain legacy logger interface', () => {
      // These should not throw errors
      expect(() => {
        logger.debug('Legacy debug message');
        logger.info('Legacy info message');
        logger.warn('Legacy warning message');
        logger.error('Legacy error message');
        logger.log('info', 'Legacy log message');
      }).not.toThrow();
    });

    test('should handle legacy error logging with Error objects', () => {
      const error = new Error('Legacy test error');

      expect(() => {
        logger.error('Legacy error message', error);
      }).not.toThrow();

      const logContent = readFileSync(testLogFile, 'utf8');
      const logEntry = JSON.parse(logContent.trim());

      expect(logEntry.service).toBe('backend');
      expect(logEntry.event).toBe('legacy_error');
      expect(logEntry.message).toBe('Legacy error message');
      expect(logEntry.error).toBeDefined();
    });
  });

  describe('Constitution §10 Compliance', () => {
    test('should include required fields in JSON logs', () => {
      const serviceLogger = createServiceLogger('constitution-test');
      const traceId = serviceLogger.generateTraceId();

      serviceLogger.info('test-event', 'Constitution compliance test', traceId);

      const logContent = readFileSync(testLogFile, 'utf8');
      const logEntry = JSON.parse(logContent.trim());

      // Check required fields from Constitution §10
      expect(logEntry.service).toBe('constitution-test');
      expect(logEntry.event).toBe('test-event');
      expect(logEntry.severity).toBe('info');
      expect(logEntry.trace_id).toBe(traceId);
      expect(logEntry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });

    test('should support health check performance budget (<500ms)', async () => {
      const serviceLogger = createServiceLogger('health-test');

      const startTime = Date.now();
      serviceLogger.healthCheck('healthy');
      const endTime = Date.now();

      const duration = endTime - startTime;

      // Health check should complete quickly
      expect(duration).toBeLessThan(100);

      const logContent = readFileSync(testLogFile, 'utf8');
      const lines = logContent.trim().split('\n');

      // Should include performance timing
      expect(lines.length).toBeGreaterThanOrEqual(1);
      const healthEntry = JSON.parse(lines[lines.length - 1]);
      expect(healthEntry.duration).toBeGreaterThan(0);
    });
  });
});