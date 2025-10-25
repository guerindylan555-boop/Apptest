import { appendFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';
import { resolve } from 'path';
import { randomUUID } from 'crypto';

// ============================================================================
// TypeScript Interfaces (Constitution §10 Compliance)
// ============================================================================

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type LogFormat = 'json' | 'text';

export interface LogContext {
  /** Service name (e.g., "webrtc-manager", "adb-bridge", "ui-capture") */
  service: string;

  /** Event type/name */
  event: string;

  /** Severity level */
  severity: LogLevel;

  /** ISO timestamp */
  timestamp: string;

  /** Request/operation correlation ID */
  trace_id?: string;

  /** Additional context-specific fields */
  [key: string]: unknown;
}

export interface LogEntry extends LogContext {
  /** Human-readable log message */
  message: string;

  /** Performance timing data (ms) */
  duration?: number;

  /** Error details if applicable */
  error?: {
    name: string;
    message: string;
    stack?: string;
    code?: string | number;
  };

  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

export interface LoggerConfig {
  /** Overall logging level */
  level: LogLevel;

  /** Output format */
  format: LogFormat;

  /** Whether to include trace IDs */
  includeTrace: boolean;

  /** Log directory */
  logDir: string;

  /** Log file name */
  logFile: string;

  /** Service-specific log levels */
  serviceLevels?: Record<string, LogLevel>;

  /** Performance monitoring enabled */
  enablePerformanceMonitoring: boolean;

  /** Health check performance budget (ms) */
  healthCheckBudget: number;
}

export interface PerformanceTimer {
  /** Start timestamp */
  startTime: number;

  /** Operation description */
  operation: string;

  /** Trace ID */
  traceId?: string;

  /** Additional context */
  context?: Record<string, unknown>;

  /** End the timer and log duration */
  end(additionalContext?: Record<string, unknown>): number;
}

// ============================================================================
// Environment Configuration
// ============================================================================

const getConfig = (): LoggerConfig => {
  const logDir = resolve(process.env.LOG_DIR || process.cwd(), '../var/log/autoapp');

  // Ensure log directory exists
  if (!existsSync(logDir)) {
    mkdirSync(logDir, { recursive: true });
  }

  return {
    level: (process.env.LOG_LEVEL as LogLevel) || 'info',
    format: (process.env.LOG_FORMAT as LogFormat) || 'json',
    includeTrace: process.env.LOG_INCLUDE_TRACE !== 'false',
    logDir,
    logFile: process.env.LOG_FILE || 'backend.log',
    serviceLevels: parseServiceLevels(process.env.SERVICE_LOG_LEVELS),
    enablePerformanceMonitoring: process.env.ENABLE_PERFORMANCE_MONITORING !== 'false',
    healthCheckBudget: parseInt(process.env.HEALTH_CHECK_BUDGET || '500', 10)
  };
};

const parseServiceLevels = (env?: string): Record<string, LogLevel> => {
  if (!env) return {};

  try {
    const levels: Record<string, LogLevel> = {};
    env.split(',').forEach(pair => {
      const [service, level] = pair.trim().split('=');
      if (service && level && ['debug', 'info', 'warn', 'error'].includes(level)) {
        levels[service.trim()] = level as LogLevel;
      }
    });
    return levels;
  } catch {
    return {};
  }
};

// ============================================================================
// Logger Implementation
// ============================================================================

class StructuredLogger {
  private config: LoggerConfig;
  private logFilePath: string;

  constructor() {
    this.config = getConfig();
    this.logFilePath = resolve(this.config.logDir, this.config.logFile);
  }

  /**
   * Generate a new trace ID
   */
  generateTraceId(): string {
    return randomUUID().replace(/-/g, '').substring(0, 16);
  }

  /**
   * Create a performance timer for measuring operation duration
   */
  startTimer(operation: string, traceId?: string, context?: Record<string, unknown>): PerformanceTimer {
    const startTime = Date.now();

    return {
      startTime,
      operation,
      traceId,
      context,
      end: (additionalContext?: Record<string, unknown>) => {
        const duration = Date.now() - startTime;

        this.logEntry({
          service: 'performance-monitor',
          event: 'operation_duration',
          severity: 'info',
          timestamp: new Date().toISOString(),
          trace_id: traceId,
          operation,
          duration,
          message: `Operation ${operation} completed in ${duration}ms`,
          ...context,
          ...additionalContext
        });

        // Health check performance budget warning
        if (operation.includes('health') && duration > this.config.healthCheckBudget) {
          this.logEntry({
            service: 'performance-monitor',
            event: 'health_check_budget_exceeded',
            severity: 'warn',
            timestamp: new Date().toISOString(),
            trace_id: traceId,
            operation,
            duration,
            budget: this.config.healthCheckBudget,
            message: `Health check exceeded budget: ${duration}ms > ${this.config.healthCheckBudget}ms`
          });
        }

        return duration;
      }
    };
  }

  /**
   * Check if a log level should be filtered out
   */
  private shouldLog(service: string, severity: LogLevel): boolean {
    const levels = ['debug', 'info', 'warn', 'error'] as const;
    const configLevel = this.config.serviceLevels?.[service] || this.config.level;

    const configIndex = levels.indexOf(configLevel);
    const severityIndex = levels.indexOf(severity);

    return severityIndex >= configIndex;
  }

  /**
   * Format log entry based on configuration
   */
  private format(entry: LogEntry): string {
    if (this.config.format === 'text') {
      const parts = [
        `[${entry.timestamp}]`,
        `[${entry.severity.toUpperCase()}]`,
        entry.service,
        entry.event,
        entry.message
      ];

      if (entry.trace_id && this.config.includeTrace) {
        parts.push(`[trace:${entry.trace_id}]`);
      }

      if (entry.duration) {
        parts.push(`(${entry.duration}ms)`);
      }

      let formatted = parts.join(' ');

      if (entry.error) {
        formatted += ` Error: ${entry.error.name}: ${entry.error.message}`;
      }

      if (entry.metadata && Object.keys(entry.metadata).length > 0) {
        formatted += ` ${JSON.stringify(entry.metadata)}`;
      }

      return formatted;
    }

    // JSON format (default)
    const jsonEntry = { ...entry };

    if (!this.config.includeTrace && jsonEntry.trace_id) {
      delete jsonEntry.trace_id;
    }

    return JSON.stringify(jsonEntry);
  }

  /**
   * Write log entry to file and console
   */
  private write(formattedEntry: string, severity: LogLevel): void {
    // Write to file
    try {
      appendFileSync(this.logFilePath, formattedEntry + '\n');
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }

    // Write to console for errors and warnings
    if (severity === 'error') {
      console.error(formattedEntry);
    } else if (severity === 'warn') {
      console.warn(formattedEntry);
    } else if (this.config.level === 'debug') {
      console.log(formattedEntry);
    }
  }

  /**
   * Internal log method
   */
  logEntry(entry: LogEntry): void {
    if (!this.shouldLog(entry.service, entry.severity)) {
      return;
    }

    const formatted = this.format(entry);
    this.write(formatted, entry.severity);
  }

  /**
   * Log a message with structured context
   */
  log(context: LogContext, message: string, metadata?: Record<string, unknown>): void {
    this.logEntry({
      ...context,
      message,
      timestamp: context.timestamp || new Date().toISOString(),
      metadata
    });
  }

  /**
   * Debug level logging
   */
  debug(service: string, event: string, message: string, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logEntry({
      service,
      event,
      severity: 'debug',
      timestamp: new Date().toISOString(),
      trace_id: this.config.includeTrace ? traceId : undefined,
      message,
      metadata
    });
  }

  /**
   * Info level logging
   */
  info(service: string, event: string, message: string, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logEntry({
      service,
      event,
      severity: 'info',
      timestamp: new Date().toISOString(),
      trace_id: this.config.includeTrace ? traceId : undefined,
      message,
      metadata
    });
  }

  /**
   * Warning level logging
   */
  warn(service: string, event: string, message: string, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logEntry({
      service,
      event,
      severity: 'warn',
      timestamp: new Date().toISOString(),
      trace_id: this.config.includeTrace ? traceId : undefined,
      message,
      metadata
    });
  }

  /**
   * Error level logging
   */
  error(service: string, event: string, message: string, error?: Error, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logEntry({
      service,
      event,
      severity: 'error',
      timestamp: new Date().toISOString(),
      trace_id: this.config.includeTrace ? traceId : undefined,
      message,
      metadata,
      error: error ? {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: (error as any).code
      } : undefined
    });
  }

  /**
   * Get current configuration
   */
  getConfig(): LoggerConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(updates: Partial<LoggerConfig>): void {
    this.config = { ...this.config, ...updates };
  }
}

// ============================================================================
// Service-Specific Logger Factory
// ============================================================================

class ServiceLogger {
  constructor(
    private logger: StructuredLogger,
    private serviceName: string
  ) {}

  /**
   * Generate a trace ID for this service
   */
  generateTraceId(): string {
    return this.logger.generateTraceId();
  }

  /**
   * Start a performance timer for this service
   */
  startTimer(operation: string, traceId?: string, context?: Record<string, unknown>): PerformanceTimer {
    return this.logger.startTimer(`${this.serviceName}:${operation}`, traceId, context);
  }

  debug(event: string, message: string, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logger.debug(this.serviceName, event, message, traceId, metadata);
  }

  info(event: string, message: string, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logger.info(this.serviceName, event, message, traceId, metadata);
  }

  warn(event: string, message: string, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logger.warn(this.serviceName, event, message, traceId, metadata);
  }

  error(event: string, message: string, error?: Error, traceId?: string, metadata?: Record<string, unknown>): void {
    this.logger.error(this.serviceName, event, message, error, traceId, metadata);
  }

  /**
   * Log health check with performance monitoring
   */
  healthCheck(status: 'healthy' | 'unhealthy', details?: Record<string, unknown>): void {
    const timer = this.startTimer('health_check');
    const duration = timer.end();

    if (status === 'healthy') {
      this.info('health_check', `Service health check passed`, undefined, {
        status,
        duration,
        ...details
      });
    } else {
      this.error('health_check', `Service health check failed`, undefined, undefined, {
        status,
        duration,
        ...details
      });
    }
  }
}

// ============================================================================
// Export Instances
// ============================================================================

// Global logger instance
const structuredLogger = new StructuredLogger();

// Create service-specific logger factory
export const createServiceLogger = (serviceName: string): ServiceLogger => {
  return new ServiceLogger(structuredLogger, serviceName);
};

// Export the main logger for backward compatibility
export const logger = {
  // Legacy methods for backward compatibility
  log: (level: LogLevel, message: string, details?: Record<string, unknown>) => {
    structuredLogger.logEntry({
      service: 'backend',
      event: 'legacy_log',
      severity: level,
      timestamp: new Date().toISOString(),
      trace_id: structuredLogger.generateTraceId(),
      message,
      metadata: details
    });
  },

  debug: (message: string, details?: Record<string, unknown>) => {
    structuredLogger.debug('backend', 'legacy_debug', message, undefined, details);
  },

  info: (message: string, details?: Record<string, unknown>) => {
    structuredLogger.info('backend', 'legacy_info', message, undefined, details);
  },

  warn: (message: string, details?: Record<string, unknown>) => {
    structuredLogger.warn('backend', 'legacy_warn', message, undefined, details);
  },

  error: (message: string, details?: Record<string, unknown> | Error) => {
    if (details instanceof Error) {
      structuredLogger.error('backend', 'legacy_error', message, details);
    } else {
      structuredLogger.error('backend', 'legacy_error', message, undefined, undefined, details);
    }
  },

  // New structured logging methods
  createServiceLogger,

  // Performance monitoring
  startTimer: (operation: string, traceId?: string, context?: Record<string, unknown>) => {
    return structuredLogger.startTimer(operation, traceId, context);
  },

  generateTraceId: () => structuredLogger.generateTraceId(),

  // Configuration
  getConfig: () => structuredLogger.getConfig(),
  updateConfig: (updates: Partial<LoggerConfig>) => structuredLogger.updateConfig(updates)
};

// Export types and classes
export { StructuredLogger, ServiceLogger };
