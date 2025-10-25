# Structured JSON Logging Service

This document describes the structured JSON logging service implemented in `/home/blhack/project/Apptest/backend/src/services/logger.ts`, which provides Constitution §10 compliant logging for the AutoApp system.

## Overview

The structured logging service provides:
- **JSON structured logs** with required fields (service, event, severity, timestamp, trace_id)
- **Service-specific loggers** for different components
- **Request correlation** via trace IDs
- **Performance monitoring** with timing helpers
- **Error context capture** with detailed error information
- **Health check logging** with performance budget monitoring (<500ms)
- **Environment configuration** support
- **Backward compatibility** with existing code

## Constitution §10 Compliance

The logger is fully compliant with Constitution §10 requirements:

### Required Fields
All JSON log entries include:
- `service`: Service name (e.g., "webrtc-manager", "adb-bridge", "ui-capture")
- `event`: Event type/name
- `severity`: debug, info, warn, error
- `timestamp`: ISO timestamp
- `trace_id`: Request/operation correlation ID (optional, configurable)

### Health Check Performance Budget
- Health checks must complete within 500ms performance budget
- Automatic warnings when budget is exceeded
- Performance metrics included in health check logs

## Usage

### Service-Specific Loggers

```typescript
import { createServiceLogger } from './logger';

// Create a service-specific logger
const webrtcLogger = createServiceLogger('webrtc-manager');

// Generate trace ID for request correlation
const traceId = webrtcLogger.generateTraceId();

// Log structured messages
webrtcLogger.info('connection_start', 'WebRTC connection initiated', traceId, {
  clientId: 'client-123',
  protocol: 'webrtc'
});

// Log errors with context
webrtcLogger.error('connection_failed', 'WebRTC connection failed', error, traceId, {
  clientId: 'client-123',
  errorCode: 'TIMEOUT'
});
```

### Performance Monitoring

```typescript
// Start a performance timer
const timer = webrtcLogger.startTimer('connection_establishment', traceId, {
  clientId: 'client-123'
});

// When operation completes
const duration = timer.end({
  status: 'success',
  iceCandidates: 5
});

// Automatic performance budget warnings for health checks
webrtcLogger.healthCheck('healthy', {
  activeConnections: 12,
  bandwidth: '2.5 Mbps'
});
```

### Error Logging

```typescript
try {
  await riskyOperation();
} catch (error) {
  webrtcLogger.error('operation_failed', 'Risky operation failed', error, traceId, {
    operationType: 'webrtc_negotiation',
    retryCount: 3
  });
}
```

### Request Correlation

```typescript
class RequestHandler {
  private traceId: string;

  constructor() {
    this.traceId = logger.generateTraceId();
  }

  async processRequest(request: Request) {
    // Start request
    logger.info('request_start', `Processing ${request.method} ${request.path}`, undefined, {
      requestId: this.traceId,
      method: request.method,
      path: request.path
    });

    try {
      // Process using service loggers with same trace ID
      const result = await service.process(request, this.traceId);

      logger.info('request_complete', 'Request processed successfully', undefined, {
        requestId: this.traceId,
        duration: Date.now() - startTime
      });

      return result;
    } catch (error) {
      logger.error('request_failed', 'Request processing failed', error, undefined, {
        requestId: this.traceId
      });
      throw error;
    }
  }
}
```

## Environment Configuration

The logger supports configuration via environment variables:

### Basic Configuration
- `LOG_LEVEL`: Overall logging level (debug, info, warn, error) - default: info
- `LOG_FORMAT`: Output format (json, text) - default: json
- `LOG_INCLUDE_TRACE`: Include trace IDs (true/false) - default: true
- `LOG_DIR`: Log directory path - default: ../var/log/autoapp
- `LOG_FILE`: Log file name - default: backend.log

### Advanced Configuration
- `SERVICE_LOG_LEVELS`: Service-specific log levels (comma-separated)
  - Example: `webrtc-manager=debug,adb-bridge=warn,flow-service=error`
- `ENABLE_PERFORMANCE_MONITORING`: Enable performance monitoring - default: true
- `HEALTH_CHECK_BUDGET`: Health check performance budget in ms - default: 500

### Example Configuration
```bash
# Set debug logging for development
export LOG_LEVEL=debug
export LOG_FORMAT=json

# Service-specific levels
export SERVICE_LOG_LEVELS="webrtc-manager=debug,adb-bridge=info,flow-service=warn"

# Performance settings
export HEALTH_CHECK_BUDGET=300
export ENABLE_PERFORMANCE_MONITORING=true
```

## API Reference

### createServiceLogger(serviceName: string): ServiceLogger

Creates a service-specific logger instance.

### ServiceLogger Methods

#### Logging Methods
- `debug(event: string, message: string, traceId?: string, metadata?: Record<string, unknown>)`
- `info(event: string, message: string, traceId?: string, metadata?: Record<string, unknown>)`
- `warn(event: string, message: string, traceId?: string, metadata?: Record<string, unknown>)`
- `error(event: string, message: string, error?: Error, traceId?: string, metadata?: Record<string, unknown>)`

#### Utility Methods
- `generateTraceId(): string` - Generate a new trace ID
- `startTimer(operation: string, traceId?: string, context?: Record<string, unknown>): PerformanceTimer` - Start performance timer
- `healthCheck(status: 'healthy' | 'unhealthy', details?: Record<string, unknown>)` - Log health check with performance monitoring

### PerformanceTimer Methods
- `end(additionalContext?: Record<string, unknown>): number` - End timer and return duration

### Global Logger Methods
- `logger.generateTraceId(): string` - Generate trace ID
- `logger.startTimer(operation: string, traceId?: string, context?: Record<string, unknown>): PerformanceTimer` - Start timer
- `logger.getConfig(): LoggerConfig` - Get current configuration
- `logger.updateConfig(updates: Partial<LoggerConfig>): void` - Update configuration

### Legacy Methods (Backward Compatibility)
- `logger.debug(message: string, details?: Record<string, unknown>)`
- `logger.info(message: string, details?: Record<string, unknown>)`
- `logger.warn(message: string, details?: Record<string, unknown>)`
- `logger.error(message: string, details?: Record<string, unknown> | Error)`

## Integration Examples

### WebRTC Manager Integration

```typescript
import { createServiceLogger } from './logger';

const webrtcLogger = createServiceLogger('webrtc-manager');

export class WebRTCManager {
  async connect(clientId: string): Promise<void> {
    const traceId = webrtcLogger.generateTraceId();
    const timer = webrtcLogger.startTimer('webrtc_connection', traceId);

    try {
      webrtcLogger.info('connection_start', 'Initiating WebRTC connection', traceId, {
        clientId,
        protocol: 'webrtc'
      });

      // Connection logic...

      const duration = timer.end({ status: 'connected' });
      webrtcLogger.info('connection_established', 'WebRTC connection established', traceId, {
        clientId,
        duration
      });

    } catch (error) {
      timer.end({ status: 'failed', error: error.message });
      webrtcLogger.error('connection_failed', 'WebRTC connection failed', error, traceId, {
        clientId
      });
      throw error;
    }
  }

  async performHealthCheck(): Promise<void> {
    webrtcLogger.healthCheck('healthy', {
      activeConnections: this.getActiveConnections(),
      totalBandwidth: this.getTotalBandwidth()
    });
  }
}
```

### ADB Bridge Integration

```typescript
const adbLogger = createServiceLogger('adb-bridge');

export class ADBBridge {
  async executeCommand(command: string, deviceId: string): Promise<string> {
    const traceId = adbLogger.generateTraceId();
    const timer = adbLogger.startTimer('adb_command', traceId, { command, deviceId });

    try {
      adbLogger.info('command_start', `Executing ADB command: ${command}`, traceId);

      const result = await this.executeCommandInternal(command, deviceId);
      const duration = timer.end({ status: 'success', outputLength: result.length });

      adbLogger.info('command_complete', 'ADB command executed successfully', traceId, {
        command,
        deviceId,
        duration,
        outputSize: result.length
      });

      return result;

    } catch (error) {
      timer.end({ status: 'failed', error: error.message });
      adbLogger.error('command_failed', 'ADB command failed', error, traceId, {
        command,
        deviceId
      });
      throw error;
    }
  }
}
```

## Log Format Examples

### JSON Format (Default)
```json
{
  "service": "webrtc-manager",
  "event": "connection_established",
  "severity": "info",
  "timestamp": "2025-10-25T17:01:04.462Z",
  "trace_id": "941904dfaf6d4308",
  "message": "WebRTC connection established successfully",
  "duration": 150,
  "metadata": {
    "clientId": "client-123",
    "protocol": "webrtc",
    "iceCandidates": 5
  }
}
```

### Error Log with Context
```json
{
  "service": "adb-bridge",
  "event": "command_failed",
  "severity": "error",
  "timestamp": "2025-10-25T17:01:04.462Z",
  "trace_id": "219df7d5924246b5",
  "message": "ADB command failed",
  "error": {
    "name": "ADBError",
    "message": "Device not found: emulator-5554",
    "stack": "Error: Device not found...",
    "code": "DEVICE_NOT_FOUND"
  },
  "metadata": {
    "command": "devices",
    "deviceId": "emulator-5554"
  }
}
```

### Text Format
```
[2025-10-25T17:01:04.462Z] [INFO] webrtc-manager connection_established WebRTC connection established successfully [trace:941904dfaf6d4308] (150ms) {"clientId":"client-123","protocol":"webrtc"}
```

## Performance Monitoring

The logger automatically monitors performance for:
- **Health checks**: Warns when exceeding the 500ms budget
- **Operation timing**: Tracks duration of timed operations
- **Request correlation**: Links related operations across services

### Performance Budget Warnings
```json
{
  "service": "performance-monitor",
  "event": "health_check_budget_exceeded",
  "severity": "warn",
  "timestamp": "2025-10-25T17:01:04.462Z",
  "trace_id": "941904dfaf6d4308",
  "message": "Health check exceeded budget: 750ms > 500ms",
  "operation": "webrtc:health_check",
  "duration": 750,
  "budget": 500
}
```

## Testing

Run the demo to test all logger features:

```bash
npx ts-node src/services/logger-demo.ts
```

Run the test suite:

```bash
npm test -- src/services/__tests__/logger.test.ts
```

## Migration Guide

### From Legacy Logger

**Before:**
```typescript
logger.info('User authenticated', {
  userId: 123,
  method: 'oauth'
});
```

**After:**
```typescript
const authLogger = createServiceLogger('auth-service');
const traceId = authLogger.generateTraceId();

authLogger.info('user_authenticated', 'User authenticated successfully', traceId, {
  userId: 123,
  method: 'oauth'
});
```

### Benefits of Migration
1. **Service-specific loggers** for better organization
2. **Trace correlation** across service boundaries
3. **Performance monitoring** with automatic budget warnings
4. **Better error context** with structured error information
5. **Consistent log format** across all services
6. **Filtering capabilities** by service and log level

## File Structure

```
backend/src/services/
├── logger.ts                    # Main logger implementation
├── logger-examples.ts          # Comprehensive usage examples
├── logger-demo.ts              # Interactive demo script
├── __tests__/
│   └── logger.test.ts          # Test suite
└── README-logger.md           # This documentation
```

## Support

For questions or issues with the structured logging service:
1. Check the demo script for usage examples
2. Review the test suite for edge cases
3. Consult the Constitution §10 requirements for compliance
4. Check the environment variables for configuration options

The logger is designed to be backwards compatible while providing modern structured logging capabilities for the AutoApp system.