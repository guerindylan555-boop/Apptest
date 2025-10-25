# UI Capture Service (T024)

A specialized UIAutomator2-based capture service for Android UI state discovery. Implements high-performance state capture with XML hierarchy parsing, selector extraction, screenshot storage, and comprehensive error handling.

## Features

- **UIAutomator2 Integration**: Uses existing ADB bridge for UIAutomator2 communication
- **Parallel Execution**: Optimized for sub-1s capture performance with concurrent ADB commands
- **State Entity Integration**: Creates State entities using the existing State model from `backend/src/models/state.ts`
- **Comprehensive Selector Extraction**: Extracts resource-id, text, content-desc, class, bounds, and XPath
- **Screenshot Management**: Captures and stores screenshots with deduplication
- **Structured Logging**: Integration with existing logger service for performance monitoring
- **Production-Ready**: Comprehensive error handling, timeouts, and health checks
- **Constitution Compliant**: Follows existing code patterns and requirements

## Installation

```typescript
import { UICaptureService, captureUIState, uiCaptureService } from './services/ui-capture';
```

## Quick Start

### Basic Usage

```typescript
import { captureUIState } from './services/ui-capture';

// Simple UI state capture
try {
  const result = await captureUIState();

  console.log('State captured:', result.state.id);
  console.log('Package:', result.state.package);
  console.log('Activity:', result.state.activity);
  console.log('Selectors found:', result.state.selectors.length);
  console.log('Capture time:', result.captureTime + 'ms');
} catch (error) {
  console.error('Capture failed:', error);
}
```

### Advanced Usage

```typescript
import { captureUIState } from './services/ui-capture';

// Capture with custom options
const result = await captureUIState({
  timeout: 10000,           // 10 second timeout
  skipScreenshot: false,    // Include screenshot
  forceScreenshot: true,    // Force screenshot recreation
  tags: ['test-capture'],   // Tags for the state
  minImportance: 0.5,       // Only capture important elements
  includeXPath: true,       // Include XPath in selectors
  traceId: 'custom-trace'   // Custom trace ID
});

// Access captured state
const state = result.state;
console.log('Interactive elements:', state.getInteractiveSelectors());
console.log('Available text:', state.getAvailableText());
console.log('Contains login text:', state.containsText('Login'));
```

## API Reference

### UICaptureOptions

Configuration options for UI state capture:

```typescript
interface UICaptureOptions {
  /** Capture timeout in milliseconds (default: 5000) */
  timeout?: number;

  /** Skip screenshot capture for performance (default: false) */
  skipScreenshot?: boolean;

  /** Force screenshot recreation even if exists (default: false) */
  forceScreenshot?: boolean;

  /** Tags to apply to captured state */
  tags?: string[];

  /** Minimum selector importance threshold (0-1, default: 0.3) */
  minImportance?: number;

  /** Include XPath in selectors (default: true) */
  includeXPath?: boolean;

  /** Trace ID for correlation */
  traceId?: string;
}
```

### UICaptureResult

Result object returned by capture operations:

```typescript
interface UICaptureResult {
  /** Captured state entity */
  state: State;

  /** Total capture time in milliseconds */
  captureTime: number;

  /** Whether state was merged with existing */
  merged: boolean;

  /** ID of state merged into (if applicable) */
  mergedInto?: string;

  /** Capture metadata */
  metadata: {
    /** XML hierarchy hash */
    xmlHash: string;

    /** Total selectors found */
    totalSelectors: number;

    /** Interactive selectors found */
    interactiveSelectors: number;

    /** Hierarchy depth */
    hierarchyDepth: number;

    /** Screenshot captured successfully */
    screenshotCaptured: boolean;

    /** Package name */
    packageName: string;

    /** Activity name */
    activityName: string;
  };
}
```

### UICaptureService Class

Main service class for UI capture operations:

```typescript
class UICaptureService {
  // Capture current UI state
  async captureState(options?: UICaptureOptions): Promise<UICaptureResult>

  // Validate device readiness
  async validateDevice(traceId?: string): Promise<DeviceValidationResult>

  // Get device information
  async getDeviceInfo(traceId?: string): Promise<DeviceInfo>

  // Test performance
  async testPerformance(iterations?: number, options?: Partial<UICaptureOptions>): Promise<PerformanceMetrics>

  // Get performance metrics
  getPerformanceMetrics(): PerformanceMetrics

  // Reset performance metrics
  resetPerformanceMetrics(): void

  // Health check
  async healthCheck(): Promise<{ healthy: boolean; details: Record<string, any> }>

  // Cleanup
  close(): void
}
```

## Usage Examples

### Device Validation

```typescript
import { UICaptureService } from './services/ui-capture';

const service = new UICaptureService();

try {
  const validation = await service.validateDevice();

  if (!validation.connected) {
    console.log('Device not connected');
    return;
  }

  if (!validation.responsive) {
    console.log('Device not responsive');
    return;
  }

  console.log('Device ready:', {
    activity: validation.activity,
    package: validation.package,
    model: validation.model,
    version: validation.version
  });

  // Proceed with capture
  const result = await service.captureState();

} finally {
  service.close();
}
```

### Performance Testing

```typescript
import { uiCaptureService } from './services/ui-capture';

// Test performance with 10 iterations
const metrics = await uiCaptureService.testPerformance(10, {
  skipScreenshot: true,
  minImportance: 0.3
});

console.log('Performance Results:', {
  averageTime: metrics.averageTime,
  successRate: metrics.successRate,
  minTime: metrics.minTime,
  maxTime: metrics.maxTime
});
```

### State Analysis

```typescript
import { captureUIState } from './services/ui-capture';

const result = await captureUIState();
const state = result.state;

// Get interactive elements
const interactiveElements = state.getInteractiveSelectors(0.5);
console.log('Interactive elements:', interactiveElements.length);

// Filter by criteria
const buttons = state.getSelectorsByCriteria({
  cls: /Button/i,
  interactive: true,
  minImportance: 0.5
});

// Check for specific text
const hasLogin = state.containsText('Login');

// Get state summary
const summary = state.getSummary();
console.log('State summary:', summary);
```

### Batch Capture

```typescript
import { captureUIState } from './services/ui-capture';

const configurations = [
  { name: 'Fast', options: { skipScreenshot: true, minImportance: 0.7 } },
  { name: 'Full', options: { forceScreenshot: true, minImportance: 0.1 } },
  { name: 'Interactive', options: { minImportance: 0.8 } }
];

for (const config of configurations) {
  try {
    const result = await captureUIState({
      ...config.options,
      tags: [config.name.toLowerCase()]
    });

    console.log(`${config.name}: ${result.captureTime}ms, ${result.metadata.totalSelectors} selectors`);
  } catch (error) {
    console.log(`${config.name} failed:`, error);
  }
}
```

## Performance Optimization

The service is optimized for sub-1s capture performance:

### Parallel Execution

```typescript
// ADB commands run in parallel:
const [activity, xml, screenshot] = await Promise.all([
  getCurrentActivity(),
  getUIHierarchy(),
  captureScreenshot()
]);
```

### Selective Capture

```typescript
// Fast capture (no screenshot, high importance threshold)
const fastResult = await captureUIState({
  skipScreenshot: true,
  minImportance: 0.7
});

// Detailed capture (full screenshot, low importance threshold)
const detailedResult = await captureUIState({
  forceScreenshot: true,
  minImportance: 0.1
});
```

### Performance Monitoring

```typescript
// Get current performance metrics
const metrics = uiCaptureService.getPerformanceMetrics();

if (metrics.averageTime > 1000) {
  console.warn('Capture performance below target:', metrics.averageTime + 'ms');
}

// Test performance under load
const testMetrics = await uiCaptureService.testPerformance(20);
console.log('Load test results:', testMetrics);
```

## Error Handling

The service provides comprehensive error handling:

```typescript
import { UICaptureError, captureUIState } from './services/ui-capture';

try {
  const result = await captureUIState();
} catch (error) {
  if (error instanceof UICaptureError) {
    console.error('UI Capture Error:', error.message);
    console.error('Error Code:', error.code);
    console.error('Context:', error.context);
    console.error('Timestamp:', error.timestamp);
  } else {
    console.error('Unexpected Error:', error);
  }
}
```

### Common Error Scenarios

```typescript
// Handle device connection issues
const service = new UICaptureService();

try {
  const validation = await service.validateDevice();
  if (!validation.connected) {
    throw new Error('Device not connected');
  }

  const result = await service.captureState();
} catch (error) {
  if (error.message.includes('timeout')) {
    console.log('Capture timed out, retrying...');
    // Implement retry logic
  } else if (error.message.includes('not connected')) {
    console.log('Device disconnected, checking connection...');
    // Implement device reconnection
  }
}
```

## Configuration

### Environment Variables

```bash
# ADB Configuration
ADB_HOST=host.docker.internal
ADB_PORT=5555
ANDROID_SERIAL=emulator-5554

# Capture Configuration
SNAPSHOT_TIMEOUT_MS=5000
SCREENSHOTS_DIR=/app/data/screenshots

# Logging Configuration
LOG_LEVEL=info
LOG_FORMAT=json
LOG_DIR=/app/logs
```

### Service Configuration

```typescript
// Custom service instance
import { UICaptureService } from './services/ui-capture';

const service = new UICaptureService();

// Configure logging
const logger = service['logger']; // Access to service logger
```

## Integration

### With Graph Service

```typescript
import { captureUIState } from './services/ui-capture';
import { graphService } from './services/graph';

// Capture and add to graph
const result = await captureUIState();
const graphResult = await graphService.addState(result.state);

console.log('State added to graph:', graphResult.stateId);
```

### With Flow Engine

```typescript
import { captureUIState } from './services/ui-capture';
import { flowEngine } from './services/flow-engine';

// Capture state and update flow
const result = await captureUIState();
const flowUpdate = await flowEngine.updateCurrentState(result.state);

console.log('Flow updated:', flowUpdate);
```

## Testing

### Unit Tests

```typescript
import { UICaptureService } from './services/ui-capture';

// Mock dependencies for testing
jest.mock('../utils/adb');
jest.mock('../utils/xml');

describe('UICaptureService', () => {
  let service: UICaptureService;

  beforeEach(() => {
    service = new UICaptureService();
  });

  afterEach(() => {
    service.close();
  });

  it('should capture state successfully', async () => {
    // Test implementation
  });
});
```

### Integration Tests

```typescript
// Integration tests require actual device/emulator
describe('UICaptureService Integration', () => {
  it('should capture real UI state', async () => {
    const service = new UICaptureService();

    try {
      const result = await service.captureState();
      expect(result.state.id).toBeDefined();
      expect(result.captureTime).toBeLessThan(2000);
    } finally {
      service.close();
    }
  });
});
```

## Best Practices

### Performance

1. **Use parallel execution** - The service automatically runs ADB commands in parallel
2. **Selective screenshots** - Skip screenshots when not needed for faster captures
3. **Importance thresholds** - Use `minImportance` to focus on relevant elements
4. **Monitor performance** - Use `getPerformanceMetrics()` to track capture times

### Error Handling

1. **Validate device first** - Use `validateDevice()` before capture operations
2. **Handle timeouts** - Implement appropriate timeout values and retry logic
3. **Health checks** - Use `healthCheck()` for service monitoring
4. **Structured logging** - All operations include structured logging for debugging

### Resource Management

1. **Close connections** - Always call `close()` when done with service instances
2. **Monitor memory** - Use performance metrics to track resource usage
3. **Cleanup resources** - Service automatically manages connection pooling

## Troubleshooting

### Common Issues

1. **Capture timeout**:
   - Increase timeout value in options
   - Check device responsiveness with `validateDevice()`
   - Monitor network connectivity

2. **Screenshot failures**:
   - Check available disk space
   - Verify screenshots directory permissions
   - Use `skipScreenshot: true` for testing

3. **XML parsing errors**:
   - Ensure UIAutomator2 is properly installed
   - Check device screen is on and unlocked
   - Verify app is in foreground

4. **Performance issues**:
   - Use `skipScreenshot: true` for faster captures
   - Increase `minImportance` threshold
   - Monitor device CPU and memory usage

### Debug Logging

```typescript
// Enable debug logging
process.env.LOG_LEVEL = 'debug';

// Use custom trace ID for correlation
const result = await captureUIState({
  traceId: 'debug-session-123'
});

// Check logs for trace ID
// Logs will include structured debugging information
```

## License

This service is part of the AutoApp UI Map & Intelligent Flow Engine project. See project license for details.