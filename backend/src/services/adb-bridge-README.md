# ADB Bridge Service

Enhanced ADB service specialized for UIAutomator2 communication and UI state capture in the AutoApp UI Map & Flow Engine.

## Overview

The ADB Bridge Service provides robust connection management, health checks, and error handling for Android emulator interaction. It extends the existing ADB utility with specialized UIAutomator2 operations, structured logging, and comprehensive error recovery mechanisms.

## Features

### Core Functionality
- **ADB Device Connection Management**: Reliable connection to Android emulators with automatic retry logic
- **UIAutomator2 Command Execution**: Optimized UIAutomator2 operations for UI inspection and automation
- **Device State Monitoring**: Real-time connection health checks and automatic recovery
- **Comprehensive Error Handling**: Structured error types with detailed context and retry strategies
- **Environment Variable Support**: Full configuration via environment variables

### UI Operations
- **UI Hierarchy Capture**: XML dump with filtering, compression, and depth limiting options
- **Screenshot Capture**: High-quality screenshot capture with flexible output formats
- **Combined UI State Capture**: Simultaneous hierarchy and screenshot capture for efficiency
- **Device Information Retrieval**: Comprehensive device properties and current activity detection

### Device Control
- **Touch Gestures**: Tap, swipe, and long press with precise coordinate control
- **Text Input**: Virtual keyboard text input with special character support
- **Navigation**: Back button press and system navigation
- **Orientation Control**: Portrait/landscape orientation management

### Monitoring & Health
- **Connection Health Monitoring**: Real-time status tracking with performance metrics
- **Command Statistics**: Response time tracking and success/failure rates
- **Automatic Reconnection**: Intelligent recovery from connection failures
- **Structured Logging**: Detailed operation logging with context metadata

## Installation

The ADB Bridge Service is integrated into the existing backend structure. No additional dependencies required.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANDROID_SERIAL` | `emulator-5554` | Android device serial number |
| `ADB_HOST` | `host.docker.internal` | ADB server host |
| `ADB_PORT` | `5555` | ADB server port |
| `ADB_TIMEOUT` | `10000` | ADB command timeout (ms) |
| `UIAUTOMATOR2_TIMEOUT` | `15000` | UIAutomator2 command timeout (ms) |
| `UI_CAPTURE_TIMEOUT` | `30000` | UI capture operation timeout (ms) |
| `HEALTH_CHECK_INTERVAL` | `30000` | Health check interval (ms) |
| `MAX_CONNECTION_RETRIES` | `5` | Maximum connection retry attempts |
| `RETRY_BACKOFF_MULTIPLIER` | `1.5` | Exponential backoff multiplier |
| `DEBUG_UI_AUTOMATOR` | `false` | Enable debug logging for UIAutomator |
| `EMULATOR_GRPC_ENDPOINT` | - | gRPC endpoint for emulator communication |

### Custom Configuration

```typescript
import { ADBBridgeService } from './services/adb-bridge';

const adbBridge = new ADBBridgeService({
  serial: 'custom-emulator-5556',
  timeout: 15000,
  uiAutomatorTimeout: 20000,
  uiCaptureTimeout: 45000,
  healthCheckInterval: 15000,
  maxConnectionRetries: 8,
  debugUiAutomator: true
});
```

## Usage

### Basic Usage

```typescript
import { initializeADBBridge, closeADBBridge } from './services/adb-bridge';

// Initialize the service
const adbBridge = await initializeADBBridge();

try {
  // Get device information
  const deviceInfo = await adbBridge.getDeviceInfo();
  console.log('Device:', deviceInfo.model, deviceInfo.androidVersion);

  // Capture UI state
  const uiState = await adbBridge.captureUIState();
  console.log('UI captured:', uiState.elementCount, 'elements');

} finally {
  // Clean up
  await closeADBBridge();
}
```

### Advanced Usage

```typescript
import { ADBBridgeService } from './services/adb-bridge';

const adbBridge = new ADBBridgeService({
  uiAutomatorTimeout: 20000,
  debugUiAutomator: true
});

await adbBridge.initialize();

// Capture UI with custom options
const uiState = await adbBridge.captureUIState(
  { includeData: true, quality: 90 }, // Screenshot options
  {
    compress: true,
    maxDepth: 15,
    filterAttributes: ['bounds', 'focused']
  } // Hierarchy options
);

// Perform device interactions
await adbBridge.performTap(500, 800);
await adbBridge.performType('Hello World');
await adbBridge.performSwipe(100, 500, 100, 200, 300);

await adbBridge.close();
```

### Health Monitoring

```typescript
// Check connection health
const health = await adbBridge.getConnectionHealth();
console.log('Connection status:', {
  isConnected: health.isConnected,
  isUiAutomatorReady: health.isUiAutomatorReady,
  failureRate: (health.failedCommands / health.totalCommands * 100) + '%',
  averageResponseTime: health.averageResponseTime + 'ms'
});
```

## API Reference

### Main Classes

#### `ADBBridgeService`

Primary service class for ADB and UIAutomator2 operations.

**Constructor:**
```typescript
new ADBBridgeService(config?: Partial<ADBBridgeConfig>)
```

**Methods:**
- `initialize(): Promise<void>` - Initialize connection to device
- `close(): Promise<void>` - Close connection and cleanup resources
- `getDeviceInfo(): Promise<DeviceInfo>` - Get comprehensive device information
- `captureScreenshot(options?: ScreenshotOptions): Promise<Buffer | string>` - Capture screenshot
- `getUIHierarchy(options?: UIHierarchyOptions): Promise<string>` - Get UI hierarchy XML
- `captureUIState(screenshotOpts?, hierarchyOpts?): Promise<UIStateCapture>` - Combined UI state capture
- `performTap(x, y): Promise<void>` - Perform tap gesture
- `performType(text): Promise<void>` - Type text input
- `performSwipe(startX, startY, endX, endY, duration?): Promise<void>` - Perform swipe gesture
- `performBack(): Promise<void>` - Press back button
- `setOrientation(orientation): Promise<void>` - Set device orientation
- `getConnectionHealth(): Promise<ConnectionHealth>` - Get connection health status

### Type Definitions

#### `DeviceInfo`
```typescript
interface DeviceInfo {
  serial: string;
  androidVersion: string;
  sdkVersion: string;
  model: string;
  resolution: string;
  currentPackage?: string;
  currentActivity?: string;
  orientation: 'portrait' | 'landscape';
  uiAutomatorVersion?: string;
}
```

#### `UIStateCapture`
```typescript
interface UIStateCapture {
  hierarchy: string;
  screenshot?: string; // base64 encoded
  deviceInfo: DeviceInfo;
  currentActivity: string;
  timestamp: string;
  duration: number;
  elementCount: number;
  orientation: 'portrait' | 'landscape';
}
```

#### `ConnectionHealth`
```typescript
interface ConnectionHealth {
  isConnected: boolean;
  isUiAutomatorReady: boolean;
  lastSuccessfulCommand: string;
  totalCommands: number;
  failedCommands: number;
  averageResponseTime: number;
  uptime: number;
}
```

### Error Types

#### `ADBBridgeError`
Base error class for all ADB Bridge errors.

#### `DeviceConnectionError`
Thrown when device connection fails or is lost.

#### `UIAutomatorError`
Thrown when UIAutomator2 operations fail.

#### `CommandTimeoutError`
Thrown when commands exceed timeout limits.

## Error Handling

The service provides comprehensive error handling with detailed context:

```typescript
import {
  ADBBridgeService,
  DeviceConnectionError,
  UIAutomatorError,
  CommandTimeoutError
} from './services/adb-bridge';

try {
  await adbBridge.captureUIState();
} catch (error) {
  if (error instanceof DeviceConnectionError) {
    console.error('Device connection failed:', error.details);
    // Implement reconnection logic
  } else if (error instanceof UIAutomatorError) {
    console.error('UIAutomator error:', error.code, error.details);
    // Handle UIAutomator-specific issues
  } else if (error instanceof CommandTimeoutError) {
    console.error('Command timed out after', error.details.timeout, 'ms');
    // Handle timeout scenarios
  }
}
```

## Integration Examples

### With Graph Service

```typescript
// Capture UI state and process for graph generation
const uiState = await adbBridge.captureUIState();

const graphNode = {
  id: generateStateId(uiState.hierarchy),
  package: uiState.deviceInfo.currentPackage,
  activity: uiState.currentActivity,
  hierarchy: uiState.hierarchy,
  screenshot: uiState.screenshot,
  timestamp: uiState.timestamp,
  metadata: {
    captureDuration: uiState.duration,
    elementCount: uiState.elementCount,
    orientation: uiState.orientation
  }
};

await graphService.addNode(graphNode);
```

### With Flow Engine

```typescript
// Use ADB Bridge for flow execution
async function executeAction(action: UserAction) {
  switch (action.type) {
    case 'tap':
      if (action.target?.bounds) {
        const [left, top, right, bottom] = action.target.bounds;
        const x = Math.floor((left + right) / 2);
        const y = Math.floor((top + bottom) / 2);
        await adbBridge.performTap(x, y);
      }
      break;

    case 'type':
      if (action.text) {
        await adbBridge.performType(action.text);
      }
      break;

    case 'swipe':
      if (action.swipe) {
        // Convert swipe direction to coordinates
        const { direction, distance } = action.swipe;
        const coords = calculateSwipeCoords(direction, distance);
        await adbBridge.performSwipe(...coords);
      }
      break;

    case 'back':
      await adbBridge.performBack();
      break;
  }
}
```

## Performance Considerations

### Optimization Tips

1. **Batch Operations**: Use `captureUIState()` for combined hierarchy and screenshot capture
2. **Timeout Configuration**: Adjust timeouts based on device performance and network conditions
3. **Health Check Frequency**: Balance monitoring frequency with resource usage
4. **Hierarchy Filtering**: Use `maxDepth` and `filterAttributes` for large UI hierarchies

### Resource Management

- The service automatically manages connection pooling and cleanup
- Health monitoring uses minimal resources with configurable intervals
- Large screenshots and hierarchies are handled efficiently with memory management

## Troubleshooting

### Common Issues

1. **Connection Timeouts**: Increase `ADB_TIMEOUT` and check emulator status
2. **UIAutomator Errors**: Ensure UIAutomator2 is installed on the target device
3. **Permission Issues**: Verify ADB permissions and emulator accessibility
4. **Performance Issues**: Adjust timeout values and reduce hierarchy complexity

### Debug Logging

Enable debug logging for detailed operation traces:

```typescript
const adbBridge = new ADBBridgeService({
  debugUiAutomator: true
});
```

Or via environment variable:
```bash
DEBUG_UI_AUTOMATOR=true npm run dev
```

## Contributing

When modifying the ADB Bridge Service:

1. Maintain backward compatibility with existing APIs
2. Add comprehensive error handling for new operations
3. Include detailed logging for debugging and monitoring
4. Update this README with new features and configuration options
5. Add unit tests following the existing test patterns

## License

This service is part of the AutoApp UI Map & Flow Engine project.