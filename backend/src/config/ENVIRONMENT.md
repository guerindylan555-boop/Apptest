# Environment Configuration System

## Overview

The AutoApp UI Map & Intelligent Flow Engine uses a comprehensive environment configuration validation system located in `backend/src/config/environment.ts`. This system ensures all required environment variables are present, properly typed, and within valid ranges.

## Configuration Structure

The configuration is organized into logical sections:

### WebRTC Configuration (`WebRTCConfig`)
- `publicUrl`: Public URL for WebRTC connections
- `iceServers`: STUN/TURN servers for peer connections
- `grpcEndpoint`: gRPC endpoint for emulator communication
- `timeout`: Connection timeout in milliseconds
- `iceTimeout`: ICE connection timeout
- `reconnectionAttempts`: Maximum reconnection attempts
- `resolution`: Video resolution (e.g., '720p')
- `frameRate`: Video frame rate
- `bitrate`: Video bitrate in kbps

### ADB Configuration (`ADBConfig`)
- `host`: ADB host address
- `port`: ADB port number
- `deviceSerial`: Android device serial number
- `timeout`: ADB connection timeout
- `uiAutomatorTimeout`: UIAutomator2 timeout
- `uiCaptureTimeout`: UI capture timeout
- `xmlTempPath`: Temporary UI XML file path
- `stateDedupThreshold`: State deduplication threshold (0-1)
- `mergeThreshold`: State merge threshold (0-1)

### Storage Configuration (`StorageConfig`)
- `graphRoot`: Root directory for graphs
- `flowRoot`: Root directory for flows
- `sessionsDir`: Sessions directory
- `screenshotsDir`: Screenshots directory
- `graphPath`: Specific graph file path
- `graphStateLimit`: Maximum graph states
- `graphTransitionLimit`: Maximum graph transitions

### Flow Configuration (`FlowConfig`)
- `replayRetryLimit`: Maximum replay retry attempts
- `replayStepTimeout`: Replay step timeout
- `executionTimeout`: Flow execution timeout
- `validationTimeout`: Flow validation timeout
- `stateDetectionTimeout`: State detection timeout
- `stateRecoveryTimeout`: State recovery timeout
- `recoveryMaxAttempts`: Maximum recovery attempts

### MaynDrive Configuration (`MaynDriveConfig`)
- `packageName`: MaynDrive package name
- `mainActivity`: Main activity name
- `loginActivity`: Login activity name
- `loginFlow`: Login flow file path
- `unlockFlow`: Unlock flow file path
- `lockFlow`: Lock flow file path

### Performance Configuration (`PerformanceConfig`)
- `snapshotTimeout`: Snapshot timeout
- `snapshotBatchSize`: Snapshot batch size
- `captureConcurrentLimit`: Concurrent capture limit
- `graphValidationTimeout`: Graph validation timeout
- `graphPathfindingTimeout`: Graph pathfinding timeout
- `stateComparisonCacheSize`: State comparison cache size
- `maxSessionMemoryMB`: Maximum session memory in MB
- `maxGraphLoadTime`: Maximum graph load time
- `concurrentFlowLimit`: Concurrent flow limit

### Logging Configuration (`LoggingConfig`)
- `level`: Global log level (error, warn, info, debug, trace)
- `format`: Log format (json, text)
- `output`: Log output destination
- `filePath`: Log file path
- `flowEngineLevel`: Flow engine log level
- `graphLevel`: Graph log level
- `replayLevel`: Replay log level
- `webrtcLevel`: WebRTC log level
- `sessionRetentionDays`: Session log retention in days
- `debugScreenshotCapture`: Debug screenshot capture flag
- `detailedStateLogging`: Detailed state logging flag

### API Configuration (`APIConfig`)
- `port`: Flow API port
- `prefix`: API prefix
- `timeout`: API timeout
- `authEnabled`: Authentication enabled flag
- `corsOrigin`: CORS origin
- `rateLimit`: Rate limit

### Security Configuration (`SecurityConfig`)
- `adbKeyPath`: ADB key path
- `allowExternalADB`: Allow external ADB connections
- `requireDeviceAuth`: Require device authentication
- `sessionTimeout`: Session timeout in seconds

### Development Configuration (`DevelopmentConfig`)
- `devMode`: Development mode flag
- `debugGraphExports`: Debug graph exports flag
- `enableLLMFlowAssistance`: Enable LLM flow assistance
- `testMode`: Test mode flag
- `mockADBResponses`: Mock ADB responses flag
- `enableFlowValidation`: Enable flow validation

## Usage

### Basic Usage

```typescript
import { environmentConfig } from './config';

// Access configuration sections
const webrtcUrl = environmentConfig.webrtc.publicUrl;
const adbTimeout = environmentConfig.adb.timeout;
const logLevel = environmentConfig.logging.level;
```

### Getting Environment-Specific Configuration

```typescript
import { getEnvironmentConfig } from './config';

// Get configuration with validation for specific environment
const config = getEnvironmentConfig('production');
```

### Feature Flag Checking

```typescript
import { isFeatureEnabled } from './config';

// Check if discovery is enabled
if (isFeatureEnabled('discovery')) {
  // Enable discovery features
}
```

### Configuration Summary

```typescript
import { getConfigSummary } from './config';

// Get a summary suitable for logging
const summary = getConfigSummary(environmentConfig);
console.log('Configuration loaded:', summary);
```

### Error Handling

```typescript
import { ConfigValidationError, loadEnvironmentConfig } from './config';

try {
  const config = loadEnvironmentConfig();
} catch (error) {
  if (error instanceof ConfigValidationError) {
    console.error(`Configuration error: ${error.message}`);
    console.error(`Variable: ${error.variable}`);
    console.error(`Suggestion: ${error.suggestion}`);
  }
}
```

## Validation Rules

### URL Validation
- Must include protocol (http:// or https://)
- Must be a valid URL format

### Port Validation
- Must be between 1 and 65535
- Must be a valid integer

### Timeout Validation
- Must be between 100ms and 1 hour (3,600,000ms)
- Must be a valid integer

### Boolean Validation
- Accepts: true, false, 1, 0, yes, no, on, off (case insensitive)

### Threshold Validation
- Must be between 0 and 1
- Must be a valid number

### Path Validation
- Cannot be empty
- Resolves to absolute path
- Optional existence checking

### Log Level Validation
- Must be one of: error, warn, info, debug, trace

### Log Format Validation
- Must be one of: json, text

### ICE Server Validation
- Must start with stun: or turn:
- Comma-separated for multiple servers

## Environment Variables

### Required Variables

#### WebRTC
- `EMULATOR_WEBRTC_PUBLIC_URL`: WebRTC public URL
- `EMULATOR_WEBRTC_ICE_SERVERS`: ICE servers (comma-separated)
- `EMULATOR_GRPC_ENDPOINT`: gRPC endpoint

#### Storage
- `GRAPH_ROOT`: Graph storage directory
- `FLOW_ROOT`: Flow storage directory
- `SESSIONS_DIR`: Sessions directory
- `SCREENSHOTS_DIR`: Screenshots directory

#### ADB
- `ADB_HOST`: ADB host address
- `ADB_PORT`: ADB port number
- `ANDROID_SERIAL`: Device serial number

#### Logging
- `LOG_LEVEL`: Global log level
- `LOG_FORMAT`: Log format

### Optional Variables

Most variables have sensible defaults and are optional. See `.env.example` for a complete list.

## Environment-Specific Behavior

### Development Environment
- Enables debug features by default
- Allows more permissive settings
- Provides additional logging

### Production Environment
- Warns about debug logging
- Warns about permissive security settings
- Enforces stricter validation

### Test Environment
- Suggests test mode settings
- Allows mock configurations

## Configuration Reloading

The configuration is loaded once at application startup. For hot reloading, you can implement a configuration watcher:

```typescript
import { loadEnvironmentConfig } from './config';

function reloadConfiguration() {
  try {
    const newConfig = loadEnvironmentConfig();
    // Apply new configuration
  } catch (error) {
    console.error('Failed to reload configuration:', error);
  }
}
```

## Best Practices

1. **Use Type Safety**: Always import the types for configuration sections
2. **Validate Early**: Load configuration at application startup
3. **Handle Errors**: Catch and handle `ConfigValidationError` appropriately
4. **Use Feature Flags**: Use `isFeatureEnabled()` for optional features
5. **Environment Separation**: Use different configurations for different environments
6. **Security**: Avoid sensitive values in configuration; use secrets management
7. **Documentation**: Keep environment variable documentation up to date

## Troubleshooting

### Common Issues

1. **Invalid URLs**: Ensure URLs include the protocol (http:// or https://)
2. **Port Conflicts**: Check that ports are not already in use
3. **Path Permissions**: Ensure the application has write permissions for storage directories
4. **Timeout Values**: Ensure timeouts are reasonable for your environment
5. **Log Levels**: Use appropriate log levels for your environment

### Debug Configuration

To debug configuration issues:

1. Check environment variables are set: `printenv | grep EMULATOR_`
2. Validate file paths exist and are accessible
3. Check network connectivity for external services
4. Review validation error messages for specific issues

### Getting Help

For configuration issues:
1. Check the error message and suggestion
2. Review this documentation
3. Check the `.env.example` file
4. Validate environment variable formats
5. Check system permissions and resources