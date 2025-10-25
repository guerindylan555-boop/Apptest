# UI State Capture Integration Tests

Comprehensive integration test suite for UI state capture functionality via UIAutomator2 in the AutoApp UI Map & Intelligent Flow Engine.

## Overview

This test suite validates the core UI state capture functionality that powers the Discovery Panel and graph generation. Tests cover UIAutomator2 communication, UI hierarchy extraction, screenshot capture, state metadata extraction, state digest generation, and error handling scenarios.

## Test Coverage

### ✅ Connection & Communication Tests
- **Device Connection**: Validates ADB Bridge connection to Android emulator
- **UIAutomator2 Availability**: Verifies UIAutomator2 service is ready
- **Health Monitoring**: Tests connection health checks and monitoring

### ✅ UI Hierarchy Capture Tests
- **Basic Hierarchy Capture**: Captures UI XML from MaynDrive app
- **Compression**: Tests hierarchy compression for storage efficiency
- **Depth Limiting**: Validates hierarchy depth limitation
- **Attribute Filtering**: Tests selective attribute extraction

### ✅ Screenshot Capture Tests
- **Basic Screenshot**: Captures screenshots as base64 strings
- **Buffer Capture**: Captures screenshots as binary buffers
- **File Storage**: Saves screenshots to filesystem
- **Sequential Capture**: Tests multiple screenshot captures

### ✅ State Metadata Extraction Tests
- **Device Information**: Extracts comprehensive device metadata
- **Activity Detection**: Identifies current app and activity
- **Selector Extraction**: Extracts interactive element selectors

### ✅ State Digest Generation Tests
- **Digest Consistency**: Generates consistent state hashes
- **Screen Differentiation**: Creates different digests for different screens
- **State Deduplication**: Uses digests for duplicate state detection

### ✅ Complete State Capture Tests
- **Full State Capture**: Captures hierarchy + screenshot + metadata
- **Multi-Screen Capture**: Captures states from different app screens
- **Performance Testing**: Validates performance under load

### ✅ Error Handling Tests
- **Timeout Handling**: Handles capture timeouts gracefully
- **Device Disconnection**: Handles device offline scenarios
- **UIAutomator2 Errors**: Handles UIAutomator2 service errors
- **Result Validation**: Validates and detects corrupted captures

### ✅ Storage & Persistence Tests
- **JSON Storage**: Saves capture results to storage
- **Digest Storage**: Stores and retrieves state digests
- **Concurrent Operations**: Handles parallel storage operations

### ✅ Docker Environment Tests
- **Docker Compatibility**: Runs in Docker containers
- **Network Configuration**: Handles Docker network setups

## Configuration

### Environment Variables

```bash
# Device Configuration
TEST_DEVICE_SERIAL=emulator-5554              # Android device serial
TEST_CONNECTION_TIMEOUT=15000                  # Connection timeout (ms)
TEST_CAPTURE_TIMEOUT=10000                     # Capture timeout (ms)
TEST_PERFORMANCE_TIMEOUT=2000                  # Performance threshold (ms)

# Test Directories
TEST_DATA_DIR=./test-data                      # Test data directory
TEST_SCREENSHOT_DIR=./test-data/screenshots    # Screenshot directory

# Debug Options
DEBUG_TESTS=true                               # Enable debug logging
```

### Test Configuration

```typescript
const TEST_CONFIG = {
  DEVICE_SERIAL: 'emulator-5554',
  CONNECTION_TIMEOUT: 15000,
  CAPTURE_TIMEOUT: 10000,
  PERFORMANCE_TIMEOUT: 2000,
  MAX_CAPTURE_DURATION: 2000,    // 2 seconds
  MIN_HIERARCHY_SIZE: 1000,      // Minimum XML size
  MIN_SCREENSHOT_SIZE: 10000,    // Minimum screenshot size
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000
};
```

## Running Tests

### Prerequisites

1. **Android Emulator**: Ensure Android emulator is running with MaynDrive app installed
2. **ADB Setup**: ADB must be properly configured and accessible
3. **UIAutomator2**: UIAutomator2 service must be available on the device
4. **Test Directories**: Ensure test directories have write permissions

### Basic Test Execution

```bash
# Run all integration tests
npm test

# Run specific test file
npx jest tests/integration/state-capture.test.ts

# Run with verbose output
npx jest tests/integration/state-capture.test.ts --verbose

# Run with custom configuration
TEST_DEVICE_SERIAL=emulator-5556 npm test
```

### Running in Docker

```bash
# Build test environment
docker build -t autoapp-test .

# Run tests in Docker
docker run --rm \
  -v /path/to/android-sdk:/opt/android-sdk \
  -e ANDROID_SERIAL=emulator-5554 \
  autoapp-test npm test
```

### Performance Testing

```bash
# Run performance-focused tests
TEST_PERFORMANCE_TIMEOUT=1000 npm test

# Run with strict performance validation
TEST_PERFORMANCE_TIMEOUT=500 npm test -- --testNamePattern="Performance"
```

## Test Usage Examples

### Basic State Capture

```typescript
import { ADBBridgeService } from '../../src/services/adb-bridge';

// Initialize service
const adbService = new ADBBridgeService({
  serial: 'emulator-5554',
  timeout: 15000,
  uiAutomatorTimeout: 10000
});

// Connect to device
await adbService.initialize();

// Capture complete UI state
const uiState = await adbService.captureUIState(
  { includeData: true },           // Include screenshot
  { includeAttributes: true }      // Include full attributes
);

console.log('Captured state:', {
  activity: uiState.currentActivity,
  elements: uiState.elementCount,
  hierarchySize: uiState.hierarchy.length,
  hasScreenshot: !!uiState.screenshot
});
```

### State Digest Generation

```typescript
import { generateStateDigest } from './state-capture.test';

// Generate digest for deduplication
const digest = generateStateDigest(uiState);

console.log('State digest:', {
  hash: digest.hash,
  activity: digest.activity,
  elementCount: digest.elementCount,
  signature: digest.hierarchySignature
});

// Check for duplicate states
const knownDigests = new Set(['abc123', 'def456']);
const isDuplicate = knownDigests.has(digest.hash);
```

### Error Handling

```typescript
import {
  ADBBridgeService,
  DeviceConnectionError,
  UIAutomatorError
} from '../../src/services/adb-bridge';

try {
  const adbService = new ADBBridgeService({
    serial: 'emulator-5554',
    maxConnectionRetries: 3
  });

  await adbService.initialize();
  const state = await adbService.captureUIState();

} catch (error) {
  if (error instanceof DeviceConnectionError) {
    console.error('Device connection failed:', error.message);
  } else if (error instanceof UIAutomatorError) {
    console.error('UIAutomator error:', error.message);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

### Performance Monitoring

```typescript
// Capture with performance tracking
const startTime = Date.now();
const uiState = await adbService.captureUIState();
const captureTime = Date.now() - startTime;

// Validate performance
if (captureTime > 2000) {
  console.warn(`Slow capture detected: ${captureTime}ms`);
}

// Monitor system health
const health = await adbService.getConnectionHealth();
console.log('Connection health:', {
  isConnected: health.isConnected,
  isUiAutomatorReady: health.isUiAutomatorReady,
  averageResponseTime: health.averageResponseTime,
  uptime: health.uptime
});
```

## Test Results Interpretation

### Success Indicators

✅ **Connection Established**: Device connected and UIAutomator2 ready
✅ **Hierarchy Captured**: UI XML extracted with interactive elements
✅ **Screenshot Captured**: Valid screenshot with minimum size
✅ **Metadata Extracted**: Device info and activity detected
✅ **Digest Generated**: Consistent state hash created
✅ **Performance Met**: Capture completed within 2-second threshold

### Common Issues & Solutions

#### Connection Failures
```
Error: Device connection timeout after 15000ms
```
**Solutions:**
- Verify emulator is running: `adb devices`
- Check device serial: `TEST_DEVICE_SERIAL=emulator-5556`
- Ensure ADB server: `adb start-server`

#### UIAutomator2 Errors
```
Error: UIAutomator2 not available on device
```
**Solutions:**
- Install UIAutomator2: `adb shell pm install-uiautomator-tests`
- Check service: `adb shell which uiautomator`
- Restart emulator if needed

#### Performance Issues
```
Warning: Slow capture detected: 3500ms
```
**Solutions:**
- Increase timeout: `TEST_CAPTURE_TIMEOUT=20000`
- Check emulator resources
- Use hierarchy compression: `{ compress: true }`

#### Storage Failures
```
Error: Failed to save capture result
```
**Solutions:**
- Check directory permissions: `chmod 755 test-data/`
- Verify disk space: `df -h`
- Check file paths in configuration

## Test Data Management

### Test Artifacts

- **JSON Captures**: `test-data/test-*.json` - Complete state captures
- **Screenshots**: `test-data/screenshots/test-*.png` - Device screenshots
- **Hierarchies**: `test-data/test-hierarchy-*.xml` - UI hierarchy XML
- **Digests**: `test-data/digests/*.json` - State digests

### Cleanup

```bash
# Clean test artifacts
rm -rf test-data/

# Clean specific file types
find test-data/ -name "test-*.json" -delete
find test-data/ -name "test-*.png" -delete
```

### Debug Output

Enable debug logging for detailed test execution:

```bash
DEBUG_TESTS=true npm test
```

This provides:
- Detailed device connection information
- UI hierarchy capture statistics
- Screenshot capture metrics
- Storage operation details
- Error stack traces

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: UI State Capture Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2

    - name: Setup Android SDK
      uses: android-actions/setup-android@v2

    - name: Start Android Emulator
      run: |
        echo "y" | $ANDROID_HOME/tools/bin/sdkmanager --install "system-images;android-30;google_apis;x86_64"
        echo "no" | $ANDROID_HOME/tools/bin/avdmanager create avd -n test -k "system-images;android-30;google_apis;x86_64"
        $ANDROID_HOME/emulator/emulator -avd test -no-audio -no-window &
        $ANDROID_HOME/platform-tools/adb wait-for-device

    - name: Install Dependencies
      run: npm ci

    - name: Run Integration Tests
      run: npm test
      env:
        TEST_DEVICE_SERIAL: emulator-5554
        DEBUG_TESTS: true
```

## Troubleshooting

### Common Test Failures

1. **Emulator Not Found**
   - Ensure emulator is running before tests
   - Verify device serial matches configuration
   - Check ADB connection: `adb devices`

2. **UIAutomator2 Not Available**
   - Install UIAutomator2 on device
   - Check service status: `adb shell ps | grep uiautomator`
   - Restart emulator if needed

3. **Permission Errors**
   - Ensure test directories are writable
   - Check file system permissions
   - Run with appropriate user context

4. **Performance Timeouts**
   - Increase timeout values
   - Check system resources
   - Optimize capture options

### Debug Commands

```bash
# Check device status
adb devices
adb -s emulator-5554 shell getprop

# Check UIAutomator
adb -s emulator-5554 shell which uiautomator
adb -s emulator-5554 shell uiautomator dump

# Test capture manually
adb -s emulator-5554 shell uiautomator dump
adb -s emulator-5554 shell screencap -p > test.png

# Check test logs
DEBUG_TESTS=true npm test 2>&1 | grep -E "(ERROR|WARN|Failed)"
```

## Future Enhancements

### Planned Test Additions

1. **Multi-Device Testing**: Tests across multiple devices/emulators
2. **Network Conditions**: Tests under various network scenarios
3. **Large App Testing**: Tests with complex, large applications
4. **Accessibility Testing**: Verify accessibility features in captures
5. **Security Testing**: Validate secure handling of sensitive UI data

### Performance Improvements

1. **Parallel Capture**: Test concurrent state captures
2. **Incremental Updates**: Test delta-based state changes
3. **Caching**: Test state caching and reuse
4. **Compression**: Test advanced compression techniques

## Support

For issues with these integration tests:

1. Check the troubleshooting section above
2. Review test logs with debug output enabled
3. Verify environment configuration
4. Check emulator and device status
5. Consult the main project documentation

## License

This test suite is part of the AutoApp UI Map & Intelligent Flow Engine project and follows the same license terms.