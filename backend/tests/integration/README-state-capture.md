# UI State Capture Integration Tests

### Overview

The UI State Capture Integration Tests validate the core functionality that powers the Discovery Panel and graph generation. These tests verify:

- UIAutomator2 connection and communication
- UI hierarchy capture from Android emulator
- Screenshot capture functionality
- State metadata extraction (activity, package, selectors)
- State digest generation for deduplication
- Error handling for capture failures
- Storage and persistence of captured states

### Files

- **`state-capture-simple.test.ts`** - Main test implementation with comprehensive test suite
- **`state-capture.test.ts`** - Full Jest-based test suite (requires Jest setup)
- **`run-state-capture-tests.ts`** - Test runner script for manual execution
- **`state-capture-test-docs.md`** - Detailed documentation and usage examples

### Quick Start

#### Prerequisites

1. **Android Emulator**: Ensure an Android emulator is running
   ```bash
   # Check if emulator is running
   adb devices

   # Start emulator if needed
   emulator -avd <avd_name> -no-audio -no-window
   ```

2. **ADB Server**: Ensure ADB server is running and accessible
   ```bash
   adb start-server
   ```

3. **UIAutomator2**: Verify UIAutomator2 is available on device
   ```bash
   adb shell which uiautomator
   ```

#### Running Tests

1. **Using the Test Runner (Recommended)**:
   ```bash
   # Run with default settings
   npx ts-node tests/integration/run-state-capture-tests.ts

   # Run with custom device
   npx ts-node tests/integration/run-state-capture-tests.ts --device emulator-5556

   # Run with debug logging
   npx ts-node tests/integration/run-state-capture-tests.ts --debug
   ```

2. **Direct execution**:
   ```bash
   npx ts-node tests/integration/state-capture-simple.test.ts
   ```

### Configuration

#### Environment Variables

```bash
# Device Configuration
export TEST_DEVICE_SERIAL=emulator-5554
export TEST_CONNECTION_TIMEOUT=15000
export TEST_CAPTURE_TIMEOUT=10000
export TEST_PERFORMANCE_TIMEOUT=2000

# Test Directories
export TEST_DATA_DIR=./test-data
export TEST_SCREENSHOT_DIR=./test-data/screenshots

# Debug Options
export DEBUG_TESTS=true
```

#### Command Line Options

```bash
Usage: ts-node run-state-capture-tests.ts [OPTIONS]

Options:
  -d, --device <serial>         Device serial number
  -c, --connection-timeout <ms> Connection timeout in milliseconds
  -t, --capture-timeout <ms>    Capture timeout in milliseconds
  -p, --performance-timeout <ms> Performance timeout in milliseconds
      --data-dir <path>         Test data directory
      --debug                   Enable debug logging
  -h, --help                    Show help message
```

### Test Coverage

#### ✅ Connection & Communication Tests
- Device connection establishment
- UIAutomator2 availability verification
- Connection health monitoring

#### ✅ UI Hierarchy Capture Tests
- Basic UI XML extraction
- Hierarchy compression
- Depth limiting
- Attribute filtering

#### ✅ Screenshot Capture Tests
- Base64 screenshot capture
- Binary buffer capture
- File storage
- Sequential capture validation

#### ✅ State Metadata Extraction Tests
- Device information extraction
- Current activity/package detection
- Interactive element selector extraction

#### ✅ State Digest Generation Tests
- Consistent digest generation
- Screen differentiation
- State deduplication validation

#### ✅ Complete State Capture Tests
- Full state capture (hierarchy + screenshot + metadata)
- Multi-screen capture scenarios
- Performance validation under load

#### ✅ Storage & Persistence Tests
- JSON storage of capture results
- State digest storage
- Concurrent operation handling

### Expected Test Results

#### Success Indicators
- ✅ **Device Connected**: Emulator accessible via ADB
- ✅ **Hierarchy Captured**: UI XML extracted with interactive elements
- ✅ **Screenshot Captured**: Valid screenshot generated
- ✅ **Metadata Extracted**: Device info and current activity identified
- ✅ **State Digest Generated**: Consistent hash created for deduplication
- ✅ **Performance Met**: Capture completed within 2-second threshold
- ✅ **Storage Working**: Results saved to JSON storage successfully

#### Performance Thresholds
- **Connection Time**: < 15 seconds
- **Capture Time**: < 2 seconds
- **Hierarchy Size**: > 1,000 characters
- **Screenshot Size**: > 10,000 bytes

### Troubleshooting

#### Common Issues

1. **Emulator Not Found**
   ```
   Error: Device connection timeout after 15000ms
   ```
   **Solutions:**
   - Verify emulator is running: `adb devices`
   - Check device serial: `TEST_DEVICE_SERIAL=emulator-5556`
   - Ensure ADB server: `adb start-server`

2. **UIAutomator2 Not Available**
   ```
   Error: UIAutomator2 not available on device
   ```
   **Solutions:**
   - Install UIAutomator2: `adb shell pm install-uiautomator-tests`
   - Check service: `adb shell which uiautomator`
   - Restart emulator if needed

3. **Permission Errors**
   ```
   Error: EACCES: permission denied, mkdir 'test-data'
   ```
   **Solutions:**
   - Check directory permissions: `ls -la`
   - Create directory manually: `mkdir -p test-data`
   - Run with appropriate permissions

4. **Performance Timeouts**
   ```
   Warning: Slow capture detected: 3500ms
   ```
   **Solutions:**
   - Increase timeout: `TEST_PERFORMANCE_TIMEOUT=5000`
   - Check emulator resources
   - Use hierarchy compression

#### Debug Commands

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

# Check test logs with debug
DEBUG_TESTS=true npx ts-node tests/integration/run-state-capture-tests.ts
```

### Test Artifacts

After running tests, you'll find various artifacts in the test data directory:

```
test-data/
├── captures/           # Complete state captures
│   └── test-capture-*.json
├── digests/           # State digests for deduplication
│   └── test-digest-*.json
├── screenshots/       # Device screenshots
│   └── test-screenshot-*.png
└── test-*.json        # Various test outputs
```

### Contributing

When adding new tests:

1. **Follow the existing pattern** in `state-capture-simple.test.ts`
2. **Add proper error handling** with try-catch blocks
3. **Include performance validation** where appropriate
4. **Update documentation** with new test coverage
5. **Test both success and failure** scenarios
6. **Add debug logging** for troubleshooting

### Support

For issues with these integration tests:

1. Check the troubleshooting section above
2. Review test logs with debug output enabled (`--debug`)
3. Verify environment configuration
4. Check emulator and device status
5. Consult the main project documentation

### License

These integration tests are part of the AutoApp UI Map & Intelligent Flow Engine project and follow the same license terms.