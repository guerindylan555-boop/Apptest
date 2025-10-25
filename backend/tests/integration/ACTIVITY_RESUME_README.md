# MaynDrive Activity Resume Integration Tests

## Overview

This directory contains comprehensive integration tests for MaynDrive activity-specific resume procedures. These tests validate that the AutoApp UI Map & Intelligent Flow Engine can reliably capture UI state and manage activity transitions regardless of which MaynDrive activity is currently active.

## Files

### Core Test Files

- **`activity-resume.test.ts`** - Main test suite implementation
- **`run-activity-resume-tests.ts`** - Command-line test runner
- **`ACTIVITY_RESUME_TEST_GUIDE.md`** - Comprehensive test documentation
- **`ACTIVITY_RESUME_README.md`** - This file

### Supporting Files

- **`remote-access.test.ts`** - Remote API accessibility tests
- **`run-tests.ts`** - Remote test runner

## Quick Start

### Prerequisites

1. **Android Emulator Running**:
   ```bash
   # Start Android emulator
   emulator @avd_name -no-window -no-audio
   ```

2. **ADB Connection**:
   ```bash
   # Verify device connection
   adb devices
   ```

3. **MaynDrive Installed**:
   - Ensure MaynDrive app is installed on the emulator
   - App package: `com.mayn.mayndrive`

### Running Tests

#### Basic Test Run
```bash
# From backend directory
npm run test:activity:resume
```

#### Verbose Test Run with Artifacts
```bash
npm run test:activity:resume:verbose
```

#### Debug Test Run with Performance Monitoring
```bash
npm run test:activity:resume:debug
```

#### CI/CD Pipeline Run
```bash
npm run test:activity:resume:ci
```

#### Custom Configuration
```bash
ts-node tests/integration/run-activity-resume-tests.ts \
  --device emulator-5556 \
  --artifacts \
  --debug \
  --performance
```

## Test Coverage

### Activity Procedures Tested

1. **MainActivity** (`com.mayn.mayndrive.MainActivity`)
   - Home screen launch and resume
   - Navigation widget loading
   - Bottom navigation validation

2. **LoginScreen** (`com.mayn.mayndrive.LoginActivity`)
   - Authentication state detection
   - Login form validation
   - Credential input handling

3. **MapScreen** (`com.mayn.mayndrive.MapActivity`)
   - Map loading and initialization
   - Location services validation
   - Map controls functionality

### Test Scenarios

- **Activity Launch Procedures**: Direct launch to each activity
- **Activity State Detection**: Current activity identification and validation
- **Resume Procedures**: Resume from background, crash, and low memory states
- **Activity Transitions**: Navigation between activities
- **Error Scenarios**: Invalid activities, timeouts, failures
- **Performance Benchmarks**: <5s resume time validation

### Success Criteria

- ✅ Activity launches successfully
- ✅ Correct activity detected with ≥80% confidence
- ✅ UI state captured accurately
- ✅ Resume procedures complete within timeouts
- ✅ Performance benchmarks met (<5s per activity)
- ✅ Error handling works correctly

## Configuration

### Environment Variables

```bash
# Device Configuration
ANDROID_SERIAL=emulator-5554
MAYNDRIVE_PACKAGE=com.mayn.mayndrive

# Timeouts (milliseconds)
ACTIVITY_TEST_TIMEOUT=60000
ACTIVITY_LAUNCH_TIMEOUT=15000
ACTIVITY_CAPTURE_TIMEOUT=10000
ACTIVITY_STABILIZATION_TIMEOUT=10000
ACTIVITY_RETRY_ATTEMPTS=3

# Features
ENABLE_PERFORMANCE_MONITORING=true
SAVE_ACTIVITY_TEST_ARTIFACTS=true
ACTIVITY_TEST_DEBUG=true
```

### Command Line Options

```bash
Options:
  -d, --device <serial>           Android device serial number
  -p, --package <package>         MaynDrive package name
  -t, --timeout <ms>              Overall test timeout
  --launch-timeout <ms>           Activity launch timeout
  --capture-timeout <ms>          UI capture timeout
  --stabilization-timeout <ms>    Activity stabilization timeout
  -r, --retries <count>           Number of retry attempts
  -a, --artifacts                 Save test artifacts
  --artifacts-dir <path>          Artifacts output directory
  --debug                         Enable debug logging
  --performance                   Enable performance monitoring
  -v, --verbose                   Verbose output
  -h, --help                      Show help message
```

## Test Results

### Output Structure

```
test-results/activity-resume/
├── MainActivity_1699123456789/
│   ├── ui_hierarchy.xml          # UI XML dump
│   ├── screenshot.png            # Screen capture
│   └── test_result.json          # Detailed test result
├── LoginScreen_1699123456789/
│   ├── ui_hierarchy.xml
│   ├── screenshot.png
│   └── test_result.json
├── MapScreen_1699123456789/
│   ├── ui_hierarchy.xml
│   ├── screenshot.png
│   └── test_result.json
└── activity-resume-results-1699123456789.json  # Complete results
```

### Sample Output

```
================================================================================
MAYNDRIVE ACTIVITY-SPECIFIC RESUME PROCEDURES INTEGRATION TESTS
================================================================================

⚙️  Test Configuration:
   Device: emulator-5554
   Package: com.mayn.mayndrive
   Test Timeout: 60000ms
   Launch Timeout: 15000ms
   Capture Timeout: 10000ms
   Stabilization Timeout: 10000ms
   Retry Attempts: 3
   Performance Monitoring: Enabled
   Save Artifacts: Enabled
   Artifacts Directory: ./test-results/activity-resume
   Debug Logging: Enabled

================================================================================
📊 TEST RESULTS SUMMARY
================================================================================
✅ Overall Status: PASSED
📈 Success Rate: 95%
📋 Total Tests: 24
✅ Passed: 23
❌ Failed: 1

⏱️  Performance Benchmarks:
   Average Launch Time: 2340ms
   Average Capture Time: 890ms
   Average Resume Time: 3780ms
   Fastest Activity: LoginScreen
   Slowest Activity: MapScreen

📱 Activity Results:
   ✅ MainActivity: 8/8 (100%)
   ✅ LoginScreen: 8/8 (100%)
   ⚠️  MapScreen: 7/8 (88%)

🔄 Activity Transitions: 4/4 (100%)

⏰ Test completed at: 10/25/2024, 5:30:45 PM
```

## Troubleshooting

### Common Issues

#### Device Connection Issues
```bash
# Check device connection
adb devices

# Restart ADB server
adb kill-server && adb start-server

# Check device status
adb -s $ANDROID_SERIAL shell getprop sys.boot_completed
```

#### MaynDrive App Issues
```bash
# Check if app is installed
adb shell pm list packages | grep mayn

# Check app process
adb shell ps | grep mayn

# Clear app data
adb shell pm clear com.mayn.mayndrive
```

#### Test Timeout Issues
```bash
# Increase timeouts
export ACTIVITY_LAUNCH_TIMEOUT=30000
export ACTIVITY_STABILIZATION_TIMEOUT=20000

# Run with debug logging
npm run test:activity:resume:debug
```

#### Performance Issues
```bash
# Check device performance
adb shell dumpsys cpuinfo | grep mayn
adb shell dumpsys meminfo com.mayn.mayndrive

# Restart emulator for better performance
```

## Integration with AutoApp System

### Flow Engine Integration

These tests validate the foundation for the AutoApp UI Map & Intelligent Flow Engine:

- **State Detection**: Ensures reliable UI state capture from any activity
- **Activity Awareness**: Validates activity context preservation
- **Transition Handling**: Confirms proper activity transition management
- **Error Recovery**: Tests robustness of state recovery mechanisms

### Graph Integration

The test results feed into the AutoApp graph system:

- **Node Mapping**: Activities map to graph nodes
- **Edge Validation**: Transitions validate graph edges
- **State Preservation**: Activity states enhance graph context
- **Recovery Paths**: Alternative routes through activity graph

## Maintenance

### Updating UI Patterns

When MaynDrive app updates:

1. **Review Test Failures**: Check which UI patterns need updates
2. **Update Selectors**: Modify resource IDs, text patterns, or class names
3. **Adjust Timeouts**: Update stabilization times if needed
4. **Validate Performance**: Ensure benchmarks still met

### Adding New Activities

To support new MaynDrive activities:

1. **Define Activity Configuration**: Add to `MAYNDRIVE_ACTIVITIES`
2. **Specify UI Patterns**: Define key elements and identifiers
3. **Configure Resume Procedure**: Set stabilization and validation
4. **Add Test Scenarios**: Include in transition tests
5. **Update Documentation**: Modify guides and help text

### Performance Optimization

Monitor and optimize test performance:

- **Track Benchmarks**: Monitor average times over runs
- **Adjust Timeouts**: Balance reliability vs speed
- **Optimize Selectors**: Use most reliable UI patterns
- **Reduce Overhead**: Minimize unnecessary captures

## Contributing

### Code Style

- Follow TypeScript best practices
- Use comprehensive error handling
- Add detailed logging for debugging
- Include performance metrics

### Test Coverage

- Test all activity launch scenarios
- Include error conditions
- Validate performance benchmarks
- Test device disconnection scenarios

### Documentation

- Update guides when adding features
- Include troubleshooting steps
- Document configuration options
- Provide examples for common use cases

## Support

For questions or issues:

1. **Check Documentation**: Review `ACTIVITY_RESUME_TEST_GUIDE.md`
2. **Review Logs**: Enable debug logging for detailed output
3. **Check Artifacts**: Examine saved screenshots and UI hierarchies
4. **Validate Environment**: Ensure emulator and app are properly configured

## License

These tests are part of the AutoApp UI Map & Intelligent Flow Engine project.