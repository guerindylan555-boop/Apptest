# MaynDrive Activity-Specific Resume Procedures Test Guide

## Overview

This guide provides comprehensive documentation for the MaynDrive Activity-Specific Resume Procedures integration tests. These tests validate that the AutoApp UI Map & Intelligent Flow Engine can reliably capture UI state and manage activity transitions regardless of which MaynDrive activity is currently active.

## Test Architecture

### Test Components

1. **Activity Detection Utilities** (`ActivityDetectionUtils`)
   - Current activity detection
   - UI pattern validation
   - Activity confidence scoring
   - Stabilization monitoring

2. **Activity Resume Test Engine** (`ActivityResumeTestEngine`)
   - Complete test suite execution
   - Performance benchmarking
   - Error scenario simulation
   - Results aggregation

3. **MaynDrive Activity Configurations**
   - MainActivity definition and patterns
   - LoginScreen definition and patterns
   - MapScreen definition and patterns
   - Activity-specific UI selectors

### Test Scope

The test suite covers:

- **Activity Launch Procedures**: Testing direct launch to each MaynDrive activity
- **Activity State Detection**: Validating current activity detection accuracy
- **Resume Procedures**: Testing resume from background, crash, and low memory states
- **Activity Validation**: Performing activity-specific validation actions
- **Activity Transitions**: Testing navigation between activities
- **Error Scenarios**: Handling invalid activities, timeouts, and failures
- **Performance Benchmarks**: Ensuring <5s resume times per activity

## MaynDrive Activities

### MainActivity (com.mayn.mayndrive.MainActivity)

**Purpose**: Main home screen of MaynDrive application

**Key UI Elements**:
- `home_container` - Main content container
- `navigation_bottom` - Bottom navigation bar
- `fab_main` - Main floating action button
- Home screen widgets and shortcuts

**Resume Procedure**:
- Stabilization time: 3 seconds
- Minimum interactive elements: 5
- Validation actions: Wait → Tap navigation home → Wait

**Screen Identifiers**:
- MainActivity class name
- home_container element
- navigation_bottom element
- "Accueil" text elements

### LoginScreen (com.mayn.mayndrive.LoginActivity)

**Purpose**: User authentication screen

**Key UI Elements**:
- `login_email` - Email input field
- `login_password` - Password input field
- `login_button` - Login submit button
- `forgot_password` - Password recovery link

**Resume Procedure**:
- Stabilization time: 2 seconds
- Minimum interactive elements: 3
- Validation actions: Wait → Tap email field → Wait

**Screen Identifiers**:
- LoginActivity class name
- login_email element
- login_password element
- "Se connecter" button text

### MapScreen (com.mayn.mayndrive.MapActivity)

**Purpose**: Map display and navigation interface

**Key UI Elements**:
- `map_container` - Map view container
- `map_search` - Search functionality
- `map_current_location` - Current location button
- `map_zoom_in/out` - Zoom controls

**Resume Procedure**:
- Stabilization time: 4 seconds
- Minimum interactive elements: 4
- Validation actions: Wait → Tap current location → Wait

**Screen Identifiers**:
- MapActivity class name
- map_container element
- map_search element
- Google Maps MapView class

## Test Configuration

### Environment Variables

```bash
# Core Configuration
ANDROID_SERIAL=emulator-5554                    # ADB device serial
MAYNDRIVE_PACKAGE=com.mayn.mayndrive            # MaynDrive package name

# Timeouts (milliseconds)
ACTIVITY_TEST_TIMEOUT=60000                     # Overall test timeout
ACTIVITY_LAUNCH_TIMEOUT=15000                   # Activity launch timeout
ACTIVITY_CAPTURE_TIMEOUT=10000                  # UI capture timeout
ACTIVITY_STABILIZATION_TIMEOUT=10000            # Activity stabilization timeout

# Retry and Performance
ACTIVITY_RETRY_ATTEMPTS=3                       # Number of retry attempts
ENABLE_PERFORMANCE_MONITORING=true              # Enable performance tracking

# Artifacts and Debugging
SAVE_ACTIVITY_TEST_ARTIFACTS=true               # Save test screenshots and data
ACTIVITY_TEST_ARTIFACTS_DIR=./test-results/activity-resume
ACTIVITY_TEST_DEBUG=true                         # Enable debug logging
```

### Test Configuration Structure

```typescript
interface ActivityTestConfig {
  deviceSerial: string;           // ADB device serial number
  maynDrivePackage: string;       // MaynDrive package name
  testTimeout: number;            // Overall test timeout (ms)
  launchTimeout: number;          // Activity launch timeout (ms)
  captureTimeout: number;         // UI capture timeout (ms)
  stabilizationTimeout: number;   // Activity stabilization timeout (ms)
  retryAttempts: number;          // Number of retry attempts
  enablePerformanceMonitoring: boolean;  // Performance tracking
  saveArtifacts: boolean;         // Save test artifacts
  artifactsDirectory: string;     // Artifacts output directory
  debugLogging: boolean;          // Enable debug logging
}
```

## Running the Tests

### Direct Execution

```bash
# Run the complete test suite
npx ts-node backend/tests/integration/activity-resume.test.ts

# Run with custom configuration
ANDROID_SERIAL=emulator-5556 \
ACTIVITY_TEST_DEBUG=true \
SAVE_ACTIVITY_TEST_ARTIFACTS=true \
npx ts-node backend/tests/integration/activity-resume.test.ts
```

### Programmatic Execution

```typescript
import { runActivityResumeTests } from './backend/tests/integration/activity-resume.test';

async function main() {
  try {
    const results = await runActivityResumeTests();
    console.log(`Tests completed with ${results.summary.successRate}% success rate`);
  } catch (error) {
    console.error('Test execution failed:', error);
  }
}

main();
```

### Custom Test Configuration

```typescript
import { ActivityResumeTestEngine, getActivityTestConfig } from './backend/tests/integration/activity-resume.test';

const config = getActivityTestConfig();
config.testTimeout = 120000;  // 2 minutes
config.debugLogging = true;

const testEngine = new ActivityResumeTestEngine(config);
await testEngine.initialize();
const results = await testEngine.runCompleteTestSuite();
await testEngine.cleanup();
```

## Test Results

### Result Structure

```typescript
interface ActivityResumeTestResults {
  testConfig: ActivityTestConfig;
  timestamp: string;
  environment: EnvironmentInfo;
  activityResults: ActivityTestResult[];
  transitionResults: ActivityTransitionResult[];
  performanceBenchmarks: PerformanceBenchmarks;
  errorSummary: ErrorSummary;
  summary: TestSummary;
}
```

### Sample Output

```
================================================================================
MAYNDRIVE ACTIVITY-SPECIFIC RESUME PROCEDURES INTEGRATION TESTS
================================================================================

================================================================================
ACTIVITY RESUME TEST RESULTS SUMMARY
================================================================================
Overall Status: PASSED
Total Tests: 24
Passed: 22
Failed: 2
Success Rate: 92%

PERFORMANCE BENCHMARKS:
Average Launch Time: 2340ms
Average Capture Time: 890ms
Average Resume Time: 3780ms
Fastest Activity: LoginScreen
Slowest Activity: MapScreen

ERROR SUMMARY:
Total Errors: 2
  Activity launch timeout: 1
  UI state capture failure: 1
```

### Result Files

Test artifacts are saved to `./test-results/activity-resume/` with the following structure:

```
activity-resume/
├── MainActivity_1699123456789/
│   ├── ui_hierarchy.xml
│   ├── screenshot.png
│   └── test_result.json
├── LoginScreen_1699123456789/
│   ├── ui_hierarchy.xml
│   ├── screenshot.png
│   └── test_result.json
├── MapScreen_1699123456789/
│   ├── ui_hierarchy.xml
│   ├── screenshot.png
│   └── test_result.json
└── activity-resume-results-1699123456789.json
```

## Test Scenarios

### 1. Activity Launch Procedures

**Objective**: Test direct launch to each MaynDrive activity

**Test Steps**:
1. Stop MaynDrive application
2. Launch to specific activity using ADB
3. Wait for activity stabilization
4. Capture UI state
5. Validate correct activity is active
6. Verify minimum interactive elements
7. Record performance metrics

**Success Criteria**:
- Activity launches successfully
- Correct activity detected with ≥80% confidence
- Stabilization completes within timeout
- Minimum interactive elements present
- Performance benchmarks met (<5s total)

### 2. Activity State Detection

**Objective**: Validate activity detection accuracy and consistency

**Test Steps**:
1. Launch to target activity
2. Wait for stabilization
3. Perform multiple detection attempts
4. Calculate confidence scores
5. Verify detection consistency
6. Validate UI pattern matching

**Success Criteria**:
- Average confidence ≥80%
- Detection consistency (max-min confidence) ≤20%
- UI patterns match expected activity
- Activity class name correctly identified

### 3. Resume Procedures

**Objective**: Test resume from different application states

**Resume Scenarios**:

#### Background Resume
1. Launch to activity
2. Send app to background (home button)
3. Wait 3 seconds
4. Resume application
5. Validate activity state

#### Crash Recovery Resume
1. Launch to activity
2. Force-stop application
3. Relaunch application
4. Validate activity recovery

#### Low Memory Resume
1. Launch to activity
2. Simulate memory pressure
3. Trigger memory cleanup
4. Validate activity restoration

**Success Criteria**:
- Activity resumes correctly
- UI state preserved or properly restored
- No crashes during resume
- Interactive elements available

### 4. Activity Transitions

**Objective**: Test navigation between MaynDrive activities

**Transition Tests**:
- MainActivity → LoginScreen (tap login button)
- MainActivity → MapScreen (tap map button)
- LoginScreen → MainActivity (back button)
- MapScreen → MainActivity (back button)

**Test Steps**:
1. Start with source activity
2. Capture before state
3. Perform transition action
4. Wait for destination stabilization
5. Capture after state
6. Validate transition success

**Success Criteria**:
- Correct destination activity reached
- UI state changes appropriately
- No crashes during transition
- Navigation completes within timeout

### 5. Error Scenarios

**Objective**: Test error handling and recovery

**Error Tests**:
- Invalid activity launch
- Activity launch timeout
- UI state capture failure
- Device disconnection during resume

**Success Criteria**:
- Errors handled gracefully
- Appropriate error messages
- Recovery mechanisms work
- Test suite continues execution

### 6. Performance Benchmarks

**Objective**: Ensure performance requirements are met

**Performance Tests**:
- Multiple iterations per activity
- Launch time measurement
- UI capture time measurement
- Total resume time measurement

**Success Criteria**:
- Average launch time <3s
- Average capture time <1s
- Total resume time <5s
- Performance consistency across iterations

## Activity Management Guidelines

### Adding New Activities

To add support for new MaynDrive activities:

1. **Define Activity Configuration**:

```typescript
const NEW_ACTIVITY: MaynDriveActivity = {
  name: 'NewActivity',
  className: 'com.mayn.mayndrive.NewActivity',
  packageName: 'com.mayn.mayndrive',
  uiPatterns: {
    keyElements: [
      { resource_id: 'com.mayn.mayndrive:id/key_element', clickable: true },
      { text: 'Expected Text', clickable: false }
    ],
    screenIdentifiers: ['NewActivity', 'unique_identifier'],
    loadingIndicators: ['loading_indicator']
  },
  resumeProcedure: {
    stabilizationTime: 3000,
    minInteractiveElements: 3,
    validationActions: [
      { type: 'wait', duration: 1000 }
    ]
  }
};
```

2. **Add to Activities Map**:

```typescript
const MAYNDRIVE_ACTIVITIES: Record<string, MaynDriveActivity> = {
  // ... existing activities
  NewActivity: NEW_ACTIVITY
};
```

3. **Update Test Scenarios**:
   - Add transition tests if needed
   - Update performance benchmarks
   - Add validation actions specific to the activity

### Customizing UI Patterns

UI patterns can be customized using several selector types:

```typescript
keyElements: [
  { resource_id: 'com.mayn.mayndrive:id/button', clickable: true },
  { text: 'Button Text', clickable: true },
  { content_desc: 'Content Description', clickable: true },
  { class: 'android.widget.Button', clickable: true }
]
```

**Selector Types**:
- `resource_id`: Android resource ID (most reliable)
- `text`: Visible text content
- `content_desc`: Content description for accessibility
- `class`: Android class name
- `clickable`: Whether element should be clickable

### Validation Actions

Custom validation actions can be defined for each activity:

```typescript
validationActions: [
  { type: 'wait', duration: 1000 },
  { type: 'tap', target: 'button_id' },
  { type: 'tap', coordinates: { x: 540, y: 800 } },
  { type: 'swipe', coordinates: { startX: 100, startY: 500, endX: 500, endY: 500 } },
  { type: 'back' }
]
```

**Action Types**:
- `wait`: Pause execution
- `tap`: Tap element or coordinates
- `swipe`: Perform swipe gesture
- `back`: Press back button

### Performance Tuning

Adjust performance parameters based on device capabilities:

```typescript
// For faster devices
resumeProcedure: {
  stabilizationTime: 2000,  // Reduce wait time
  minInteractiveElements: 3  // Lower minimum requirement
}

// For slower devices
resumeProcedure: {
  stabilizationTime: 5000,  // Increase wait time
  minInteractiveElements: 5  // Higher minimum requirement
}
```

## Troubleshooting

### Common Issues

#### 1. Activity Detection Failures

**Symptoms**: Low confidence scores or incorrect activity detection

**Solutions**:
- Verify UI patterns match current app version
- Update screen identifiers
- Check for app layout changes
- Increase stabilization timeout

**Debug Commands**:
```bash
# Check current activity
adb shell dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'

# Capture UI hierarchy manually
adb shell uiautomator dump
adb pull /sdcard/window_dump.xml
```

#### 2. Launch Timeouts

**Symptoms**: Activities fail to launch within timeout

**Solutions**:
- Increase `ACTIVITY_LAUNCH_TIMEOUT`
- Check device performance
- Verify app installation
- Restart emulator if needed

**Debug Commands**:
```bash
# Check app installation
adb shell pm list packages | grep mayn

# Check app process
adb shell ps | grep mayn

# Launch app manually
adb shell am start -n com.mayn.mayndrive/.MainActivity
```

#### 3. UI Capture Failures

**Symptoms**: UI state capture returns empty or invalid data

**Solutions**:
- Increase `ACTIVITY_CAPTURE_TIMEOUT`
- Check UIAutomator2 availability
- Verify screen is on and unlocked
- Restart ADB server

**Debug Commands**:
```bash
# Check UIAutomator2
adb shell which uiautomator

# Test UI dump
adb shell uiautomator dump && adb shell cat /sdcard/window_dump.xml

# Restart ADB
adb kill-server && adb start-server
```

#### 4. Performance Issues

**Symptoms**: Tests consistently exceed 5-second benchmark

**Solutions**:
- Check device resource usage
- Close unnecessary apps
- Use faster emulator configuration
- Increase performance thresholds

**Debug Commands**:
```bash
# Check device performance
adb shell dumpsys cpuinfo | grep mayn
adb shell dumpsys meminfo com.mayn.mayndrive

# Check emulator performance
adb shell getprop ro.product.cpu.abi
adb shell cat /proc/meminfo
```

### Debug Mode

Enable comprehensive debugging:

```bash
ACTIVITY_TEST_DEBUG=true \
SAVE_ACTIVITY_TEST_ARTIFACTS=true \
npx ts-node backend/tests/integration/activity-resume.test.ts
```

This provides:
- Detailed logging for each step
- UI hierarchy and screenshot artifacts
- Performance metrics breakdown
- Error stack traces and context

## Best Practices

### Test Environment Setup

1. **Use Consistent Emulator Configuration**:
   - Android API level 29+
   - 2GB+ RAM
   - 1080p resolution
   - Hardware acceleration enabled

2. **Maintain Clean Test State**:
   - Clear app data before tests
   - Ensure stable network connection
   - Close unnecessary applications
   - Use dedicated test emulator

3. **Configure Appropriate Timeouts**:
   - Adjust based on device performance
   - Account for network latency
   - Include buffer for loading screens

### Test Execution

1. **Run Tests Regularly**:
   - Include in CI/CD pipeline
   - Schedule daily runs
   - Run after app updates

2. **Monitor Performance Trends**:
   - Track average launch times
   - Identify performance regressions
   - Optimize based on metrics

3. **Review Test Artifacts**:
   - Analyze failed tests
   - Check UI hierarchy changes
   - Update patterns as needed

### Maintenance

1. **Update UI Patterns**:
   - Review after app updates
   - Monitor for layout changes
   - Add new elements as needed

2. **Optimize Performance**:
   - Tune stabilization times
   - Adjust validation actions
   - Update benchmark thresholds

3. **Expand Test Coverage**:
   - Add new activities
   - Include additional scenarios
   - Enhance error testing

## Integration with AutoApp Flow Engine

The activity resume tests integrate with the broader AutoApp UI Map & Intelligent Flow Engine:

### Flow Engine Integration

- **State Detection**: Uses same UI state capture mechanisms
- **Activity Awareness**: Flow engine respects current activity context
- **Transition Handling**: Validates activity transitions for flow execution
- **Error Recovery**: Provides fallback mechanisms for flow failures

### Graph Integration

- **Node Identification**: Activities map to graph nodes
- **Edge Validation**: Transitions validate graph edges
- **State Preservation**: Activity states preserved in graph context
- **Recovery Paths**: Alternative paths through activity graph

### Session Management

- **Activity Context**: Sessions maintain current activity state
- **Resume Capability**: Sessions can resume from any activity
- **State Validation**: Session states validated against activity patterns
- **Error Handling**: Session recovery from activity failures

This comprehensive test suite ensures that the AutoApp system can reliably interact with MaynDrive regardless of the current activity state, providing a solid foundation for automated UI mapping and flow execution.