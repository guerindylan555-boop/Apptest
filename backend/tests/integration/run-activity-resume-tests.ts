#!/usr/bin/env ts-node

/**
 * Activity Resume Test Runner
 *
 * Simple command-line interface for running MaynDrive activity-specific
 * resume procedure tests with different configurations and options.
 */

import { runActivityResumeTests, getActivityTestConfig } from './activity-resume.test';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';

// ============================================================================
// COMMAND LINE ARGUMENTS
// ============================================================================

interface TestOptions {
  device?: string;
  package?: string;
  timeout?: number;
  launchTimeout?: number;
  captureTimeout?: number;
  stabilizationTimeout?: number;
  retries?: number;
  artifacts?: boolean;
  artifactsDir?: string;
  debug?: boolean;
  performance?: boolean;
  verbose?: boolean;
  help?: boolean;
}

function parseArguments(): TestOptions {
  const args = process.argv.slice(2);
  const options: TestOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];

    switch (arg) {
      case '--device':
      case '-d':
        options.device = nextArg;
        i++;
        break;
      case '--package':
      case '-p':
        options.package = nextArg;
        i++;
        break;
      case '--timeout':
      case '-t':
        options.timeout = parseInt(nextArg);
        i++;
        break;
      case '--launch-timeout':
        options.launchTimeout = parseInt(nextArg);
        i++;
        break;
      case '--capture-timeout':
        options.captureTimeout = parseInt(nextArg);
        i++;
        break;
      case '--stabilization-timeout':
        options.stabilizationTimeout = parseInt(nextArg);
        i++;
        break;
      case '--retries':
      case '-r':
        options.retries = parseInt(nextArg);
        i++;
        break;
      case '--artifacts':
      case '-a':
        options.artifacts = true;
        break;
      case '--artifacts-dir':
        options.artifactsDir = nextArg;
        i++;
        break;
      case '--debug':
        options.debug = true;
        break;
      case '--performance':
        options.performance = true;
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        if (arg.startsWith('--')) {
          console.error(`Unknown option: ${arg}`);
          process.exit(1);
        }
    }
  }

  return options;
}

// ============================================================================
// HELP TEXT
// ============================================================================

function showHelp(): void {
  console.log(`
MaynDrive Activity Resume Test Runner

USAGE:
  ts-node run-activity-resume-tests.ts [OPTIONS]

OPTIONS:
  -d, --device <serial>           Android device serial number
  -p, --package <package>         MaynDrive package name
  -t, --timeout <ms>              Overall test timeout (default: 60000)
  --launch-timeout <ms>           Activity launch timeout (default: 15000)
  --capture-timeout <ms>          UI capture timeout (default: 10000)
  --stabilization-timeout <ms>    Activity stabilization timeout (default: 10000)
  -r, --retries <count>           Number of retry attempts (default: 3)
  -a, --artifacts                 Save test artifacts (screenshots, UI hierarchies)
  --artifacts-dir <path>          Artifacts output directory
  --debug                         Enable debug logging
  --performance                   Enable detailed performance monitoring
  -v, --verbose                   Verbose output
  -h, --help                      Show this help message

EXAMPLES:
  # Run tests with default configuration
  ts-node run-activity-resume-tests.ts

  # Run tests with custom device and save artifacts
  ts-node run-activity-resume-tests.ts --device emulator-5556 --artifacts

  # Run tests with custom timeouts and debug logging
  ts-node run-activity-resume-tests.ts --timeout 120000 --debug --verbose

  # Run tests with performance monitoring
  ts-node run-activity-resume-tests.ts --performance --artifacts --verbose

ENVIRONMENT VARIABLES:
  ANDROID_SERIAL                   Android device serial number
  MAYNDRIVE_PACKAGE                MaynDrive package name
  ACTIVITY_TEST_TIMEOUT            Overall test timeout
  ACTIVITY_LAUNCH_TIMEOUT          Activity launch timeout
  ACTIVITY_CAPTURE_TIMEOUT         UI capture timeout
  ACTIVITY_STABILIZATION_TIMEOUT   Activity stabilization timeout
  ACTIVITY_RETRY_ATTEMPTS          Number of retry attempts
  SAVE_ACTIVITY_TEST_ARTIFACTS     Save test artifacts (true/false)
  ACTIVITY_TEST_ARTIFACTS_DIR      Artifacts output directory
  ACTIVITY_TEST_DEBUG              Enable debug logging
  ENABLE_PERFORMANCE_MONITORING    Enable performance monitoring

TEST SCENARIOS:
  The test suite covers the following scenarios:

  1. Activity Launch Procedures
     - Direct launch to MainActivity, LoginScreen, MapScreen
     - Activity stabilization and validation
     - Performance benchmarking (<5s per activity)

  2. Activity State Detection
     - Current activity detection accuracy
     - UI pattern matching and confidence scoring
     - Detection consistency across multiple attempts

  3. Resume Procedures
     - Resume from background state
     - Resume after application crash
     - Resume from low memory conditions

  4. Activity Transitions
     - MainActivity → LoginScreen navigation
     - MainActivity → MapScreen navigation
     - Back navigation and state preservation

  5. Error Scenarios
     - Invalid activity launch handling
     - Launch timeout recovery
     - UI state capture failures
     - Device disconnection recovery

  6. Performance Benchmarks
     - Launch time measurements
     - UI capture performance
     - Total resume time validation
     - Consistency across multiple iterations

ACTIVITY CONFIGURATIONS:
  MainActivity (com.mayn.mayndrive.MainActivity)
    - Home screen with navigation and widgets
    - Stabilization: 3s, Min elements: 5

  LoginScreen (com.mayn.mayndrive.LoginActivity)
    - Authentication interface with login form
    - Stabilization: 2s, Min elements: 3

  MapScreen (com.mayn.mayndrive.MapActivity)
    - Map display with navigation controls
    - Stabilization: 4s, Min elements: 4

EXIT CODES:
  0  - All tests passed
  1  - Tests failed
  2  - Partial success (some tests failed)

For more detailed information, see ACTIVITY_RESUME_TEST_GUIDE.md
`);
}

// ============================================================================
// CONFIGURATION MANAGEMENT
// ============================================================================

function applyCommandLineOptions(config: any, options: TestOptions): void {
  if (options.device) {
    config.deviceSerial = options.device;
    process.env.ANDROID_SERIAL = options.device;
  }

  if (options.package) {
    config.maynDrivePackage = options.package;
    process.env.MAYNDRIVE_PACKAGE = options.package;
  }

  if (options.timeout) {
    config.testTimeout = options.timeout;
    process.env.ACTIVITY_TEST_TIMEOUT = options.timeout.toString();
  }

  if (options.launchTimeout) {
    config.launchTimeout = options.launchTimeout;
    process.env.ACTIVITY_LAUNCH_TIMEOUT = options.launchTimeout.toString();
  }

  if (options.captureTimeout) {
    config.captureTimeout = options.captureTimeout;
    process.env.ACTIVITY_CAPTURE_TIMEOUT = options.captureTimeout.toString();
  }

  if (options.stabilizationTimeout) {
    config.stabilizationTimeout = options.stabilizationTimeout;
    process.env.ACTIVITY_STABILIZATION_TIMEOUT = options.stabilizationTimeout.toString();
  }

  if (options.retries) {
    config.retryAttempts = options.retries;
    process.env.ACTIVITY_RETRY_ATTEMPTS = options.retries.toString();
  }

  if (options.artifacts) {
    config.saveArtifacts = true;
    process.env.SAVE_ACTIVITY_TEST_ARTIFACTS = 'true';
  }

  if (options.artifactsDir) {
    config.artifactsDirectory = options.artifactsDir;
    process.env.ACTIVITY_TEST_ARTIFACTS_DIR = options.artifactsDir;
  }

  if (options.debug) {
    config.debugLogging = true;
    process.env.ACTIVITY_TEST_DEBUG = 'true';
  }

  if (options.performance) {
    config.enablePerformanceMonitoring = true;
    process.env.ENABLE_PERFORMANCE_MONITORING = 'true';
  }

  if (options.verbose) {
    config.debugLogging = true;
    process.env.ACTIVITY_TEST_DEBUG = 'true';
  }
}

function validateConfiguration(config: any): void {
  if (!config.deviceSerial) {
    console.error('❌ Error: No device specified. Use --device or set ANDROID_SERIAL environment variable.');
    process.exit(1);
  }

  if (!config.maynDrivePackage) {
    console.error('❌ Error: No package specified. Use --package or set MAYNDRIVE_PACKAGE environment variable.');
    process.exit(1);
  }

  if (config.saveArtifacts && config.artifactsDirectory) {
    try {
      if (!existsSync(config.artifactsDirectory)) {
        mkdirSync(config.artifactsDirectory, { recursive: true });
        console.log(`📁 Created artifacts directory: ${config.artifactsDirectory}`);
      }
    } catch (error) {
      console.warn(`⚠️  Warning: Could not create artifacts directory: ${error}`);
    }
  }
}

function printConfiguration(config: any): void {
  console.log('⚙️  Test Configuration:');
  console.log(`   Device: ${config.deviceSerial}`);
  console.log(`   Package: ${config.maynDrivePackage}`);
  console.log(`   Test Timeout: ${config.testTimeout}ms`);
  console.log(`   Launch Timeout: ${config.launchTimeout}ms`);
  console.log(`   Capture Timeout: ${config.captureTimeout}ms`);
  console.log(`   Stabilization Timeout: ${config.stabilizationTimeout}ms`);
  console.log(`   Retry Attempts: ${config.retryAttempts}`);
  console.log(`   Performance Monitoring: ${config.enablePerformanceMonitoring ? 'Enabled' : 'Disabled'}`);
  console.log(`   Save Artifacts: ${config.saveArtifacts ? 'Enabled' : 'Disabled'}`);
  if (config.saveArtifacts) {
    console.log(`   Artifacts Directory: ${config.artifactsDirectory}`);
  }
  console.log(`   Debug Logging: ${config.debugLogging ? 'Enabled' : 'Disabled'}`);
  console.log();
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

function printTestStart(config: any): void {
  console.log('🚀 Starting MaynDrive Activity Resume Tests');
  console.log('='.repeat(60));
  printConfiguration(config);
}

function printTestResults(results: any): void {
  console.log('='.repeat(60));
  console.log('📊 TEST RESULTS SUMMARY');
  console.log('='.repeat(60));

  const status = results.summary.overallStatus.toUpperCase();
  const statusEmoji = status === 'PASSED' ? '✅' : status === 'FAILED' ? '❌' : '⚠️';

  console.log(`${statusEmoji} Overall Status: ${status}`);
  console.log(`📈 Success Rate: ${results.summary.successRate}%`);
  console.log(`📋 Total Tests: ${results.summary.totalTests}`);
  console.log(`✅ Passed: ${results.summary.passedTests}`);
  console.log(`❌ Failed: ${results.summary.failedTests}`);

  console.log('\n⏱️  Performance Benchmarks:');
  console.log(`   Average Launch Time: ${results.performanceBenchmarks.averageLaunchTime.toFixed(0)}ms`);
  console.log(`   Average Capture Time: ${results.performanceBenchmarks.averageCaptureTime.toFixed(0)}ms`);
  console.log(`   Average Resume Time: ${results.performanceBenchmarks.averageResumeTime.toFixed(0)}ms`);
  console.log(`   Fastest Activity: ${results.performanceBenchmarks.fastestActivity}`);
  console.log(`   Slowest Activity: ${results.performanceBenchmarks.slowestActivity}`);

  // Activity-specific results
  const activityGroups = results.activityResults.reduce((groups: any, result: any) => {
    if (!groups[result.activity]) {
      groups[result.activity] = { passed: 0, failed: 0, total: 0 };
    }
    groups[result.activity].total++;
    if (result.success) {
      groups[result.activity].passed++;
    } else {
      groups[result.activity].failed++;
    }
    return groups;
  }, {});

  console.log('\n📱 Activity Results:');
  for (const [activity, stats] of Object.entries(activityGroups)) {
    const stat = stats as any;
    const rate = Math.round((stat.passed / stat.total) * 100);
    const emoji = rate === 100 ? '✅' : rate >= 80 ? '⚠️' : '❌';
    console.log(`   ${emoji} ${activity}: ${stat.passed}/${stat.total} (${rate}%)`);
  }

  // Transition results
  if (results.transitionResults.length > 0) {
    const passedTransitions = results.transitionResults.filter((t: any) => t.success).length;
    const transitionRate = Math.round((passedTransitions / results.transitionResults.length) * 100);
    console.log(`\n🔄 Activity Transitions: ${passedTransitions}/${results.transitionResults.length} (${transitionRate}%)`);
  }

  // Error summary
  if (results.errorSummary.totalErrors > 0) {
    console.log('\n❌ Error Summary:');
    console.log(`   Total Errors: ${results.errorSummary.totalErrors}`);

    for (const [errorType, count] of Object.entries(results.errorSummary.errorTypes)) {
      console.log(`   ${errorType}: ${count}`);
    }

    if (results.errorSummary.criticalFailures.length > 0) {
      console.log('\n🚨 Critical Failures:');
      results.errorSummary.criticalFailures.forEach((failure: string, index: number) => {
        console.log(`   ${index + 1}. ${failure}`);
      });
    }
  }

  console.log('\n⏰ Test completed at:', new Date(results.timestamp).toLocaleString());
  console.log('='.repeat(60));
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

async function main(): Promise<void> {
  try {
    const options = parseArguments();

    if (options.help) {
      showHelp();
      return;
    }

    // Get base configuration
    const config = getActivityTestConfig();

    // Apply command line options
    applyCommandLineOptions(config, options);

    // Validate configuration
    validateConfiguration(config);

    // Print test start information
    printTestStart(config);

    // Run tests
    console.log('🔄 Running activity resume test suite...');
    const startTime = Date.now();

    const results = await runActivityResumeTests();

    const duration = Date.now() - startTime;
    console.log(`\n⏱️  Total execution time: ${(duration / 1000).toFixed(1)}s`);

    // Print results
    printTestResults(results);

    // Exit with appropriate code
    if (results.summary.overallStatus === 'failed') {
      console.log('\n❌ Tests failed. Check the logs and artifacts for details.');
      process.exit(1);
    } else if (results.summary.overallStatus === 'partial') {
      console.log('\n⚠️  Some tests failed. Review the results for details.');
      process.exit(2);
    } else {
      console.log('\n✅ All tests passed successfully!');
      process.exit(0);
    }

  } catch (error) {
    console.error('\n💥 Test execution failed:', error);

    if (options.verbose) {
      console.error('\nStack trace:');
      console.error((error as Error).stack);
    }

    process.exit(1);
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { main, parseArguments, applyCommandLineOptions, validateConfiguration };

// ============================================================================
// SELF-EXECUTION
// ============================================================================

if (require.main === module) {
  main();
}