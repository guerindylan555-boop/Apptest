#!/usr/bin/env ts-node

/**
 * UI State Capture Integration Test Runner
 *
 * Simple script to run the UI state capture integration tests.
 * This can be used for manual testing, CI/CD, and debugging.
 */

import { TestRunner, TEST_CONFIG } from './state-capture-simple.test';
import { logger } from '../../src/services/logger';

// ============================================================================
// COMMAND LINE ARGUMENTS
// ============================================================================

interface TestOptions {
  deviceSerial?: string;
  connectionTimeout?: number;
  captureTimeout?: number;
  performanceTimeout?: number;
  testDataDir?: string;
  debug?: boolean;
  help?: boolean;
}

function parseArgs(): TestOptions {
  const args = process.argv.slice(2);
  const options: TestOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--device':
      case '-d':
        options.deviceSerial = args[++i];
        break;
      case '--connection-timeout':
      case '-c':
        options.connectionTimeout = parseInt(args[++i]);
        break;
      case '--capture-timeout':
      case '-t':
        options.captureTimeout = parseInt(args[++i]);
        break;
      case '--performance-timeout':
      case '-p':
        options.performanceTimeout = parseInt(args[++i]);
        break;
      case '--data-dir':
        options.testDataDir = args[++i];
        break;
      case '--debug':
        options.debug = true;
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

function showHelp(): void {
  console.log(`
UI State Capture Integration Test Runner

USAGE:
  ts-node run-state-capture-tests.ts [OPTIONS]

OPTIONS:
  -d, --device <serial>         Device serial number (default: emulator-5554)
  -c, --connection-timeout <ms> Connection timeout in milliseconds (default: 15000)
  -t, --capture-timeout <ms>    Capture timeout in milliseconds (default: 10000)
  -p, --performance-timeout <ms> Performance timeout in milliseconds (default: 2000)
      --data-dir <path>         Test data directory (default: ./test-data)
      --debug                   Enable debug logging
  -h, --help                    Show this help message

EXAMPLES:
  # Run with default settings
  ts-node run-state-capture-tests.ts

  # Run with custom device
  ts-node run-state-capture-tests.ts --device emulator-5556

  # Run with debug logging
  ts-node run-state-capture-tests.ts --debug

  # Run with custom timeouts
  ts-node run-state-capture-tests.ts --connection-timeout 30000 --capture-timeout 20000

ENVIRONMENT VARIABLES:
  TEST_DEVICE_SERIAL           Device serial number
  TEST_CONNECTION_TIMEOUT      Connection timeout in milliseconds
  TEST_CAPTURE_TIMEOUT         Capture timeout in milliseconds
  TEST_PERFORMANCE_TIMEOUT     Performance timeout in milliseconds
  TEST_DATA_DIR               Test data directory
  DEBUG_TESTS                 Enable debug logging (true/false)

REQUIREMENTS:
  - Android emulator running
  - ADB server running and accessible
  - UIAutomator2 available on device
  - MaynDrive app installed (optional for specific tests)

EXIT CODES:
  0  All tests passed
  1  One or more tests failed
  2  Fatal error or invalid arguments
`);
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

async function main(): Promise<void> {
  const options = parseArgs();

  if (options.help) {
    showHelp();
    process.exit(0);
  }

  // Set environment variables from command line options
  if (options.deviceSerial) {
    process.env.TEST_DEVICE_SERIAL = options.deviceSerial;
  }
  if (options.connectionTimeout) {
    process.env.TEST_CONNECTION_TIMEOUT = options.connectionTimeout.toString();
  }
  if (options.captureTimeout) {
    process.env.TEST_CAPTURE_TIMEOUT = options.captureTimeout.toString();
  }
  if (options.performanceTimeout) {
    process.env.TEST_PERFORMANCE_TIMEOUT = options.performanceTimeout.toString();
  }
  if (options.testDataDir) {
    process.env.TEST_DATA_DIR = options.testDataDir;
  }
  if (options.debug) {
    process.env.DEBUG_TESTS = 'true';
  }

  // Show test configuration
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║          UI State Capture Integration Tests                ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log();
  console.log('Configuration:');
  console.log(`  Device Serial:     ${process.env.TEST_DEVICE_SERIAL || TEST_CONFIG.DEVICE_SERIAL}`);
  console.log(`  Connection Timeout: ${process.env.TEST_CONNECTION_TIMEOUT || TEST_CONFIG.CONNECTION_TIMEOUT}ms`);
  console.log(`  Capture Timeout:    ${process.env.TEST_CAPTURE_TIMEOUT || TEST_CONFIG.CAPTURE_TIMEOUT}ms`);
  console.log(`  Performance Timeout: ${process.env.TEST_PERFORMANCE_TIMEOUT || TEST_CONFIG.PERFORMANCE_TIMEOUT}ms`);
  console.log(`  Test Data Directory: ${process.env.TEST_DATA_DIR || TEST_CONFIG.TEST_DATA_DIR}`);
  console.log(`  Debug Mode:         ${process.env.DEBUG_TESTS === 'true' ? 'Enabled' : 'Disabled'}`);
  console.log();

  // Initialize logger
  logger.info('Starting UI State Capture Integration Tests', {
    deviceSerial: process.env.TEST_DEVICE_SERIAL || TEST_CONFIG.DEVICE_SERIAL,
    connectionTimeout: process.env.TEST_CONNECTION_TIMEOUT || TEST_CONFIG.CONNECTION_TIMEOUT,
    captureTimeout: process.env.TEST_CAPTURE_TIMEOUT || TEST_CONFIG.CAPTURE_TIMEOUT,
    performanceTimeout: process.env.TEST_PERFORMANCE_TIMEOUT || TEST_CONFIG.PERFORMANCE_TIMEOUT,
    testDataDir: process.env.TEST_DATA_DIR || TEST_CONFIG.TEST_DATA_DIR,
    debugMode: process.env.DEBUG_TESTS === 'true'
  });

  // Create and run test runner
  const runner = new TestRunner();

  try {
    console.log('🔧 Setting up test environment...');
    await runner.setup();

    console.log('🧪 Running integration tests...');
    const results = await runner.runAllTests();

    console.log();
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    Test Results                              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log();
    console.log(`  Total Tests:    ${results.total}`);
    console.log(`  Passed:         ${results.passed}`);
    console.log(`  Failed:         ${results.failed}`);
    console.log(`  Success Rate:   ${Math.round((results.passed / results.total) * 100)}%`);
    console.log();

    if (results.failed === 0) {
      console.log('🎉 All tests passed!');
      process.exit(0);
    } else {
      console.log('❌ Some tests failed. Check the logs above for details.');
      process.exit(1);
    }

  } catch (error) {
    console.error();
    console.error('💥 Fatal test execution error:');
    console.error('   ', (error as Error).message);
    console.error();

    if (process.env.DEBUG_TESTS === 'true') {
      console.error('Stack trace:');
      console.error((error as Error).stack);
    }

    logger.error('Fatal test execution error', { error: (error as Error).message, stack: (error as Error).stack });
    process.exit(2);
  } finally {
    try {
      console.log('🧹 Cleaning up test environment...');
      await runner.cleanup();
    } catch (cleanupError) {
      console.error('Warning: Cleanup failed:', (cleanupError as Error).message);
    }
  }
}

// Handle uncaught exceptions and rejections
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(3);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(3);
});

// Run main function
if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error in main execution:', error);
    process.exit(3);
  });
}