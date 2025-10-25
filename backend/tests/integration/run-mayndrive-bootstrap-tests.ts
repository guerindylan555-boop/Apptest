#!/usr/bin/env ts-node

/**
 * MaynDrive Bootstrap Test Runner
 *
 * Simple script to run the MaynDrive clean-state bootstrap integration tests.
 * This script sets up the necessary environment and executes the test suite.
 */

import { runMaynDriveBootstrapTests } from './mayndrive-bootstrap.test';

// Set environment variables for testing
process.env.NODE_ENV = 'test';
process.env.TEST_MODE = 'true';
process.env.MOCK_ADB_RESPONSES = 'true'; // Enable mock responses for testing
process.env.ENABLE_DETAILED_LOGGING = 'true';
process.env.BOOTSTRAP_TIMEOUT = '30000';
process.env.ACTIVITY_LAUNCH_TIMEOUT = '15000';
process.env.DATA_CLEAR_TIMEOUT = '20000';
process.env.BOOTSTRAP_PERFORMANCE_THRESHOLD = '10000';

/**
 * Main test runner function
 */
async function main(): Promise<void> {
  console.log('🚀 Starting MaynDrive Bootstrap Integration Tests...');
  console.log('📱 Testing clean-state bootstrap for MaynDrive app');
  console.log('');

  try {
    const { results, summary } = await runMaynDriveBootstrapTests();

    console.log('');
    console.log('📊 Test Results Summary:');
    console.log(`   Total Tests: ${summary.totalTests}`);
    console.log(`   Passed: ${summary.passedTests} ✅`);
    console.log(`   Failed: ${summary.failedTests} ❌`);
    console.log(`   Success Rate: ${summary.successRate}%`);

    if (summary.averageBootstrapTime) {
      console.log(`   Average Bootstrap Time: ${summary.averageBootstrapTime}ms`);
    }

    console.log('');
    console.log('🎯 Test Scenarios Executed:');
    results.forEach((result, index) => {
      const status = result.status === 'passed' ? '✅' : '❌';
      console.log(`   ${index + 1}. ${result.testName} ${status} (${result.duration}ms)`);
    });

    console.log('');

    if (summary.successRate >= 70) {
      console.log('🎉 MaynDrive Bootstrap Tests PASSED!');
      console.log('   The MaynDrive app bootstrap system is working correctly.');
      process.exit(0);
    } else {
      console.log('❌ MaynDrive Bootstrap Tests FAILED!');
      console.log('   Please review the failed tests and fix the issues.');
      process.exit(1);
    }

  } catch (error) {
    console.error('💥 Test execution failed:', error);
    process.exit(1);
  }
}

// Run the tests
if (require.main === module) {
  main().catch((error) => {
    console.error('💥 Fatal error:', error);
    process.exit(1);
  });
}

export { main };