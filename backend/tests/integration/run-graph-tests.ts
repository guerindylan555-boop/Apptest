#!/usr/bin/env ts-node

/**
 * Graph Serialization Test Runner
 *
 * Convenience script for running the graph JSON serialization integration tests
 * with various configuration options and reporting.
 */

import { runGraphSerializationTests } from './graph-serialization.test';
import { promises as fs } from 'fs';
import { resolve } from 'path';

// ============================================================================
// COMMAND LINE OPTIONS
// ============================================================================

interface TestRunnerOptions {
  verbose?: boolean;
  performance?: boolean;
  cleanup?: boolean;
  output?: string;
  environment?: string;
  filter?: string;
  help?: boolean;
}

/**
 * Parse command line arguments
 */
function parseArgs(): TestRunnerOptions {
  const args = process.argv.slice(2);
  const options: TestRunnerOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '-v':
      case '--verbose':
        options.verbose = true;
        break;
      case '-p':
      case '--performance':
        options.performance = true;
        break;
      case '-c':
      case '--cleanup':
        options.cleanup = true;
        break;
      case '-o':
      case '--output':
        options.output = args[++i];
        break;
      case '-e':
      case '--environment':
        options.environment = args[++i];
        break;
      case '-f':
      case '--filter':
        options.filter = args[++i];
        break;
      case '-h':
      case '--help':
        options.help = true;
        break;
      default:
        if (arg.startsWith('--')) {
          console.error(`Unknown option: ${arg}`);
          options.help = true;
        }
    }
  }

  return options;
}

/**
 * Show help information
 */
function showHelp(): void {
  console.log(`
Graph Serialization Test Runner

USAGE:
  ts-node run-graph-tests.ts [OPTIONS]

OPTIONS:
  -v, --verbose        Enable verbose logging
  -p, --performance    Enable performance benchmark tests
  -c, --cleanup        Cleanup test files after completion
  -o, --output FILE    Save test results to JSON file
  -e, --environment ENV Set test environment (development, staging, production)
  -f, --filter PATTERN Filter tests by name pattern
  -h, --help          Show this help message

EXAMPLES:
  ts-node run-graph-tests.ts                           # Run all tests
  ts-node run-graph-tests.ts -v -p                     # Verbose with performance tests
  ts-node run-graph-tests.ts -o results.json           # Save results to file
  ts-node run-graph-tests.ts -f "performance"          # Run only performance tests
  ts-node run-graph-tests.ts -e production -c          # Production environment with cleanup

ENVIRONMENT VARIABLES:
  ENABLE_PERFORMANCE_TESTS=true   Enable performance benchmarks
  VERBOSE_TESTS=true              Enable verbose logging
  CLEANUP_AFTER_TEST=false       Keep test files after completion
`);
}

// ============================================================================
// REPORTING UTILITIES
// ============================================================================

/**
 * Generate test report
 */
function generateReport(results: any): string {
  const { summary, results: testResults } = results;

  let report = `# Graph JSON Serialization Test Report

## Summary
- **Total Tests**: ${summary.totalTests}
- **Passed**: ${summary.passedTests}
- **Failed**: ${summary.failedTests}
- **Success Rate**: ${summary.successRate}%
- **Duration**: ${summary.totalDuration}ms

## Test Results

`;

  // Group tests by category
  const categories = {
    'Graph Creation': testResults.filter((r: any) => r.testName.includes('graph') || r.testName.includes('Create')),
    'State Management': testResults.filter((r: any) => r.testName.includes('state') || r.testName.includes('State')),
    'Transition Management': testResults.filter((r: any) => r.testName.includes('transition') || r.testName.includes('Transition')),
    'Serialization': testResults.filter((r: any) => r.testName.includes('serialization') || r.testName.includes('JSON')),
    'Version Management': testResults.filter((r: any) => r.testName.includes('version') || r.testName.includes('Version')),
    'Performance': testResults.filter((r: any) => r.testName.includes('performance') || r.testName.includes('Performance')),
    'Error Handling': testResults.filter((r: any) => r.testName.includes('error') || r.testName.includes('Error')),
    'Edge Cases': testResults.filter((r: any) => r.testName.includes('edge') || r.testName.includes('Edge')),
    'Concurrency': testResults.filter((r: any) => r.testName.includes('concurrent') || r.testName.includes('Concurrency'))
  };

  for (const [category, tests] of Object.entries(categories)) {
    if (tests.length === 0) continue;

    report += `### ${category}\n\n`;

    for (const test of tests) {
      const status = test.passed ? '✅' : '❌';
      const duration = `${test.duration}ms`;

      report += `- ${status} **${test.testName}** (${duration})\n`;

      if (!test.passed) {
        report += `  - Error: ${test.error}\n`;
      }

      if (test.performance) {
        report += `  - Performance: ${test.performance.memoryUsage}B memory, ${test.performance.cpuTime}ms CPU\n`;
      }

      report += '\n';
    }
  }

  // Add failed tests summary
  const failedTests = testResults.filter((r: any) => !r.passed);
  if (failedTests.length > 0) {
    report += `## Failed Tests\n\n`;
    for (const test of failedTests) {
      report += `### ${test.testName}\n`;
      report += `**Error**: ${test.error}\n\n`;
    }
  }

  // Add performance summary
  const performanceTests = testResults.filter((r: any) => r.performance);
  if (performanceTests.length > 0) {
    report += `## Performance Summary\n\n`;

    const totalMemory = performanceTests.reduce((sum: number, t: any) => sum + t.performance.memoryUsage, 0);
    const totalTime = performanceTests.reduce((sum: number, t: any) => sum + t.performance.cpuTime, 0);
    const avgMemory = Math.round(totalMemory / performanceTests.length);
    const avgTime = Math.round(totalTime / performanceTests.length);

    report += `- **Average Memory Usage**: ${avgMemory} bytes\n`;
    report += `- **Average CPU Time**: ${avgTime} ms\n`;
    report += `- **Total Test Time**: ${totalTime} ms\n\n`;
  }

  return report;
}

/**
 * Save test results to file
 */
async function saveResults(results: any, outputPath: string): Promise<void> {
  try {
    const resolvedPath = resolve(process.cwd(), outputPath);

    // Save JSON results
    await fs.writeFile(resolvedPath, JSON.stringify(results, null, 2));

    // Save markdown report
    const reportPath = outputPath.replace(/\.json$/, '.md');
    const report = generateReport(results);
    await fs.writeFile(resolve(process.cwd(), reportPath), report);

    console.log(`\n📄 Test results saved to:`);
    console.log(`   JSON: ${resolvedPath}`);
    console.log(`   Report: ${resolve(process.cwd(), reportPath)}`);
  } catch (error) {
    console.error(`Failed to save results: ${error}`);
  }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

/**
 * Main test runner function
 */
async function main(): Promise<void> {
  const options = parseArgs();

  if (options.help) {
    showHelp();
    return;
  }

  // Set environment variables based on options
  if (options.verbose) {
    process.env.VERBOSE_TESTS = 'true';
  }

  if (options.performance) {
    process.env.ENABLE_PERFORMANCE_TESTS = 'true';
  }

  if (options.cleanup) {
    process.env.CLEANUP_AFTER_TEST = 'true';
  }

  if (options.environment) {
    process.env.NODE_ENV = options.environment;
  }

  console.log('🚀 Starting Graph JSON Serialization Tests...');

  if (options.verbose) {
    console.log('Configuration:');
    console.log(`  Verbose: ${options.verbose || false}`);
    console.log(`  Performance: ${options.performance || false}`);
    console.log(`  Cleanup: ${options.cleanup || false}`);
    console.log(`  Environment: ${options.environment || 'default'}`);
    console.log(`  Output: ${options.output || 'none'}`);
    console.log('');
  }

  try {
    const startTime = Date.now();
    const results = await runGraphSerializationTests();
    const totalDuration = Date.now() - startTime;

    console.log('\n' + '='.repeat(80));
    console.log('TEST EXECUTION COMPLETE');
    console.log('='.repeat(80));
    console.log(`Overall Status: ${results.summary.successRate >= 90 ? '✅ PASSED' : '❌ FAILED'}`);
    console.log(`Success Rate: ${results.summary.successRate}%`);
    console.log(`Duration: ${totalDuration}ms`);
    console.log(`Tests Passed: ${results.summary.passedTests}/${results.summary.totalTests}`);

    // Save results if requested
    if (options.output) {
      await saveResults(results, options.output);
    }

    // Exit with appropriate code
    if (results.summary.failedTests > 0) {
      console.log(`\n❌ ${results.summary.failedTests} test(s) failed`);
      process.exit(1);
    } else {
      console.log(`\n✅ All tests passed!`);
      process.exit(0);
    }

  } catch (error) {
    console.error('\n❌ Test execution failed:', error);
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}