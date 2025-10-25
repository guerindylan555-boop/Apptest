#!/usr/bin/env ts-node

/**
 * Remote Accessibility Test Runner
 *
 * Simple command-line interface for running remote API accessibility tests
 * with different environments and configurations.
 */

import { runRemoteAccessibilityTests, getTestConfig, saveTestResults } from './remote-access.test';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// ============================================================================
// CONFIGURATION LOADING
// ============================================================================

interface EnvironmentConfig {
  baseUrl: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  dockployDomain?: string;
  traefikProxy?: string;
  customHeaders?: Record<string, string>;
  corsOrigins: string[];
  expectedEndpoints: string[];
}

interface TestEnvironments {
  environments: Record<string, EnvironmentConfig>;
  performanceThresholds: Record<string, any>;
  testScenarios: Record<string, any>;
  monitoring: Record<string, any>;
}

function loadEnvironmentConfig(environment: string): EnvironmentConfig | null {
  try {
    const configPath = join(__dirname, 'config', 'environments.json');
    if (!existsSync(configPath)) {
      console.warn('Environment configuration file not found, using defaults');
      return null;
    }

    const config: TestEnvironments = JSON.parse(readFileSync(configPath, 'utf8'));
    return config.environments[environment] || null;
  } catch (error) {
    console.warn('Failed to load environment configuration:', error);
    return null;
  }
}

// ============================================================================
// COMMAND LINE ARGUMENTS
// ============================================================================

interface TestOptions {
  environment?: string;
  baseUrl?: string;
  timeout?: number;
  retryAttempts?: number;
  retryDelay?: number;
  dockployDomain?: string;
  scenario?: string;
  verbose?: boolean;
  saveResults?: boolean;
  outputFormat?: 'json' | 'table' | 'summary';
}

function parseArguments(): TestOptions {
  const args = process.argv.slice(2);
  const options: TestOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];

    switch (arg) {
      case '--environment':
      case '-e':
        options.environment = nextArg;
        i++;
        break;
      case '--url':
      case '-u':
        options.baseUrl = nextArg;
        i++;
        break;
      case '--timeout':
      case '-t':
        options.timeout = parseInt(nextArg);
        i++;
        break;
      case '--retry':
      case '-r':
        options.retryAttempts = parseInt(nextArg);
        i++;
        break;
      case '--delay':
      case '-d':
        options.retryDelay = parseInt(nextArg);
        i++;
        break;
      case '--dockploy-domain':
        options.dockployDomain = nextArg;
        i++;
        break;
      case '--scenario':
      case '-s':
        options.scenario = nextArg;
        i++;
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--save':
        options.saveResults = true;
        break;
      case '--format':
      case '-f':
        options.outputFormat = nextArg as 'json' | 'table' | 'summary';
        i++;
        break;
      case '--help':
      case '-h':
        showHelp();
        process.exit(0);
        break;
    }
  }

  return options;
}

// ============================================================================
// HELP TEXT
// ============================================================================

function showHelp(): void {
  console.log(`
Remote Accessibility Test Runner

USAGE:
  ts-node run-tests.ts [OPTIONS]

OPTIONS:
  -e, --environment <name>     Test environment (development, staging, production, traefik-local, docker-compose, custom-domain)
  -u, --url <url>             Base URL for testing (overrides environment config)
  -t, --timeout <ms>          Request timeout in milliseconds (default: 10000)
  -r, --retry <count>         Number of retry attempts (default: 3)
  -d, --delay <ms>            Delay between retries in milliseconds (default: 1000)
  --dockploy-domain <domain>  Dockploy domain for testing
  -s, --scenario <name>       Test scenario (basic-access, full-suite, cors-only, health-only, api-coverage)
  -v, --verbose               Enable verbose output
  --save                      Save test results to file
  -f, --format <format>       Output format (json, table, summary)
  -h, --help                  Show this help message

EXAMPLES:
  # Run tests against development environment
  ts-node run-tests.ts --environment development

  # Run tests against specific URL
  ts-node run-tests.ts --url https://autoapp.dockploy.io

  # Run with custom timeout and retry settings
  ts-node run-tests.ts --environment production --timeout 30000 --retry 5

  # Run specific test scenario
  ts-node run-tests.ts --environment staging --scenario health-only

  # Run with verbose output and save results
  ts-node run-tests.ts --environment production --verbose --save

  # Run against localhost with custom settings
  ts-node run-tests.ts --url http://localhost:3001 --timeout 15000 --verbose

ENVIRONMENT VARIABLES:
  TEST_BASE_URL               Base URL for API testing
  TEST_TIMEOUT                Request timeout in milliseconds
  TEST_RETRY_ATTEMPTS         Number of retry attempts
  TEST_RETRY_DELAY            Delay between retries in milliseconds
  DOCKPLOY_DOMAIN             Dockploy domain
  TRAEFIK_PROXY               Traefik proxy URL
  CORS_ALLOWED_ORIGINS        Comma-separated list of allowed origins
  NODE_ENV                    Environment mode
  PORT                        Application port
  HOST                        Application host
`);
}

// ============================================================================
// OUTPUT FORMATTING
// ============================================================================

function formatOutput(results: any, format: 'json' | 'table' | 'summary'): void {
  switch (format) {
    case 'json':
      console.log(JSON.stringify(results, null, 2));
      break;
    case 'table':
      formatAsTable(results);
      break;
    case 'summary':
      formatAsSummary(results);
      break;
    default:
      formatAsSummary(results);
  }
}

function formatAsTable(results: any): void {
  console.log('\n' + '='.repeat(80));
  console.log('REMOTE ACCESSIBILITY TEST RESULTS');
  console.log('='.repeat(80));

  // Basic information
  console.log(`\nTest Configuration:`);
  console.log(`  Base URL: ${results.testConfig.baseUrl}`);
  console.log(`  Environment: ${results.environment.nodeVersion} on ${results.environment.platform}`);
  console.log(`  Docker Container: ${results.environment.dockerContainer ? 'Yes' : 'No'}`);
  console.log(`  Test Time: ${results.timestamp}`);

  // Summary table
  console.log(`\nSummary:`);
  console.log(`┌─────────────────────┬──────────┬────────┬────────┬──────────────┐`);
  console.log(`│ Test Category       │ Total    │ Passed │ Failed │ Success Rate │`);
  console.log(`├─────────────────────┼──────────┼────────┼────────┼──────────────┤`);

  const categories = [
    { name: 'CORS Tests', results: results.cors },
    { name: 'Health Checks', results: results.health },
    { name: 'API Endpoints', results: results.api },
    { name: 'WebRTC Config', results: results.webrtc }
  ];

  categories.forEach(category => {
    const total = category.results.length;
    const passed = category.results.filter((r: any) => r.passed).length;
    const failed = total - passed;
    const rate = total > 0 ? Math.round((passed / total) * 100) : 0;

    console.log(`│ ${category.name.padEnd(19)} │ ${total.toString().padEnd(8)} │ ${passed.toString().padEnd(6)} │ ${failed.toString().padEnd(6)} │ ${rate.toString().padEnd(12)}% │`);
  });

  console.log(`├─────────────────────┼──────────┼────────┼────────┼──────────────┤`);
  console.log(`│ ${'TOTAL'.padEnd(19)} │ ${results.summary.totalTests.toString().padEnd(8)} │ ${results.summary.passedTests.toString().padEnd(6)} │ ${results.summary.failedTests.toString().padEnd(6)} │ ${results.summary.successRate.toString().padEnd(12)}% │`);
  console.log(`└─────────────────────┴──────────┴────────┴────────┴──────────────┘`);

  // Failed tests
  const allTests = [
    ...results.cors.map((t: any) => ({ ...t, type: 'CORS' })),
    ...results.health.map((t: any) => ({ ...t, type: 'Health' })),
    ...results.api.map((t: any) => ({ ...t, type: 'API' })),
    ...results.webrtc.map((t: any) => ({ ...t, type: 'WebRTC' }))
  ];

  const failedTests = allTests.filter((t: any) => !t.passed);

  if (failedTests.length > 0) {
    console.log(`\nFailed Tests:`);
    console.log(`┌─────┬──────────┬─────────────────────────────────────────────────────────┐`);
    console.log(`│ Type │ Endpoint │ Details                                               │`);
    console.log(`├─────┼──────────┼─────────────────────────────────────────────────────────┤`);

    failedTests.forEach((test: any) => {
      const endpoint = test.endpoint || test.origin || 'N/A';
      const details = (test.details || 'Unknown failure').substring(0, 55);
      console.log(`│ ${(test.type || '').padEnd(4)} │ ${endpoint.substring(0, 8).padEnd(8)} │ ${details.padEnd(55)} │`);
    });

    console.log(`└─────┴──────────┴─────────────────────────────────────────────────────────┘`);
  }

  console.log(`\nOverall Status: ${results.summary.overallStatus.toUpperCase()}`);
  console.log('='.repeat(80));
}

function formatAsSummary(results: any): void {
  console.log('\n' + '='.repeat(60));
  console.log('REMOTE ACCESSIBILITY TEST SUMMARY');
  console.log('='.repeat(60));

  console.log(`\n📊 Test Results:`);
  console.log(`   Overall Status: ${results.summary.overallStatus.toUpperCase()}`);
  console.log(`   Success Rate: ${results.summary.successRate}%`);
  console.log(`   Total Tests: ${results.summary.totalTests}`);
  console.log(`   Passed: ${results.summary.passedTests}`);
  console.log(`   Failed: ${results.summary.failedTests}`);

  console.log(`\n🌐 Test Environment:`);
  console.log(`   Base URL: ${results.testConfig.baseUrl}`);
  console.log(`   Node.js: ${results.environment.nodeVersion}`);
  console.log(`   Platform: ${results.environment.platform}`);
  console.log(`   Docker: ${results.environment.dockerContainer ? 'Yes' : 'No'}`);

  console.log(`\n📋 Category Results:`);
  const categories = [
    { name: 'CORS Tests', results: results.cors },
    { name: 'Health Checks', results: results.health },
    { name: 'API Endpoints', results: results.api },
    { name: 'WebRTC Config', results: results.webrtc }
  ];

  categories.forEach(category => {
    const total = category.results.length;
    const passed = category.results.filter((r: any) => r.passed).length;
    const rate = total > 0 ? Math.round((passed / total) * 100) : 0;
    const emoji = rate === 100 ? '✅' : rate >= 80 ? '⚠️' : '❌';
    console.log(`   ${emoji} ${category.name}: ${passed}/${total} (${rate}%)`);
  });

  const failedTests = [
    ...results.cors.map((t: any) => ({ ...t, type: 'CORS' })),
    ...results.health.map((t: any) => ({ ...t, type: 'Health' })),
    ...results.api.map((t: any) => ({ ...t, type: 'API' })),
    ...results.webrtc.map((t: any) => ({ ...t, type: 'WebRTC' }))
  ].filter((t: any) => !t.passed);

  if (failedTests.length > 0) {
    console.log(`\n❌ Failed Tests (${failedTests.length}):`);
    failedTests.slice(0, 5).forEach((test: any, index: number) => {
      const details = test.details || 'Unknown failure';
      console.log(`   ${index + 1}. [${test.type}] ${details.substring(0, 70)}`);
    });
    if (failedTests.length > 5) {
      console.log(`   ... and ${failedTests.length - 5} more`);
    }
  }

  console.log(`\n⏰ Test completed at: ${new Date(results.timestamp).toLocaleString()}`);
  console.log('='.repeat(60));
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

async function main(): Promise<void> {
  try {
    const options = parseArguments();

    // Load environment configuration if specified
    let envConfig: EnvironmentConfig | null = null;
    if (options.environment) {
      envConfig = loadEnvironmentConfig(options.environment);
      if (!envConfig) {
        console.error(`Error: Environment '${options.environment}' not found in configuration`);
        process.exit(1);
      }
    }

    // Set environment variables based on configuration and options
    if (envConfig) {
      process.env.TEST_BASE_URL = options.baseUrl || envConfig.baseUrl;
      process.env.TEST_TIMEOUT = (options.timeout || envConfig.timeout).toString();
      process.env.TEST_RETRY_ATTEMPTS = (options.retryAttempts || envConfig.retryAttempts).toString();
      process.env.TEST_RETRY_DELAY = (options.retryDelay || envConfig.retryDelay).toString();
      process.env.DOCKPLOY_DOMAIN = options.dockployDomain || envConfig.dockployDomain || '';
      process.env.TRAEFIK_PROXY = envConfig.traefikProxy || '';
    } else {
      // Use command line options or environment variables
      if (options.baseUrl) process.env.TEST_BASE_URL = options.baseUrl;
      if (options.timeout) process.env.TEST_TIMEOUT = options.timeout.toString();
      if (options.retryAttempts) process.env.TEST_RETRY_ATTEMPTS = options.retryAttempts.toString();
      if (options.retryDelay) process.env.TEST_RETRY_DELAY = options.retryDelay.toString();
      if (options.dockployDomain) process.env.DOCKPLOY_DOMAIN = options.dockployDomain;
    }

    // Verbose output
    if (options.verbose) {
      console.log('Test Configuration:');
      console.log(`  Base URL: ${process.env.TEST_BASE_URL}`);
      console.log(`  Timeout: ${process.env.TEST_TIMEOUT}ms`);
      console.log(`  Retry Attempts: ${process.env.TEST_RETRY_ATTEMPTS}`);
      console.log(`  Retry Delay: ${process.env.TEST_RETRY_DELAY}ms`);
      console.log(`  Dockploy Domain: ${process.env.DOCKPLOY_DOMAIN || 'Not set'}`);
      console.log(`  Environment: ${options.environment || 'Custom'}`);
      console.log(`  Scenario: ${options.scenario || 'full-suite'}`);
      console.log();
    }

    // Run tests
    const results = await runRemoteAccessibilityTests();

    // Save results if requested
    if (options.saveResults !== false) {
      await saveTestResults(results);
    }

    // Format output
    const format = options.outputFormat || 'summary';
    formatOutput(results, format);

    // Exit with appropriate code
    if (results.summary.overallStatus === 'failed') {
      process.exit(1);
    } else if (results.summary.overallStatus === 'partial') {
      process.exit(2);
    } else {
      process.exit(0);
    }

  } catch (error) {
    console.error('Test execution failed:', error);
    process.exit(1);
  }
}

// Run if this file is executed directly
if (require.main === module) {
  main();
}

export { main, parseArguments, loadEnvironmentConfig, formatOutput };