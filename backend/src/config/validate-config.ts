#!/usr/bin/env node

/**
 * Configuration Validation Utility
 *
 * This script validates the current environment configuration and provides
 * detailed feedback about any issues found.
 *
 * Usage: node validate-config.ts [environment]
 */

import { loadEnvironmentConfig, validateEnvironmentConfig, getConfigSummary, ConfigValidationError } from './environment';

const args = process.argv.slice(2);
const targetEnvironment = args[0] || process.env.NODE_ENV || 'development';

console.log('🔍 AutoApp Environment Configuration Validator');
console.log('=============================================\n');

try {
  console.log(`📋 Validating configuration for environment: ${targetEnvironment}\n`);

  // Load and validate configuration
  const config = loadEnvironmentConfig();
  validateEnvironmentConfig(config, targetEnvironment);

  console.log('✅ Configuration validation passed!\n');

  // Display configuration summary
  console.log('📊 Configuration Summary:');
  console.log('------------------------');
  const summary = getConfigSummary(config);
  console.log(JSON.stringify(summary, null, 2));
  console.log('');

  // Display important paths
  console.log('📁 Important Paths:');
  console.log('-------------------');
  console.log(`Project Root: ${config.projectRoot}`);
  console.log(`Graph Root: ${config.storage.graphRoot}`);
  console.log(`Flow Root: ${config.storage.flowRoot}`);
  console.log(`Sessions Dir: ${config.storage.sessionsDir}`);
  console.log(`Screenshots Dir: ${config.storage.screenshotsDir}`);
  console.log(`Log File: ${config.logging.filePath}`);
  console.log('');

  // Display connection information
  console.log('🌐 Connection Information:');
  console.log('-------------------------');
  console.log(`WebRTC URL: ${config.webrtc.publicUrl}`);
  console.log(`gRPC Endpoint: ${config.webrtc.grpcEndpoint}`);
  console.log(`ADB Host: ${config.adb.host}:${config.adb.port}`);
  console.log(`Device Serial: ${config.adb.deviceSerial}`);
  console.log(`ICE Servers: ${config.webrtc.iceServers.length > 0 ? config.webrtc.iceServers.join(', ') : 'None configured'}`);
  console.log('');

  // Display timeouts and limits
  console.log('⏱️  Timeouts and Limits:');
  console.log('-----------------------');
  console.log(`WebRTC Timeout: ${config.webrtc.timeout}ms`);
  console.log(`ADB Timeout: ${config.adb.timeout}ms`);
  console.log(`Flow Execution Timeout: ${config.flow.executionTimeout}ms`);
  console.log(`Replay Retry Limit: ${config.flow.replayRetryLimit}`);
  console.log(`Graph Validation Timeout: ${config.performance.graphValidationTimeout}ms`);
  console.log('');

  // Display development settings
  console.log('🛠️  Development Settings:');
  console.log('------------------------');
  console.log(`Development Mode: ${config.development.devMode}`);
  console.log(`Test Mode: ${config.development.testMode}`);
  console.log(`LLM Flow Assistance: ${config.development.enableLLMFlowAssistance}`);
  console.log(`Flow Validation: ${config.development.enableFlowValidation}`);
  console.log(`Mock ADB Responses: ${config.development.mockADBResponses}`);
  console.log('');

  // Display logging configuration
  console.log('📝 Logging Configuration:');
  console.log('------------------------');
  console.log(`Log Level: ${config.logging.level}`);
  console.log(`Log Format: ${config.logging.format}`);
  console.log(`Log Output: ${config.logging.output}`);
  console.log(`Debug Screenshot Capture: ${config.logging.debugScreenshotCapture}`);
  console.log(`Detailed State Logging: ${config.logging.detailedStateLogging}`);
  console.log('');

  // Display security warnings
  console.log('🔒 Security Configuration:');
  console.log('-------------------------');
  console.log(`External ADB Allowed: ${config.security.allowExternalADB}`);
  console.log(`Device Auth Required: ${config.security.requireDeviceAuth}`);
  console.log(`API Auth Enabled: ${config.api.authEnabled}`);
  console.log(`CORS Origin: ${config.api.corsOrigin}`);
  console.log('');

  // Environment-specific warnings
  if (targetEnvironment === 'production') {
    console.log('⚠️  Production Environment Warnings:');
    console.log('----------------------------------');

    if (config.logging.level === 'debug' || config.logging.level === 'trace') {
      console.log('  • Debug logging is enabled in production');
    }

    if (config.security.allowExternalADB) {
      console.log('  • External ADB connections are allowed in production');
    }

    if (config.api.corsOrigin === '*') {
      console.log('  • CORS origin is set to wildcard in production');
    }

    if (!config.api.authEnabled) {
      console.log('  • API authentication is disabled in production');
    }

    if (console.log.toString().includes('⚠️')) {
      console.log('');
    }
  }

  // Check for common issues
  console.log('🔍 Common Issue Checks:');
  console.log('-----------------------');

  // Check if using default development URLs
  if (config.webrtc.publicUrl.includes('127.0.0.1') && targetEnvironment === 'production') {
    console.log('  • Using localhost URL in production environment');
  }

  // Check if timeouts are very short
  if (config.webrtc.timeout < 5000) {
    console.log('  • WebRTC timeout is very short (< 5s)');
  }

  if (config.adb.timeout < 10000) {
    console.log('  • ADB timeout is very short (< 10s)');
  }

  // Check if storage directories are in /tmp
  if (config.storage.graphRoot.includes('/tmp/') || config.storage.flowRoot.includes('/tmp/')) {
    console.log('  • Storage directories are in /tmp (data may be lost on restart)');
  }

  console.log('\n🎉 Configuration validation completed successfully!');
  console.log(`   Environment: ${targetEnvironment}`);
  console.log(`   Project Root: ${config.projectRoot}`);

} catch (error) {
  console.error('❌ Configuration validation failed!\n');

  if (error instanceof ConfigValidationError) {
    console.error('Configuration Error Details:');
    console.error('-----------------------------');
    console.error(`Variable: ${error.variable}`);
    console.error(`Issue: ${error.message}`);
    console.error(`Suggestion: ${error.suggestion}`);
    console.error('');

    console.error('Troubleshooting Steps:');
    console.error('---------------------');
    console.error('1. Check your .env file for the missing/invalid variable');
    console.error('2. Ensure the variable is set with a valid value');
    console.error('3. Verify file paths exist and are accessible');
    console.error('4. Check network connectivity for URLs');
    console.error('5. Review the suggestion above for specific guidance');
    console.error('');

    console.error('Example .env entry:');
    console.error(`# ${error.variable}=<valid_value>`);
    console.error(`# ${error.suggestion}`);

  } else {
    console.error('Unexpected error occurred:');
    console.error(error);
    console.error('');
    console.error('Please check your environment variables and try again.');
  }

  process.exit(1);
}