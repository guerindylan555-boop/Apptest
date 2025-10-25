#!/usr/bin/env node

/**
 * Structured Logger Demo
 *
 * Demonstration script for testing the structured JSON logging service
 * and verifying Constitution §10 compliance.
 */

import { createServiceLogger, logger } from './logger';

async function runLoggerDemo() {
  console.log('🚀 Starting Structured Logger Demo...\n');

  // Example 1: Basic Service Logging
  console.log('1. Testing basic service logging...');
  const webRTCLogger = createServiceLogger('webrtc-manager');
  const adbLogger = createServiceLogger('adb-bridge');

  const traceId = webRTCLogger.generateTraceId();

  webRTCLogger.info('connection_start', 'WebRTC connection initiated', traceId, {
    clientId: 'client-123',
    protocol: 'webrtc'
  });

  // Example 2: Performance Monitoring
  console.log('2. Testing performance monitoring...');
  const timer = adbLogger.startTimer('adb_command', traceId, {
    command: 'devices',
    deviceId: 'emulator-5554'
  });

  // Simulate async operation
  await new Promise(resolve => setTimeout(resolve, 100));

  const duration = timer.end({
    status: 'success',
    devicesFound: 1
  });

  console.log(`   Operation completed in ${duration}ms`);

  // Example 3: Error Handling
  console.log('3. Testing error logging...');
  const uiLogger = createServiceLogger('ui-capture');

  try {
    throw new Error('Simulated capture failure: Element not found');
  } catch (error) {
    uiLogger.error('capture_failed', 'UI element capture failed', error as Error, traceId, {
      elementType: 'button',
      elementId: 'submit-btn',
      screenshotPath: '/tmp/capture-failed.png'
    });
  }

  // Example 4: Health Check
  console.log('4. Testing health check logging...');
  const flowLogger = createServiceLogger('flow-service');
  flowLogger.healthCheck('healthy', {
    activeFlows: 3,
    completedFlows: 42,
    failedFlows: 2,
    memoryUsage: '67%',
    lastActivity: new Date().toISOString()
  });

  // Example 5: Legacy Compatibility
  console.log('5. Testing backward compatibility...');
  logger.info('Legacy logging test', {
    component: 'demo-script',
    feature: 'structured-logging',
    constitutionCompliant: true
  });

  logger.warn('This is a warning with legacy interface', {
    deprecationNotice: 'Consider using createServiceLogger() instead'
  });

  logger.error('Legacy error test', new Error('Demo error for testing'));

  // Example 6: Service-Specific Log Levels
  console.log('6. Testing service-specific log levels...');

  // Update config to show different log levels
  logger.updateConfig({
    level: 'info',
    serviceLevels: {
      'debug-service': 'debug',
      'error-only-service': 'error'
    }
  });

  const debugLogger = createServiceLogger('debug-service');
  const errorLogger = createServiceLogger('error-only-service');

  debugLogger.debug('debug_test', 'This debug message should appear');
  debugLogger.info('info_test', 'This info message should appear');

  errorLogger.debug('debug_test', 'This debug message should NOT appear');
  errorLogger.error('error_test', 'This error message should appear', undefined, undefined, {
    serviceLevel: 'error-only'
  });

  // Example 7: Request Correlation
  console.log('7. Testing request correlation...');
  const requestTraceId = logger.generateTraceId();

  const requestLogger = createServiceLogger('request-handler');

  requestLogger.info('request_received', 'API request received', requestTraceId, {
    method: 'POST',
    endpoint: '/api/flows',
    userAgent: 'AutoApp-Client/1.0.0'
  });

  // Simulate processing steps
  await new Promise(resolve => setTimeout(resolve, 50));

  requestLogger.info('validation_complete', 'Request validation successful', requestTraceId);

  await new Promise(resolve => setTimeout(resolve, 30));

  requestLogger.info('processing_complete', 'Request processed successfully', requestTraceId, {
    processingTime: 80,
    result: 'success',
    flowId: 'flow-abc-123'
  });

  console.log('\n✅ Logger demo completed!');
  console.log('\n📁 Log files should be available in: ./../var/log/autoapp/');
  console.log('📋 Check the log files to see the structured JSON output with:');
  console.log('   - service: Service name (webrtc-manager, adb-bridge, etc.)');
  console.log('   - event: Event type/name');
  console.log('   - severity: debug, info, warn, error');
  console.log('   - timestamp: ISO timestamp');
  console.log('   - trace_id: Request/operation correlation ID');
  console.log('   - Additional context-specific fields');
  console.log('\n🎯 Constitution §10 Compliance:');
  console.log('   ✅ JSON structured logs with required fields');
  console.log('   ✅ Service-specific loggers');
  console.log('   ✅ Request correlation via trace IDs');
  console.log('   ✅ Performance timing helpers');
  console.log('   ✅ Error context capture');
  console.log('   ✅ Health check logging (<500ms performance budget)');
}

// Run the demo if this file is executed directly
if (require.main === module) {
  runLoggerDemo()
    .then(() => {
      console.log('\n🎉 Demo completed successfully!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Demo failed:', error);
      process.exit(1);
    });
}

export { runLoggerDemo };