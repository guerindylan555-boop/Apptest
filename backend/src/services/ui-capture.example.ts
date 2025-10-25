/**
 * UI Capture Service Usage Examples
 *
 * Practical examples demonstrating how to use the UIAutomator2-based capture service
 * for Android UI state discovery in various scenarios.
 */

import { UICaptureService, captureUIState, uiCaptureService } from './ui-capture';
import { State } from '../models/state';

// ============================================================================
// Basic Usage Examples
// ============================================================================

/**
 * Example 1: Basic UI state capture
 */
export async function basicCaptureExample(): Promise<void> {
  console.log('=== Basic UI State Capture ===');

  try {
    // Simple capture with default options
    const result = await captureUIState();

    console.log('Capture successful!');
    console.log(`State ID: ${result.state.id}`);
    console.log(`Package: ${result.state.package}`);
    console.log(`Activity: ${result.state.activity}`);
    console.log(`Selectors found: ${result.state.selectors.length}`);
    console.log(`Capture time: ${result.captureTime}ms`);
    console.log(`Screenshot: ${result.metadata.screenshotCaptured ? 'Yes' : 'No'}`);

  } catch (error) {
    console.error('Capture failed:', error);
  }
}

/**
 * Example 2: Advanced capture with custom options
 */
export async function advancedCaptureExample(): Promise<void> {
  console.log('=== Advanced UI State Capture ===');

  try {
    // Capture with custom options
    const result = await captureUIState({
      timeout: 10000, // 10 second timeout
      skipScreenshot: false, // Include screenshot
      forceScreenshot: true, // Force screenshot recreation
      tags: ['test-capture', 'user-flow'],
      minImportance: 0.5, // Only capture important elements
      includeXPath: true, // Include XPath in selectors
      traceId: 'custom-trace-id' // Custom trace ID for correlation
    });

    console.log('Advanced capture successful!');
    console.log(`State ID: ${result.state.id}`);
    console.log(`Total selectors: ${result.metadata.totalSelectors}`);
    console.log(`Interactive selectors: ${result.metadata.interactiveSelectors}`);
    console.log(`Hierarchy depth: ${result.metadata.hierarchyDepth}`);
    console.log(`XML hash: ${result.metadata.xmlHash}`);

    // Display interactive selectors
    const interactiveSelectors = result.state.getInteractiveSelectors(0.5);
    console.log(`\nInteractive Elements (${interactiveSelectors.length}):`);
    interactiveSelectors.forEach((selector, index) => {
      console.log(`${index + 1}. ${selector.cls} - ${selector.text || selector.desc || selector.rid}`);
    });

  } catch (error) {
    console.error('Advanced capture failed:', error);
  }
}

// ============================================================================
// Device Validation Examples
// ============================================================================

/**
 * Example 3: Device validation before capture
 */
export async function deviceValidationExample(): Promise<void> {
  console.log('=== Device Validation ===');

  const service = new UICaptureService();

  try {
    // Validate device readiness
    const validation = await service.validateDevice();

    if (!validation.connected) {
      console.log('❌ Device not connected');
      return;
    }

    if (!validation.responsive) {
      console.log('❌ Device not responsive');
      console.log(`Response time: ${validation.responseTime}ms`);
      console.log(`Error: ${validation.error}`);
      return;
    }

    console.log('✅ Device is ready for capture');
    console.log(`Activity: ${validation.activity}`);
    console.log(`Package: ${validation.package}`);
    console.log(`Model: ${validation.model}`);
    console.log(`Version: ${validation.version}`);
    console.log(`Response time: ${validation.responseTime}ms`);

    // Proceed with capture
    const result = await service.captureState();
    console.log(`\nCapture completed: ${result.state.id}`);

  } catch (error) {
    console.error('Device validation failed:', error);
  } finally {
    service.close();
  }
}

/**
 * Example 4: Getting device information
 */
export async function deviceInfoExample(): Promise<void> {
  console.log('=== Device Information ===');

  try {
    const deviceInfo = await uiCaptureService.getDeviceInfo();

    console.log('Device Details:');
    console.log(`Model: ${deviceInfo.model || 'Unknown'}`);
    console.log(`Android Version: ${deviceInfo.version || 'Unknown'}`);
    console.log(`Current Package: ${deviceInfo.package || 'Unknown'}`);
    console.log(`Current Activity: ${deviceInfo.activity || 'Unknown'}`);

    if (deviceInfo.properties) {
      console.log('\nAll Properties:');
      Object.entries(deviceInfo.properties).forEach(([key, value]) => {
        console.log(`  ${key}: ${value}`);
      });
    }

  } catch (error) {
    console.error('Failed to get device info:', error);
  }
}

// ============================================================================
// Performance Testing Examples
// ============================================================================

/**
 * Example 5: Performance testing
 */
export async function performanceTestExample(): Promise<void> {
  console.log('=== Performance Testing ===');

  try {
    // Test performance with 10 iterations
    const metrics = await uiCaptureService.testPerformance(10, {
      skipScreenshot: true, // Skip screenshots for faster testing
      minImportance: 0.3
    });

    console.log('Performance Test Results:');
    console.log(`Total captures: ${metrics.totalCaptures}`);
    console.log(`Successful captures: ${metrics.successfulCaptures}`);
    console.log(`Success rate: ${(metrics.successRate * 100).toFixed(1)}%`);
    console.log(`Average time: ${metrics.averageTime.toFixed(1)}ms`);
    console.log(`Min time: ${metrics.minTime}ms`);
    console.log(`Max time: ${metrics.maxTime}ms`);

    if (metrics.lastCapture) {
      console.log(`Last capture: ${new Date(metrics.lastCapture).toISOString()}`);
    }

    // Performance evaluation
    if (metrics.averageTime < 1000) {
      console.log('✅ Excellent performance (< 1s average)');
    } else if (metrics.averageTime < 2000) {
      console.log('⚠️  Good performance (< 2s average)');
    } else {
      console.log('❌ Poor performance (> 2s average)');
    }

  } catch (error) {
    console.error('Performance test failed:', error);
  }
}

/**
 * Example 6: Monitoring performance over time
 */
export async function performanceMonitoringExample(): Promise<void> {
  console.log('=== Performance Monitoring ===');

  // Simulate multiple captures over time
  for (let i = 0; i < 5; i++) {
    try {
      console.log(`\nCapture ${i + 1}/5:`);
      const result = await captureUIState({
        skipScreenshot: i % 2 === 0, // Alternate screenshot capture
        traceId: `monitoring-${i + 1}`
      });

      console.log(`  Time: ${result.captureTime}ms`);
      console.log(`  Selectors: ${result.metadata.totalSelectors}`);

      // Get current metrics
      const metrics = uiCaptureService.getPerformanceMetrics();
      console.log(`  Average so far: ${metrics.averageTime.toFixed(1)}ms`);

      // Small delay between captures
      await new Promise(resolve => setTimeout(resolve, 1000));

    } catch (error) {
      console.error(`  Capture ${i + 1} failed:`, error);
    }
  }

  // Final metrics
  const finalMetrics = uiCaptureService.getPerformanceMetrics();
  console.log('\nFinal Performance Metrics:');
  console.log(`  Total captures: ${finalMetrics.totalCaptures}`);
  console.log(`  Success rate: ${(finalMetrics.successRate * 100).toFixed(1)}%`);
  console.log(`  Average time: ${finalMetrics.averageTime.toFixed(1)}ms`);
}

// ============================================================================
// Error Handling Examples
// ============================================================================

/**
 * Example 7: Comprehensive error handling
 */
export async function errorHandlingExample(): Promise<void> {
  console.log('=== Error Handling Examples ===');

  const service = new UICaptureService();

  try {
    // Test with very short timeout to force timeout error
    console.log('Testing timeout handling...');
    const result = await service.captureState({
      timeout: 1, // 1ms timeout (will likely fail)
      traceId: 'timeout-test'
    });

  } catch (error) {
    if (error instanceof Error) {
      console.log(`✅ Caught timeout error: ${error.message}`);
    }
  }

  try {
    // Test with invalid device scenario
    console.log('\nTesting device validation...');
    const validation = await service.validateDevice('validation-test');

    if (!validation.connected) {
      console.log('⚠️  Device not connected - handle this scenario');
    }

    if (!validation.responsive) {
      console.log('⚠️  Device not responsive - may need to wait or retry');
    }

  } catch (error) {
    console.log('✅ Caught validation error:', error);
  }

  try {
    // Test health check
    console.log('\nTesting health check...');
    const health = await service.healthCheck();

    if (health.healthy) {
      console.log('✅ Service is healthy');
    } else {
      console.log('❌ Service health issues detected:');
      console.log(JSON.stringify(health.details, null, 2));
    }

  } catch (error) {
    console.log('✅ Caught health check error:', error);
  }

  service.close();
}

// ============================================================================
// Advanced Usage Examples
// ============================================================================

/**
 * Example 8: State analysis and filtering
 */
export async function stateAnalysisExample(): Promise<void> {
  console.log('=== State Analysis ===');

  try {
    const result = await captureUIState({
      tags: ['analysis-example'],
      traceId: 'state-analysis'
    });

    const state = result.state;

    console.log(`State Analysis for: ${state.id}`);
    console.log(`Package: ${state.package}`);
    console.log(`Activity: ${state.activity}`);

    // Get all interactive elements
    const interactiveElements = state.getInteractiveSelectors();
    console.log(`\nInteractive Elements (${interactiveElements.length}):`);

    interactiveElements.forEach((selector, index) => {
      const importance = state.getSelectorImportance(selector);
      console.log(`${index + 1}. ${selector.cls}`);
      console.log(`   Text: ${selector.text || 'N/A'}`);
      console.log(`   Resource ID: ${selector.rid || 'N/A'}`);
      console.log(`   Importance: ${(importance * 100).toFixed(1)}%`);
    });

    // Filter selectors by criteria
    const buttonElements = state.getSelectorsByCriteria({
      cls: /Button/i,
      interactive: true,
      minImportance: 0.5
    });

    console.log(`\nButton Elements (${buttonElements.length}):`);
    buttonElements.forEach((button, index) => {
      console.log(`${index + 1}. ${button.text || button.desc || button.rid}`);
    });

    // Check for specific text
    const searchText = 'Login';
    const hasLoginText = state.containsText(searchText);
    console.log(`\nContains "${searchText}": ${hasLoginText ? 'Yes' : 'No'}`);

    // Get state summary
    const summary = state.getSummary();
    console.log('\nState Summary:');
    console.log(`  Simple activity: ${summary.simpleActivity}`);
    console.log(`  Selector count: ${summary.selectorCount}`);
    console.log(`  Interactive count: ${summary.interactiveCount}`);
    console.log(`  Has screenshot: ${summary.hasScreenshot}`);

  } catch (error) {
    console.error('State analysis failed:', error);
  }
}

/**
 * Example 9: Batch capture with different configurations
 */
export async function batchCaptureExample(): Promise<void> {
  console.log('=== Batch Capture with Different Configurations ===');

  const configurations = [
    { name: 'Full Capture', options: {} },
    { name: 'Fast Capture', options: { skipScreenshot: true, minImportance: 0.7 } },
    { name: 'High Detail', options: { forceScreenshot: true, minImportance: 0.1 } },
    { name: 'Interactive Only', options: { minImportance: 0.8, includeXPath: false } }
  ];

  const results: any[] = [];

  for (const config of configurations) {
    try {
      console.log(`\n${config.name}:`);
      console.time(config.name);

      const result = await captureUIState({
        ...config.options,
        tags: [config.name.toLowerCase().replace(' ', '-')],
        traceId: `batch-${config.name.toLowerCase().replace(' ', '-')}`
      });

      console.timeEnd(config.name);

      const summary = {
        name: config.name,
        stateId: result.state.id,
        captureTime: result.captureTime,
        totalSelectors: result.metadata.totalSelectors,
        interactiveSelectors: result.metadata.interactiveSelectors,
        hierarchyDepth: result.metadata.hierarchyDepth,
        hasScreenshot: result.metadata.screenshotCaptured
      };

      results.push(summary);
      console.log(`  ✓ ${summary.captureTime}ms, ${summary.totalSelectors} selectors`);

    } catch (error) {
      console.log(`  ✗ Failed: ${error}`);
    }
  }

  // Compare results
  console.log('\n=== Batch Capture Comparison ===');
  results.forEach(result => {
    const efficiency = (result.interactiveSelectors / result.totalSelectors * 100).toFixed(1);
    console.log(`${result.name}:`);
    console.log(`  Time: ${result.captureTime}ms`);
    console.log(`  Selectors: ${result.totalSelectors} (${result.interactiveSelectors} interactive)`);
    console.log(`  Efficiency: ${efficiency}%`);
    console.log(`  Screenshot: ${result.hasScreenshot ? 'Yes' : 'No'}`);
  });
}

// ============================================================================
// Usage Examples Export
// ============================================================================

/**
 * Run all examples (for demonstration)
 */
export async function runAllExamples(): Promise<void> {
  console.log('🚀 UI Capture Service - Usage Examples\n');

  const examples = [
    { name: 'Basic Capture', fn: basicCaptureExample },
    { name: 'Advanced Capture', fn: advancedCaptureExample },
    { name: 'Device Validation', fn: deviceValidationExample },
    { name: 'Device Info', fn: deviceInfoExample },
    { name: 'Performance Test', fn: performanceTestExample },
    { name: 'Performance Monitoring', fn: performanceMonitoringExample },
    { name: 'Error Handling', fn: errorHandlingExample },
    { name: 'State Analysis', fn: stateAnalysisExample },
    { name: 'Batch Capture', fn: batchCaptureExample }
  ];

  for (const example of examples) {
    console.log(`\n${'='.repeat(50)}`);
    console.log(`Running: ${example.name}`);
    console.log('='.repeat(50));

    try {
      await example.fn();
      console.log(`✅ ${example.name} completed`);
    } catch (error) {
      console.error(`❌ ${example.name} failed:`, error);
    }

    // Small delay between examples
    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  console.log('\n🎉 All examples completed!');
}

// Export individual examples for selective execution
export {
  basicCaptureExample,
  advancedCaptureExample,
  deviceValidationExample,
  deviceInfoExample,
  performanceTestExample,
  performanceMonitoringExample,
  errorHandlingExample,
  stateAnalysisExample,
  batchCaptureExample
};