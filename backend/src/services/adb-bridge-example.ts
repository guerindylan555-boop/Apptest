/**
 * ADB Bridge Service Usage Example
 *
 * This file demonstrates how to use the ADB Bridge Service for UIAutomator2
 * communication in the AutoApp UI Map & Flow Engine.
 */

import {
  ADBBridgeService,
  initializeADBBridge,
  closeADBBridge,
  UIStateCapture,
  DeviceInfo
} from './adb-bridge';
import { logger } from './logger';

/**
 * Example: Initialize and use ADB Bridge Service for UI capture
 */
async function exampleUICapture() {
  logger.info('Starting ADB Bridge UI capture example');

  try {
    // Initialize the ADB Bridge Service with custom configuration
    const adbBridge = await initializeADBBridge({
      serial: process.env.ANDROID_SERIAL || 'emulator-5554',
      uiAutomatorTimeout: 15000,
      uiCaptureTimeout: 30000,
      debugUiAutomator: true
    });

    logger.info('ADB Bridge Service initialized successfully');

    // Get device information
    const deviceInfo: DeviceInfo = await adbBridge.getDeviceInfo();
    logger.info('Device information retrieved', {
      androidVersion: deviceInfo.androidVersion,
      model: deviceInfo.model,
      resolution: deviceInfo.resolution,
      currentActivity: deviceInfo.currentActivity
    });

    // Capture complete UI state (hierarchy + screenshot)
    const uiState: UIStateCapture = await adbBridge.captureUIState(
      { includeData: true }, // Screenshot options
      {
        compress: true,
        maxDepth: 10,
        includeAttributes: true
      } // Hierarchy options
    );

    logger.info('UI state captured successfully', {
      elementCount: uiState.elementCount,
      hierarchyLength: uiState.hierarchy.length,
      hasScreenshot: !!uiState.screenshot,
      captureDuration: uiState.duration,
      orientation: uiState.orientation
    });

    // Check connection health
    const health = await adbBridge.getConnectionHealth();
    logger.info('Connection health status', {
      isConnected: health.isConnected,
      isUiAutomatorReady: health.isUiAutomatorReady,
      totalCommands: health.totalCommands,
      averageResponseTime: health.averageResponseTime,
      uptime: health.uptime
    });

    // Example: Perform device interactions
    logger.info('Performing device interactions example');

    // Tap at coordinates (if you have specific coordinates)
    // await adbBridge.performTap(500, 800);

    // Type text (if a text field is focused)
    // await adbBridge.performType('Hello World');

    // Perform swipe gesture
    // await adbBridge.performSwipe(100, 500, 100, 200, 300);

    // Press back button
    // await adbBridge.performBack();

    // Close the service when done
    await closeADBBridge();
    logger.info('ADB Bridge Service closed successfully');

  } catch (error) {
    logger.error('ADB Bridge example failed', {
      error: (error as Error).message,
      stack: (error as Error).stack
    });

    // Ensure cleanup even on error
    await closeADBBridge();
  }
}

/**
 * Example: Health monitoring and recovery
 */
async function exampleHealthMonitoring() {
  logger.info('Starting ADB Bridge health monitoring example');

  const adbBridge = new ADBBridgeService({
    serial: process.env.ANDROID_SERIAL || 'emulator-5554',
    healthCheckInterval: 10000, // Check every 10 seconds
    maxConnectionRetries: 5,
    retryBackoffMultiplier: 1.5
  });

  try {
    await adbBridge.initialize();

    // Set up periodic health checks
    const healthCheckInterval = setInterval(async () => {
      const health = await adbBridge.getConnectionHealth();

      logger.info('Health check result', {
        isConnected: health.isConnected,
        isUiAutomatorReady: health.isUiAutomatorReady,
        failureRate: health.totalCommands > 0
          ? (health.failedCommands / health.totalCommands * 100).toFixed(2) + '%'
          : '0%',
        averageResponseTime: health.averageResponseTime + 'ms'
      });

      // If connection is unhealthy, you might want to take action
      if (!health.isConnected || !health.isUiAutomatorReady) {
        logger.warn('Connection health degraded, consider reinitializing');
      }
    }, 30000); // Every 30 seconds

    // Run for 2 minutes then cleanup
    setTimeout(async () => {
      clearInterval(healthCheckInterval);
      await adbBridge.close();
      logger.info('Health monitoring example completed');
    }, 120000);

  } catch (error) {
    logger.error('Health monitoring example failed', {
      error: (error as Error).message
    });
  }
}

/**
 * Example: Error handling and retry logic
 */
async function exampleErrorHandling() {
  logger.info('Starting ADB Bridge error handling example');

  const adbBridge = new ADBBridgeService({
    serial: 'invalid-device-123', // Intentionally invalid to demonstrate error handling
    timeout: 5000,
    maxConnectionRetries: 3,
    maxRetries: 2
  });

  try {
    await adbBridge.initialize();

    // This might fail if device connection has issues
    const uiState = await adbBridge.captureUIState();
    logger.info('UI state captured despite connection challenges');

  } catch (error) {
    logger.error('Expected error occurred in error handling example', {
      error: (error as Error).message,
      errorCode: (error as any).code
    });

    // Implement your error recovery logic here
    // For example:
    // - Try different device serial
    // - Restart emulator
    // - Fall back to alternative capture method
  } finally {
    await adbBridge.close();
  }
}

/**
 * Example: Integration with existing graph service
 */
async function exampleGraphIntegration() {
  logger.info('Starting ADB Bridge graph integration example');

  try {
    const adbBridge = await initializeADBBridge();

    // This would integrate with your existing graph service
    const uiState = await adbBridge.captureUIState();

    // Process the UI state for graph generation
    const graphData = {
      timestamp: uiState.timestamp,
      deviceInfo: uiState.deviceInfo,
      currentActivity: uiState.currentActivity,
      hierarchy: uiState.hierarchy,
      screenshot: uiState.screenshot,
      elementCount: uiState.elementCount,
      orientation: uiState.orientation
    };

    // Here you would pass this data to your graph service
    // For example: await graphService.processUIState(graphData);

    logger.info('Graph integration data prepared', {
      activity: graphData.currentActivity,
      elementCount: graphData.elementCount,
      hasHierarchy: !!graphData.hierarchy,
      hasScreenshot: !!graphData.screenshot
    });

    await closeADBBridge();

  } catch (error) {
    logger.error('Graph integration example failed', {
      error: (error as Error).message
    });
  }
}

// Export examples for use in other modules
export {
  exampleUICapture,
  exampleHealthMonitoring,
  exampleErrorHandling,
  exampleGraphIntegration
};

// Run examples if this file is executed directly
if (require.main === module) {
  logger.info('Running ADB Bridge Service examples');

  // Run the UI capture example
  exampleUICapture()
    .then(() => {
      logger.info('UI capture example completed');
      process.exit(0);
    })
    .catch((error) => {
      logger.error('UI capture example failed', { error: error.message });
      process.exit(1);
    });
}