/**
 * UI State Capture Integration Tests via UIAutomator2
 *
 * Simplified test suite for UI state capture functionality from Android emulator.
 * Tests UIAutomator2 connection, UI hierarchy extraction, screenshot capture,
 * state metadata extraction, state digest generation, and error handling scenarios.
 */

import { ADBBridgeService, ADBBridgeError, DeviceConnectionError, UIAutomatorError } from '../../src/services/adb-bridge';
import { JsonStorageService } from '../../src/services/json-storage';
import { logger } from '../../src/services/logger';
import { createHash } from 'crypto';
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';

// ============================================================================
// TEST CONFIGURATION AND SETUP
// ============================================================================

const TEST_CONFIG = {
  /** Device serial for testing */
  DEVICE_SERIAL: process.env.TEST_DEVICE_SERIAL || 'emulator-5554',

  /** Test timeout configuration */
  CONNECTION_TIMEOUT: parseInt(process.env.TEST_CONNECTION_TIMEOUT || '15000'),
  CAPTURE_TIMEOUT: parseInt(process.env.TEST_CAPTURE_TIMEOUT || '10000'),
  PERFORMANCE_TIMEOUT: parseInt(process.env.TEST_PERFORMANCE_TIMEOUT || '2000'),

  /** Test directories */
  TEST_DATA_DIR: process.env.TEST_DATA_DIR || './test-data',
  SCREENSHOT_DIR: process.env.TEST_SCREENSHOT_DIR || './test-data/screenshots',

  /** Test app configuration */
  TEST_PACKAGE: process.env.TEST_PACKAGE || 'com.maybank.maydrive',
  TEST_ACTIVITY: process.env.TEST_ACTIVITY || 'com.maybank.maydrive.ui.MainActivity',

  /** Performance thresholds */
  MAX_CAPTURE_DURATION: 2000, // 2 seconds
  MIN_HIERARCHY_SIZE: 1000,   // Minimum XML size
  MIN_SCREENSHOT_SIZE: 10000, // Minimum screenshot size

  /** Retry configuration */
  MAX_RETRIES: 3,
  RETRY_DELAY: 1000
};

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

interface StateCaptureResult {
  hierarchy: string;
  screenshot?: string;
  deviceInfo: any;
  currentActivity: string;
  timestamp: string;
  duration: number;
  elementCount: number;
  orientation: 'portrait' | 'landscape';
}

interface TestDeviceInfo {
  serial: string;
  androidVersion: string;
  sdkVersion: string;
  model: string;
  resolution: string;
  currentPackage?: string;
  currentActivity?: string;
  orientation: 'portrait' | 'landscape';
}

interface StateDigest {
  hash: string;
  timestamp: string;
  activity: string;
  elementCount: number;
  orientation: string;
  hierarchySignature: string;
}

// ============================================================================
// TEST UTILITIES
// ============================================================================

function generateStateDigest(capture: StateCaptureResult): StateDigest {
  const hierarchySignature = createHash('sha256')
    .update(capture.hierarchy.replace(/\s+/g, ' ').trim())
    .digest('hex')
    .substring(0, 16);

  const hash = createHash('sha256')
    .update(`${capture.currentActivity}-${capture.elementCount}-${hierarchySignature}`)
    .digest('hex')
    .substring(0, 16);

  return {
    hash,
    timestamp: capture.timestamp,
    activity: capture.currentActivity,
    elementCount: capture.elementCount,
    orientation: capture.orientation,
    hierarchySignature
  };
}

function validateCaptureResult(result: StateCaptureResult): boolean {
  return !!(result &&
    result.hierarchy &&
    typeof result.hierarchy === 'string' &&
    result.deviceInfo &&
    result.currentActivity &&
    result.timestamp &&
    typeof result.duration === 'number' &&
    typeof result.elementCount === 'number' &&
    result.orientation);
}

async function isMaynDriveRunning(service: ADBBridgeService): Promise<boolean> {
  try {
    const deviceInfo = await service.getDeviceInfo();
    return deviceInfo.currentPackage === TEST_CONFIG.TEST_PACKAGE ||
           deviceInfo.currentActivity?.includes('.maydrive') ||
           false;
  } catch {
    return false;
  }
}

function ensureTestDirectories(): void {
  const dirs = [TEST_CONFIG.TEST_DATA_DIR, TEST_CONFIG.SCREENSHOT_DIR];
  dirs.forEach(dir => {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  });
}

function cleanupTestArtifacts(): void {
  try {
    if (existsSync(TEST_CONFIG.TEST_DATA_DIR)) {
      const testFiles = [
        join(TEST_CONFIG.TEST_DATA_DIR, 'test-state-*.json'),
        join(TEST_CONFIG.SCREENSHOT_DIR, 'test-screenshot-*.png'),
        join(TEST_CONFIG.TEST_DATA_DIR, 'test-hierarchy-*.xml')
      ];
    }
  } catch (error) {
    logger.warn('Failed to cleanup test artifacts', { error: (error as Error).message });
  }
}

function saveTestCapture(capture: StateCaptureResult, testName: string): void {
  try {
    const filename = `test-${testName}-${Date.now()}.json`;
    const filepath = join(TEST_CONFIG.TEST_DATA_DIR, filename);
    writeFileSync(filepath, JSON.stringify(capture, null, 2));
    logger.debug('Test capture saved', { filepath });
  } catch (error) {
    logger.warn('Failed to save test capture', { error: (error as Error).message });
  }
}

async function waitForDeviceWithTimeout(service: ADBBridgeService, timeout: number): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    try {
      await service.getDeviceInfo();
      return;
    } catch (error) {
      if (Date.now() - startTime > timeout) {
        throw error;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  throw new Error(`Device connection timeout after ${timeout}ms`);
}

// ============================================================================
// SIMPLE TEST EXECUTION
// ============================================================================

class TestRunner {
  private adbService: ADBBridgeService;
  private storageService: JsonStorageService;
  private testDeviceInfo: TestDeviceInfo;

  constructor() {
    ensureTestDirectories();

    this.adbService = new ADBBridgeService({
      serial: TEST_CONFIG.DEVICE_SERIAL,
      timeout: TEST_CONFIG.CONNECTION_TIMEOUT,
      uiAutomatorTimeout: TEST_CONFIG.CAPTURE_TIMEOUT,
      uiCaptureTimeout: TEST_CONFIG.CAPTURE_TIMEOUT,
      maxConnectionRetries: TEST_CONFIG.MAX_RETRIES,
      debugUiAutomator: process.env.DEBUG_TESTS === 'true'
    });

    this.storageService = new JsonStorageService();
  }

  async setup(): Promise<void> {
    await this.adbService.initialize();
    await waitForDeviceWithTimeout(this.adbService, TEST_CONFIG.CONNECTION_TIMEOUT);
    this.testDeviceInfo = await this.adbService.getDeviceInfo();

    logger.info('Test setup completed', {
      device: this.testDeviceInfo.serial,
      androidVersion: this.testDeviceInfo.androidVersion,
      model: this.testDeviceInfo.model
    });
  }

  async cleanup(): Promise<void> {
    if (this.adbService) {
      await this.adbService.close();
    }
    cleanupTestArtifacts();
    logger.info('Test cleanup completed');
  }

  async testDeviceConnection(): Promise<boolean> {
    try {
      const startTime = Date.now();
      const deviceInfo = await this.adbService.getDeviceInfo();
      const connectionTime = Date.now() - startTime;

      if (!deviceInfo || !deviceInfo.serial || connectionTime > TEST_CONFIG.CONNECTION_TIMEOUT) {
        logger.error('Device connection test failed', {
          deviceInfo,
          connectionTime,
          expectedSerial: TEST_CONFIG.DEVICE_SERIAL
        });
        return false;
      }

      logger.info('Device connection test passed', {
        device: deviceInfo.serial,
        androidVersion: deviceInfo.androidVersion,
        model: deviceInfo.model,
        connectionTime
      });
      return true;
    } catch (error) {
      logger.error('Device connection test failed', { error: (error as Error).message });
      return false;
    }
  }

  async testUIHierarchyCapture(): Promise<boolean> {
    try {
      const startTime = Date.now();
      const hierarchy = await this.adbService.getUIHierarchy({
        includeAttributes: true,
        compress: false
      });
      const captureTime = Date.now() - startTime;

      if (!hierarchy ||
          typeof hierarchy !== 'string' ||
          hierarchy.length < TEST_CONFIG.MIN_HIERARCHY_SIZE ||
          !hierarchy.includes('<hierarchy>') ||
          !hierarchy.includes('</hierarchy>') ||
          captureTime > TEST_CONFIG.PERFORMANCE_TIMEOUT) {
        logger.error('UI hierarchy capture test failed', {
          hierarchyLength: hierarchy?.length,
          hasHierarchy: hierarchy?.includes('<hierarchy>'),
          captureTime,
          expectedMinSize: TEST_CONFIG.MIN_HIERARCHY_SIZE
        });
        return false;
      }

      logger.info('UI hierarchy capture test passed', {
        hierarchyLength: hierarchy.length,
        captureTime,
        hasClickableElements: hierarchy.includes('clickable="true"')
      });
      return true;
    } catch (error) {
      logger.error('UI hierarchy capture test failed', { error: (error as Error).message });
      return false;
    }
  }

  async testScreenshotCapture(): Promise<boolean> {
    try {
      const startTime = Date.now();
      const screenshot = await this.adbService.captureScreenshot({
        includeData: true
      });
      const captureTime = Date.now() - startTime;

      if (!screenshot ||
          typeof screenshot !== 'string' ||
          screenshot.length < TEST_CONFIG.MIN_SCREENSHOT_SIZE ||
          captureTime > TEST_CONFIG.PERFORMANCE_TIMEOUT) {
        logger.error('Screenshot capture test failed', {
          screenshotSize: screenshot?.length,
          captureTime,
          expectedMinSize: TEST_CONFIG.MIN_SCREENSHOT_SIZE
        });
        return false;
      }

      // Verify it's valid base64
      try {
        Buffer.from(screenshot, 'base64');
      } catch {
        logger.error('Screenshot is not valid base64');
        return false;
      }

      logger.info('Screenshot capture test passed', {
        screenshotSize: screenshot.length,
        captureTime,
        isValidBase64: true
      });
      return true;
    } catch (error) {
      logger.error('Screenshot capture test failed', { error: (error as Error).message });
      return false;
    }
  }

  async testStateMetadataExtraction(): Promise<boolean> {
    try {
      const deviceInfo = await this.adbService.getDeviceInfo();

      if (!deviceInfo ||
          !deviceInfo.serial ||
          !deviceInfo.androidVersion ||
          !deviceInfo.sdkVersion ||
          !deviceInfo.model ||
          !deviceInfo.resolution ||
          !['portrait', 'landscape'].includes(deviceInfo.orientation)) {
        logger.error('State metadata extraction test failed', { deviceInfo });
        return false;
      }

      logger.info('State metadata extraction test passed', {
        serial: deviceInfo.serial,
        androidVersion: deviceInfo.androidVersion,
        model: deviceInfo.model,
        resolution: deviceInfo.resolution,
        orientation: deviceInfo.orientation,
        hasPackageInfo: !!deviceInfo.currentPackage,
        hasActivityInfo: !!deviceInfo.currentActivity
      });
      return true;
    } catch (error) {
      logger.error('State metadata extraction test failed', { error: (error as Error).message });
      return false;
    }
  }

  async testCompleteStateCapture(): Promise<boolean> {
    try {
      const startTime = Date.now();
      const uiState = await this.adbService.captureUIState(
        { includeData: true }, // screenshot options
        { includeAttributes: true, compress: false } // hierarchy options
      );
      const captureTime = Date.now() - startTime;

      if (!validateCaptureResult(uiState) ||
          uiState.hierarchy.length < TEST_CONFIG.MIN_HIERARCHY_SIZE ||
          !uiState.screenshot ||
          uiState.screenshot.length < TEST_CONFIG.MIN_SCREENSHOT_SIZE ||
          captureTime > TEST_CONFIG.PERFORMANCE_TIMEOUT) {
        logger.error('Complete state capture test failed', {
          hasValidResult: validateCaptureResult(uiState),
          hierarchyLength: uiState?.hierarchy?.length,
          screenshotSize: uiState?.screenshot?.length,
          captureTime,
          expectedMinHierarchySize: TEST_CONFIG.MIN_HIERARCHY_SIZE,
          expectedMinScreenshotSize: TEST_CONFIG.MIN_SCREENSHOT_SIZE
        });
        return false;
      }

      saveTestCapture(uiState, 'complete-state');

      logger.info('Complete state capture test passed', {
        hierarchyLength: uiState.hierarchy.length,
        screenshotSize: uiState.screenshot.length,
        elementCount: uiState.elementCount,
        currentActivity: uiState.currentActivity,
        captureTime,
        orientation: uiState.orientation
      });
      return true;
    } catch (error) {
      logger.error('Complete state capture test failed', { error: (error as Error).message });
      return false;
    }
  }

  async testStateDigestGeneration(): Promise<boolean> {
    try {
      const uiState = await this.adbService.captureUIState();
      const digest = generateStateDigest(uiState);

      if (!digest ||
          !digest.hash ||
          !digest.timestamp ||
          !digest.activity ||
          typeof digest.elementCount !== 'number' ||
          !digest.hierarchySignature ||
          !/^[a-f0-9]{16}$/.test(digest.hash)) {
        logger.error('State digest generation test failed', { digest });
        return false;
      }

      logger.info('State digest generation test passed', {
        digestHash: digest.hash,
        activity: digest.activity,
        elementCount: digest.elementCount,
        orientation: digest.orientation,
        signature: digest.hierarchySignature
      });
      return true;
    } catch (error) {
      logger.error('State digest generation test failed', { error: (error as Error).message });
      return false;
    }
  }

  async testStoragePersistence(): Promise<boolean> {
    try {
      const uiState = await this.adbService.captureUIState();
      const captureId = `test-capture-${Date.now()}`;

      const saveResult = await this.storageService.create(
        `captures/${captureId}.json`,
        uiState,
        {
          createdBy: 'integration-test',
          comment: 'Test capture result'
        }
      );

      if (!saveResult || !saveResult.success || !saveResult.data) {
        logger.error('Storage save test failed', { saveResult });
        return false;
      }

      // Verify retrieval
      const retrieveResult = await this.storageService.read(`captures/${captureId}.json`);
      if (!retrieveResult || !retrieveResult.data) {
        logger.error('Storage retrieval test failed', { retrieveResult });
        return false;
      }

      // Verify data integrity
      const originalString = JSON.stringify(uiState);
      const retrievedString = JSON.stringify(retrieveResult.data);
      if (originalString !== retrievedString) {
        logger.error('Storage data integrity test failed', {
          originalLength: originalString.length,
          retrievedLength: retrievedString.length,
          areEqual: originalString === retrievedString
        });
        return false;
      }

      logger.info('Storage persistence test passed', {
        captureId,
        saveSuccess: saveResult.success,
        version: saveResult.metadata?.version,
        dataIntegrity: true
      });
      return true;
    } catch (error) {
      logger.error('Storage persistence test failed', { error: (error as Error).message });
      return false;
    }
  }

  async runAllTests(): Promise<{ passed: number; failed: number; total: number }> {
    logger.info('Starting UI State Capture Integration Tests', {
      deviceSerial: TEST_CONFIG.DEVICE_SERIAL,
      testDataDir: TEST_CONFIG.TEST_DATA_DIR,
      performanceThreshold: TEST_CONFIG.MAX_CAPTURE_DURATION
    });

    const tests = [
      { name: 'Device Connection', fn: () => this.testDeviceConnection() },
      { name: 'UI Hierarchy Capture', fn: () => this.testUIHierarchyCapture() },
      { name: 'Screenshot Capture', fn: () => this.testScreenshotCapture() },
      { name: 'State Metadata Extraction', fn: () => this.testStateMetadataExtraction() },
      { name: 'Complete State Capture', fn: () => this.testCompleteStateCapture() },
      { name: 'State Digest Generation', fn: () => this.testStateDigestGeneration() },
      { name: 'Storage Persistence', fn: () => this.testStoragePersistence() }
    ];

    let passed = 0;
    let failed = 0;

    for (const test of tests) {
      try {
        const result = await test.fn();
        if (result) {
          passed++;
          logger.info(`✅ ${test.name} test passed`);
        } else {
          failed++;
          logger.error(`❌ ${test.name} test failed`);
        }
      } catch (error) {
        failed++;
        logger.error(`❌ ${test.name} test error`, { error: (error as Error).message });
      }
    }

    const total = tests.length;
    logger.info('UI State Capture Integration Tests Completed', {
      passed,
      failed,
      total,
      successRate: Math.round((passed / total) * 100)
    });

    return { passed, failed, total };
  }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

async function runTests(): Promise<void> {
  const runner = new TestRunner();

  try {
    await runner.setup();
    const results = await runner.runAllTests();

    if (results.failed > 0) {
      process.exit(1);
    }
  } catch (error) {
    logger.error('Test execution failed', { error: (error as Error).message });
    process.exit(1);
  } finally {
    await runner.cleanup();
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests().catch(error => {
    console.error('Fatal test error:', error);
    process.exit(1);
  });
}

export { TestRunner, TEST_CONFIG, generateStateDigest, validateCaptureResult };
export type { StateCaptureResult, TestDeviceInfo, StateDigest };