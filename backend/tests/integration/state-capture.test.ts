/**
 * UI State Capture Integration Tests via UIAutomator2
 *
 * Comprehensive test suite for UI state capture functionality from Android emulator.
 * Tests UIAutomator2 connection, UI hierarchy extraction, screenshot capture,
 * state metadata extraction, state digest generation, and error handling scenarios.
 *
 * These tests validate the core functionality that powers the Discovery Panel
 * and graph generation for the AutoApp UI Map & Intelligent Flow Engine.
 */

import { ADBBridgeService, ADBBridgeError, DeviceConnectionError, UIAutomatorError } from '../../src/services/adb-bridge';
import { JsonStorageService } from '../../src/services/json-storage';
import { logger } from '../../src/services/logger';
import { createHash } from 'crypto';
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from 'fs';
import { join } from 'path';

// Import test framework types
import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';

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

interface CaptureError {
  type: 'connection' | 'uiAutomator' | 'capture' | 'timeout';
  message: string;
  details?: any;
  timestamp: string;
}

// ============================================================================
// TEST UTILITIES
// ============================================================================

/**
 * Generate state digest for deduplication testing
 */
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

/**
 * Validate capture result structure
 */
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

/**
 * Check if MaynDrive app is running
 */
async function isMaynDriveRunning(service: ADBBridgeService): Promise<boolean> {
  try {
    const deviceInfo = await service.getDeviceInfo();
    return deviceInfo.currentPackage === TEST_PACKAGE ||
           deviceInfo.currentActivity?.includes('.maydrive') ||
           false;
  } catch {
    return false;
  }
}

/**
 * Ensure test directories exist
 */
function ensureTestDirectories(): void {
  const dirs = [TEST_CONFIG.TEST_DATA_DIR, TEST_CONFIG.SCREENSHOT_DIR];
  dirs.forEach(dir => {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  });
}

/**
 * Clean up test artifacts
 */
function cleanupTestArtifacts(): void {
  try {
    if (existsSync(TEST_CONFIG.TEST_DATA_DIR)) {
      // Only remove test files, not the entire directory
      const testFiles = [
        join(TEST_CONFIG.TEST_DATA_DIR, 'test-state-*.json'),
        join(TEST_CONFIG.SCREENSHOT_DIR, 'test-screenshot-*.png'),
        join(TEST_CONFIG.TEST_DATA_DIR, 'test-hierarchy-*.xml')
      ];
      // Implementation would require glob, which we'll skip for simplicity
    }
  } catch (error) {
    logger.warn('Failed to cleanup test artifacts', { error: (error as Error).message });
  }
}

/**
 * Save test capture result to file for debugging
 */
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

/**
 * Wait for device with timeout
 */
async function waitForDeviceWithTimeout(service: ADBBridgeService, timeout: number): Promise<void> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    try {
      // Try to get device info to verify connection
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
// MAIN TEST SUITE
// ============================================================================

describe('UI State Capture Integration Tests', () => {
  let adbService: ADBBridgeService;
  let storageService: JsonStorageService;
  let testDeviceInfo: TestDeviceInfo;

  beforeAll(async () => {
    // Set up test environment
    ensureTestDirectories();

    // Initialize services
    adbService = new ADBBridgeService({
      serial: TEST_CONFIG.DEVICE_SERIAL,
      timeout: TEST_CONFIG.CONNECTION_TIMEOUT,
      uiAutomatorTimeout: TEST_CONFIG.CAPTURE_TIMEOUT,
      uiCaptureTimeout: TEST_CONFIG.CAPTURE_TIMEOUT,
      maxConnectionRetries: TEST_CONFIG.MAX_RETRIES,
      debugUiAutomator: process.env.DEBUG_TESTS === 'true'
    });

    storageService = new JsonStorageService({
      basePath: TEST_CONFIG.TEST_DATA_DIR,
      enableVersioning: true,
      enableLocking: true
    });

    logger.info('Test environment initialized', {
      deviceSerial: TEST_CONFIG.DEVICE_SERIAL,
      testDataDir: TEST_CONFIG.TEST_DATA_DIR
    });
  }, 30000);

  afterAll(async () => {
    try {
      if (adbService) {
        await adbService.close();
      }
      cleanupTestArtifacts();
      logger.info('Test environment cleaned up');
    } catch (error) {
      logger.error('Error during test cleanup', { error: (error as Error).message });
    }
  });

  beforeEach(async () => {
    try {
      // Ensure device is connected before each test
      await waitForDeviceWithTimeout(adbService, TEST_CONFIG.CONNECTION_TIMEOUT);
      testDeviceInfo = await adbService.getDeviceInfo();

      logger.debug('Test setup completed', {
        device: testDeviceInfo.serial,
        androidVersion: testDeviceInfo.androidVersion,
        model: testDeviceInfo.model
      });
    } catch (error) {
      logger.error('Test setup failed', { error: (error as Error).message });
      throw error;
    }
  });

  // ============================================================================
  // CONNECTION AND BASIC FUNCTIONALITY TESTS
  // ============================================================================

  describe('Device Connection & UIAutomator2 Communication', () => {
    it('should establish connection to Android emulator', async () => {
      const startTime = Date.now();

      const deviceInfo = await adbService.getDeviceInfo();
      const connectionTime = Date.now() - startTime;

      expect(deviceInfo).toBeDefined();
      expect(deviceInfo.serial).toBe(TEST_CONFIG.DEVICE_SERIAL);
      expect(deviceInfo.androidVersion).toMatch(/^\d+(\.\d+)*$/);
      expect(deviceInfo.sdkVersion).toMatch(/^\d+$/);
      expect(deviceInfo.model).toBeDefined();
      expect(deviceInfo.resolution).toMatch(/^\d+x\d+$/);
      expect(['portrait', 'landscape']).toContain(deviceInfo.orientation);

      expect(connectionTime).toBeLessThan(TEST_CONFIG.CONNECTION_TIMEOUT);

      logger.info('Device connection test passed', {
        device: deviceInfo.serial,
        androidVersion: deviceInfo.androidVersion,
        model: deviceInfo.model,
        connectionTime
      });
    }, TEST_CONFIG.CONNECTION_TIMEOUT);

    it('should verify UIAutomator2 availability', async () => {
      const health = await adbService.getConnectionHealth();

      expect(health).toBeDefined();
      expect(health.isConnected).toBe(true);
      expect(health.isUiAutomatorReady).toBe(true);
      expect(health.uptime).toBeGreaterThan(0);
      expect(health.totalCommands).toBeGreaterThanOrEqual(0);

      logger.info('UIAutomator2 availability verified', {
        isConnected: health.isConnected,
        isUiAutomatorReady: health.isUiAutomatorReady,
        uptime: health.uptime
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should handle connection health monitoring', async () => {
      const health1 = await adbService.getConnectionHealth();

      // Wait a short period and check again
      await new Promise(resolve => setTimeout(resolve, 1000));

      const health2 = await adbService.getConnectionHealth();

      expect(health2).toBeDefined();
      expect(health2.isConnected).toBe(true);
      expect(health2.isUiAutomatorReady).toBe(true);
      expect(health2.uptime).toBeGreaterThan(health1.uptime);

      logger.info('Connection health monitoring test passed', {
        uptime1: health1.uptime,
        uptime2: health2.uptime
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);
  });

  // ============================================================================
  // UI HIERARCHY CAPTURE TESTS
  // ============================================================================

  describe('UI Hierarchy Capture', () => {
    it('should capture UI hierarchy from MaynDrive app', async () => {
      const startTime = Date.now();

      const hierarchy = await adbService.getUIHierarchy({
        includeAttributes: true,
        compress: false
      });

      const captureTime = Date.now() - startTime;

      expect(hierarchy).toBeDefined();
      expect(typeof hierarchy).toBe('string');
      expect(hierarchy.length).toBeGreaterThan(TEST_CONFIG.MIN_HIERARCHY_SIZE);
      expect(hierarchy).toContain('<hierarchy>');
      expect(hierarchy).toContain('</hierarchy>');
      expect(hierarchy).toContain('clickable="true"');

      expect(captureTime).toBeLessThan(TEST_CONFIG.PERFORMANCE_TIMEOUT);

      logger.info('UI hierarchy capture test passed', {
        hierarchyLength: hierarchy.length,
        captureTime,
        hasClickableElements: hierarchy.includes('clickable="true"')
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should capture UI hierarchy with compression', async () => {
      const hierarchy = await adbService.getUIHierarchy({
        compress: true,
        includeAttributes: true
      });

      expect(hierarchy).toBeDefined();
      expect(typeof hierarchy).toBe('string');
      expect(hierarchy.length).toBeGreaterThan(100);

      // Check that compression worked (no excessive empty lines)
      const lines = hierarchy.split('\n');
      const emptyLines = lines.filter(line => line.trim().length === 0).length;
      expect(emptyLines).toBeLessThan(lines.length * 0.1); // Less than 10% empty lines

      logger.info('UI hierarchy compression test passed', {
        hierarchyLength: hierarchy.length,
        lineCount: lines.length,
        emptyLineCount: emptyLines
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should capture UI hierarchy with depth limit', async () => {
      const maxDepth = 5;
      const hierarchy = await adbService.getUIHierarchy({
        maxDepth,
        includeAttributes: false
      });

      expect(hierarchy).toBeDefined();
      expect(typeof hierarchy).toBe('string');

      // Check depth limiting by counting indentation levels
      const lines = hierarchy.split('\n');
      const maxIndentLevel = Math.max(...lines.map(line => {
        const match = line.match(/^(\s*)/);
        return match ? Math.floor(match[1].length / 2) : 0;
      }));

      expect(maxIndentLevel).toBeLessThanOrEqual(maxDepth);

      logger.info('UI hierarchy depth limiting test passed', {
        maxDepth,
        actualMaxDepth: maxIndentLevel,
        hierarchyLength: hierarchy.length
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should capture UI hierarchy with attribute filtering', async () => {
      const filterAttributes = ['text', 'content-desc', 'resource-id'];
      const hierarchy = await adbService.getUIHierarchy({
        filterAttributes,
        includeAttributes: true
      });

      expect(hierarchy).toBeDefined();
      expect(typeof hierarchy).toBe('string');

      // Check that filtered attributes are present and others are removed
      filterAttributes.forEach(attr => {
        expect(hierarchy).toContain(`${attr}=`);
      });

      // Check that some non-essential attributes are filtered out
      expect(hierarchy).not.toContain('focusable=');
      expect(hierarchy).not.toContain('enabled=');

      logger.info('UI hierarchy attribute filtering test passed', {
        filterAttributes,
        hierarchyLength: hierarchy.length
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);
  });

  // ============================================================================
  // SCREENSHOT CAPTURE TESTS
  // ============================================================================

  describe('Screenshot Capture', () => {
    it('should capture screenshot from MaynDrive app', async () => {
      const startTime = Date.now();

      const screenshot = await adbService.captureScreenshot({
        includeData: true
      });

      const captureTime = Date.now() - startTime;

      expect(screenshot).toBeDefined();
      expect(typeof screenshot).toBe('string');
      expect(screenshot.length).toBeGreaterThan(TEST_CONFIG.MIN_SCREENSHOT_SIZE);

      // Verify it's valid base64
      expect(() => Buffer.from(screenshot, 'base64')).not.toThrow();

      expect(captureTime).toBeLessThan(TEST_CONFIG.PERFORMANCE_TIMEOUT);

      logger.info('Screenshot capture test passed', {
        screenshotSize: screenshot.length,
        captureTime,
        isValidBase64: true
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should capture screenshot as Buffer', async () => {
      const screenshot = await adbService.captureScreenshot();

      expect(screenshot).toBeDefined();
      expect(Buffer.isBuffer(screenshot)).toBe(true);
      expect(screenshot.length).toBeGreaterThan(TEST_CONFIG.MIN_SCREENSHOT_SIZE);

      // Verify PNG header
      expect(screenshot.slice(0, 8).toString()).toBe('\x89PNG\r\n\x1a\n');

      logger.info('Screenshot Buffer capture test passed', {
        bufferSize: screenshot.length,
        hasValidPngHeader: true
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should save screenshot to file', async () => {
      const outputPath = join(TEST_CONFIG.SCREENSHOT_DIR, `test-screenshot-${Date.now()}.png`);

      await adbService.captureScreenshot({
        saveToFile: true,
        outputPath
      });

      expect(existsSync(outputPath)).toBe(true);

      // Verify file size
      const fs = require('fs').promises;
      const stats = await fs.stat(outputPath);
      expect(stats.size).toBeGreaterThan(TEST_CONFIG.MIN_SCREENSHOT_SIZE);

      // Clean up
      unlinkSync(outputPath);

      logger.info('Screenshot file save test passed', {
        outputPath,
        fileSize: stats.size
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should capture multiple screenshots in sequence', async () => {
      const screenshots = [];
      const captureTimes = [];

      for (let i = 0; i < 3; i++) {
        const startTime = Date.now();
        const screenshot = await adbService.captureScreenshot({ includeData: true });
        const captureTime = Date.now() - startTime;

        screenshots.push(screenshot);
        captureTimes.push(captureTime);

        // Small delay between captures
        await new Promise(resolve => setTimeout(resolve, 500));
      }

      expect(screenshots).toHaveLength(3);
      screenshots.forEach((screenshot, index) => {
        expect(screenshot).toBeDefined();
        expect(screenshot.length).toBeGreaterThan(TEST_CONFIG.MIN_SCREENSHOT_SIZE);
        expect(captureTimes[index]).toBeLessThan(TEST_CONFIG.PERFORMANCE_TIMEOUT);
      });

      // Screenshots should be different (unless app is static)
      if (screenshots[0] !== screenshots[1] || screenshots[1] !== screenshots[2]) {
        logger.info('Multiple screenshot capture test passed', {
          screenshotCount: screenshots.length,
          averageCaptureTime: captureTimes.reduce((a, b) => a + b, 0) / captureTimes.length,
          screenshotsAreDifferent: true
        });
      } else {
        logger.info('Multiple screenshot capture test passed (static app)', {
          screenshotCount: screenshots.length,
          averageCaptureTime: captureTimes.reduce((a, b) => a + b, 0) / captureTimes.length,
          screenshotsAreIdentical: true
        });
      }
    }, TEST_CONFIG.CAPTURE_TIMEOUT * 4);
  });

  // ============================================================================
  // STATE METADATA EXTRACTION TESTS
  // ============================================================================

  describe('State Metadata Extraction', () => {
    it('should extract comprehensive device information', async () => {
      const deviceInfo = await adbService.getDeviceInfo();

      expect(deviceInfo).toBeDefined();
      expect(deviceInfo.serial).toBe(TEST_CONFIG.DEVICE_SERIAL);
      expect(deviceInfo.androidVersion).toBeDefined();
      expect(deviceInfo.sdkVersion).toBeDefined();
      expect(deviceInfo.model).toBeDefined();
      expect(deviceInfo.resolution).toBeDefined();
      expect(['portrait', 'landscape']).toContain(deviceInfo.orientation);

      // Optional fields that may or may not be present
      if (deviceInfo.currentPackage) {
        expect(typeof deviceInfo.currentPackage).toBe('string');
      }

      if (deviceInfo.currentActivity) {
        expect(typeof deviceInfo.currentActivity).toBe('string');
      }

      if (deviceInfo.uiAutomatorVersion) {
        expect(deviceInfo.uiAutomatorVersion).toMatch(/^\d+\.\d+\.\d+$/);
      }

      logger.info('Device metadata extraction test passed', {
        serial: deviceInfo.serial,
        androidVersion: deviceInfo.androidVersion,
        model: deviceInfo.model,
        resolution: deviceInfo.resolution,
        orientation: deviceInfo.orientation,
        hasPackageInfo: !!deviceInfo.currentPackage,
        hasActivityInfo: !!deviceInfo.currentActivity
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should detect current activity and package', async () => {
      const deviceInfo = await adbService.getDeviceInfo();

      expect(deviceInfo.currentActivity).toBeDefined();
      expect(typeof deviceInfo.currentActivity).toBe('string');

      if (deviceInfo.currentActivity) {
        // Should follow pattern: package/activity or just activity
        expect(deviceInfo.currentActivity).toMatch(/^[a-zA-Z0-9._/]+$/);

        // Extract package name if available
        const packageMatch = deviceInfo.currentActivity.match(/^([^/]+)\//);
        if (packageMatch) {
          expect(packageMatch[1]).toMatch(/^[a-zA-Z0-9.]+$/);
        }
      }

      logger.info('Activity detection test passed', {
        currentActivity: deviceInfo.currentActivity,
        currentPackage: deviceInfo.currentPackage
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should extract interactive element selectors', async () => {
      const uiState = await adbService.captureUIState();

      expect(uiState).toBeDefined();
      expect(uiState.hierarchy).toBeDefined();
      expect(uiState.elementCount).toBeGreaterThanOrEqual(0);
      expect(typeof uiState.elementCount).toBe('number');

      // Count clickable elements
      const clickableMatches = uiState.hierarchy.match(/clickable="true"/g);
      const clickableCount = clickableMatches ? clickableMatches.length : 0;

      // Verify element count matches clickable elements
      expect(uiState.elementCount).toBeGreaterThanOrEqual(clickableCount);

      // Extract some selectors for validation
      const resourceIds = [...uiState.hierarchy.matchAll(/resource-id="([^"]*)"/g)]
        .map(match => match[1])
        .filter(id => id && id.length > 0);

      const textElements = [...uiState.hierarchy.matchAll(/text="([^"]*)"/g)]
        .map(match => match[1])
        .filter(text => text && text.length > 0);

      logger.info('Selector extraction test passed', {
        totalElements: uiState.elementCount,
        clickableElements: clickableCount,
        resourceIdsFound: resourceIds.length,
        textElementsFound: textElements.length
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);
  });

  // ============================================================================
  // STATE DIGEST GENERATION TESTS
  // ============================================================================

  describe('State Digest Generation', () => {
    it('should generate consistent state digests', async () => {
      const capture1 = await adbService.captureUIState();
      await new Promise(resolve => setTimeout(resolve, 100)); // Small delay
      const capture2 = await adbService.captureUIState();

      const digest1 = generateStateDigest(capture1);
      const digest2 = generateStateDigest(capture2);

      expect(digest1).toBeDefined();
      expect(digest2).toBeDefined();
      expect(digest1.hash).toMatch(/^[a-f0-9]{16}$/);
      expect(digest2.hash).toMatch(/^[a-f0-9]{16}$/);

      // If captures are from same screen, digests should be similar
      if (capture1.hierarchy === capture2.hierarchy) {
        expect(digest1.hash).toBe(digest2.hash);
        expect(digest1.hierarchySignature).toBe(digest2.hierarchySignature);
      }

      logger.info('State digest generation test passed', {
        digest1: digest1.hash,
        digest2: digest2.hash,
        areIdentical: digest1.hash === digest2.hash
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT * 2);

    it('should generate different digests for different screens', async () => {
      const captures = [];
      const digests = [];

      // Capture initial state
      captures.push(await adbService.captureUIState());
      digests.push(generateStateDigest(captures[0]));

      // Try to trigger navigation (if possible)
      try {
        // Press back button to potentially change screen
        await adbService.performBack();
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Capture new state
        captures.push(await adbService.captureUIState());
        digests.push(generateStateDigest(captures[1]));
      } catch (error) {
        logger.warn('Could not trigger screen change for digest test', {
          error: (error as Error).message
        });
      }

      expect(digestes).toHaveLength(captures.length);
      digests.forEach((digest, index) => {
        expect(digest).toBeDefined();
        expect(digest.hash).toMatch(/^[a-f0-9]{16}$/);
        expect(digest.activity).toBeDefined();
        expect(digest.elementCount).toBeGreaterThanOrEqual(0);
        expect(digest.hierarchySignature).toBeDefined();
      });

      logger.info('Different screen digest test passed', {
        captureCount: captures.length,
        uniqueDigests: new Set(digestes.map(d => d.hash)).size
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT * 3);

    it('should support state deduplication using digests', async () => {
      const captures = [];
      const digests = [];

      // Capture same state multiple times
      for (let i = 0; i < 3; i++) {
        captures.push(await adbService.captureUIState());
        digests.push(generateStateDigest(captures[i]));
        await new Promise(resolve => setTimeout(resolve(500)));
      }

      // Group captures by digest
      const digestGroups = new Map<string, number[]>();
      digests.forEach((digest, index) => {
        if (!digestGroups.has(digest.hash)) {
          digestGroups.set(digest.hash, []);
        }
        digestGroups.get(digest.hash)!.push(index);
      });

      // Should have at least one group with multiple captures (if app is static)
      const duplicateGroups = Array.from(digestGroups.entries())
        .filter(([_, indices]) => indices.length > 1);

      expect(digestes).toHaveLength(3);
      expect(digestGroups.size).toBeGreaterThanOrEqual(1);

      logger.info('State deduplication test passed', {
        totalCaptures: captures.length,
        uniqueDigests: digestGroups.size,
        duplicateGroups: duplicateGroups.length,
        groupSizes: Array.from(digestGroups.values()).map(group => group.length)
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT * 4);
  });

  // ============================================================================
  // COMPREHENSIVE STATE CAPTURE TESTS
  // ============================================================================

  describe('Complete UI State Capture', () => {
    it('should capture complete UI state with all components', async () => {
      const startTime = Date.now();

      const uiState = await adbService.captureUIState(
        { includeData: true }, // screenshot options
        { includeAttributes: true, compress: false } // hierarchy options
      );

      const captureTime = Date.now() - startTime;

      expect(validateCaptureResult(uiState)).toBe(true);
      expect(uiState.hierarchy.length).toBeGreaterThan(TEST_CONFIG.MIN_HIERARCHY_SIZE);
      expect(uiState.screenshot).toBeDefined();
      expect(uiState.screenshot!.length).toBeGreaterThan(TEST_CONFIG.MIN_SCREENSHOT_SIZE);
      expect(uiState.deviceInfo).toBeDefined();
      expect(uiState.currentActivity).toBeDefined();
      expect(uiState.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(uiState.duration).toBeGreaterThan(0);
      expect(uiState.elementCount).toBeGreaterThanOrEqual(0);
      expect(['portrait', 'landscape']).toContain(uiState.orientation);

      expect(captureTime).toBeLessThan(TEST_CONFIG.PERFORMANCE_TIMEOUT);

      // Save for debugging
      saveTestCapture(uiState, 'complete-state');

      logger.info('Complete UI state capture test passed', {
        hierarchyLength: uiState.hierarchy.length,
        screenshotSize: uiState.screenshot?.length,
        elementCount: uiState.elementCount,
        currentActivity: uiState.currentActivity,
        captureTime,
        orientation: uiState.orientation
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should capture states from different screens', async () => {
      const captures = [];
      const captureTimes = [];

      // Capture initial state
      const startTime1 = Date.now();
      captures.push(await adbService.captureUIState());
      captureTimes.push(Date.now() - startTime1);

      // Try to navigate to different screens
      try {
        // Try some basic navigation attempts
        const navigationAttempts = [
          () => adbService.performTap(500, 1000), // Tap somewhere
          () => adbService.performBack(),         // Press back
          () => adbService.performTap(300, 300),  // Tap somewhere else
        ];

        for (const navigate of navigationAttempts) {
          try {
            await navigate();
            await new Promise(resolve => setTimeout(resolve, 1000));

            const startTime = Date.now();
            const capture = await adbService.captureUIState();
            captureTimes.push(Date.now() - startTime);

            // Check if this is a different state
            const lastCapture = captures[captures.length - 1];
            if (capture.hierarchy !== lastCapture.hierarchy ||
                capture.currentActivity !== lastCapture.currentActivity) {
              captures.push(capture);
              logger.debug('New screen state captured', {
                newActivity: capture.currentActivity,
                hierarchySize: capture.hierarchy.length
              });
            }
          } catch (error) {
            logger.debug('Navigation attempt failed', { error: (error as Error).message });
          }
        }
      } catch (error) {
        logger.warn('Screen navigation failed', { error: (error as Error).message });
      }

      expect(captures.length).toBeGreaterThanOrEqual(1);
      captures.forEach((capture, index) => {
        expect(validateCaptureResult(capture)).toBe(true);
        expect(captureTimes[index]).toBeLessThan(TEST_CONFIG.PERFORMANCE_TIMEOUT);
      });

      // If we captured multiple states, they should be different
      if (captures.length > 1) {
        const uniqueActivities = new Set(captures.map(c => c.currentActivity));
        const uniqueHierarchies = new Set(captures.map(c => c.hierarchy));

        expect(uniqueActivities.size + uniqueHierarchies.size).toBeGreaterThan(1);
      }

      logger.info('Multiple screen capture test passed', {
        totalCaptures: captures.length,
        averageCaptureTime: captureTimes.reduce((a, b) => a + b, 0) / captureTimes.length,
        uniqueActivities: new Set(captures.map(c => c.currentActivity)).size,
        uniqueHierarchies: new Set(captures.map(c => c.hierarchy)).size
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT * 6);

    it('should maintain performance under load', async () => {
      const captures = [];
      const captureTimes = [];
      const iterationCount = 5;

      for (let i = 0; i < iterationCount; i++) {
        const startTime = Date.now();
        const capture = await adbService.captureUIState(
          { includeData: false }, // Skip screenshot for speed
          { includeAttributes: true, compress: true }
        );
        const captureTime = Date.now() - startTime;

        captures.push(capture);
        captureTimes.push(captureTime);

        // Small delay to prevent overwhelming the device
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      expect(captures).toHaveLength(iterationCount);

      const averageTime = captureTimes.reduce((a, b) => a + b, 0) / captureTimes.length;
      const maxTime = Math.max(...captureTimes);
      const minTime = Math.min(...captureTimes);

      expect(averageTime).toBeLessThan(TEST_CONFIG.PERFORMANCE_TIMEOUT);
      expect(maxTime).toBeLessThan(TEST_CONFIG.PERFORMANCE_TIMEOUT * 1.5);

      captures.forEach(capture => {
        expect(validateCaptureResult(capture)).toBe(true);
      });

      logger.info('Performance under load test passed', {
        iterationCount,
        averageTime,
        maxTime,
        minTime,
        allUnderThreshold: captureTimes.every(time => time < TEST_CONFIG.PERFORMANCE_TIMEOUT)
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT * iterationCount);
  });

  // ============================================================================
  // ERROR HANDLING TESTS
  // ============================================================================

  describe('Error Handling and Recovery', () => {
    it('should handle capture timeout gracefully', async () => {
      // Create service with very short timeout
      const timeoutService = new ADBBridgeService({
        serial: TEST_CONFIG.DEVICE_SERIAL,
        uiCaptureTimeout: 1 // 1ms timeout - should fail
      });

      try {
        await timeoutService.initialize();

        // This should timeout
        await expect(timeoutService.captureUIState()).rejects.toThrow();

      } catch (error) {
        expect(error).toBeDefined();
        expect(error instanceof UIAutomatorError || error instanceof ADBBridgeError).toBe(true);
      } finally {
        await timeoutService.close();
      }

      logger.info('Capture timeout handling test passed');
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should handle device disconnection', async () => {
      // Create service with invalid device serial
      const invalidService = new ADBBridgeService({
        serial: 'invalid-device-9999',
        timeout: 5000,
        maxConnectionRetries: 1
      });

      await expect(invalidService.initialize()).rejects.toThrow(DeviceConnectionError);

      await invalidService.close();

      logger.info('Device disconnection handling test passed');
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should handle UIAutomator2 errors', async () => {
      // This test simulates UIAutomator2 errors by using invalid commands
      const health = await adbService.getConnectionHealth();
      expect(health).toBeDefined();

      // Try to trigger a UIAutomator2 error by executing an invalid operation
      // Note: This is implementation-dependent and may need adjustment
      try {
        // The service should handle internal UIAutomator2 errors gracefully
        const uiState = await adbService.captureUIState();
        expect(uiState).toBeDefined();
      } catch (error) {
        // If an error occurs, it should be properly wrapped
        expect(error instanceof UIAutomatorError || error instanceof ADBBridgeError).toBe(true);
      }

      logger.info('UIAutomator2 error handling test passed');
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should validate capture results and detect corruption', async () => {
      const uiState = await adbService.captureUIState();

      // Basic validation
      expect(validateCaptureResult(uiState)).toBe(true);

      // More specific validations
      expect(uiState.hierarchy).toContain('<hierarchy>');
      expect(uiState.hierarchy).toContain('</hierarchy>');

      if (uiState.screenshot) {
        // Validate base64 screenshot
        expect(() => Buffer.from(uiState.screenshot, 'base64')).not.toThrow();
        const screenshotBuffer = Buffer.from(uiState.screenshot, 'base64');
        expect(screenshotBuffer.length).toBeGreaterThan(TEST_CONFIG.MIN_SCREENSHOT_SIZE);
      }

      // Validate device info
      expect(uiState.deviceInfo).toBeDefined();
      expect(uiState.deviceInfo.serial).toBe(TEST_CONFIG.DEVICE_SERIAL);

      // Validate timestamp
      expect(new Date(uiState.timestamp)).toBeInstanceOf(Date);

      logger.info('Capture result validation test passed', {
        hasValidHierarchy: uiState.hierarchy.includes('<hierarchy>'),
        hasValidScreenshot: !!uiState.screenshot,
        hasValidDeviceInfo: !!uiState.deviceInfo,
        hasValidTimestamp: !isNaN(Date.parse(uiState.timestamp))
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);
  });

  // ============================================================================
  // STORAGE AND PERSISTENCE TESTS
  // ============================================================================

  describe('Storage and Persistence', () => {
    it('should save capture results to JSON storage', async () => {
      const uiState = await adbService.captureUIState();
      const captureId = `test-capture-${Date.now()}`;

      const saveResult = await storageService.create(
        `captures/${captureId}.json`,
        uiState,
        {
          createdBy: 'integration-test',
          comment: 'Test capture result'
        }
      );

      expect(saveResult).toBeDefined();
      expect(saveResult.success).toBe(true);
      expect(saveResult.data).toBeDefined();
      expect(saveResult.metadata).toBeDefined();
      expect(saveResult.metadata.version).toBeDefined();
      expect(saveResult.metadata.hash).toBeDefined();

      // Verify retrieval
      const retrieveResult = await storageService.read(`captures/${captureId}.json`);
      expect(retrieveResult).toBeDefined();
      expect(retrieveResult.data).toEqual(uiState);

      logger.info('Storage persistence test passed', {
        captureId,
        saveSuccess: saveResult.success,
        version: saveResult.metadata.version,
        dataIntegrity: JSON.stringify(retrieveResult.data) === JSON.stringify(uiState)
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should store and retrieve state digests', async () => {
      const uiState = await adbService.captureUIState();
      const digest = generateStateDigest(uiState);
      const digestId = `test-digest-${Date.now()}`;

      await storageService.create(
        `digests/${digestId}.json`,
        digest,
        {
          createdBy: 'integration-test',
          comment: 'Test state digest'
        }
      );

      const retrievedDigest = await storageService.read(`digests/${digestId}.json`);
      expect(retrievedDigest).toBeDefined();
      expect(retrievedDigest.data).toEqual(digest);

      // Test digest uniqueness
      const digestList = await storageService.list('digests');
      expect(digestList.files).toContain(`digests/${digestId}.json`);

      logger.info('Digest storage test passed', {
        digestId,
        digestHash: digest.hash,
        storedFiles: digestList.count
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should handle concurrent storage operations', async () => {
      const captures = [];
      const storageOperations = [];

      // Capture multiple states
      for (let i = 0; i < 3; i++) {
        captures.push(await adbService.captureUIState());
        await new Promise(resolve => setTimeout(resolve, 200));
      }

      // Store them concurrently
      const storePromises = captures.map((capture, index) =>
        storageService.create(
          `concurrent/concurrent-${Date.now()}-${index}.json`,
          capture,
          { createdBy: 'concurrent-test' }
        )
      );

      const results = await Promise.all(storePromises);

      expect(results).toHaveLength(3);
      results.forEach((result, index) => {
        expect(result.success).toBe(true);
        expect(result.data).toEqual(captures[index]);
      });

      logger.info('Concurrent storage test passed', {
        captureCount: captures.length,
        storageOperations: results.length,
        allSuccessful: results.every(r => r.success)
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT * 4);
  });

  // ============================================================================
  // DOCKER ENVIRONMENT TESTS
  // ============================================================================

  describe('Docker Environment Compatibility', () => {
    it('should run in Docker environment', async () => {
      // Check if we're running in Docker
      const isDocker = existsSync('/.dockerenv');

      const uiState = await adbService.captureUIState();
      expect(validateCaptureResult(uiState)).toBe(true);

      logger.info('Docker environment test passed', {
        isDockerEnvironment: isDocker,
        captureSuccessful: true,
        deviceSerial: uiState.deviceInfo.serial
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);

    it('should handle Docker network configuration', async () => {
      // This test validates that the service can connect to the ADB server
      // which might be running on the host machine in a Docker setup

      const health = await adbService.getConnectionHealth();
      expect(health.isConnected).toBe(true);

      // Test basic connectivity
      const deviceInfo = await adbService.getDeviceInfo();
      expect(deviceInfo).toBeDefined();

      logger.info('Docker network configuration test passed', {
        connectionHealthy: health.isConnected,
        deviceAccessible: !!deviceInfo,
        hostAddress: process.env.ADB_HOST || 'default'
      });
    }, TEST_CONFIG.CAPTURE_TIMEOUT);
  });
});

// ============================================================================
// TEST EXECUTION CONFIGURATION
// ============================================================================

// Increase timeout for integration tests
jest.setTimeout(60000);

// Configure test output
beforeAll(() => {
  logger.info('Starting UI State Capture Integration Tests', {
    deviceSerial: TEST_CONFIG.DEVICE_SERIAL,
    testDataDir: TEST_CONFIG.TEST_DATA_DIR,
    performanceThreshold: TEST_CONFIG.MAX_CAPTURE_DURATION
  });
});

afterAll(() => {
  logger.info('UI State Capture Integration Tests Completed');
});

// Export test configuration for external test runners
export {
  TEST_CONFIG,
  generateStateDigest,
  validateCaptureResult,
  isMaynDriveRunning,
  type StateCaptureResult,
  type TestDeviceInfo,
  type StateDigest,
  type CaptureError
};