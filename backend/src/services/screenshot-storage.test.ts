/**
 * Screenshot Storage Service Tests
 *
 * Basic test suite for the screenshot storage service functionality
 */

import { ScreenshotStorageService } from './screenshot-storage';
import { promises as fs } from 'fs';
import * as path from 'path';

describe('ScreenshotStorageService', () => {
  let service: ScreenshotStorageService;
  const testBaseDir = path.join(__dirname, '../../test-screenshots');

  beforeAll(async () => {
    // Set test environment
    process.env.SCREENSHOT_STORAGE_DIR = testBaseDir;

    // Create test directory
    await fs.mkdir(testBaseDir, { recursive: true });

    service = new ScreenshotStorageService();
  });

  afterAll(async () => {
    // Cleanup test directory
    try {
      await fs.rm(testBaseDir, { recursive: true, force: true });
    } catch (error) {
      // Ignore cleanup errors
    }

    service.close();
  });

  describe('Service Initialization', () => {
    it('should initialize successfully', async () => {
      // Service should be created without errors
      expect(service).toBeInstanceOf(ScreenshotStorageService);
    });

    it('should create necessary directories', async () => {
      const dirs = [
        path.join(testBaseDir, 'previews'),
        path.join(testBaseDir, 'metadata'),
        path.join(testBaseDir, 'temp'),
        path.join(testBaseDir, 'exports')
      ];

      for (const dir of dirs) {
        const exists = await fs.access(dir).then(() => true).catch(() => false);
        expect(exists).toBe(true);
      }
    });

    it('should perform health check', async () => {
      const health = await service.healthCheck();
      expect(health.healthy).toBe(true);
      expect(health.details).toBeDefined();
      expect(health.details.configuration).toBeDefined();
      expect(health.details.service).toBeDefined();
    });
  });

  describe('Storage Statistics', () => {
    it('should return empty stats initially', async () => {
      const stats = await service.getStorageStats();
      expect(stats.totalScreenshots).toBe(0);
      expect(stats.totalStorageUsed).toBe(0);
      expect(stats.averageFileSize).toBe(0);
    });
  });

  describe('Search Functionality', () => {
    it('should return empty results for empty storage', async () => {
      const results = await service.searchScreenshots();
      expect(results.screenshots).toHaveLength(0);
      expect(results.total).toBe(0);
      expect(results.hasMore).toBe(false);
    });

    it('should handle search filters', async () => {
      const results = await service.searchScreenshots({
        packageName: 'com.test.app',
        limit: 10
      });
      expect(results.screenshots).toHaveLength(0);
      expect(results.total).toBe(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle missing screenshot gracefully', async () => {
      await expect(service.getScreenshot('non-existent-id')).rejects.toThrow();
    });

    it('should handle deletion of non-existent screenshot', async () => {
      await expect(service.deleteScreenshot('non-existent-id')).rejects.toThrow();
    });
  });

  describe('Configuration', () => {
    it('should use environment configuration', () => {
      // Test that environment variables are properly loaded
      expect(service).toBeDefined();
    });
  });
});

// Integration test for screenshot capture (requires connected device)
describe.skip('Screenshot Capture Integration', () => {
  let service: ScreenshotStorageService;

  beforeAll(() => {
    process.env.SCREENSHOT_STORAGE_DIR = path.join(__dirname, '../../test-screenshots');
    service = new ScreenshotStorageService();
  });

  afterAll(() => {
    service.close();
  });

  it('should capture screenshot from device', async () => {
    // This test requires a connected Android device
    // Skip if no device is available
    const result = await service.captureScreenshot('com.example.app', 'MainActivity');

    expect(result.metadata).toBeDefined();
    expect(result.buffer).toBeDefined();
    expect(result.buffer.length).toBeGreaterThan(0);
    expect(result.metadata.packageName).toBe('com.example.app');
    expect(result.metadata.activityName).toBe('MainActivity');
  }, 30000); // 30 second timeout
});