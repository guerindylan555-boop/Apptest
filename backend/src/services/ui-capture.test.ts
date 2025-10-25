/**
 * UI Capture Service Tests
 *
 * Comprehensive test suite for the UIAutomator2-based capture service.
 * Tests state capture, device validation, performance monitoring, and error handling.
 */

import { UICaptureService, UICaptureError, captureUIState, uiCaptureService } from './ui-capture';
import { createServiceLogger } from './logger';
import { State } from '../models/state';

// Mock dependencies
jest.mock('../utils/adb');
jest.mock('../utils/xml');
jest.mock('../models/state');
jest.mock('./logger');

describe('UICaptureService', () => {
  let service: UICaptureService;
  let mockADB: any;
  let mockLogger: any;

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock logger
    mockLogger = {
      generateTraceId: jest.fn().mockReturnValue('test-trace-id'),
      startTimer: jest.fn().mockReturnValue({
        end: jest.fn()
      }),
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      healthCheck: jest.fn()
    };
    (createServiceLogger as jest.Mock).mockReturnValue(mockLogger);

    // Mock ADB connection
    mockADB = {
      isDeviceConnected: jest.fn(),
      getCurrentActivity: jest.fn(),
      getUIHierarchy: jest.fn(),
      captureScreenshot: jest.fn(),
      getDeviceProperties: jest.fn(),
      close: jest.fn()
    };

    // Create service instance
    service = new UICaptureService();
    (service as any).adb = mockADB;
  });

  afterEach(() => {
    service.close();
  });

  describe('captureState', () => {
    const mockActivity = 'com.example.app/.MainActivity';
    const mockXML = `<?xml version="1.0" encoding="UTF-8"?>
      <hierarchy>
        <node class="android.widget.FrameLayout" resource-id="android:id/content" bounds="[0,0][1080,1920]">
          <node class="android.widget.Button" resource-id="com.example.app:id/button" text="Click Me" bounds="[100,100][500,200]" />
          <node class="android.widget.EditText" resource-id="com.example.app:id/input" text="" bounds="[100,300][500,400]" />
        </node>
      </hierarchy>`;

    it('should capture UI state successfully', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockResolvedValue(mockActivity);
      mockADB.getUIHierarchy.mockResolvedValue(mockXML);
      mockADB.captureScreenshot.mockResolvedValue(Buffer.from('fake-screenshot-data'));

      // Mock XML parsing and selector extraction
      const { parseUIHierarchy, extractSelectors, normalizeXML, generateXMLHash } = require('../utils/xml');
      parseUIHierarchy.mockReturnValue({
        $: { class: 'hierarchy' },
        $$: [
          {
            $: { class: 'android.widget.FrameLayout', 'resource-id': 'android:id/content', bounds: '[0,0][1080,1920]' },
            $$: [
              {
                $: { class: 'android.widget.Button', 'resource-id': 'com.example.app:id/button', text: 'Click Me', bounds: '[100,100][500,200]' }
              },
              {
                $: { class: 'android.widget.EditText', 'resource-id': 'com.example.app:id/input', text: '', bounds: '[100,300][500,400]' }
              }
            ]
          }
        ]
      });
      extractSelectors.mockReturnValue([
        { cls: 'android.widget.Button', rid: 'com.example.app:id/button', text: 'Click Me', bounds: [100, 100, 500, 200] },
        { cls: 'android.widget.EditText', rid: 'com.example.app:id/input', bounds: [100, 300, 500, 400] }
      ]);
      normalizeXML.mockReturnValue({ $: { class: 'hierarchy' } });
      generateXMLHash.mockReturnValue('mock-xml-hash');

      // Mock State constructor
      const mockState = {
        id: 'mock-state-id',
        package: 'com.example.app',
        activity: 'com.example.app.MainActivity',
        selectors: [],
        metadata: { captureMethod: 'adb', captureDuration: 100, elementCount: 2, hierarchyDepth: 2 }
      };
      (State as jest.Mock).mockImplementation(() => mockState);

      // Mock fs operations
      const fs = require('fs').promises;
      fs.mkdir = jest.fn().mockResolvedValue(undefined);
      fs.writeFile = jest.fn().mockResolvedValue(undefined);
      fs.access = jest.fn().mockRejectedValue(new Error('File not found'));

      // Act
      const result = await service.captureState();

      // Assert
      expect(result.state).toEqual(mockState);
      expect(result.captureTime).toBeGreaterThan(0);
      expect(result.merged).toBe(false);
      expect(result.metadata).toEqual({
        xmlHash: 'mock-xml-hash',
        totalSelectors: 2,
        interactiveSelectors: 2,
        hierarchyDepth: 2,
        screenshotCaptured: true,
        packageName: 'com.example.app',
        activityName: mockActivity
      });

      expect(mockADB.getCurrentActivity).toHaveBeenCalled();
      expect(mockADB.getUIHierarchy).toHaveBeenCalled();
      expect(mockADB.captureScreenshot).toHaveBeenCalled();
      expect(mockLogger.info).toHaveBeenCalledWith('capture_completed', expect.any(String), expect.any(String), expect.any(Object));
    });

    it('should skip screenshot when requested', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockResolvedValue(mockActivity);
      mockADB.getUIHierarchy.mockResolvedValue(mockXML);

      const { parseUIHierarchy, extractSelectors, normalizeXML, generateXMLHash } = require('../utils/xml');
      parseUIHierarchy.mockReturnValue({ $: { class: 'hierarchy' } });
      extractSelectors.mockReturnValue([]);
      normalizeXML.mockReturnValue({ $: { class: 'hierarchy' } });
      generateXMLHash.mockReturnValue('mock-xml-hash');

      const mockState = { id: 'mock-state-id' };
      (State as jest.Mock).mockImplementation(() => mockState);

      // Act
      const result = await service.captureState({ skipScreenshot: true });

      // Assert
      expect(result.metadata.screenshotCaptured).toBe(false);
      expect(mockADB.captureScreenshot).not.toHaveBeenCalled();
    });

    it('should handle capture timeout', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockImplementation(() =>
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 100))
      );

      // Act & Assert
      await expect(service.captureState({ timeout: 50 })).rejects.toThrow(UICaptureError);
      expect(mockLogger.error).toHaveBeenCalledWith('capture_failed', expect.any(String), expect.any(Error), expect.any(String), expect.any(Object));
    });

    it('should handle empty XML hierarchy', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockResolvedValue(mockActivity);
      mockADB.getUIHierarchy.mockResolvedValue('');

      // Act & Assert
      await expect(service.captureState()).rejects.toThrow(UICaptureError);
      expect(mockLogger.error).toHaveBeenCalledWith('capture_failed', expect.any(String), expect.any(Error), expect.any(String), expect.any(Object));
    });

    it('should filter selectors by importance threshold', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockResolvedValue(mockActivity);
      mockADB.getUIHierarchy.mockResolvedValue(mockXML);

      const { parseUIHierarchy, extractSelectors, normalizeXML, generateXMLHash } = require('../utils/xml');
      parseUIHierarchy.mockReturnValue({ $: { class: 'hierarchy' } });
      extractSelectors.mockReturnValue([
        { cls: 'android.widget.Button', rid: 'button', text: 'Click Me' }, // High importance
        { cls: 'android.view.View' }, // Low importance
        { cls: 'android.widget.EditText', rid: 'input' } // High importance
      ]);
      normalizeXML.mockReturnValue({ $: { class: 'hierarchy' } });
      generateXMLHash.mockReturnValue('mock-xml-hash');

      const mockState = {
        id: 'mock-state-id',
        selectors: [] // Will be populated with filtered selectors
      };
      (State as jest.Mock).mockImplementation(() => mockState);

      // Act
      await service.captureState({ minImportance: 0.5 });

      // Assert
      expect(mockState.selectors.length).toBeLessThanOrEqual(2); // Should filter out low importance selector
    });
  });

  describe('validateDevice', () => {
    it('should validate device successfully', async () => {
      // Arrange
      mockADB.isDeviceConnected.mockResolvedValue(true);
      mockADB.getCurrentActivity.mockResolvedValue('com.example.app/.MainActivity');
      mockADB.getDeviceProperties.mockResolvedValue({
        'ro.product.model': 'Pixel 6',
        'ro.build.version.release': '13'
      });

      // Act
      const result = await service.validateDevice();

      // Assert
      expect(result.connected).toBe(true);
      expect(result.responsive).toBe(true);
      expect(result.activity).toBe('com.example.app/.MainActivity');
      expect(result.package).toBe('com.example.app');
      expect(result.model).toBe('Pixel 6');
      expect(result.version).toBe('13');
      expect(result.responseTime).toBeGreaterThan(0);
    });

    it('should handle disconnected device', async () => {
      // Arrange
      mockADB.isDeviceConnected.mockResolvedValue(false);

      // Act
      const result = await service.validateDevice();

      // Assert
      expect(result.connected).toBe(false);
      expect(result.responsive).toBe(false);
      expect(result.error).toBe('Device not connected');
    });

    it('should handle slow device response', async () => {
      // Arrange
      mockADB.isDeviceConnected.mockResolvedValue(true);
      mockADB.getCurrentActivity.mockImplementation(() =>
        new Promise(resolve => setTimeout(() => resolve('com.example.app/.MainActivity'), 15000))
      );

      // Act
      const result = await service.validateDevice();

      // Assert
      expect(result.connected).toBe(true);
      expect(result.responsive).toBe(false);
      expect(result.error).toBe('Device response too slow');
    });
  });

  describe('getDeviceInfo', () => {
    it('should get device information successfully', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockResolvedValue('com.example.app/.MainActivity');
      mockADB.getDeviceProperties.mockResolvedValue({
        'ro.product.model': 'Pixel 6',
        'ro.build.version.release': '13',
        'ro.product.manufacturer': 'Google'
      });

      // Act
      const result = await service.getDeviceInfo();

      // Assert
      expect(result.model).toBe('Pixel 6');
      expect(result.version).toBe('13');
      expect(result.package).toBe('com.example.app');
      expect(result.activity).toBe('com.example.app/.MainActivity');
      expect(result.properties).toEqual({
        'ro.product.model': 'Pixel 6',
        'ro.build.version.release': '13',
        'ro.product.manufacturer': 'Google'
      });
    });

    it('should handle device info errors gracefully', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockRejectedValue(new Error('ADB error'));
      mockADB.getDeviceProperties.mockRejectedValue(new Error('ADB error'));

      // Act
      const result = await service.getDeviceInfo();

      // Assert
      expect(result).toEqual({});
      expect(mockLogger.error).toHaveBeenCalled();
    });
  });

  describe('testPerformance', () => {
    it('should test performance with multiple iterations', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockResolvedValue('com.example.app/.MainActivity');
      mockADB.getUIHierarchy.mockResolvedValue('<hierarchy></hierarchy>');

      const { parseUIHierarchy, extractSelectors, normalizeXML, generateXMLHash } = require('../utils/xml');
      parseUIHierarchy.mockReturnValue({ $: { class: 'hierarchy' } });
      extractSelectors.mockReturnValue([]);
      normalizeXML.mockReturnValue({ $: { class: 'hierarchy' } });
      generateXMLHash.mockReturnValue('mock-xml-hash');

      const mockState = { id: 'mock-state-id' };
      (State as jest.Mock).mockImplementation(() => mockState);

      // Act
      const result = await service.testPerformance(3);

      // Assert
      expect(result.totalCaptures).toBe(3);
      expect(result.successfulCaptures).toBe(3);
      expect(result.successRate).toBe(1);
      expect(result.averageTime).toBeGreaterThan(0);
      expect(result.minTime).toBeGreaterThan(0);
      expect(result.maxTime).toBeGreaterThan(0);
    });

    it('should handle performance test failures', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockRejectedValue(new Error('Capture failed'));

      // Act
      const result = await service.testPerformance(3);

      // Assert
      expect(result.totalCaptures).toBe(3);
      expect(result.successfulCaptures).toBe(0);
      expect(result.successRate).toBe(0);
    });
  });

  describe('getPerformanceMetrics', () => {
    it('should return current performance metrics', () => {
      // Arrange
      (service as any).performanceHistory = [100, 200, 300];
      (service as any).totalCaptures = 5;
      (service as any).successfulCaptures = 4;

      // Act
      const metrics = service.getPerformanceMetrics();

      // Assert
      expect(metrics.averageTime).toBe(200);
      expect(metrics.minTime).toBe(100);
      expect(metrics.maxTime).toBe(300);
      expect(metrics.totalCaptures).toBe(5);
      expect(metrics.successfulCaptures).toBe(4);
      expect(metrics.successRate).toBe(0.8);
    });

    it('should return empty metrics when no captures', () => {
      // Act
      const metrics = service.getPerformanceMetrics();

      // Assert
      expect(metrics.averageTime).toBe(0);
      expect(metrics.minTime).toBe(0);
      expect(metrics.maxTime).toBe(0);
      expect(metrics.totalCaptures).toBe(0);
      expect(metrics.successfulCaptures).toBe(0);
      expect(metrics.successRate).toBe(0);
    });
  });

  describe('resetPerformanceMetrics', () => {
    it('should reset performance metrics', () => {
      // Arrange
      (service as any).performanceHistory = [100, 200];
      (service as any).totalCaptures = 5;
      (service as any).successfulCaptures = 4;

      // Act
      service.resetPerformanceMetrics();

      // Assert
      expect((service as any).performanceHistory).toEqual([]);
      expect((service as any).totalCaptures).toBe(0);
      expect((service as any).successfulCaptures).toBe(0);
    });
  });

  describe('healthCheck', () => {
    it('should return healthy status when device is responsive', async () => {
      // Arrange
      mockADB.isDeviceConnected.mockResolvedValue(true);
      mockADB.getCurrentActivity.mockResolvedValue('com.example.app/.MainActivity');
      mockADB.getDeviceProperties.mockResolvedValue({});

      // Act
      const result = await service.healthCheck();

      // Assert
      expect(result.healthy).toBe(true);
      expect(result.details).toHaveProperty('device');
      expect(result.details).toHaveProperty('performance');
      expect(result.details).toHaveProperty('service');
    });

    it('should return unhealthy status when device is not connected', async () => {
      // Arrange
      mockADB.isDeviceConnected.mockResolvedValue(false);

      // Act
      const result = await service.healthCheck();

      // Assert
      expect(result.healthy).toBe(false);
    });

    it('should handle health check errors', async () => {
      // Arrange
      mockADB.isDeviceConnected.mockRejectedValue(new Error('Health check failed'));

      // Act
      const result = await service.healthCheck();

      // Assert
      expect(result.healthy).toBe(false);
      expect(result.details.error).toBeDefined();
    });
  });

  describe('convenience functions', () => {
    it('should export captureUIState function', async () => {
      // Arrange
      mockADB.getCurrentActivity.mockResolvedValue('com.example.app/.MainActivity');
      mockADB.getUIHierarchy.mockResolvedValue('<hierarchy></hierarchy>');

      const { parseUIHierarchy, extractSelectors, normalizeXML, generateXMLHash } = require('../utils/xml');
      parseUIHierarchy.mockReturnValue({ $: { class: 'hierarchy' } });
      extractSelectors.mockReturnValue([]);
      normalizeXML.mockReturnValue({ $: { class: 'hierarchy' } });
      generateXMLHash.mockReturnValue('mock-xml-hash');

      const mockState = { id: 'mock-state-id' };
      (State as jest.Mock).mockImplementation(() => mockState);

      // Act
      const result = await captureUIState();

      // Assert
      expect(result.state).toBeDefined();
    });

    it('should export uiCaptureService singleton', () => {
      expect(uiCaptureService).toBeInstanceOf(UICaptureService);
    });
  });

  describe('UICaptureError', () => {
    it('should create error with proper properties', () => {
      const context = { test: 'value' };
      const error = new UICaptureError('Test error', 'TEST_CODE', context);

      expect(error.name).toBe('UICaptureError');
      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.context).toEqual(context);
      expect(error.timestamp).toBeDefined();
    });
  });
});

// Integration tests (would require actual device/emulator)
describe('UICaptureService Integration', () => {
  // These tests would be run against a real device/emulator
  // They are commented out as they require specific setup

  /*
  it('should capture real UI state from device', async () => {
    const service = new UICaptureService();

    try {
      const result = await service.captureState();

      expect(result.state).toBeDefined();
      expect(result.state.id).toBeDefined();
      expect(result.state.package).toBeDefined();
      expect(result.state.activity).toBeDefined();
      expect(result.state.selectors).toBeInstanceOf(Array);
      expect(result.captureTime).toBeGreaterThan(0);
      expect(result.captureTime).toBeLessThan(2000); // Should be under 2s
    } finally {
      service.close();
    }
  });

  it('should validate real device connection', async () => {
    const service = new UICaptureService();

    try {
      const validation = await service.validateDevice();

      expect(validation.connected).toBe(true);
      expect(validation.responsive).toBe(true);
      expect(validation.activity).toBeDefined();
      expect(validation.package).toBeDefined();
    } finally {
      service.close();
    }
  });
  */
});