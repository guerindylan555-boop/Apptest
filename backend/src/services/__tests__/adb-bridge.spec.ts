/**
 * ADB Bridge Service Tests
 */

import { ADBBridgeService, ADBBridgeError, DeviceConnectionError, UIAutomatorError } from '../adb-bridge';

// Mock the logger
jest.mock('../logger', () => ({
  logger: {
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}));

// Mock the ADB connection
jest.mock('../../utils/adb', () => ({
  createADBConnection: jest.fn(() => ({
    waitForDevice: jest.fn().mockResolvedValue(undefined),
    executeCommand: jest.fn().mockResolvedValue({
      stdout: 'mock output',
      stderr: '',
      exitCode: 0
    }),
    isDeviceConnected: jest.fn().mockResolvedValue(true),
    getDeviceProperties: jest.fn().mockResolvedValue({
      'ro.build.version.release': '11',
      'ro.build.version.sdk': '30',
      'ro.product.model': 'Pixel 4'
    }),
    getCurrentActivity: jest.fn().mockResolvedValue('com.example.app/.MainActivity'),
    captureScreenshot: jest.fn().mockResolvedValue(Buffer.from('mock screenshot')),
    getUIHierarchy: jest.fn().mockResolvedValue('<hierarchy>mock</hierarchy>'),
    tap: jest.fn().mockResolvedValue(undefined),
    type: jest.fn().mockResolvedValue(undefined),
    swipe: jest.fn().mockResolvedValue(undefined),
    pressBack: jest.fn().mockResolvedValue(undefined),
    close: jest.fn()
  }))
}));

describe('ADBBridgeService', () => {
  let service: ADBBridgeService;

  beforeEach(() => {
    service = new ADBBridgeService({
      serial: 'test-emulator-5554',
      timeout: 5000,
      uiAutomatorTimeout: 10000,
      uiCaptureTimeout: 20000
    });
  });

  afterEach(async () => {
    await service.close();
  });

  describe('initialization', () => {
    it('should initialize with default configuration', () => {
      const defaultService = new ADBBridgeService();
      expect(defaultService).toBeDefined();
    });

    it('should accept custom configuration', () => {
      const customConfig = {
        serial: 'custom-emulator-5556',
        timeout: 15000,
        uiAutomatorTimeout: 20000
      };

      const customService = new ADBBridgeService(customConfig);
      expect(customService).toBeDefined();
    });
  });

  describe('connection management', () => {
    it('should initialize connection successfully', async () => {
      await expect(service.initialize()).resolves.not.toThrow();
    });

    it('should close connection properly', async () => {
      await service.initialize();
      await expect(service.close()).resolves.not.toThrow();
    });
  });

  describe('device operations', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should get device information', async () => {
      const deviceInfo = await service.getDeviceInfo();

      expect(deviceInfo).toBeDefined();
      expect(deviceInfo.serial).toBe('test-emulator-5554');
      expect(deviceInfo.androidVersion).toBe('11');
      expect(deviceInfo.sdkVersion).toBe('30');
      expect(deviceInfo.model).toBe('Pixel 4');
    });

    it('should capture screenshot', async () => {
      const screenshot = await service.captureScreenshot();

      expect(screenshot).toBeDefined();
      expect(Buffer.isBuffer(screenshot)).toBe(true);
    });

    it('should capture screenshot with base64 output', async () => {
      const screenshot = await service.captureScreenshot({ includeData: true });

      expect(screenshot).toBeDefined();
      expect(typeof screenshot).toBe('string');
    });

    it('should get UI hierarchy', async () => {
      const hierarchy = await service.getUIHierarchy();

      expect(hierarchy).toBeDefined();
      expect(typeof hierarchy).toBe('string');
      expect(hierarchy).toContain('<hierarchy>');
    });

    it('should capture complete UI state', async () => {
      const uiState = await service.captureUIState();

      expect(uiState).toBeDefined();
      expect(uiState.hierarchy).toBeDefined();
      expect(uiState.deviceInfo).toBeDefined();
      expect(uiState.timestamp).toBeDefined();
      expect(uiState.duration).toBeGreaterThan(0);
      expect(uiState.elementCount).toBe(0); // Mock hierarchy has no interactive elements
    });
  });

  describe('device control', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should perform tap gesture', async () => {
      await expect(service.performTap(100, 200)).resolves.not.toThrow();
    });

    it('should perform text input', async () => {
      await expect(service.performType('test text')).resolves.not.toThrow();
    });

    it('should perform swipe gesture', async () => {
      await expect(service.performSwipe(100, 200, 300, 400, 500)).resolves.not.toThrow();
    });

    it('should press back button', async () => {
      await expect(service.performBack()).resolves.not.toThrow();
    });
  });

  describe('health monitoring', () => {
    beforeEach(async () => {
      await service.initialize();
    });

    it('should get connection health', async () => {
      const health = await service.getConnectionHealth();

      expect(health).toBeDefined();
      expect(health.isConnected).toBe(true);
      expect(health.isUiAutomatorReady).toBe(true);
      expect(health.totalCommands).toBeGreaterThanOrEqual(0);
      expect(health.uptime).toBeGreaterThan(0);
    });
  });
});

describe('Error handling', () => {
  let service: ADBBridgeService;

  beforeEach(() => {
    service = new ADBBridgeService({
      serial: 'test-emulator-error',
      timeout: 1000,
      maxRetries: 1,
      maxConnectionRetries: 1
    });
  });

  it('should handle connection errors', async () => {
    // Mock connection failure
    const { createADBConnection } = require('../../utils/adb');
    createADBConnection.mockReturnValueOnce({
      waitForDevice: jest.fn().mockRejectedValue(new Error('Device not found')),
      close: jest.fn()
    });

    await expect(service.initialize()).resolves.not.toThrow();
  });

  it('should handle UIAutomator errors', async () => {
    // Mock UIAutomator failure
    const { createADBConnection } = require('../../utils/adb');
    createADBConnection.mockReturnValueOnce({
      waitForDevice: jest.fn().mockResolvedValue(undefined),
      executeCommand: jest.fn().mockResolvedValue({
        stdout: '',
        stderr: 'uiautomator: not found',
        exitCode: 1
      }),
      close: jest.fn()
    });

    await expect(service.initialize()).resolves.not.toThrow();
  });
});