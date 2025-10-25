/**
 * ADB Bridge Service for UIAutomator2 Communication
 *
 * Enhanced ADB service specialized for UIAutomator2 commands and UI state capture.
 * Provides robust connection management, health checks, and error handling for
 * Android emulator interaction in the AutoApp UI Map & Flow Engine.
 */

import { spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';
import { ADBConnection, createADBConnection } from '../utils/adb';
import { logger } from './logger';
import { ADBConfig } from '../types/graph';

// ============================================================================
// Configuration Types
// ============================================================================

export interface ADBBridgeConfig extends ADBConfig {
  /** UIAutomator2 command timeout (ms) */
  uiAutomatorTimeout: number;

  /** UI capture timeout (ms) */
  uiCaptureTimeout: number;

  /** Device connection health check interval (ms) */
  healthCheckInterval: number;

  /** Maximum connection retry attempts */
  maxConnectionRetries: number;

  /** Connection retry backoff multiplier */
  retryBackoffMultiplier: number;

  /** Enable debug logging for UIAutomator operations */
  debugUiAutomator: boolean;
}

export interface DeviceInfo {
  /** Device serial number */
  serial: string;

  /** Android version */
  androidVersion: string;

  /** SDK version */
  sdkVersion: string;

  /** Device model */
  model: string;

  /** Screen resolution */
  resolution: string;

  /** Current activity package */
  currentPackage?: string;

  /** Current activity name */
  currentActivity?: string;

  /** Device orientation */
  orientation: 'portrait' | 'landscape';

  /** UIAutomator2 version */
  uiAutomatorVersion?: string;
}

export interface ScreenshotOptions {
  /** Save screenshot to file */
  saveToFile?: boolean;

  /** Output file path */
  outputPath?: string;

  /** Image quality (0-100) */
  quality?: number;

  /** Include in capture response */
  includeData?: boolean;
}

export interface UIHierarchyOptions {
  /** Compress XML output */
  compress?: boolean;

  /** Include attribute details */
  includeAttributes?: boolean;

  /** Max hierarchy depth */
  maxDepth?: number;

  /** Filter by specific attributes */
  filterAttributes?: string[];
}

export interface UIStateCapture {
  /** UI hierarchy XML */
  hierarchy: string;

  /** Screenshot data (base64) */
  screenshot?: string;

  /** Device information */
  deviceInfo: DeviceInfo;

  /** Current activity information */
  currentActivity: string;

  /** Capture timestamp */
  timestamp: string;

  /** Capture duration (ms) */
  duration: number;

  /** Interactive elements count */
  elementCount: number;

  /** Screen orientation */
  orientation: 'portrait' | 'landscape';
}

export interface ConnectionHealth {
  /** Is device connected */
  isConnected: boolean;

  /** Is UIAutomator2 available */
  isUiAutomatorReady: boolean;

  /** Last successful command timestamp */
  lastSuccessfulCommand: string;

  /** Total commands executed */
  totalCommands: number;

  /** Failed commands count */
  failedCommands: number;

  /** Average response time (ms) */
  averageResponseTime: number;

  /** Connection uptime (ms) */
  uptime: number;
}

// ============================================================================
// Error Types
// ============================================================================

export class ADBBridgeError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'ADBBridgeError';
  }
}

export class DeviceConnectionError extends ADBBridgeError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'DEVICE_CONNECTION_ERROR', details);
  }
}

export class UIAutomatorError extends ADBBridgeError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'UI_AUTOMATOR_ERROR', details);
  }
}

export class CommandTimeoutError extends ADBBridgeError {
  constructor(message: string, timeout: number, details?: Record<string, any>) {
    super(message, 'COMMAND_TIMEOUT', { timeout, ...details });
  }
}

// ============================================================================
// Main ADB Bridge Service
// ============================================================================

export class ADBBridgeService {
  private config: ADBBridgeConfig;
  private adbConnection: ADBConnection;
  private healthCheckTimer?: NodeJS.Timeout;
  private connectionStartTime: number = Date.now();
  private commandStats = {
    totalCommands: 0,
    failedCommands: 0,
    totalResponseTime: 0,
    lastSuccessfulCommand: '',
    lastCommandTime: 0
  };

  constructor(config?: Partial<ADBBridgeConfig>) {
    this.config = this.createConfig(config);
    this.adbConnection = createADBConnection();

    logger.info('ADB Bridge Service initialized', {
      serial: this.config.serial,
      host: this.config.host,
      port: this.config.port,
      uiAutomatorTimeout: this.config.uiAutomatorTimeout,
      uiCaptureTimeout: this.config.uiCaptureTimeout
    });
  }

  private createConfig(override?: Partial<ADBBridgeConfig>): ADBBridgeConfig {
    const baseConfig: ADBBridgeConfig = {
      host: process.env.ADB_HOST || 'host.docker.internal',
      port: parseInt(process.env.ADB_PORT || '5555'),
      serial: process.env.ANDROID_SERIAL || 'emulator-5554',
      timeout: parseInt(process.env.ADB_TIMEOUT || '10000'),
      maxRetries: 3,
      poolSize: 5,
      uiAutomatorTimeout: parseInt(process.env.UIAUTOMATOR2_TIMEOUT || '15000'),
      uiCaptureTimeout: parseInt(process.env.UI_CAPTURE_TIMEOUT || '30000'),
      healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL || '30000'),
      maxConnectionRetries: parseInt(process.env.MAX_CONNECTION_RETRIES || '5'),
      retryBackoffMultiplier: parseFloat(process.env.RETRY_BACKOFF_MULTIPLIER || '1.5'),
      debugUiAutomator: process.env.DEBUG_UI_AUTOMATOR === 'true'
    };

    return { ...baseConfig, ...override };
  }

  // ============================================================================
  // Connection Management
  // ============================================================================

  /**
   * Initialize connection to Android emulator
   */
  async initialize(): Promise<void> {
    logger.info('Initializing ADB Bridge connection', {
      serial: this.config.serial,
      maxRetries: this.config.maxConnectionRetries
    });

    let lastError: Error | null = null;
    let retryCount = 0;

    while (retryCount < this.config.maxConnectionRetries) {
      try {
        // Wait for device to be available
        await this.adbConnection.waitForDevice(this.config.timeout);

        // Verify UIAutomator2 availability
        await this.verifyUIAutomator2();

        // Get initial device info
        const deviceInfo = await this.getDeviceInfo();

        this.connectionStartTime = Date.now();
        this.startHealthChecks();

        logger.info('ADB Bridge connection established', {
          serial: this.config.serial,
          androidVersion: deviceInfo.androidVersion,
          model: deviceInfo.model,
          retryCount
        });

        return;
      } catch (error) {
        lastError = error as Error;
        retryCount++;

        const delay = Math.min(
          1000 * Math.pow(this.config.retryBackoffMultiplier, retryCount - 1),
          10000
        );

        logger.warn('ADB Bridge connection attempt failed, retrying', {
          attempt: retryCount,
          maxRetries: this.config.maxConnectionRetries,
          delay,
          error: lastError.message
        });

        if (retryCount < this.config.maxConnectionRetries) {
          await this.sleep(delay);
        }
      }
    }

    throw new DeviceConnectionError(
      `Failed to establish ADB Bridge connection after ${retryCount} attempts`,
      {
        serial: this.config.serial,
        lastError: lastError?.message,
        attempts: retryCount
      }
    );
  }

  /**
   * Close ADB Bridge connection and cleanup resources
   */
  async close(): Promise<void> {
    logger.info('Closing ADB Bridge connection', {
      serial: this.config.serial,
      uptime: Date.now() - this.connectionStartTime
    });

    this.stopHealthChecks();
    this.adbConnection.close();

    logger.info('ADB Bridge connection closed', {
      serial: this.config.serial
    });
  }

  /**
   * Start health check monitoring
   */
  private startHealthChecks(): void {
    this.healthCheckTimer = setInterval(
      () => this.performHealthCheck(),
      this.config.healthCheckInterval
    );

    logger.debug('Health check monitoring started', {
      interval: this.config.healthCheckInterval
    });
  }

  /**
   * Stop health check monitoring
   */
  private stopHealthChecks(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = undefined;
      logger.debug('Health check monitoring stopped');
    }
  }

  /**
   * Perform connection health check
   */
  private async performHealthCheck(): Promise<void> {
    try {
      const isConnected = await this.adbConnection.isDeviceConnected();

      if (!isConnected) {
        logger.warn('Device disconnected during health check', {
          serial: this.config.serial
        });

        // Attempt to reconnection
        await this.attemptReconnection();
        return;
      }

      // Test UIAutomator2 availability
      await this.verifyUIAutomator2();

      logger.debug('Health check passed', {
        serial: this.config.serial,
        uptime: Date.now() - this.connectionStartTime,
        commands: this.commandStats.totalCommands,
        failures: this.commandStats.failedCommands
      });

    } catch (error) {
      logger.error('Health check failed', {
        serial: this.config.serial,
        error: (error as Error).message
      });
    }
  }

  /**
   * Attempt to reconnect to device
   */
  private async attemptReconnection(): Promise<void> {
    logger.info('Attempting device reconnection', {
      serial: this.config.serial
    });

    try {
      await this.adbConnection.waitForDevice(this.config.timeout);
      await this.verifyUIAutomator2();

      logger.info('Device reconnection successful', {
        serial: this.config.serial
      });
    } catch (error) {
      logger.error('Device reconnection failed', {
        serial: this.config.serial,
        error: (error as Error).message
      });
    }
  }

  // ============================================================================
  // UIAutomator2 Operations
  // ============================================================================

  /**
   * Verify UIAutomator2 is available on device
   */
  private async verifyUIAutomator2(): Promise<void> {
    const startTime = Date.now();

    try {
      const result = await this.adbConnection.executeCommand(
        ['shell', 'which', 'uiautomator'],
        this.config.uiAutomatorTimeout
      );

      if (result.exitCode !== 0) {
        throw new UIAutomatorError(
          'UIAutomator2 not available on device',
          {
            serial: this.config.serial,
            exitCode: result.exitCode,
            stderr: result.stderr
          }
        );
      }

      logger.debug('UIAutomator2 verification successful', {
        serial: this.config.serial,
        duration: Date.now() - startTime
      });

    } catch (error) {
      if (error instanceof UIAutomatorError) {
        throw error;
      }

      throw new UIAutomatorError(
        `UIAutomator2 verification failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          duration: Date.now() - startTime
        }
      );
    }
  }

  /**
   * Get comprehensive device information
   */
  async getDeviceInfo(): Promise<DeviceInfo> {
    const startTime = Date.now();

    try {
      const properties = await this.adbConnection.getDeviceProperties();
      const currentActivity = await this.adbConnection.getCurrentActivity();

      // Parse device orientation
      const orientationOutput = await this.adbConnection.executeCommand(
        ['shell', 'dumpsys', 'input'],
        this.config.timeout
      );

      const orientationMatch = orientationOutput.stdout.match(/SurfaceOrientation: (\d)/);
      const orientation = orientationMatch?.[1] === '1' ? 'landscape' : 'portrait';

      // Parse screen resolution
      const wmSizeOutput = await this.adbConnection.executeCommand(
        ['shell', 'wm', 'size'],
        this.config.timeout
      );

      const sizeMatch = wmSizeOutput.stdout.match(/Physical size: (\d+x\d+)/);
      const resolution = sizeMatch?.[1] || 'Unknown';

      // Get UIAutomator2 version
      let uiAutomatorVersion: string | undefined;
      try {
        const versionResult = await this.adbConnection.executeCommand(
          ['shell', 'dumpsys', 'package', 'androidx.test.uiautomator'],
          this.config.timeout
        );

        const versionMatch = versionResult.stdout.match(/versionName=(\d+\.\d+\.\d+)/);
        uiAutomatorVersion = versionMatch?.[1];
      } catch {
        // UIAutomator2 version check failed, continue without it
      }

      const deviceInfo: DeviceInfo = {
        serial: this.config.serial,
        androidVersion: properties['ro.build.version.release'] || 'Unknown',
        sdkVersion: properties['ro.build.version.sdk'] || 'Unknown',
        model: properties['ro.product.model'] || 'Unknown',
        resolution,
        currentPackage: currentActivity?.split('/')[0],
        currentActivity,
        orientation,
        uiAutomatorVersion
      };

      logger.debug('Device info retrieved', {
        serial: this.config.serial,
        duration: Date.now() - startTime,
        androidVersion: deviceInfo.androidVersion,
        model: deviceInfo.model
      });

      return deviceInfo;

    } catch (error) {
      throw new DeviceConnectionError(
        `Failed to get device info: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          duration: Date.now() - startTime
        }
      );
    }
  }

  /**
   * Capture screenshot with options
   */
  async captureScreenshot(options: ScreenshotOptions = {}): Promise<Buffer | string> {
    const startTime = Date.now();

    try {
      const screenshotBuffer = await this.adbConnection.captureScreenshot();

      if (options.saveToFile && options.outputPath) {
        const fs = require('fs').promises;
        await fs.writeFile(options.outputPath, screenshotBuffer);

        logger.debug('Screenshot saved to file', {
          serial: this.config.serial,
          outputPath: options.outputPath,
          size: screenshotBuffer.length,
          duration: Date.now() - startTime
        });
      }

      this.updateCommandStats(Date.now() - startTime, true);

      if (options.includeData) {
        return screenshotBuffer.toString('base64');
      }

      return screenshotBuffer;

    } catch (error) {
      this.updateCommandStats(Date.now() - startTime, false);

      throw new UIAutomatorError(
        `Screenshot capture failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          duration: Date.now() - startTime,
          options
        }
      );
    }
  }

  /**
   * Get UI hierarchy with options
   */
  async getUIHierarchy(options: UIHierarchyOptions = {}): Promise<string> {
    const startTime = Date.now();

    try {
      let hierarchy = await this.adbConnection.getUIHierarchy();

      // Apply options processing
      if (options.maxDepth && options.maxDepth > 0) {
        hierarchy = this.limitHierarchyDepth(hierarchy, options.maxDepth);
      }

      if (options.filterAttributes && options.filterAttributes.length > 0) {
        hierarchy = this.filterHierarchyAttributes(hierarchy, options.filterAttributes);
      }

      if (options.compress) {
        hierarchy = this.compressHierarchy(hierarchy);
      }

      this.updateCommandStats(Date.now() - startTime, true);

      logger.debug('UI hierarchy retrieved', {
        serial: this.config.serial,
        duration: Date.now() - startTime,
        originalLength: hierarchy.length,
        options
      });

      return hierarchy;

    } catch (error) {
      this.updateCommandStats(Date.now() - startTime, false);

      throw new UIAutomatorError(
        `UI hierarchy capture failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          duration: Date.now() - startTime,
          options
        }
      );
    }
  }

  /**
   * Capture complete UI state (hierarchy + screenshot + device info)
   */
  async captureUIState(
    screenshotOptions?: ScreenshotOptions,
    hierarchyOptions?: UIHierarchyOptions
  ): Promise<UIStateCapture> {
    const startTime = Date.now();

    try {
      logger.debug('Starting UI state capture', {
        serial: this.config.serial,
        screenshotOptions,
        hierarchyOptions
      });

      // Execute captures in parallel for efficiency
      const [hierarchy, screenshot, deviceInfo] = await Promise.allSettled([
        this.getUIHierarchy(hierarchyOptions),
        this.captureScreenshot({ ...screenshotOptions, includeData: true }),
        this.getDeviceInfo()
      ]);

      const hierarchyData = hierarchy.status === 'fulfilled' ? hierarchy.value : '';
      const screenshotData = screenshot.status === 'fulfilled' ? screenshot.value as string : undefined;
      const deviceInfoData = deviceInfo.status === 'fulfilled' ? deviceInfo.value : await this.getDeviceInfo();

      // Count interactive elements
      const elementCount = this.countInteractiveElements(hierarchyData);

      const capture: UIStateCapture = {
        hierarchy: hierarchyData,
        screenshot: screenshotData,
        deviceInfo: deviceInfoData,
        currentActivity: deviceInfoData.currentActivity || 'Unknown',
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
        elementCount,
        orientation: deviceInfoData.orientation
      };

      logger.info('UI state capture completed', {
        serial: this.config.serial,
        duration: capture.duration,
        elementCount: capture.elementCount,
        hierarchyLength: capture.hierarchy.length,
        hasScreenshot: !!capture.screenshot
      });

      return capture;

    } catch (error) {
      logger.error('UI state capture failed', {
        serial: this.config.serial,
        duration: Date.now() - startTime,
        error: (error as Error).message
      });

      throw new UIAutomatorError(
        `UI state capture failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          duration: Date.now() - startTime
        }
      );
    }
  }

  // ============================================================================
  // Device Control Operations
  // ============================================================================

  /**
   * Set device orientation
   */
  async setOrientation(orientation: 'portrait' | 'landscape'): Promise<void> {
    const startTime = Date.now();

    try {
      const rotation = orientation === 'landscape' ? '1' : '0';

      await this.adbConnection.executeCommand(
        ['shell', 'content', 'insert', '--uri', 'content://settings/system', '--bind', `name:s:user_rotation`, '--bind', `value:i:${rotation}`],
        this.config.timeout
      );

      logger.debug('Device orientation set', {
        serial: this.config.serial,
        orientation,
        duration: Date.now() - startTime
      });

    } catch (error) {
      throw new UIAutomatorError(
        `Failed to set orientation: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          orientation,
          duration: Date.now() - startTime
        }
      );
    }
  }

  /**
   * Perform tap gesture at coordinates
   */
  async performTap(x: number, y: number): Promise<void> {
    const startTime = Date.now();

    try {
      await this.adbConnection.tap(x, y);

      logger.debug('Tap gesture performed', {
        serial: this.config.serial,
        x,
        y,
        duration: Date.now() - startTime
      });

    } catch (error) {
      throw new UIAutomatorError(
        `Tap gesture failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          x,
          y,
          duration: Date.now() - startTime
        }
      );
    }
  }

  /**
   * Type text on device
   */
  async performType(text: string): Promise<void> {
    const startTime = Date.now();

    try {
      await this.adbConnection.type(text);

      logger.debug('Text input performed', {
        serial: this.config.serial,
        textLength: text.length,
        duration: Date.now() - startTime
      });

    } catch (error) {
      throw new UIAutomatorError(
        `Text input failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          textLength: text.length,
          duration: Date.now() - startTime
        }
      );
    }
  }

  /**
   * Perform swipe gesture
   */
  async performSwipe(
    startX: number, startY: number,
    endX: number, endY: number,
    duration: number = 300
  ): Promise<void> {
    const startTime = Date.now();

    try {
      await this.adbConnection.swipe(startX, startY, endX, endY, duration);

      logger.debug('Swipe gesture performed', {
        serial: this.config.serial,
        startX,
        startY,
        endX,
        endY,
        duration,
        actualDuration: Date.now() - startTime
      });

    } catch (error) {
      throw new UIAutomatorError(
        `Swipe gesture failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          startX,
          startY,
          endX,
          endY,
          duration,
          actualDuration: Date.now() - startTime
        }
      );
    }
  }

  /**
   * Press back button
   */
  async performBack(): Promise<void> {
    const startTime = Date.now();

    try {
      await this.adbConnection.pressBack();

      logger.debug('Back button pressed', {
        serial: this.config.serial,
        duration: Date.now() - startTime
      });

    } catch (error) {
      throw new UIAutomatorError(
        `Back button press failed: ${(error as Error).message}`,
        {
          serial: this.config.serial,
          duration: Date.now() - startTime
        }
      );
    }
  }

  // ============================================================================
  // Health and Monitoring
  // ============================================================================

  /**
   * Get connection health information
   */
  async getConnectionHealth(): Promise<ConnectionHealth> {
    const startTime = Date.now();

    try {
      const isConnected = await this.adbConnection.isDeviceConnected();
      let isUiAutomatorReady = false;

      if (isConnected) {
        try {
          await this.verifyUIAutomator2();
          isUiAutomatorReady = true;
        } catch {
          // UIAutomator2 not ready
        }
      }

      const health: ConnectionHealth = {
        isConnected,
        isUiAutomatorReady,
        lastSuccessfulCommand: this.commandStats.lastSuccessfulCommand,
        totalCommands: this.commandStats.totalCommands,
        failedCommands: this.commandStats.failedCommands,
        averageResponseTime: this.commandStats.totalCommands > 0
          ? Math.round(this.commandStats.totalResponseTime / this.commandStats.totalCommands)
          : 0,
        uptime: Date.now() - this.connectionStartTime
      };

      logger.debug('Connection health retrieved', {
        serial: this.config.serial,
        duration: Date.now() - startTime,
        health
      });

      return health;

    } catch (error) {
      logger.error('Failed to get connection health', {
        serial: this.config.serial,
        error: (error as Error).message
      });

      return {
        isConnected: false,
        isUiAutomatorReady: false,
        lastSuccessfulCommand: this.commandStats.lastSuccessfulCommand,
        totalCommands: this.commandStats.totalCommands,
        failedCommands: this.commandStats.failedCommands,
        averageResponseTime: 0,
        uptime: Date.now() - this.connectionStartTime
      };
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  private updateCommandStats(duration: number, success: boolean): void {
    this.commandStats.totalCommands++;
    this.commandStats.totalResponseTime += duration;

    if (success) {
      this.commandStats.lastSuccessfulCommand = new Date().toISOString();
    } else {
      this.commandStats.failedCommands++;
    }

    this.commandStats.lastCommandTime = Date.now();
  }

  private countInteractiveElements(hierarchy: string): number {
    const interactiveRegex = /clickable="true"/g;
    const matches = hierarchy.match(interactiveRegex);
    return matches ? matches.length : 0;
  }

  private limitHierarchyDepth(hierarchy: string, maxDepth: number): string {
    const lines = hierarchy.split('\n');
    const limited: string[] = [];

    for (const line of lines) {
      const indent = line.match(/^(\s*)/)?.[1]?.length || 0;
      const depth = Math.floor(indent / 2);

      if (depth <= maxDepth) {
        limited.push(line);
      }
    }

    return limited.join('\n');
  }

  private filterHierarchyAttributes(hierarchy: string, attributes: string[]): string {
    let filtered = hierarchy;

    for (const attr of attributes) {
      const regex = new RegExp(`\\s+${attr}="[^"]*"`, 'g');
      filtered = filtered.replace(regex, '');
    }

    return filtered;
  }

  private compressHierarchy(hierarchy: string): string {
    // Remove empty lines and excessive whitespace
    return hierarchy
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .join('\n');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// Service Factory
// ============================================================================

let adbBridgeInstance: ADBBridgeService | null = null;

/**
 * Get singleton ADB Bridge service instance
 */
export function getADBBridgeService(config?: Partial<ADBBridgeConfig>): ADBBridgeService {
  if (!adbBridgeInstance) {
    adbBridgeInstance = new ADBBridgeService(config);
  }
  return adbBridgeInstance;
}

/**
 * Initialize ADB Bridge service
 */
export async function initializeADBBridge(config?: Partial<ADBBridgeConfig>): Promise<ADBBridgeService> {
  const service = getADBBridgeService(config);
  await service.initialize();
  return service;
}

/**
 * Close ADB Bridge service
 */
export async function closeADBBridge(): Promise<void> {
  if (adbBridgeInstance) {
    await adbBridgeInstance.close();
    adbBridgeInstance = null;
  }
}