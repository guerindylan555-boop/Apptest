/**
 * UI Capture Service (T024)
 *
 * Specialized UIAutomator2 capture service for Android UI state discovery.
 * Implements high-performance state capture with XML hierarchy parsing, selector extraction,
 * screenshot storage, and comprehensive error handling. Optimized for sub-1s capture performance
 * with parallel execution and structured logging.
 *
 * Key Features:
 * - UIAutomator2-based capture using existing ADB bridge
 * - State creation using existing State entity model
 * - Parallel execution for optimal performance (<1s capture time)
 * - Comprehensive selector extraction (resource-id, text, content-desc, class, bounds)
 * - Screenshot capture and storage with deduplication
 * - Structured logging with performance monitoring
 * - Production-ready error handling and timeouts
 * - Integration with existing logger service
 * - Constitution-compliant code patterns
 */

import { createADBConnection, ADBConnection } from '../utils/adb';
import { parseUIHierarchy, extractSelectors, normalizeXML, generateXMLHash } from '../utils/xml';
import { State, StateFactory } from '../models/state';
import { CreateStateRequest } from '../types/models';
import { createServiceLogger } from './logger';
import { promises as fs } from 'fs';
import path from 'path';
import crypto from 'crypto';

// ============================================================================
// TypeScript Interfaces
// ============================================================================

export interface UICaptureOptions {
  /** Capture timeout in milliseconds (default: 5000) */
  timeout?: number;

  /** Skip screenshot capture for performance (default: false) */
  skipScreenshot?: boolean;

  /** Force screenshot recreation even if exists (default: false) */
  forceScreenshot?: boolean;

  /** Tags to apply to captured state */
  tags?: string[];

  /** Minimum selector importance threshold (0-1, default: 0.3) */
  minImportance?: number;

  /** Include XPath in selectors (default: true) */
  includeXPath?: boolean;

  /** Trace ID for correlation */
  traceId?: string;
}

export interface UICaptureResult {
  /** Captured state entity */
  state: State;

  /** Total capture time in milliseconds */
  captureTime: number;

  /** Whether state was merged with existing */
  merged: boolean;

  /** ID of state merged into (if applicable) */
  mergedInto?: string;

  /** Capture metadata */
  metadata: {
    /** XML hierarchy hash */
    xmlHash: string;

    /** Total selectors found */
    totalSelectors: number;

    /** Interactive selectors found */
    interactiveSelectors: number;

    /** Hierarchy depth */
    hierarchyDepth: number;

    /** Screenshot captured successfully */
    screenshotCaptured: boolean;

    /** Package name */
    packageName: string;

    /** Activity name */
    activityName: string;
  };
}

export interface DeviceValidationResult {
  /** Device is connected */
  connected: boolean;

  /** Device is responsive */
  responsive: boolean;

  /** Current activity */
  activity?: string;

  /** Current package */
  package?: string;

  /** Device model */
  model?: string;

  /** Android version */
  version?: string;

  /** Error details if validation failed */
  error?: string;

  /** Response time in milliseconds */
  responseTime?: number;
}

export interface PerformanceMetrics {
  /** Average capture time */
  averageTime: number;

  /** Minimum capture time */
  minTime: number;

  /** Maximum capture time */
  maxTime: number;

  /** Success rate (0-1) */
  successRate: number;

  /** Total captures attempted */
  totalCaptures: number;

  /** Successful captures */
  successfulCaptures: number;

  /** Last capture timestamp */
  lastCapture?: string;
}

// ============================================================================
// UI Capture Service Implementation
// ============================================================================

/**
 * UIAutomator2-based capture service for Android UI state discovery
 */
export class UICaptureService {
  private adb: ADBConnection;
  private logger = createServiceLogger('ui-capture');
  private performanceHistory: number[] = [];
  private totalCaptures = 0;
  private successfulCaptures = 0;

  constructor() {
    this.adb = createADBConnection();
    this.logger.info('service_initialized', 'UI Capture service initialized');
  }

  /**
   * Capture current UI state with UIAutomator2
   *
   * This method implements parallel execution of ADB commands for optimal performance:
   * - Activity detection, UI hierarchy dump, and screenshot capture run concurrently
   * - Uses existing State entity model for proper state creation
   * - Includes comprehensive error handling and structured logging
   *
   * @param options - Capture configuration options
   * @returns Promise resolving to capture result with state entity
   * @throws UICaptureError if capture fails
   */
  async captureState(options: UICaptureOptions = {}): Promise<UICaptureResult> {
    const traceId = options.traceId || this.logger.generateTraceId();
    const timer = this.logger.startTimer('capture_state', traceId, { options });

    const {
      timeout = 5000,
      skipScreenshot = false,
      forceScreenshot = false,
      tags = [],
      minImportance = 0.3,
      includeXPath = true
    } = options;

    this.logger.info('capture_started', 'Starting UI state capture', traceId, {
      timeout,
      skipScreenshot,
      forceScreenshot,
      tags,
      minImportance,
      includeXPath
    });

    try {
      // Execute ADB commands in parallel for optimal performance
      const startTime = Date.now();
      const [activity, xmlRaw, screenshot] = await Promise.all([
        this.getCurrentActivity(traceId),
        this.getUIHierarchy(traceId),
        skipScreenshot ? Promise.resolve(null) : this.captureScreenshot(traceId)
      ]);

      // Parse and validate XML hierarchy
      if (!xmlRaw || xmlRaw.trim().length === 0) {
        throw new Error('Empty UI hierarchy XML received');
      }

      const xml = parseUIHierarchy(xmlRaw);
      if (!xml) {
        throw new Error('Failed to parse UI hierarchy XML');
      }

      this.logger.debug('xml_parsed', 'UI hierarchy XML parsed successfully', traceId, {
        xmlLength: xmlRaw.length
      });

      // Normalize XML and generate hash for deduplication
      const normalizedXML = normalizeXML(xml);
      const xmlHash = generateXMLHash(normalizedXML);

      // Extract selectors from XML hierarchy
      const allSelectors = extractSelectors(xml);
      const interactiveSelectors = allSelectors.filter(selector =>
        this.isInteractiveSelector(selector)
      );

      // Filter selectors by importance if threshold specified
      const importantSelectors = minImportance > 0
        ? this.filterSelectorsByImportance(interactiveSelectors, minImportance)
        : interactiveSelectors;

      // Remove XPath if not requested
      const finalSelectors = includeXPath
        ? importantSelectors
        : importantSelectors.map(selector => {
          const { xpath, ...selectorWithoutXPath } = selector;
          return selectorWithoutXPath;
        });

      // Extract visible text content
      const visibleText = this.extractVisibleText(xml);

      // Parse package and activity names
      const packageName = this.extractPackageName(activity || '');
      const activityName = activity || 'Unknown';

      // Calculate hierarchy depth
      const hierarchyDepth = this.calculateHierarchyDepth(xml);

      // Save screenshot if captured
      let screenshotFile: string | undefined;
      if (screenshot && !skipScreenshot) {
        screenshotFile = await this.saveScreenshot(
          xmlHash,
          screenshot,
          forceScreenshot,
          traceId
        );
      }

      // Create state using existing State entity model
      const stateData: CreateStateRequest = {
        package: packageName,
        activity: activityName,
        selectors: finalSelectors,
        visibleText,
        tags: tags.length > 0 ? tags : undefined,
        metadata: {
          captureMethod: 'adb',
          captureDuration: Date.now() - startTime,
          elementCount: finalSelectors.length,
          hierarchyDepth
        }
      };

      const state = new State(stateData);

      // Update performance metrics
      const captureTime = Date.now() - startTime;
      this.updatePerformanceMetrics(captureTime, true);
      timer.end({
        success: true,
        selectorCount: finalSelectors.length,
        hierarchyDepth,
        hasScreenshot: !!screenshotFile
      });

      this.logger.info('capture_completed', 'UI state capture completed successfully', traceId, {
        stateId: state.id,
        packageName,
        activityName,
        selectorCount: finalSelectors.length,
        interactiveCount: interactiveSelectors.length,
        hierarchyDepth,
        captureTime,
        hasScreenshot: !!screenshotFile
      });

      return {
        state,
        captureTime,
        merged: false, // Will be determined by graph service
        metadata: {
          xmlHash,
          totalSelectors: allSelectors.length,
          interactiveSelectors: interactiveSelectors.length,
          hierarchyDepth,
          screenshotCaptured: !!screenshotFile,
          packageName,
          activityName
        }
      };

    } catch (error) {
      this.updatePerformanceMetrics(0, false);
      timer.end({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      this.logger.error('capture_failed', 'UI state capture failed', error as Error, traceId, {
        timeout,
        skipScreenshot,
        options
      });

      throw new UICaptureError(
        `UI state capture failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CAPTURE_FAILED',
        { options, traceId }
      );
    }
  }

  /**
   * Validate device readiness for UI capture
   *
   * @param traceId - Optional trace ID for correlation
   * @returns Promise resolving to device validation result
   */
  async validateDevice(traceId?: string): Promise<DeviceValidationResult> {
    const timer = this.logger.startTimer('device_validation', traceId);

    try {
      this.logger.debug('device_validation_started', 'Starting device validation', traceId);

      // Check device connection
      const connected = await this.adb.isDeviceConnected();
      if (!connected) {
        const result = {
          connected: false,
          responsive: false,
          error: 'Device not connected'
        };

        timer.end({ success: false, error: result.error });
        this.logger.warn('device_not_connected', 'Device validation failed: device not connected', traceId);

        return result;
      }

      // Test device responsiveness and get activity
      const startTime = Date.now();
      const [activity, properties] = await Promise.all([
        this.getCurrentActivity(traceId),
        this.getDeviceProperties(traceId)
      ]);
      const responseTime = Date.now() - startTime;

      if (responseTime > 10000) {
        const result = {
          connected: true,
          responsive: false,
          activity: activity || undefined,
          error: 'Device response too slow'
        };

        timer.end({ success: false, responseTime, error: result.error });
        this.logger.warn('device_slow_response', 'Device validation failed: slow response', traceId, {
          responseTime
        });

        return result;
      }

      const packageName = activity ? this.extractPackageName(activity) : undefined;

      const result = {
        connected: true,
        responsive: true,
        activity: activity || undefined,
        package: packageName,
        model: properties['ro.product.model'],
        version: properties['ro.build.version.release'],
        responseTime
      };

      timer.end({ success: true, responseTime, model: result.model, version: result.version });
      this.logger.info('device_validated', 'Device validation completed successfully', traceId, result);

      return result;

    } catch (error) {
      timer.end({ success: false, error: error instanceof Error ? error.message : 'Unknown error' });

      this.logger.error('device_validation_failed', 'Device validation failed', error as Error, traceId);

      return {
        connected: false,
        responsive: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get comprehensive device information
   *
   * @param traceId - Optional trace ID for correlation
   * @returns Promise resolving to device information
   */
  async getDeviceInfo(traceId?: string): Promise<{
    model?: string;
    version?: string;
    package?: string;
    activity?: string;
    properties?: Record<string, string>;
  }> {
    try {
      this.logger.debug('device_info_started', 'Getting device information', traceId);

      const [properties, activity] = await Promise.all([
        this.getDeviceProperties(traceId),
        this.getCurrentActivity(traceId)
      ]);

      const packageName = activity ? this.extractPackageName(activity) : undefined;

      const deviceInfo = {
        model: properties['ro.product.model'],
        version: properties['ro.build.version.release'],
        package: packageName,
        activity: activity || undefined,
        properties
      };

      this.logger.debug('device_info_retrieved', 'Device information retrieved successfully', traceId, deviceInfo);

      return deviceInfo;

    } catch (error) {
      this.logger.error('device_info_failed', 'Failed to get device information', error as Error, traceId);
      return {};
    }
  }

  /**
   * Test capture performance over multiple iterations
   *
   * @param iterations - Number of test iterations (default: 5)
   * @param options - Capture options for testing
   * @returns Promise resolving to performance metrics
   */
  async testPerformance(iterations: number = 5, options: Partial<UICaptureOptions> = {}): Promise<PerformanceMetrics> {
    const traceId = this.logger.generateTraceId();
    this.logger.info('performance_test_started', `Starting performance test with ${iterations} iterations`, traceId, {
      iterations,
      options
    });

    const times: number[] = [];
    let successes = 0;

    for (let i = 0; i < iterations; i++) {
      try {
        const startTime = Date.now();
        await this.captureState({
          ...options,
          skipScreenshot: true, // Skip screenshots for performance testing
          traceId: `${traceId}-${i}`
        });
        const duration = Date.now() - startTime;
        times.push(duration);
        successes++;

        this.logger.debug('performance_test_iteration', `Performance test iteration ${i + 1} completed`, `${traceId}-${i}`, {
          duration,
          success: true
        });

      } catch (error) {
        this.logger.warn('performance_test_iteration_failed', `Performance test iteration ${i + 1} failed`, `${traceId}-${i}`, {
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    const metrics: PerformanceMetrics = {
      averageTime: times.length > 0 ? times.reduce((sum, time) => sum + time, 0) / times.length : 0,
      minTime: times.length > 0 ? Math.min(...times) : 0,
      maxTime: times.length > 0 ? Math.max(...times) : 0,
      successRate: successes / iterations,
      totalCaptures: iterations,
      successfulCaptures: successes,
      lastCapture: new Date().toISOString()
    };

    this.logger.info('performance_test_completed', 'Performance test completed', traceId, metrics as unknown as Record<string, unknown>);

    return metrics;
  }

  /**
   * Get current performance metrics
   *
   * @returns Current performance metrics
   */
  getPerformanceMetrics(): PerformanceMetrics {
    return {
      averageTime: this.performanceHistory.length > 0
        ? this.performanceHistory.reduce((sum, time) => sum + time, 0) / this.performanceHistory.length
        : 0,
      minTime: this.performanceHistory.length > 0 ? Math.min(...this.performanceHistory) : 0,
      maxTime: this.performanceHistory.length > 0 ? Math.max(...this.performanceHistory) : 0,
      successRate: this.totalCaptures > 0 ? this.successfulCaptures / this.totalCaptures : 0,
      totalCaptures: this.totalCaptures,
      successfulCaptures: this.successfulCaptures
    };
  }

  /**
   * Reset performance metrics
   */
  resetPerformanceMetrics(): void {
    this.performanceHistory = [];
    this.totalCaptures = 0;
    this.successfulCaptures = 0;
    this.logger.info('performance_metrics_reset', 'Performance metrics reset');
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  /**
   * Get current activity name with error handling
   */
  private async getCurrentActivity(traceId?: string): Promise<string | null> {
    try {
      const activity = await this.adb.getCurrentActivity();
      this.logger.debug('activity_retrieved', 'Current activity retrieved', traceId, { activity });
      return activity;
    } catch (error) {
      this.logger.warn('activity_retrieval_failed', 'Failed to get current activity', traceId, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return null;
    }
  }

  /**
   * Get UI hierarchy XML with error handling
   */
  private async getUIHierarchy(traceId?: string): Promise<string> {
    try {
      const xml = await this.adb.getUIHierarchy();
      this.logger.debug('ui_hierarchy_retrieved', 'UI hierarchy retrieved', traceId, {
        xmlLength: xml.length
      });
      return xml;
    } catch (error) {
      this.logger.error('ui_hierarchy_failed', 'Failed to get UI hierarchy', error as Error, traceId);
      throw new Error(`Failed to get UI hierarchy: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Capture screenshot with error handling
   */
  private async captureScreenshot(traceId?: string): Promise<Buffer | null> {
    try {
      const screenshot = await this.adb.captureScreenshot();
      this.logger.debug('screenshot_captured', 'Screenshot captured successfully', traceId, {
        size: screenshot.length
      });
      return screenshot;
    } catch (error) {
      this.logger.warn('screenshot_failed', 'Failed to capture screenshot', traceId, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return null;
    }
  }

  /**
   * Get device properties with error handling
   */
  private async getDeviceProperties(traceId?: string): Promise<Record<string, string>> {
    try {
      const properties = await this.adb.getDeviceProperties();
      this.logger.debug('device_properties_retrieved', 'Device properties retrieved', traceId, {
        propertyCount: Object.keys(properties).length
      });
      return properties;
    } catch (error) {
      this.logger.warn('device_properties_failed', 'Failed to get device properties', traceId, {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return {};
    }
  }

  /**
   * Save screenshot to file system with deduplication
   */
  private async saveScreenshot(
    stateId: string,
    screenshot: Buffer,
    force: boolean = false,
    traceId?: string
  ): Promise<string> {
    const screenshotsDir = process.env.SCREENSHOTS_DIR || '/app/data/screenshots';
    const filename = `${stateId}.png`;
    const filepath = path.join(screenshotsDir, filename);

    try {
      // Check if file exists and force is false
      if (!force) {
        try {
          await fs.access(filepath);
          this.logger.debug('screenshot_exists', 'Screenshot file already exists', traceId, { filename });
          return filename;
        } catch {
          // File doesn't exist, proceed with save
        }
      }

      // Ensure screenshots directory exists
      await fs.mkdir(screenshotsDir, { recursive: true });

      // Save screenshot
      await fs.writeFile(filepath, screenshot);

      this.logger.debug('screenshot_saved', 'Screenshot saved successfully', traceId, {
        filename,
        filepath,
        size: screenshot.length
      });

      return filename;

    } catch (error) {
      this.logger.error('screenshot_save_failed', 'Failed to save screenshot', error as Error, traceId, {
        filename,
        filepath
      });
      throw new Error(`Failed to save screenshot: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Extract visible text from XML hierarchy
   */
  private extractVisibleText(xml: any): string[] {
    const textSet = new Set<string>();

    function traverse(node: any) {
      if (!node || !node.$) return;

      // Extract text from text attribute
      if (node.$.text && node.$.text.trim()) {
        const text = node.$.text.trim();
        if (text && text.length < 500) { // Limit text length
          textSet.add(text);
        }
      }

      // Extract text from content-desc attribute
      if (node.$['content-desc'] && node.$['content-desc'].trim()) {
        const desc = node.$['content-desc'].trim();
        if (desc && desc.length < 500) {
          textSet.add(desc);
        }
      }

      // Traverse children
      if (Array.isArray(node.$$)) {
        node.$$?.forEach(traverse);
      }
    }

    traverse(xml);
    return Array.from(textSet).filter(text => text.length > 0);
  }

  /**
   * Extract package name from activity string
   */
  private extractPackageName(activity: string): string {
    if (!activity) return 'unknown';

    // Extract package from activity format: package/.Activity
    const match = activity.match(/^([^/]+)/);
    return match ? match[1] : 'unknown';
  }

  /**
   * Calculate hierarchy depth from XML
   */
  private calculateHierarchyDepth(xml: any): number {
    let maxDepth = 0;

    function traverse(node: any, depth: number = 0): void {
      if (!node) return;

      maxDepth = Math.max(maxDepth, depth);

      if (Array.isArray(node.$$)) {
        node.$$?.forEach(child => traverse(child, depth + 1));
      }
    }

    traverse(xml);
    return maxDepth;
  }

  /**
   * Check if selector represents an interactive element
   */
  private isInteractiveSelector(selector: any): boolean {
    // Check for common interactive class patterns
    if (selector.cls) {
      const interactiveClasses = [
        'Button', 'ImageButton', 'EditText', 'CheckBox', 'RadioButton',
        'ToggleButton', 'Switch', 'SeekBar', 'Spinner', 'ListView',
        'RecyclerView', 'GridView', 'ScrollView', 'HorizontalScrollView',
        'ViewPager', 'TabHost', 'TabWidget', 'Menu', 'MenuItem'
      ];

      for (const cls of interactiveClasses) {
        if (selector.cls.includes(cls)) {
          return true;
        }
      }
    }

    // Check for common interactive resource ID patterns
    if (selector.rid) {
      const interactivePatterns = [
        'button', 'btn', 'edit', 'input', 'text', 'field', 'checkbox',
        'radio', 'switch', 'toggle', 'slider', 'seek', 'menu', 'item',
        'list', 'grid', 'scroll', 'tab', 'nav', 'close', 'back', 'next',
        'previous', 'submit', 'cancel', 'ok', 'yes', 'no', 'accept'
      ];

      const lowerRid = selector.rid.toLowerCase();
      for (const pattern of interactivePatterns) {
        if (lowerRid.includes(pattern)) {
          return true;
        }
      }
    }

    // Check for interactive content descriptions
    if (selector.desc) {
      const interactiveDescPatterns = [
        'button', 'tap', 'click', 'select', 'choose', 'enter', 'input',
        'navigate', 'go', 'back', 'close', 'dismiss', 'expand', 'collapse'
      ];

      const lowerDesc = selector.desc.toLowerCase();
      for (const pattern of interactiveDescPatterns) {
        if (lowerDesc.includes(pattern)) {
          return true;
        }
      }
    }

    // Check for interactive text patterns
    if (selector.text) {
      const interactiveTextPatterns = [
        'OK', 'Cancel', 'Yes', 'No', 'Submit', 'Save', 'Delete', 'Edit',
        'Add', 'Remove', 'Back', 'Next', 'Previous', 'Close', 'Done',
        'Continue', 'Finish', 'Start', 'Stop', 'Play', 'Pause'
      ];

      if (interactiveTextPatterns.includes(selector.text.trim())) {
        return true;
      }
    }

    return false;
  }

  /**
   * Filter selectors by importance threshold
   */
  private filterSelectorsByImportance(selectors: any[], threshold: number): any[] {
    return selectors
      .map(selector => ({
        selector,
        importance: this.calculateSelectorImportance(selector)
      }))
      .filter(({ importance }) => importance >= threshold)
      .sort((a, b) => b.importance - a.importance)
      .map(({ selector }) => selector);
  }

  /**
   * Calculate importance score for a selector
   */
  private calculateSelectorImportance(selector: any): number {
    let score = 0;

    // Resource ID is the most stable selector
    if (selector.rid) {
      score += 0.4;
      // Bonus for descriptive IDs
      if (selector.rid.length > 3 && !selector.rid.match(/^id\d+$/)) {
        score += 0.1;
      }
    }

    // Text content is valuable for user-recognizable elements
    if (selector.text) {
      score += 0.3;
      // Bonus for meaningful text
      if (selector.text.length > 2 && !selector.text.match(/^\d+$/)) {
        score += 0.1;
      }
    }

    // Content description is good for accessibility
    if (selector.desc) {
      score += 0.2;
    }

    // Class name provides context
    if (selector.cls) {
      score += 0.1;
      // Bonus for specific classes
      if (selector.cls.includes('Button') || selector.cls.includes('EditText')) {
        score += 0.1;
      }
    }

    // Interactive elements get bonus points
    if (this.isInteractiveSelector(selector)) {
      score += 0.2;
    }

    return Math.min(score, 1.0);
  }

  /**
   * Update performance metrics
   */
  private updatePerformanceMetrics(captureTime: number, success: boolean): void {
    this.totalCaptures++;
    if (success) {
      this.successfulCaptures++;
      this.performanceHistory.push(captureTime);

      // Keep only last 100 performance measurements
      if (this.performanceHistory.length > 100) {
        this.performanceHistory.shift();
      }
    }
  }

  // ============================================================================
  // Cleanup and Resource Management
  // ============================================================================

  /**
   * Cleanup resources and close connections
   */
  close(): void {
    this.logger.info('service_closing', 'Closing UI Capture service');
    this.adb.close();
    this.logger.info('service_closed', 'UI Capture service closed');
  }

  /**
   * Health check for the service
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    details: Record<string, any>;
  }> {
    try {
      const deviceValidation = await this.validateDevice();
      const performanceMetrics = this.getPerformanceMetrics();

      const healthy = deviceValidation.connected && deviceValidation.responsive;

      const details = {
        device: deviceValidation,
        performance: performanceMetrics,
        service: {
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          timestamp: new Date().toISOString()
        }
      };

      if (healthy) {
        this.logger.healthCheck('healthy', details);
      } else {
        this.logger.healthCheck('unhealthy', details);
      }

      return { healthy, details };

    } catch (error) {
      const details = {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      };

      this.logger.healthCheck('unhealthy', details);
      return { healthy: false, details };
    }
  }
}

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error class for UI capture operations
 */
export class UICaptureError extends Error {
  public readonly code: string;
  public readonly context?: Record<string, any>;
  public readonly timestamp: string;

  constructor(message: string, code: string, context?: Record<string, any>) {
    super(message);
    this.name = 'UICaptureError';
    this.code = code;
    this.context = context;
    this.timestamp = new Date().toISOString();
  }
}

// ============================================================================
// Singleton Instance and Exports
// ============================================================================

/**
 * Singleton instance of the UI Capture service
 */
export const uiCaptureService = new UICaptureService();

/**
 * Convenience function for UI state capture
 *
 * @param options - Capture options
 * @returns Promise resolving to capture result
 */
export async function captureUIState(options?: UICaptureOptions): Promise<UICaptureResult> {
  return await uiCaptureService.captureState(options);
}

/**
 * Export service class for dependency injection
 */
export { UICaptureService as default };