/**
 * UI Introspection Service
 *
 * Android UI state capture via ADB commands with parallel execution.
 * Optimized for sub-1s capture performance.
 */

import { createADBConnection } from '../utils/adb';
import { parseUIHierarchy, extractSelectors, normalizeXML, generateXMLHash } from '../utils/xml';
import { generateStateId, generateDigest } from '../utils/hash';
import { StateRecord, SnapshotRequest, SnapshotResponse } from '../types/graph';
import { promises as fs } from 'fs';
import path from 'path';
import crypto from 'crypto';

export interface IntrospectionOptions extends SnapshotRequest {
  /** Capture timeout in milliseconds */
  timeout?: number;
  /** Skip screenshot capture */
  skipScreenshot?: boolean;
}

export interface CaptureResult {
  state: StateRecord;
  captureTime: number;
  merged: boolean;
  mergedInto?: string;
}

export class IntrospectionService {
  private adb = createADBConnection();

  /**
   * Capture current UI state with parallel ADB execution
   */
  async captureState(options: IntrospectionOptions = {}): Promise<CaptureResult> {
    const startTime = Date.now();
    const {
      forceScreenshot = false,
      tags = [],
      timeout = 5000,
      skipScreenshot = false
    } = options;

    try {
      // Execute ADB commands in parallel for optimal performance
      const [activity, xmlRaw, screenshot] = await Promise.all([
        this.getCurrentActivity(),
        this.getUIHierarchy(),
        skipScreenshot ? Promise.resolve(null) : this.captureScreenshot()
      ]);

      // Parse and normalize XML
      const xml = parseUIHierarchy(xmlRaw);
      if (!xml) {
        throw new Error('Failed to parse UI hierarchy XML');
      }

      const normalizedXML = normalizeXML(xml);
      const xmlHash = generateXMLHash(normalizedXML);

      // Extract selectors and visible text
      const selectors = extractSelectors(xml);
      const visibleText = this.extractVisibleText(xml);

      // Get package name from activity
      const packageName = this.extractPackageName(activity || '');

      // Generate state identifiers
      const digest = generateDigest(xmlHash, selectors, visibleText);
      const stateId = generateStateId(packageName, activity || 'Unknown', digest);

      // Determine screenshot filename
      let screenshotFile: string | undefined;
      if (screenshot && !skipScreenshot) {
        screenshotFile = await this.saveScreenshot(stateId, screenshot, forceScreenshot);
      }

      // Create state record
      const state: StateRecord = {
        id: stateId,
        package: packageName,
        activity: activity || 'Unknown',
        digest,
        selectors,
        visibleText,
        screenshot: screenshotFile,
        tags: tags.length > 0 ? tags : undefined,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        metadata: {
          captureMethod: 'adb',
          captureDuration: Date.now() - startTime,
          elementCount: selectors.length,
          hierarchyDepth: this.calculateHierarchyDepth(xml)
        }
      };

      const captureTime = Date.now() - startTime;

      return {
        state,
        captureTime,
        merged: false // Will be determined by graph service
      };
    } catch (error) {
      throw new Error(`State capture failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get current activity name
   */
  private async getCurrentActivity(): Promise<string | null> {
    try {
      return await this.adb.getCurrentActivity();
    } catch (error) {
      console.warn('Failed to get current activity:', error);
      return null;
    }
  }

  /**
   * Get UI hierarchy XML
   */
  private async getUIHierarchy(): Promise<string> {
    try {
      return await this.adb.getUIHierarchy();
    } catch (error) {
      throw new Error(`Failed to get UI hierarchy: ${error}`);
    }
  }

  /**
   * Capture screenshot
   */
  private async captureScreenshot(): Promise<Buffer | null> {
    try {
      return await this.adb.captureScreenshot();
    } catch (error) {
      console.warn('Failed to capture screenshot:', error);
      return null;
    }
  }

  /**
   * Save screenshot to file
   */
  private async saveScreenshot(
    stateId: string,
    screenshot: Buffer,
    force: boolean = false
  ): Promise<string> {
    const screenshotsDir = process.env.SCREENSHOTS_DIR || '/app/data/screenshots';
    const filename = `${stateId}.png`;
    const filepath = path.join(screenshotsDir, filename);

    // Check if file exists and force is false
    if (!force) {
      try {
        await fs.access(filepath);
        return filename; // File already exists
      } catch {
        // File doesn't exist, proceed with save
      }
    }

    // Ensure screenshots directory exists
    await fs.mkdir(screenshotsDir, { recursive: true });

    // Save screenshot
    await fs.writeFile(filepath, screenshot);
    return filename;
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
   * Calculate hierarchy depth
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
   * Validate device readiness
   */
  async validateDevice(): Promise<{
    connected: boolean;
    responsive: boolean;
    activity?: string;
    error?: string;
  }> {
    try {
      // Check device connection
      const connected = await this.adb.isDeviceConnected();
      if (!connected) {
        return {
          connected: false,
          responsive: false,
          error: 'Device not connected'
        };
      }

      // Check device responsiveness
      const startTime = Date.now();
      const activity = await this.getCurrentActivity();
      const responseTime = Date.now() - startTime;

      if (responseTime > 5000) {
        return {
          connected: true,
          responsive: false,
          activity: activity || undefined,
          error: 'Device response too slow'
        };
      }

      return {
        connected: true,
        responsive: true,
        activity: activity || undefined
      };
    } catch (error) {
      return {
        connected: false,
        responsive: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get device information
   */
  async getDeviceInfo(): Promise<{
    model?: string;
    version?: string;
    package?: string;
    activity?: string;
  }> {
    try {
      const properties = await this.adb.getDeviceProperties();
      const activity = await this.getCurrentActivity();

      return {
        model: properties['ro.product.model'],
        version: properties['ro.build.version.release'],
        package: activity ? this.extractPackageName(activity) : undefined,
        activity: activity || undefined
      };
    } catch (error) {
      console.warn('Failed to get device info:', error);
      return {};
    }
  }

  /**
   * Test capture performance
   */
  async testPerformance(iterations: number = 5): Promise<{
    averageTime: number;
    minTime: number;
    maxTime: number;
    successRate: number;
  }> {
    const times: number[] = let successes = 0;

    for (let i = 0; i < iterations; i++) {
      try {
        const startTime = Date.now();
        await this.captureState({ skipScreenshot: true });
        const duration = Date.now() - startTime;
        times.push(duration);
        successes++;
      } catch (error) {
        console.warn(`Performance test iteration ${i + 1} failed:`, error);
      }
    }

    if (times.length === 0) {
      return {
        averageTime: 0,
        minTime: 0,
        maxTime: 0,
        successRate: 0
      };
    }

    return {
      averageTime: times.reduce((sum, time) => sum + time, 0) / times.length,
      minTime: Math.min(...times),
      maxTime: Math.max(...times),
      successRate: successes / iterations
    };
  }

  /**
   * Cleanup resources
   */
  close(): void {
    this.adb.close();
  }
}

/**
 * Create singleton instance
 */
export const introspectionService = new IntrospectionService();

/**
 * Convenience function for state capture
 */
export async function captureState(options?: IntrospectionOptions): Promise<SnapshotResponse> {
  const result = await introspectionService.captureState(options);
  return {
    state: result.state,
    merged: result.merged,
    mergedInto: result.mergedInto
  };
}