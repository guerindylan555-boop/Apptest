import { spawnSync, type SpawnSyncOptions } from 'child_process';
import crypto from 'crypto';
import { logger } from './logger';
import { adb, type RunOptions } from './androidCli';

/**
 * Enhanced UI State Capture Service
 *
 * Provides high-performance Android UI state capture with sub-1s latency
 * and advanced state identification algorithms.
 */

export interface UiStateCaptureOptions extends RunOptions {
  /** Include XML normalization for stable hashing */
  normalizeForStability?: boolean;
  /** Generate selectors for interactive elements */
  generateSelectors?: boolean;
  /** Include performance metrics */
  includeMetrics?: boolean;
  /** Maximum XML buffer size (default: 4MB) */
  maxXmlBuffer?: number;
  /** Maximum screenshot buffer size (default: 10MB) */
  maxScreenshotBuffer?: number;
}

export interface UiStateCaptureResult {
  /** Unique hash of the UI state */
  hash: string;
  /** Raw UI hierarchy XML */
  xml: string;
  /** Normalized XML for stable comparison */
  normalizedXml?: string;
  /** Screenshot data as PNG buffer */
  screenshot: Buffer;
  /** Current activity name */
  currentActivity: string | null;
  /** Extracted selectors for interactive elements */
  selectors?: string[];
  /** Performance metrics */
  metrics?: {
    /** Total capture time in milliseconds */
    totalTime: number;
    /** XML capture time in milliseconds */
    xmlCaptureTime: number;
    /** Screenshot capture time in milliseconds */
    screenshotCaptureTime: number;
    /** Processing time in milliseconds */
    processingTime: number;
  };
  /** Capture timestamp */
  capturedAt: string;
  /** Device serial number */
  deviceSerial: string;
}

/**
 * Main UI state capture function with sub-1s performance target
 */
export async function captureUiState(
  serial: string,
  options: UiStateCaptureOptions = {}
): Promise<UiStateCaptureResult> {
  const {
    normalizeForStability = true,
    generateSelectors = true,
    includeMetrics = true,
    maxXmlBuffer = 4 * 1024 * 1024,
    maxScreenshotBuffer = 10 * 1024 * 1024,
    timeoutMs = 5000,
    ...runOptions
  } = options;

  const startTime = Date.now();
  const deviceArgs = ['-s', serial];

  try {
    logger.info('Starting UI state capture', { serial, includeMetrics });

    // Parallel capture of XML, screenshot, and activity info
    const capturePromises = [
      captureUiXml(deviceArgs, { timeoutMs, maxBuffer: maxXmlBuffer, ...runOptions }),
      captureScreenshot(deviceArgs, { timeoutMs, maxBuffer: maxScreenshotBuffer, ...runOptions }),
      getCurrentActivity(deviceArgs, { timeoutMs: 2000, ...runOptions })
    ];

    const captureResults = await Promise.allSettled(capturePromises);
    const [xmlResult, screenshotResult, activityResult] = captureResults;

    const xmlCaptureTime = Date.now() - startTime;

    // Handle capture results
    if (xmlResult.status === 'rejected') {
      throw new Error(`UI XML capture failed: ${xmlResult.reason}`);
    }
    if (screenshotResult.status === 'rejected') {
      throw new Error(`Screenshot capture failed: ${screenshotResult.reason}`);
    }

    const xml = xmlResult.value;
    const screenshot = screenshotResult.value;
    const currentActivity = activityResult.status === 'fulfilled' ? activityResult.value : null;

    const screenshotCaptureTime = Date.now() - startTime - xmlCaptureTime;

    // Processing phase
    const processingStartTime = Date.now();
    let normalizedXml: string | undefined;
    let selectors: string[] | undefined;
    let hash: string;

    if (normalizeForStability) {
      normalizedXml = normalizeXmlForDigest(xml);
      hash = createStableDigest(normalizedXml);
    } else {
      hash = createBasicDigest(xml);
    }

    if (generateSelectors) {
      selectors = extractStableSelectors(xml);
    }

    const processingTime = Date.now() - processingStartTime;
    const totalTime = Date.now() - startTime;

    const result: UiStateCaptureResult = {
      hash,
      xml,
      screenshot,
      currentActivity,
      capturedAt: new Date().toISOString(),
      deviceSerial: serial
    };

    if (normalizedXml) result.normalizedXml = normalizedXml;
    if (selectors) result.selectors = selectors;
    if (includeMetrics) {
      result.metrics = {
        totalTime,
        xmlCaptureTime,
        screenshotCaptureTime,
        processingTime
      };
    }

    logger.info('UI state capture completed successfully', {
      serial,
      hash,
      totalTime,
      underOneSecond: totalTime < 1000,
      xmlSize: xml.length,
      screenshotSize: screenshot.length
    });

    return result;

  } catch (error) {
    const totalTime = Date.now() - startTime;
    logger.error('UI state capture failed', {
      serial,
      totalTime,
      error: (error as Error).message,
      stack: (error as Error).stack
    });
    throw error;
  }
}

/**
 * Capture UI hierarchy XML using optimal ADB commands
 */
async function captureUiXml(
  deviceArgs: string[],
  options: RunOptions & { maxBuffer?: number } = {}
): Promise<string> {
  const { maxBuffer = 4 * 1024 * 1024, timeoutMs = 5000, ...runOptions } = options;

  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const process = spawn('adb', [...deviceArgs, 'exec-out', 'uiautomator', 'dump', '/dev/tty'], {
      encoding: 'utf8',
      maxBuffer,
      timeout: timeoutMs,
      ...runOptions
    });

    let stdout = '';
    let stderr = '';

    process.stdout?.on('data', (data) => {
      stdout += data;
    });

    process.stderr?.on('data', (data) => {
      stderr += data;
    });

    process.on('error', (error) => {
      reject(error);
    });

    process.on('close', (code) => {
      const duration = Date.now() - startTime;

      if (code !== 0) {
        reject(new Error(`UI dump failed with code ${code}: ${stderr}`));
        return;
      }

      const cleaned = stdout.replace(/^UI hierarchy dumped to:.*$/gm, '').trim();

      if (!cleaned) {
        reject(new Error('Empty UI hierarchy captured'));
        return;
      }

      logger.debug('UI XML capture completed', { duration, size: cleaned.length });
      resolve(cleaned);
    });
  });
}

/**
 * Capture screenshot using optimal ADB commands
 */
async function captureScreenshot(
  deviceArgs: string[],
  options: RunOptions & { maxBuffer?: number } = {}
): Promise<Buffer> {
  const { maxBuffer = 10 * 1024 * 1024, timeoutMs = 5000, ...runOptions } = options;

  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const process = spawn('adb', [...deviceArgs, 'exec-out', 'screencap', '-p'], {
      encoding: 'binary',
      maxBuffer,
      timeout: timeoutMs,
      ...runOptions
    });

    let stdout: Buffer[] = [];
    let stderr = '';

    process.stdout?.on('data', (data) => {
      stdout.push(Buffer.from(data, 'binary'));
    });

    process.stderr?.on('data', (data) => {
      stderr += data;
    });

    process.on('error', (error) => {
      reject(error);
    });

    process.on('close', (code) => {
      const duration = Date.now() - startTime;

      if (code !== 0) {
        reject(new Error(`Screenshot capture failed with code ${code}: ${stderr}`));
        return;
      }

      const screenshot = Buffer.concat(stdout);

      if (screenshot.length === 0) {
        reject(new Error('Empty screenshot captured'));
        return;
      }

      logger.debug('Screenshot capture completed', { duration, size: screenshot.length });
      resolve(screenshot);
    });
  });
}

/**
 * Get current activity name with optimized approach
 */
async function getCurrentActivity(
  deviceArgs: string[],
  options: RunOptions = {}
): Promise<string | null> {
  try {
    const { stdout } = await adb([...deviceArgs, 'shell', 'dumpsys', 'activity', 'activities'], {
      timeoutMs: 3000,
      ...options
    });

    const match = stdout.match(/mResumedActivity[^:]+:\s+([^\\s]+)/);
    if (match) {
      const activity = match[1];
      logger.debug('Current activity resolved', { activity });
      return activity;
    }

    return null;

  } catch (error) {
    logger.warn('Failed to get current activity', {
      error: (error as Error).message
    });
    return null;
  }
}

/**
 * Normalize XML for stable digest creation
 */
function normalizeXmlForDigest(xml: string): string {
  return xml
    // Remove volatile attributes that change between captures
    .replace(/\s+instance="[^"]*"/g, '')
    .replace(/\s+focused="[^"]*"/g, '')
    .replace(/\s+selected="[^"]*"/g, '')
    .replace(/\s+pressed="[^"]*"/g, '')
    .replace(/\s+checked="[^"]*"/g, '')
    .replace(/\s+enabled="[^"]*"/g, '')
    // Remove dynamic IDs and indices
    .replace(/\s+NAF="[^"]*"/g, '')
    .replace(/\s+idx="\d+"/g, '')
    .replace(/\s+index="\d+"/g, '')
    // Remove layout-specific attributes that can vary
    .replace(/\s+bounds="[^"]*"/g, '')
    // Normalize whitespace
    .replace(/\s+/g, ' ')
    .replace(/>\s+</g, '><')
    .replace(/\s+\/>/g, '/>')
    .trim();
}

/**
 * Create basic SHA1 hash (for comparison)
 */
function createBasicDigest(xml: string): string {
  return crypto.createHash('sha1').update(xml).digest('hex');
}

/**
 * Create stable SHA256 hash for normalized XML
 */
function createStableDigest(normalizedXml: string): string {
  return crypto.createHash('sha256').update(normalizedXml).digest('hex');
}

/**
 * Extract stable selectors from UI XML
 */
function extractStableSelectors(xml: string): string[] {
  const selectors: string[] = [];
  const seenSelectors = new Set<string>();

  // Extract all node elements
  const nodes = xml.match(/<node[^>]*>/g) || [];

  for (const node of nodes) {
    const attrs = parseNodeAttributes(node);

    // Skip non-interactive elements
    if (attrs.clickable !== 'true' && attrs['long-clickable'] !== 'true') {
      continue;
    }

    // Create stable selector based on priority
    let selector = '';

    // 1. Resource ID (highest priority - most stable)
    if (attrs['resource-id'] &&
        attrs['resource-id'].includes('/') &&
        !attrs['resource-id'].includes('id/')) {
      selector = `resource-id="${attrs['resource-id']}"`;
    }
    // 2. Content description (second priority)
    else if (attrs['content-desc'] &&
             attrs['content-desc'].length > 0 &&
             attrs['content-desc'].length < 100) {
      selector = `content-desc="${attrs['content-desc']}"`;
    }
    // 3. Text content (if reasonable length)
    else if (attrs.text &&
             attrs.text.length > 0 &&
             attrs.text.length < 50 &&
             !attrs.text.match(/^\d+$/)) { // Avoid pure numbers
      selector = `text="${attrs.text}"`;
    }
    // 4. Class name with minimal context
    else if (attrs.class) {
      const className = attrs.class.split('.').pop() || 'Unknown';
      selector = `class="${className}"`;
    }

    if (selector && !seenSelectors.has(selector)) {
      seenSelectors.add(selector);
      selectors.push(selector);
    }
  }

  logger.debug('Selectors extracted', { count: selectors.length });
  return selectors;
}

/**
 * Parse node attributes from XML snippet
 */
function parseNodeAttributes(nodeSnippet: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  const regex = /([a-zA-Z0-9\-\_:]+)="([^"]*)"/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(nodeSnippet))) {
    attributes[match[1]] = match[2];
  }

  return attributes;
}

/**
 * Batch capture multiple states for performance comparison
 */
export async function batchCaptureUiState(
  serial: string,
  count: number = 5,
  intervalMs: number = 200,
  options: UiStateCaptureOptions = {}
): Promise<UiStateCaptureResult[]> {
  logger.info('Starting batch UI state capture', { serial, count, intervalMs });

  const results: UiStateCaptureResult[] = [];

  for (let i = 0; i < count; i++) {
    try {
      const result = await captureUiState(serial, options);
      results.push(result);

      if (i < count - 1 && intervalMs > 0) {
        await new Promise(resolve => setTimeout(resolve, intervalMs));
      }
    } catch (error) {
      logger.warn(`Batch capture failed at index ${i}`, {
        serial,
        error: (error as Error).message
      });
      break;
    }
  }

  logger.info('Batch UI state capture completed', {
    serial,
    requested: count,
    successful: results.length,
    avgTime: results.length > 0 ?
      results.reduce((sum, r) => sum + (r.metrics?.totalTime || 0), 0) / results.length : 0
  });

  return results;
}

/**
 * Compare two UI states for similarity
 */
export function compareUiStates(
  state1: UiStateCaptureResult,
  state2: UiStateCaptureResult
): {
  identical: boolean;
  xmlSimilarity: number;
  selectorSimilarity: number;
  activityChanged: boolean;
  hashChanged: boolean;
} {
  const identical = state1.hash === state2.hash;
  const activityChanged = state1.currentActivity !== state2.currentActivity;
  const hashChanged = state1.hash !== state2.hash;

  // Calculate XML similarity (simple text diff)
  const xmlSimilarity = calculateTextSimilarity(
    state1.normalizedXml || state1.xml,
    state2.normalizedXml || state2.xml
  );

  // Calculate selector similarity
  const selectorSimilarity = calculateArraySimilarity(
    state1.selectors || [],
    state2.selectors || []
  );

  return {
    identical,
    xmlSimilarity,
    selectorSimilarity,
    activityChanged,
    hashChanged
  };
}

/**
 * Calculate text similarity (0-1 scale)
 */
function calculateTextSimilarity(text1: string, text2: string): number {
  if (text1 === text2) return 1.0;

  const longer = text1.length > text2.length ? text1 : text2;
  const shorter = text1.length > text2.length ? text2 : text1;

  if (longer.length === 0) return 1.0;

  const editDistance = calculateLevenshteinDistance(longer, shorter);
  return (longer.length - editDistance) / longer.length;
}

/**
 * Calculate array similarity (0-1 scale)
 */
function calculateArraySimilarity(array1: string[], array2: string[]): number {
  if (array1.length === 0 && array2.length === 0) return 1.0;

  const set1 = new Set(array1);
  const set2 = new Set(array2);
  const intersection = [...set1].filter(item => set2.has(item));
  const union = new Set([...array1, ...array2]);

  return intersection.length / union.length;
}

/**
 * Calculate Levenshtein distance
 */
function calculateLevenshteinDistance(str1: string, str2: string): number {
  const matrix: number[][] = [];

  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[str2.length][str1.length];
}