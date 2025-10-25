/**
 * State Hash Utilities
 *
 * SHA256 hash generation for UI states with stable algorithms.
 * Used for state deduplication and identification.
 */

import { createHash } from 'crypto';
import { StateRecord, Selector } from '../types/graph';

/**
 * Generate state ID from package, activity, and digest
 */
export function generateStateId(
  packageName: string,
  activity: string,
  digest: string
): string {
  const input = `${packageName}:${activity}:${digest}`;
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Generate digest from UI hierarchy and selectors
 */
export function generateDigest(
  xmlHash: string,
  selectors: Selector[],
  visibleText: string[]
): string {
  // Create normalized selector representation
  const normalizedSelectors = selectors
    .sort((a, b) => {
      // Sort by priority: rid > desc > text > cls > bounds
      const priority = (s: Selector) => [
        s.rid ? 1 : 0,
        s.desc ? 1 : 0,
        s.text ? 1 : 0,
        s.cls ? 1 : 0,
        s.bounds ? 1 : 0
      ].join('');

      return priority(b).localeCompare(priority(a));
    })
    .map(selector => {
      const parts = [];
      if (selector.rid) parts.push(`rid:${selector.rid}`);
      if (selector.desc) parts.push(`desc:${selector.desc}`);
      if (selector.text) parts.push(`text:${selector.text}`);
      if (selector.cls) parts.push(`cls:${selector.cls}`);
      if (selector.bounds) parts.push(`bounds:${selector.bounds.join(',')}`);
      return parts.join('|');
    })
    .join(';');

  // Create normalized text representation
  const normalizedText = visibleText
    .filter(text => text && text.trim().length > 0)
    .map(text => text.trim().toLowerCase())
    .sort()
    .join('|');

  const input = `${xmlHash}:${normalizedSelectors}:${normalizedText}`;
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Generate transition ID
 */
export function generateTransitionId(
  fromStateId: string,
  toStateId: string,
  action: string
): string {
  const input = `${fromStateId}:${toStateId}:${action}`;
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Generate session event ID
 */
export function generateEventId(
  timestamp: string,
  type: string,
  message: string
): string {
  const input = `${timestamp}:${type}:${message}`;
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Calculate Jaccard similarity between two selector sets
 */
export function calculateJaccardSimilarity(
  selectors1: Selector[],
  selectors2: Selector[]
): number {
  if (selectors1.length === 0 && selectors2.length === 0) {
    return 1.0;
  }

  if (selectors1.length === 0 || selectors2.length === 0) {
    return 0.0;
  }

  const normalizeSelector = (selector: Selector): string => {
    const parts = [];
    if (selector.rid) parts.push(`rid:${selector.rid}`);
    if (selector.desc) parts.push(`desc:${selector.desc}`);
    if (selector.text) parts.push(`text:${selector.text}`);
    if (selector.cls) parts.push(`cls:${selector.cls}`);
    if (selector.bounds) parts.push(`bounds:${selector.bounds.join(',')}`);
    return parts.join('|');
  };

  const set1 = new Set(selectors1.map(normalizeSelector));
  const set2 = new Set(selectors2.map(normalizeSelector));

  const intersection = new Set([...set1].filter(x => set2.has(x)));
  const union = new Set([...set1, ...set2]);

  return intersection.size / union.size;
}

/**
 * Calculate text similarity between two text arrays
 */
export function calculateTextSimilarity(
  text1: string[],
  text2: string[]
): number {
  if (text1.length === 0 && text2.length === 0) {
    return 1.0;
  }

  if (text1.length === 0 || text2.length === 0) {
    return 0.0;
  }

  const normalize = (text: string[]) =>
    text
      .filter(t => t && t.trim().length > 0)
      .map(t => t.trim().toLowerCase())
      .sort();

  const set1 = new Set(normalize(text1));
  const set2 = new Set(normalize(text2));

  const intersection = new Set([...set1].filter(x => set2.has(x)));
  const union = new Set([...set1, ...set2]);

  return intersection.size / union.size;
}

/**
 * Calculate overall state similarity
 */
export function calculateStateSimilarity(
  state1: StateRecord,
  state2: StateRecord,
  selectorWeight: number = 0.7,
  textWeight: number = 0.3
): number {
  // Different packages or activities = 0 similarity
  if (state1.package !== state2.package || state1.activity !== state2.activity) {
    return 0.0;
  }

  // Identical digests = 1.0 similarity
  if (state1.digest === state2.digest) {
    return 1.0;
  }

  const selectorSimilarity = calculateJaccardSimilarity(state1.selectors, state2.selectors);
  const textSimilarity = calculateTextSimilarity(state1.visibleText, state2.visibleText);

  return (selectorWeight * selectorSimilarity) + (textWeight * textSimilarity);
}

/**
 * Check if two states should be merged based on similarity threshold
 */
export function shouldMergeStates(
  state1: StateRecord,
  state2: StateRecord,
  threshold: number = 0.9
): boolean {
  const similarity = calculateStateSimilarity(state1, state2);
  return similarity >= threshold;
}

/**
 * Generate checksum for file integrity verification
 */
export function generateFileChecksum(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Generate screenshot filename from state ID
 */
export function generateScreenshotFilename(stateId: string): string {
  return `${stateId}.png`;
}

/**
 * Validate SHA256 hash format
 */
export function isValidSHA256(hash: string): boolean {
  const sha256Regex = /^[a-f0-9]{64}$/i;
  return sha256Regex.test(hash);
}

/**
 * Extract hash components for debugging
 */
export function parseStateId(stateId: string): {
  package: string;
  activity: string;
  digest: string;
} | null {
  if (!isValidSHA256(stateId)) {
    return null;
  }

  // This is a one-way function, we can't extract components from SHA256
  // This function is just for validation
  return null;
}

/**
 * Generate deterministic hash for object properties
 */
export function hashObject(obj: Record<string, any>): string {
  const sorted = Object.keys(obj)
    .sort()
    .reduce((result, key) => {
      if (obj[key] !== undefined && obj[key] !== null) {
        result[key] = obj[key];
      }
      return result;
    }, {} as Record<string, any>);

  const input = JSON.stringify(sorted);
  return createHash('sha256').update(input).digest('hex');
}