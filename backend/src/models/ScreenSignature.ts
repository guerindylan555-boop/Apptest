/**
 * ScreenSignature Entity
 *
 * Handles deterministic signature generation from Android UI dumps
 * for reliable screen identification and matching.
 */

import crypto from 'crypto';
import { ScreenSignature } from '../types/uiGraph';

export class ScreenSignatureEntity implements ScreenSignature {
  activity: string;
  resourceIds: string[];
  requiredTexts: string[];
  layoutFingerprint: string;
  hash: string;
  version: number;

  constructor(data: Omit<ScreenSignature, 'hash' | 'version'>) {
    this.activity = data.activity;
    this.resourceIds = [...(data.resourceIds || [])].sort(); // Ensure consistent ordering
    this.requiredTexts = [...(data.requiredTexts || [])].sort(); // Normalize text ordering
    this.layoutFingerprint = data.layoutFingerprint;
    this.version = 1;
    this.hash = this.generateHash();
  }

  /**
   * Generate deterministic SHA-256 hash truncated to 16 bytes (32 hex chars)
   * Based on research.md decision: sorted tuple of (activity, resource-ids, required texts, structural fingerprint)
   */
  private generateHash(): string {
    // Create normalized signature tuple
    const signatureTuple = [
      this.activity || '',
      this.resourceIds.join('|'),  // Join with separator to maintain array structure
      this.requiredTexts.join('|'), // Normalize text tokens
      this.layoutFingerprint || ''
    ];

    // Create deterministic string representation
    const signatureString = signatureTuple.join('::');

    // Generate SHA-256 hash and truncate to 16 bytes (32 hex characters)
    const fullHash = crypto.createHash('sha256').update(signatureString, 'utf8').digest('hex');
    return fullHash.substring(0, 32); // 16 bytes = 32 hex characters
  }

  /**
   * Create ScreenSignature from UIAutomator XML dump
   */
  static fromXmlDump(xmlData: any, normalizedTexts: string[] = []): ScreenSignatureEntity {
    // Extract activity from XML dump
    const activity = xmlData?.['@_package'] || xmlData?.['@_activity'] || 'unknown';

    // Extract stable resource IDs (ignore dynamic IDs with numbers)
    const resourceIds = this.extractResourceIds(xmlData).filter(id =>
      id && !/\d{4,}/.test(id) // Filter out IDs with 4+ consecutive numbers (likely dynamic)
    );

    // Extract required texts from visible elements
    const requiredTexts = normalizedTexts.length > 0
      ? normalizedTexts
      : this.extractTexts(xmlData);

    // Generate layout fingerprint from XML structure
    const layoutFingerprint = this.generateLayoutFingerprint(xmlData);

    return new ScreenSignatureEntity({
      activity,
      resourceIds,
      requiredTexts,
      layoutFingerprint
    });
  }

  /**
   * Extract resource IDs from XML dump recursively
   */
  private static extractResourceIds(element: any): string[] {
    const ids: string[] = [];

    if (element?.['@_resource-id']) {
      ids.push(element['@_resource-id']);
    }

    // Recursively check child elements
    if (element?.node) {
      const children = Array.isArray(element.node) ? element.node : [element.node];
      for (const child of children) {
        ids.push(...this.extractResourceIds(child));
      }
    }

    return [...new Set(ids)]; // Remove duplicates
  }

  /**
   * Extract visible text content from XML dump
   */
  private static extractTexts(element: any): string[] {
    const texts: string[] = [];

    // Extract text from current element
    const text = element?.['@_text'];
    if (text && text.trim().length > 0 && text.trim().length < 100) { // Filter out very long texts
      texts.push(text.trim().toLowerCase());
    }

    // Extract content description
    const contentDesc = element?.['@_content-desc'];
    if (contentDesc && contentDesc.trim().length > 0 && contentDesc.trim().length < 100) {
      texts.push(contentDesc.trim().toLowerCase());
    }

    // Recursively check child elements
    if (element?.node) {
      const children = Array.isArray(element.node) ? element.node : [element.node];
      for (const child of children) {
        texts.push(...this.extractTexts(child));
      }
    }

    return [...new Set(texts)]; // Remove duplicates
  }

  /**
   * Generate structural fingerprint using XML depth walk
   */
  private static generateLayoutFingerprint(element: any): string {
    const signature: string[] = [];

    const walkElement = (el: any, depth: number = 0) => {
      if (!el) return;

      // Record element class and bounds (normalized)
      const className = el?.['@_class']?.replace(/^[^.]+\./, '') || 'unknown'; // Remove package prefix
      const bounds = el?.['@_bounds'] || '';
      const normalizedBounds = bounds.replace(/\d+/g, 'x'); // Normalize coordinates

      signature.push(`${'  '.repeat(depth)}${className}:${normalizedBounds}`);

      // Recursively walk children
      if (el?.node) {
        const children = Array.isArray(el.node) ? el.node : [el.node];
        for (const child of children) {
          walkElement(child, depth + 1);
        }
      }
    };

    walkElement(element);

    // Create hash of structural signature
    const structuralString = signature.join('\n');
    return crypto.createHash('md5').update(structuralString, 'utf8').digest('hex');
  }

  /**
   * Check if this signature matches another within acceptable tolerance
   */
  matches(other: ScreenSignature, tolerance: number = 0): boolean {
    // Exact hash match is required for zero tolerance
    if (tolerance === 0) {
      return this.hash === other.hash;
    }

    // For higher tolerance, check individual components
    const activityMatch = this.activity === other.activity;
    const resourceIdsMatch = this.arraysEqual(this.resourceIds, other.resourceIds);
    const requiredTextsMatch = this.textSimilarity(this.requiredTexts, other.requiredTexts) >= (1 - tolerance);

    return activityMatch && resourceIdsMatch && requiredTextsMatch;
  }

  /**
   * Calculate similarity between two text arrays using Jaccard similarity
   */
  private textSimilarity(arr1: string[], arr2: string[]): number {
    const set1 = new Set(arr1);
    const set2 = new Set(arr2);
    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);

    return intersection.size / union.size;
  }

  /**
   * Check if two arrays are equal (order-independent)
   */
  private arraysEqual(arr1: string[], arr2: string[]): boolean {
    if (arr1.length !== arr2.length) return false;
    const set1 = new Set(arr1);
    const set2 = new Set(arr2);
    return set1.size === set2.size && [...set1].every(x => set2.has(x));
  }

  /**
   * Update signature version when definition changes
   */
  incrementVersion(): void {
    this.version++;
    // Regenerate hash if needed (for future compatibility)
    // this.hash = this.generateHash();
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): ScreenSignature {
    return {
      activity: this.activity,
      resourceIds: this.resourceIds,
      requiredTexts: this.requiredTexts,
      layoutFingerprint: this.layoutFingerprint,
      hash: this.hash,
      version: this.version
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: ScreenSignature): ScreenSignatureEntity {
    const entity = Object.create(ScreenSignatureEntity.prototype);
    Object.assign(entity, data);
    return entity;
  }
}