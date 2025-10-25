/**
 * Signature Builder Service
 *
 * Creates deterministic SHA-256 hashes from stable screen traits.
 * Combines structural + semantic anchors to keep hashes stable across
 * cosmetic changes per research.md decision.
 *
 * Process: (activity, sorted resource-ids, required texts, layout fingerprint) → SHA-256 → 16-byte hex
 */

import { createHash } from 'crypto';
import { parseString } from 'fast-csv';
import type { ScreenSignature } from '../../types/uiGraph';

interface UIDump {
  activity?: string;
  package?: string;
  resourceIds: string[];
  requiredTexts: string[];
  xmlContent: string;
}

interface SignatureInput {
  activity: string;
  resourceIds: string[];
  requiredTexts: string[];
  layoutFingerprint: string;
}

export class SignatureBuilder {
  /**
   * Build a deterministic screen signature from UI dump data
   */
  async buildSignature(uiDump: UIDump): Promise<ScreenSignature> {
    // Normalize inputs
    const normalizedInput = this.normalizeInputs({
      activity: uiDump.activity || this.extractActivityFromXML(uiDump.xmlContent),
      resourceIds: uiDump.resourceIds,
      requiredTexts: uiDump.requiredTexts,
      layoutFingerprint: await this.calculateLayoutFingerprint(uiDump.xmlContent),
    });

    // Create hash from normalized tuple
    const hash = this.calculateHash(normalizedInput);

    return {
      activity: normalizedInput.activity,
      resourceIds: normalizedInput.resourceIds,
      requiredTexts: normalizedInput.requiredTexts,
      layoutFingerprint: normalizedInput.layoutFingerprint,
      hash: this.truncateHash(hash, 16), // 16 bytes as per data model
      version: 1,
    };
  }

  /**
   * Extract activity name from XML content if not provided
   */
  private extractActivityFromXML(xmlContent: string): string {
    try {
      // Look for activity attribute in the root node or first hierarchy node
      const activityMatch = xmlContent.match(/activity=['"]([^'"]+)['"]/);
      if (activityMatch) {
        return activityMatch[1];
      }

      // Fallback: look for package in the root node
      const packageMatch = xmlContent.match(/package=['"]([^'"]+)['"]/);
      if (packageMatch) {
        return `${packageMatch[1]}.UnknownActivity`;
      }

      return 'com.mayndrive.UnknownActivity';
    } catch (error) {
      console.warn('Failed to extract activity from XML:', error);
      return 'com.mayndrive.UnknownActivity';
    }
  }

  /**
   * Calculate layout fingerprint from XML structure
   */
  private async calculateLayoutFingerprint(xmlContent: string): Promise<string> {
    try {
      // Remove dynamic attributes and text content, keep only structure
      const structuralXML = xmlContent
        // Remove text content (can be dynamic)
        .replace(/text=['"][^'"]*['"]/g, '')
        // Remove bounds (coordinates)
        .replace(/bounds=['"][^'"]*['"]/g, '')
        // Remove content-desc (can be dynamic)
        .replace(/content-desc=['"][^'"]*['"]/g, '')
        // Remove NAU (resource-id that can be dynamic)
        .replace(/resource-id=['"][^'"]*['"]/g, '')
        // Normalize whitespace
        .replace(/\s+/g, ' ')
        .trim();

      // Create hash of the structural fingerprint
      const structuralHash = createHash('sha256')
        .update(structuralXML)
        .digest('hex');

      // Take first 16 characters for compact fingerprint
      return structuralHash.substring(0, 16);
    } catch (error) {
      console.warn('Failed to calculate layout fingerprint:', error);
      return 'unknown-structure';
    }
  }

  /**
   * Normalize signature inputs to ensure consistency
   */
  private normalizeInputs(input: SignatureInput): SignatureInput {
    return {
      activity: this.normalizeActivity(input.activity),
      resourceIds: this.normalizeResourceIds(input.resourceIds),
      requiredTexts: this.normalizeTexts(input.requiredTexts),
      layoutFingerprint: input.layoutFingerprint.toLowerCase(),
    };
  }

  /**
   * Normalize activity name to canonical form
   */
  private normalizeActivity(activity: string): string {
    return activity
      .trim()
      // Remove common prefixes that might vary
      .replace(/^com\./, '')
      // Ensure consistent formatting
      .replace(/\./g, '.')
      .toLowerCase();
  }

  /**
   * Normalize and sort resource IDs for consistency
   */
  private normalizeResourceIds(resourceIds: string[]): string[] {
    return resourceIds
      .filter(id => id && id.trim().length > 0)
      .map(id => id.trim().toLowerCase())
      // Filter out obviously dynamic IDs
      .filter(id => !this.isDynamicResourceId(id))
      .sort();
  }

  /**
   * Identify dynamic resource IDs that should be excluded from hashing
   */
  private isDynamicResourceId(resourceId: string): boolean {
    // Skip IDs with numbers that suggest they're dynamically generated
    const dynamicPatterns = [
      /\d+$/, // Ends with numbers
      /item_\d+/, // item_N pattern
      /row_\d+/, // row_N pattern
      /cell_\d+/, // cell_N pattern
      /btn_\d+/, // btn_N pattern
    ];

    return dynamicPatterns.some(pattern => pattern.test(resourceId));
  }

  /**
   * Normalize and sort required text tokens
   */
  private normalizeTexts(texts: string[]): string[] {
    return texts
      .filter(text => text && text.trim().length > 0)
      .map(text => text.trim().toLowerCase())
      // Remove very short texts (likely decorative)
      .filter(text => text.length >= 2)
      // Remove common UI strings that add noise
      .filter(text => !this.isNoiseText(text))
      .sort();
  }

  /**
   * Identify common UI noise text that should be excluded
   */
  private isNoiseText(text: string): boolean {
    const noisePatterns = [
      '...',
      '●',
      '■',
      '►',
      '×',
      '+',
      '-',
      '•',
      'menu',
      'more',
      'back',
      'cancel',
      'ok',
      'yes',
      'no',
      'done',
      'save',
      'delete',
      'edit',
      'close',
    ];

    return noisePatterns.includes(text.toLowerCase());
  }

  /**
   * Calculate SHA-256 hash from normalized signature inputs
   */
  private calculateHash(input: SignatureInput): string {
    const tuple = [
      input.activity,
      input.resourceIds.join('|'),
      input.requiredTexts.join('|'),
      input.layoutFingerprint,
    ].join('||');

    return createHash('sha256').update(tuple).digest('hex');
  }

  /**
   * Truncate hash to specified byte length
   */
  private truncateHash(fullHash: string, byteLength: number): string {
    const charLength = byteLength * 2; // 2 hex chars per byte
    return fullHash.substring(0, charLength);
  }

  /**
   * Validate signature format and consistency
   */
  validateSignature(signature: ScreenSignature): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!signature.activity || signature.activity.length === 0) {
      errors.push('Activity is required');
    }

    if (!Array.isArray(signature.resourceIds)) {
      errors.push('Resource IDs must be an array');
    }

    if (!Array.isArray(signature.requiredTexts)) {
      errors.push('Required texts must be an array');
    }

    if (!signature.layoutFingerprint || signature.layoutFingerprint.length === 0) {
      errors.push('Layout fingerprint is required');
    }

    if (!signature.hash || !/^[a-f0-9]{32}$/.test(signature.hash)) {
      errors.push('Hash must be a 16-byte hex string (32 characters)');
    }

    if (typeof signature.version !== 'number' || signature.version < 1) {
      errors.push('Version must be a positive number');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Compare two signatures for equality
   */
  areSignaturesEqual(sig1: ScreenSignature, sig2: ScreenSignature): boolean {
    return (
      sig1.activity === sig2.activity &&
      JSON.stringify(sig1.resourceIds.sort()) === JSON.stringify(sig2.resourceIds.sort()),
      JSON.stringify(sig1.requiredTexts.sort()) === JSON.stringify(sig2.requiredTexts.sort()),
      sig1.layoutFingerprint === sig2.layoutFingerprint
    );
  }

  /**
   * Calculate similarity score between two signatures (0-100)
   */
  calculateSimilarity(sig1: ScreenSignature, sig2: ScreenSignature): number {
    let score = 0;
    let maxScore = 0;

    // Activity match (40 points)
    maxScore += 40;
    if (sig1.activity === sig2.activity) {
      score += 40;
    }

    // Resource ID overlap (30 points)
    maxScore += 30;
    const resourceIds1 = new Set(sig1.resourceIds);
    const resourceIds2 = new Set(sig2.resourceIds);
    const resourceOverlap = [...resourceIds1].filter(id => resourceIds2.has(id)).length;
    const resourceTotal = new Set([...sig1.resourceIds, ...sig2.resourceIds]).size;
    if (resourceTotal > 0) {
      score += (resourceOverlap / resourceTotal) * 30;
    }

    // Text overlap (20 points)
    maxScore += 20;
    const texts1 = new Set(sig1.requiredTexts);
    const texts2 = new Set(sig2.requiredTexts);
    const textOverlap = [...texts1].filter(text => texts2.has(text)).length;
    const textTotal = new Set([...sig1.requiredTexts, ...sig2.requiredTexts]).size;
    if (textTotal > 0) {
      score += (textOverlap / textTotal) * 20;
    }

    // Layout fingerprint match (10 points)
    maxScore += 10;
    if (sig1.layoutFingerprint === sig2.layoutFingerprint) {
      score += 10;
    }

    return maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;
  }
}

export const signatureBuilder = new SignatureBuilder();