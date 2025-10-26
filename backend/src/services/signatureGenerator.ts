/**
 * Signature Generation Service
 *
 * Implements deterministic signature generation from XML dumps.
 * Creates SHA-256 hashes from stable screen traits based on research.md decisions.
 * Combines structural + semantic anchors for consistent identification.
 */

import { createHash } from 'crypto';
import { xmlNormalizer } from '../utils/xmlNormalizer';
import { signatureBuilder } from './ui-graph/signatureBuilder';
import type { ScreenSignature } from '../types/uiGraph';

export interface SignatureGenerationInput {
  /** Raw XML dump content */
  xmlContent: string;
  /** Activity name if known (will be extracted from XML if not provided) */
  activity?: string;
  /** Package name if known */
  package?: string;
  /** Override options for normalization */
  normalizationOptions?: {
    keepText?: boolean;
    keepBounds?: boolean;
    keepContentDesc?: boolean;
  };
}

export interface SignatureGenerationResult {
  /** Generated screen signature */
  signature: ScreenSignature;
  /** Extracted metadata during generation */
  metadata: {
    activity: string;
    package?: string;
    extractedResourceIds: string[];
    extractedTexts: string[];
    layoutFingerprint: string;
  };
  /** Normalization statistics */
  stats: {
    originalXmlSize: number;
    normalizedXmlSize: number;
    compressionRatio: number;
    processingTimeMs: number;
  };
}

export class SignatureGenerator {
  /**
   * Generate a deterministic signature from UI dump data
   */
  async generateSignature(input: SignatureGenerationInput): Promise<SignatureGenerationResult> {
    const startTime = Date.now();
    const originalSize = Buffer.byteLength(input.xmlContent, 'utf8');

    try {
      // Step 1: Normalize XML content
      const normalized = await xmlNormalizer.normalize(input.xmlContent, {
        removeText: !input.normalizationOptions?.keepText,
        removeBounds: !input.normalizationOptions?.keepBounds,
        removeContentDesc: !input.normalizationOptions?.keepContentDesc,
        keepResourceId: true, // Always keep resource-ids for signature
        normalizeWhitespace: true,
      });

      // Step 2: Extract stable features
      const activity = input.activity || normalized.activity || 'com.mayndrive.UnknownActivity';
      const resourceIds = this.extractStableResourceIds(normalized.elements);
      const requiredTexts = this.extractMeaningfulTexts(normalized.elements);
      const layoutFingerprint = this.generateLayoutFingerprint(normalized.xml);

      // Step 3: Build signature using existing signature builder
      const signature = await signatureBuilder.buildSignature({
        activity,
        resourceIds,
        requiredTexts,
        xmlContent: normalized.xml,
      });

      // Step 4: Compile result
      const processingTime = Date.now() - startTime;
      const normalizedSize = Buffer.byteLength(normalized.xml, 'utf8');

      return {
        signature,
        metadata: {
          activity: signature.activity,
          package: normalized.package || input.package,
          extractedResourceIds: resourceIds,
          extractedTexts: requiredTexts,
          layoutFingerprint: signature.layoutFingerprint,
        },
        stats: {
          originalXmlSize: originalSize,
          normalizedXmlSize: normalizedSize,
          compressionRatio: normalizedSize / originalSize,
          processingTimeMs: processingTime,
        },
      };
    } catch (error) {
      throw new Error(`Signature generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Extract stable resource IDs that are suitable for signature generation
   */
  private extractStableResourceIds(elements: any[]): string[] {
    const resourceIds = new Set<string>();

    for (const element of elements) {
      if (element.resource_id && this.isStableResourceId(element.resource_id)) {
        resourceIds.add(element.resource_id.toLowerCase().trim());
      }
    }

    return Array.from(resourceIds).sort();
  }

  /**
   * Check if a resource ID is stable (not dynamically generated)
   */
  private isStableResourceId(resourceId: string): boolean {
    if (!resourceId || resourceId.length === 0) {
      return false;
    }

    // Skip empty or obviously dynamic IDs
    const dynamicPatterns = [
      /^id\/\d+$/, // id/N pattern
      /\d+$/, // Ends with numbers only
      /^[a-f0-9-]{8,}$/i, // Long hexadecimal strings
      /^row_\d+$/, // row_N pattern
      /^item_\d+$/, // item_N pattern
      /^cell_\d+$/, // cell_N pattern
      /^btn_\d+$/, // btn_N pattern
    ];

    return !dynamicPatterns.some(pattern => pattern.test(resourceId));
  }

  /**
   * Extract meaningful text content that's stable across sessions
   */
  private extractMeaningfulTexts(elements: any[]): string[] {
    const texts = new Set<string>();

    for (const element of elements) {
      if (element.text && this.isStableText(element.text)) {
        texts.add(element.text.toLowerCase().trim());
      }

      // Also check content-desc if it has meaningful content
      if (element.content_desc && this.isStableText(element.content_desc)) {
        texts.add(element.content_desc.toLowerCase().trim());
      }
    }

    return Array.from(texts).sort();
  }

  /**
   * Check if text content is stable and meaningful
   */
  private isStableText(text: string): boolean {
    if (!text || text.length < 2 || text.length > 100) {
      return false;
    }

    // Skip purely numeric text (likely dynamic)
    if (/^\d+$/.test(text)) {
      return false;
    }

    // Skip common UI noise text
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
      'settings',
      'help',
      'about',
    ];

    const lowerText = text.toLowerCase();
    return !noisePatterns.includes(lowerText);
  }

  /**
   * Generate layout fingerprint from normalized XML structure
   */
  private generateLayoutFingerprint(normalizedXml: string): string {
    // Remove all attributes, keep only tag hierarchy and basic structure
    const structuralContent = normalizedXml
      .replace(/<node[^>]*>/g, '<node>')
      .replace(/\s+/g, ' ')
      .trim();

    // Create SHA-256 hash and take first 16 bytes
    const hash = createHash('sha256')
      .update(structuralContent)
      .digest('hex');

    return hash.substring(0, 32); // 16 bytes = 32 hex characters
  }

  /**
   * Compare two signatures and return similarity score
   */
  compareSignatures(sig1: ScreenSignature, sig2: ScreenSignature): {
    score: number;
    details: {
      activityMatch: boolean;
      resourceIdOverlap: number;
      textOverlap: number;
      layoutMatch: boolean;
    };
  } {
    // Activity match (40% weight)
    const activityMatch = sig1.activity === sig2.activity;

    // Resource ID overlap (30% weight)
    const resourceIds1 = new Set(sig1.resourceIds);
    const resourceIds2 = new Set(sig2.resourceIds);
    const resourceOverlap = [...resourceIds1].filter(id => resourceIds2.has(id)).length;
    const resourceTotal = new Set([...sig1.resourceIds, ...sig2.resourceIds]).size;
    const resourceIdOverlap = resourceTotal > 0 ? resourceOverlap / resourceTotal : 0;

    // Text overlap (20% weight)
    const texts1 = new Set(sig1.requiredTexts);
    const texts2 = new Set(sig2.requiredTexts);
    const textOverlap = [...texts1].filter(text => texts2.has(text)).length;
    const textTotal = new Set([...sig1.requiredTexts, ...sig2.requiredTexts]).size;
    const textOverlapScore = textTotal > 0 ? textOverlap / textTotal : 0;

    // Layout fingerprint match (10% weight)
    const layoutMatch = sig1.layoutFingerprint === sig2.layoutFingerprint;

    // Calculate weighted score
    const score = Math.round(
      (activityMatch ? 40 : 0) +
      (resourceIdOverlap * 30) +
      (textOverlapScore * 20) +
      (layoutMatch ? 10 : 0)
    );

    return {
      score,
      details: {
        activityMatch,
        resourceIdOverlap: Math.round(resourceIdOverlap * 100),
        textOverlap: Math.round(textOverlapScore * 100),
        layoutMatch,
      },
    };
  }

  /**
   * Validate signature quality and completeness
   */
  validateSignature(signature: ScreenSignature): {
    isValid: boolean;
    quality: 'high' | 'medium' | 'low';
    issues: string[];
    recommendations: string[];
  } {
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Check required fields
    if (!signature.activity || signature.activity === 'com.mayndrive.UnknownActivity') {
      issues.push('Activity not properly identified');
    }

    if (signature.resourceIds.length === 0) {
      issues.push('No stable resource IDs found');
      recommendations.push('Consider adding resource-id attributes to key UI elements');
    }

    if (signature.requiredTexts.length === 0) {
      recommendations.push('Consider adding text content to improve signature uniqueness');
    }

    if (!signature.layoutFingerprint) {
      issues.push('Layout fingerprint missing');
    }

    // Quality assessment
    const hasMultipleIdentifiers = signature.resourceIds.length > 0 || signature.requiredTexts.length > 0;
    const hasStableActivity = signature.activity !== 'com.mayndrive.UnknownActivity';
    const hasLayoutInfo = !!signature.layoutFingerprint;

    let quality: 'high' | 'medium' | 'low' = 'low';
    if (hasStableActivity && hasMultipleIdentifiers && hasLayoutInfo) {
      quality = 'high';
    } else if (hasStableActivity && (signature.resourceIds.length > 0 || signature.requiredTexts.length > 0)) {
      quality = 'medium';
    }

    // Additional recommendations based on quality
    if (quality === 'low') {
      recommendations.push('Screen may be too dynamic for reliable detection');
      recommendations.push('Consider using alternative selection strategies');
    } else if (quality === 'medium') {
      recommendations.push('Signature is usable but could be improved with more stable identifiers');
    }

    return {
      isValid: issues.length === 0,
      quality,
      issues,
      recommendations,
    };
  }

  /**
   * Generate multiple signature variants for robustness
   */
  async generateSignatureVariants(
    input: SignatureGenerationInput,
    variants: 'conservative' | 'standard' | 'aggressive' = 'standard'
  ): Promise<{
    primary: SignatureGenerationResult;
    alternatives: SignatureGenerationResult[];
  }> {
    const primary = await this.generateSignature(input);
    const alternatives: SignatureGenerationResult[] = [];

    switch (variants) {
      case 'conservative':
        // More strict filtering - only highly stable elements
        alternatives.push(
          await this.generateSignature({
            ...input,
            normalizationOptions: {
              keepText: false,
              keepContentDesc: false,
            },
          })
        );
        break;

      case 'standard':
        // Standard variations
        alternatives.push(
          await this.generateSignature({
            ...input,
            normalizationOptions: {
              keepText: true,
              keepContentDesc: false,
            },
          })
        );
        alternatives.push(
          await this.generateSignature({
            ...input,
            normalizationOptions: {
              keepText: false,
              keepContentDesc: true,
            },
          })
        );
        break;

      case 'aggressive':
        // Include more elements for maximum coverage
        alternatives.push(
          await this.generateSignature({
            ...input,
            normalizationOptions: {
              keepText: true,
              keepContentDesc: true,
            },
          })
        );
        break;
    }

    return {
      primary,
      alternatives,
    };
  }
}

export const signatureGenerator = new SignatureGenerator();