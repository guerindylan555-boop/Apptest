/**
 * Selector Extraction and Ranking Service
 *
 * Extracts and ranks UI selectors from normalized XML dumps.
 * Implements the Android stability hierarchy: resource-id > content-desc > text > accessibility > XPath > coordinates.
 * Provides confidence scoring and validation for selector reliability.
 */

import { v4 as uuidv4 } from 'uuid';
import { xmlNormalizer } from '../utils/xmlNormalizer';
import type { SelectorCandidate } from '../types/uiGraph';

// Define local types to avoid import issues
export interface UIDumpElement {
  index: string;
  text: string;
  resource_id: string;
  content_desc: string;
  class: string;
  package: string;
  checkable: string;
  checked: string;
  clickable: string;
  enabled: string;
  focusable: string;
  focused: string;
  scrollable: string;
  long_clickable: string;
  password: string;
  selected: string;
  bounds: string;
  accessibility: string;
}

export interface SelectorExtractionInput {
  /** Raw XML dump content */
  xmlContent: string;
  /** Target element index if focusing on specific element */
  targetIndex?: string;
  /** Minimum confidence threshold for inclusion */
  minConfidence?: number;
  /** Include coordinate-based selectors as fallback */
  includeCoordinates?: boolean;
}

export interface ExtractionResult {
  /** Extracted and ranked selector candidates */
  selectors: SelectorCandidate[];
  /** Extraction statistics */
  stats: {
    totalElements: number;
    interactiveElements: number;
    highConfidenceSelectors: number;
    mediumConfidenceSelectors: number;
    lowConfidenceSelectors: number;
  };
  /** Processing metadata */
  metadata: {
    processingTimeMs: number;
    extractionMethod: string;
    qualityScore: number;
  };
}

export interface SelectorRankingCriteria {
  /** Base weight for selector type */
  typeWeights: {
    'resource-id': number;
    'content-desc': number;
    'text': number;
    'accessibility': number;
    'xpath': number;
    'coords': number;
  };
  /** Additional modifiers */
  modifiers: {
    /** Bonus for clickable elements */
    clickableBonus: number;
    /** Penalty for dynamic content */
    dynamicPenalty: number;
    /** Bonus for unique values */
    uniquenessBonus: number;
    /** Penalty for very long selectors */
    lengthPenalty: number;
  };
}

export class SelectorExtractor {
  private defaultRankingCriteria: SelectorRankingCriteria = {
    typeWeights: {
      'resource-id': 100,
      'content-desc': 80,
      'text': 60,
      'accessibility': 40,
      'xpath': 20,
      'coords': 10,
    },
    modifiers: {
      clickableBonus: 20,
      dynamicPenalty: -30,
      uniquenessBonus: 15,
      lengthPenalty: -5,
    },
  };

  /**
   * Extract and rank selectors from XML dump
   */
  async extractSelectors(input: SelectorExtractionInput): Promise<ExtractionResult> {
    const startTime = Date.now();

    try {
      // Step 1: Normalize XML content
      const normalized = await xmlNormalizer.normalize(input.xmlContent, {
        removeText: false, // Keep text for selector extraction
        removeBounds: false, // Keep bounds for coordinate selectors
        removeContentDesc: false, // Keep content-desc for selectors
        keepResourceId: true,
        normalizeWhitespace: true,
      });

      // Step 2: Extract selectors from all elements
      const allSelectors = this.extractSelectorsFromElements(
        normalized.elements,
        input.targetIndex,
        input.includeCoordinates
      );

      // Step 3: Rank selectors by confidence
      const rankedSelectors = this.rankSelectors(allSelectors, this.defaultRankingCriteria);

      // Step 4: Filter by minimum confidence
      const filteredSelectors = input.minConfidence
        ? rankedSelectors.filter(s => s.confidence >= input.minConfidence!)
        : rankedSelectors;

      // Step 5: Calculate statistics
      const stats = this.calculateStatistics(normalized.elements, filteredSelectors);
      const processingTime = Date.now() - startTime;

      return {
        selectors: filteredSelectors,
        stats,
        metadata: {
          processingTimeMs: processingTime,
          extractionMethod: 'comprehensive',
          qualityScore: this.calculateQualityScore(filteredSelectors, stats),
        },
      };
    } catch (error) {
      throw new Error(`Selector extraction failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Extract selector candidates from UI elements
   */
  private extractSelectorsFromElements(
    elements: UIDumpElement[],
    targetIndex?: string,
    includeCoordinates = true
  ): SelectorCandidate[] {
    const selectors: SelectorCandidate[] = [];

    for (const element of elements) {
      // Skip if we're targeting a specific element and this isn't it
      if (targetIndex && element.index !== targetIndex) {
        continue;
      }

      // Extract different selector types for this element
      const elementSelectors = this.extractElementSelectors(element, includeCoordinates);
      selectors.push(...elementSelectors);
    }

    return selectors;
  }

  /**
   * Extract all possible selector types for a single element
   */
  private extractElementSelectors(element: UIDumpElement, includeCoordinates: boolean): SelectorCandidate[] {
    const selectors: SelectorCandidate[] = [];

    // Resource ID selector (highest priority)
    if (element.resource_id && this.isValidResourceId(element.resource_id)) {
      selectors.push({
        id: uuidv4(),
        type: 'resource-id',
        value: element.resource_id,
        confidence: 0, // Will be calculated during ranking
        lastValidatedAt: new Date().toISOString(),
      });
    }

    // Content description selector
    if (element.content_desc && this.isValidText(element.content_desc)) {
      selectors.push({
        id: uuidv4(),
        type: 'content-desc',
        value: element.content_desc,
        confidence: 0,
        lastValidatedAt: new Date().toISOString(),
      });
    }

    // Text selector
    if (element.text && this.isValidText(element.text)) {
      selectors.push({
        id: uuidv4(),
        type: 'text',
        value: element.text,
        confidence: 0,
        lastValidatedAt: new Date().toISOString(),
      });
    }

    // Accessibility selector (if available)
    if (element.accessibility) {
      selectors.push({
        id: uuidv4(),
        type: 'accessibility',
        value: element.accessibility,
        confidence: 0,
        lastValidatedAt: new Date().toISOString(),
      });
    }

    // XPath selector (complex but comprehensive)
    const xpathSelector = this.generateXPathSelector(element);
    if (xpathSelector) {
      selectors.push({
        id: uuidv4(),
        type: 'xpath',
        value: xpathSelector,
        confidence: 0,
        lastValidatedAt: new Date().toISOString(),
      });
    }

    // Coordinate selector (fallback option)
    if (includeCoordinates && element.bounds) {
      const coords = this.parseBounds(element.bounds);
      if (coords) {
        selectors.push({
          id: uuidv4(),
          type: 'coords',
          value: `${coords.x},${coords.y}`,
          confidence: 0,
          lastValidatedAt: new Date().toISOString(),
        });
      }
    }

    return selectors;
  }

  /**
   * Validate resource ID quality
   */
  private isValidResourceId(resourceId: string): boolean {
    if (!resourceId || resourceId.length === 0) {
      return false;
    }

    // Skip obviously dynamic IDs
    const dynamicPatterns = [
      /^id\/\d+$/,
      /\d+$/,
      /^[a-f0-9-]{8,}$/i,
      /^row_\d+$/,
      /^item_\d+$/,
      /^cell_\d+$/,
      /^btn_\d+$/,
    ];

    return !dynamicPatterns.some(pattern => pattern.test(resourceId));
  }

  /**
   * Validate text content quality
   */
  private isValidText(text: string): boolean {
    if (!text || text.length < 2 || text.length > 100) {
      return false;
    }

    // Skip purely numeric content (likely dynamic)
    if (/^\d+$/.test(text)) {
      return false;
    }

    // Skip common UI noise
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

    return !noisePatterns.includes(text.toLowerCase());
  }

  /**
   * Generate XPath selector for element
   */
  private generateXPathSelector(element: UIDumpElement): string | null {
    try {
      let xpath = `//${element.class || 'node'}`;

      // Add resource-id condition if available
      if (element.resource_id) {
        xpath += `[@resource-id='${element.resource_id}']`;
      }
      // Add text condition if available
      else if (element.text) {
        xpath += `[@text='${element.text}']`;
      }
      // Add content-desc condition if available
      else if (element.content_desc) {
        xpath += `[@content-desc='${element.content_desc}']`;
      }
      // Add clickable condition for interactive elements
      else if (element.clickable === 'true') {
        xpath += `[@clickable='true']`;
      }

      return xpath;
    } catch (error) {
      console.warn('Failed to generate XPath selector:', error);
      return null;
    }
  }

  /**
   * Parse bounds string to get coordinates
   */
  private parseBounds(bounds: string): { x: number; y: number } | null {
    try {
      // Bounds format: [x1,y1][x2,y2]
      const match = bounds.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
      if (match) {
        const x1 = parseInt(match[1], 10);
        const y1 = parseInt(match[2], 10);
        const x2 = parseInt(match[3], 10);
        const y2 = parseInt(match[4], 10);

        // Return center point
        return {
          x: Math.round((x1 + x2) / 2),
          y: Math.round((y1 + y2) / 2),
        };
      }
    } catch (error) {
      console.warn('Failed to parse bounds:', bounds);
    }
    return null;
  }

  /**
   * Rank selectors by confidence using multiple criteria
   */
  private rankSelectors(selectors: SelectorCandidate[], criteria: SelectorRankingCriteria): SelectorCandidate[] {
    return selectors
      .map(selector => ({
        ...selector,
        confidence: this.calculateConfidence(selector, criteria),
      }))
      .sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Calculate confidence score for a selector
   */
  private calculateConfidence(selector: SelectorCandidate, criteria: SelectorRankingCriteria): number {
    let confidence = criteria.typeWeights[selector.type] || 0;

    // Apply modifiers based on selector properties
    if (this.isClickableSelector(selector)) {
      confidence += criteria.modifiers.clickableBonus;
    }

    if (this.isDynamicSelector(selector)) {
      confidence += criteria.modifiers.dynamicPenalty;
    }

    if (this.isUniqueSelector(selector)) {
      confidence += criteria.modifiers.uniquenessBonus;
    }

    if (selector.value.length > 50) {
      confidence += criteria.modifiers.lengthPenalty;
    }

    // Normalize to 0-1 range
    const maxScore = 120; // Maximum possible score
    confidence = Math.max(0, Math.min(1, confidence / maxScore));

    return Math.round(confidence * 100) / 100; // Round to 2 decimal places
  }

  /**
   * Check if selector points to a clickable element
   */
  private isClickableSelector(selector: SelectorCandidate): boolean {
    // This would need access to the original element data
    // For now, assume selectors with stable IDs are more likely to be clickable
    return selector.type === 'resource-id' || selector.type === 'content-desc';
  }

  /**
   * Check if selector appears to be dynamic
   */
  private isDynamicSelector(selector: SelectorCandidate): boolean {
    if (selector.type === 'coords') {
      return true; // Coordinates are always dynamic
    }

    const dynamicPatterns = [
      /\d+$/, // Ends with numbers
      /^[a-f0-9-]{8,}$/i, // Hexadecimal strings
    ];

    return dynamicPatterns.some(pattern => pattern.test(selector.value));
  }

  /**
   * Check if selector value appears to be unique
   */
  private isUniqueSelector(selector: SelectorCandidate): boolean {
    // Resource IDs are usually unique
    if (selector.type === 'resource-id') {
      return true;
    }

    // Long text content is likely unique
    if (selector.type === 'text' && selector.value.length > 10) {
      return true;
    }

    // Content descriptions are often unique
    if (selector.type === 'content-desc' && selector.value.length > 5) {
      return true;
    }

    return false;
  }

  /**
   * Calculate extraction statistics
   */
  private calculateStatistics(elements: UIDumpElement[], selectors: SelectorCandidate[]) {
    const interactiveElements = elements.filter(el =>
      el.clickable === 'true' ||
      el.focusable === 'true' ||
      el.long_clickable === 'true'
    ).length;

    const highConfidence = selectors.filter(s => s.confidence >= 0.8).length;
    const mediumConfidence = selectors.filter(s => s.confidence >= 0.5 && s.confidence < 0.8).length;
    const lowConfidence = selectors.filter(s => s.confidence < 0.5).length;

    return {
      totalElements: elements.length,
      interactiveElements,
      highConfidenceSelectors: highConfidence,
      mediumConfidenceSelectors: mediumConfidence,
      lowConfidenceSelectors: lowConfidence,
    };
  }

  /**
   * Calculate overall quality score for the extraction
   */
  private calculateQualityScore(selectors: SelectorCandidate[], stats: any): number {
    if (selectors.length === 0) {
      return 0;
    }

    // Factors for quality score
    const highConfidenceRatio = stats.highConfidenceSelectors / selectors.length;
    const interactiveCoverage = stats.interactiveElements > 0 ?
      Math.min(1, selectors.length / stats.interactiveElements) : 0;
    const hasResourceIds = selectors.some(s => s.type === 'resource-id');
    const resourceIdBonus = hasResourceIds ? 0.2 : 0;

    // Calculate weighted quality score
    const qualityScore = (highConfidenceRatio * 0.6) +
                        (interactiveCoverage * 0.2) +
                        resourceIdBonus;

    return Math.round(qualityScore * 100) / 100;
  }

  /**
   * Find the best selector for a specific action type
   */
  findBestSelector(
    selectors: SelectorCandidate[],
    actionType: 'tap' | 'type' | 'scroll' | 'swipe' = 'tap'
  ): SelectorCandidate | null {
    // Filter selectors suitable for the action type
    let suitableSelectors = selectors;

    switch (actionType) {
      case 'type':
        // Need elements that can accept text input
        suitableSelectors = selectors.filter(s =>
          s.type === 'resource-id' || s.type === 'xpath'
        );
        break;
      case 'tap':
        // Prefer resource-id and content-desc for tapping
        suitableSelectors = selectors.filter(s =>
          ['resource-id', 'content-desc', 'text'].includes(s.type)
        );
        break;
      case 'scroll':
      case 'swipe':
        // Prefer coordinate-based selectors for gestures
        suitableSelectors = selectors.filter(s =>
          ['coords', 'xpath'].includes(s.type)
        );
        break;
    }

    // Return the highest confidence suitable selector
    return suitableSelectors.length > 0 ? suitableSelectors[0] : null;
  }

  /**
   * Validate selector syntax and format
   */
  validateSelector(selector: SelectorCandidate): {
    isValid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    if (!selector.value || selector.value.trim().length === 0) {
      issues.push('Selector value is empty');
    }

    switch (selector.type) {
      case 'resource-id':
        if (!/^id\/[a-zA-Z_][a-zA-Z0-9_]*$/.test(selector.value) &&
            !/^[a-zA-Z][a-zA-Z0-9._]*$/.test(selector.value)) {
          issues.push('Invalid resource-id format');
        }
        break;

      case 'xpath':
        if (!selector.value.startsWith('//')) {
          issues.push('XPath should start with //');
        }
        break;

      case 'coords':
        if (!/^\d+,\d+$/.test(selector.value)) {
          issues.push('Coordinates should be in format x,y');
        }
        break;

      case 'text':
      case 'content-desc':
        if (selector.value.length > 100) {
          issues.push('Selector value too long');
        }
        break;
    }

    if (selector.confidence < 0 || selector.confidence > 1) {
      issues.push('Confidence should be between 0 and 1');
    }

    return {
      isValid: issues.length === 0,
      issues,
    };
  }

  /**
   * Update selector confidence based on validation results
   */
  updateSelectorConfidence(
    selector: SelectorCandidate,
    validationSuccess: boolean,
    executionTime?: number
  ): SelectorCandidate {
    // Adjust confidence based on validation result
    let confidenceAdjustment = 0;

    if (validationSuccess) {
      confidenceAdjustment = 0.1; // Bonus for successful validation
      if (executionTime && executionTime < 1000) {
        confidenceAdjustment += 0.05; // Bonus for fast execution
      }
    } else {
      confidenceAdjustment = -0.2; // Penalty for failed validation
    }

    const newConfidence = Math.max(0, Math.min(1, selector.confidence + confidenceAdjustment));

    return {
      ...selector,
      confidence: Math.round(newConfidence * 100) / 100,
      lastValidatedAt: new Date().toISOString(),
    };
  }
}

export const selectorExtractor = new SelectorExtractor();