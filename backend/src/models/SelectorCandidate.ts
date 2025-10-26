/**
 * SelectorCandidate Entity
 *
 * Handles selector extraction, ranking, and confidence scoring
 * for reliable UI element identification and action execution.
 */

import { v4 as uuidv4 } from 'uuid';
import { SelectorCandidate } from '../types/uiGraph';

export type SelectorType = 'resource-id' | 'content-desc' | 'text' | 'accessibility' | 'xpath' | 'coords';

export interface SelectorExtractionResult {
  selector: SelectorCandidate;
  evidence: {
    source: string;
    confidence: number;
    metadata?: any;
  };
}

export class SelectorCandidateEntity implements SelectorCandidate {
  id: string;
  type: SelectorType;
  value: string;
  confidence: number;
  lastValidatedAt: string;

  constructor(type: SelectorType, value: string, confidence: number = 0.5) {
    this.id = uuidv4();
    this.type = type;
    this.value = value;
    this.confidence = Math.max(0, Math.min(1, confidence)); // Clamp between 0-1
    this.lastValidatedAt = new Date().toISOString();
  }

  /**
   * Extract and rank selector candidates from UIAutomator XML element
   */
  static extractFromElement(element: any, elementIndex: number = 0): SelectorCandidateEntity[] {
    const candidates: SelectorCandidateEntity[] = [];

    // 1. Resource ID selector (highest priority)
    const resourceId = element?.['@_resource-id'];
    if (resourceId && resourceId.trim()) {
      const confidence = this.calculateResourceIdConfidence(resourceId);
      candidates.push(new SelectorCandidateEntity('resource-id', resourceId, confidence));
    }

    // 2. Content description selector (high priority)
    const contentDesc = element?.['@_content-desc'];
    if (contentDesc && contentDesc.trim()) {
      const confidence = this.calculateContentDescConfidence(contentDesc);
      candidates.push(new SelectorCandidateEntity('content-desc', contentDesc, confidence));
    }

    // 3. Text selector (medium priority)
    const text = element?.['@_text'];
    if (text && text.trim()) {
      const confidence = this.calculateTextConfidence(text);
      candidates.push(new SelectorCandidateEntity('text', text, confidence));
    }

    // 4. Accessibility label selector (medium priority)
    const accessibilityLabel = element?.['@_accessibility-label'];
    if (accessibilityLabel && accessibilityLabel.trim()) {
      const confidence = this.calculateAccessibilityConfidence(accessibilityLabel);
      candidates.push(new SelectorCandidateEntity('accessibility', accessibilityLabel, confidence));
    }

    // 5. XPath selector (low priority, fallback)
    const xpath = this.generateXPath(element, elementIndex);
    if (xpath) {
      const confidence = this.calculateXPathConfidence(xpath);
      candidates.push(new SelectorCandidateEntity('xpath', xpath, confidence));
    }

    // 6. Coordinates selector (last resort)
    const bounds = element?.['@_bounds'];
    if (bounds) {
      const coords = this.extractCoordinates(bounds);
      if (coords) {
        const confidence = this.calculateCoordsConfidence(coords);
        candidates.push(new SelectorCandidateEntity('coords', coords, confidence));
      }
    }

    // Sort by confidence (highest first) and apply risk flags
    return candidates
      .sort((a, b) => b.confidence - a.confidence)
      .map(candidate => {
        // Apply risk flags for low confidence selectors
        if (candidate.confidence < 0.4) {
          // Low confidence selectors are flagged as risky
          candidate.confidence = Math.min(candidate.confidence, 0.4);
        }
        return candidate;
      });
  }

  /**
   * Calculate confidence score for resource-id selectors
   */
  private static calculateResourceIdConfidence(resourceId: string): number {
    let confidence = 0.8; // Base confidence for resource-id

    // Boost confidence for stable naming patterns
    if (this.hasStableNamingPattern(resourceId)) {
      confidence += 0.1;
    }

    // Reduce confidence for dynamic patterns
    if (this.hasDynamicPattern(resourceId)) {
      confidence -= 0.3;
    }

    // Reduce confidence for very generic IDs
    if (this.isGenericResourceId(resourceId)) {
      confidence -= 0.2;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  /**
   * Calculate confidence score for content-description selectors
   */
  private static calculateContentDescConfidence(contentDesc: string): number {
    let confidence = 0.6; // Base confidence for content-desc

    // Boost for descriptive content (not just labels)
    if (contentDesc.length > 10 && !contentDesc.includes('Tab') && !contentDesc.includes('Button')) {
      confidence += 0.1;
    }

    // Reduce for very generic descriptions
    if (this.isGenericContentDesc(contentDesc)) {
      confidence -= 0.2;
    }

    // Reduce for very short descriptions
    if (contentDesc.length < 3) {
      confidence -= 0.1;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  /**
   * Calculate confidence score for text selectors
   */
  private static calculateTextConfidence(text: string): number {
    let confidence = 0.4; // Base confidence for text (lower due to localization)

    // Boost for unique text patterns
    if (this.hasUniqueTextPattern(text)) {
      confidence += 0.2;
    }

    // Reduce for very common text
    if (this.isCommonText(text)) {
      confidence -= 0.2;
    }

    // Reduce for very short text
    if (text.length < 2) {
      confidence -= 0.1;
    }

    // Reduce for numeric text (likely dynamic)
    if (/^\d+$/.test(text.trim())) {
      confidence -= 0.3;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  /**
   * Calculate confidence score for accessibility label selectors
   */
  private static calculateAccessibilityConfidence(label: string): number {
    let confidence = 0.5; // Base confidence for accessibility

    // Boost for descriptive labels
    if (label.length > 8 && !label.includes('Button') && !label.includes('Tap')) {
      confidence += 0.1;
    }

    // Reduce for generic labels
    if (this.isGenericAccessibilityLabel(label)) {
      confidence -= 0.2;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  /**
   * Calculate confidence score for XPath selectors
   */
  private static calculateXPathConfidence(xpath: string): number {
    let confidence = 0.2; // Base confidence for XPath (brittle)

    // Boost for shorter XPaths
    if (xpath.length < 50) {
      confidence += 0.1;
    }

    // Boost for XPaths with stable attributes
    if (xpath.includes('@resource-id') || xpath.includes('@content-desc')) {
      confidence += 0.1;
    }

    // Reduce for deeply nested XPaths
    const depth = (xpath.match(/\//g) || []).length;
    if (depth > 5) {
      confidence -= 0.1;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  /**
   * Calculate confidence score for coordinate selectors
   */
  private static calculateCoordsConfidence(coords: string): number {
    return 0.1; // Very low confidence for coordinates (last resort)
  }

  /**
   * Check if resource ID has stable naming pattern
   */
  private static hasStableNamingPattern(resourceId: string): boolean {
    const stablePatterns = [
      /^[a-z]+_[a-z_]+$/, // snake_case without numbers
      /btn_/,             // button prefix
      /input_/,           // input field prefix
      /image_/,           // image prefix
      /text_/,            // text view prefix
    ];

    return stablePatterns.some(pattern => pattern.test(resourceId));
  }

  /**
   * Check if resource ID has dynamic pattern
   */
  private static hasDynamicPattern(resourceId: string): boolean {
    const dynamicPatterns = [
      /\d{4,}/,           // 4+ consecutive digits
      /_[a-f0-9]{8,}/i,   // hex identifiers
      /__\d+__/,         // __number__ pattern
      /^\w+\d+$/,        // trailing numbers
    ];

    return dynamicPatterns.some(pattern => pattern.test(resourceId));
  }

  /**
   * Check if resource ID is generic
   */
  private static isGenericResourceId(resourceId: string): boolean {
    const genericIds = [
      'content', 'main', 'container', 'layout', 'root',
      'button', 'text', 'image', 'view', 'widget'
    ];

    return genericIds.includes(resourceId.toLowerCase());
  }

  /**
   * Check if content description is generic
   */
  private static isGenericContentDesc(contentDesc: string): boolean {
    const genericDescs = [
      'button', 'tab', 'image', 'icon', 'menu', 'back', 'next', 'previous',
      'click', 'tap', 'select', 'cancel', 'ok', 'done', 'yes', 'no'
    ];

    return genericDescs.includes(contentDesc.toLowerCase().trim());
  }

  /**
   * Check if text has unique pattern
   */
  private static hasUniqueTextPattern(text: string): boolean {
    // Unique indicators
    const uniquePatterns = [
      /^[A-Z]{2,}/,          // All caps start
      /\d{2,}[^a-z]*$/,      // Ends with numbers
      /[a-z]\d+[a-z]/,       // Mixed alphanumeric
      /^[a-z]+_[a-z_]+$/,    // snake_case
    ];

    return uniquePatterns.some(pattern => pattern.test(text.trim()));
  }

  /**
   * Check if text is common/generic
   */
  private static isCommonText(text: string): boolean {
    const commonTexts = [
      'ok', 'cancel', 'yes', 'no', 'back', 'next', 'previous', 'submit',
      'login', 'logout', 'home', 'settings', 'menu', 'close', 'save',
      'delete', 'edit', 'add', 'remove', 'search', 'filter', 'sort'
    ];

    return commonTexts.includes(text.toLowerCase().trim());
  }

  /**
   * Check if accessibility label is generic
   */
  private static isGenericAccessibilityLabel(label: string): boolean {
    const genericLabels = [
      'button', 'tab', 'image', 'icon', 'double tap', 'single tap',
      'swipe', 'scroll', 'expand', 'collapse', 'select'
    ];

    return genericLabels.some(generic =>
      label.toLowerCase().includes(generic)
    );
  }

  /**
   * Generate XPath selector for element
   */
  private static generateXPath(element: any, elementIndex: number = 0): string {
    if (!element) return '';

    const className = element?.['@_class']?.replace(/^[^.]+\./, '') || '*';
    const text = element?.['@_text'];
    const resourceId = element?.['@_resource-id'];
    const contentDesc = element?.['@_content-desc'];

    // Build XPath based on available attributes
    let xpath = `//${className}`;

    const predicates: string[] = [];

    if (text && text.trim()) {
      predicates.push(`@text='${text}'`);
    }

    if (resourceId && resourceId.trim()) {
      predicates.push(`@resource-id='${resourceId}'`);
    }

    if (contentDesc && contentDesc.trim()) {
      predicates.push(`@content-desc='${contentDesc}'`);
    }

    if (predicates.length > 0) {
      xpath += `[${predicates.join(' and ')}]`;
    }

    // Add position if no unique attributes
    if (predicates.length === 0) {
      xpath += `[${elementIndex + 1}]`;
    }

    return xpath;
  }

  /**
   * Extract center coordinates from bounds string
   */
  private static extractCoordinates(bounds: string): string | null {
    if (!bounds || typeof bounds !== 'string') return null;

    // Parse bounds format: "[left,top][right,bottom]"
    const match = bounds.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
    if (!match) return null;

    const [, left, top, right, bottom] = match.map(Number);
    const centerX = Math.floor((left + right) / 2);
    const centerY = Math.floor((top + bottom) / 2);

    return `${centerX},${centerY}`;
  }

  /**
   * Update confidence based on validation result
   */
  updateValidationResult(success: boolean): void {
    if (success) {
      // Gradually increase confidence on successful validation
      this.confidence = Math.min(1, this.confidence + 0.1);
    } else {
      // Decrease confidence more aggressively on failure
      this.confidence = Math.max(0, this.confidence - 0.2);
    }

    this.lastValidatedAt = new Date().toISOString();
  }

  /**
   * Check if selector is considered risky (low confidence)
   */
  isRisky(): boolean {
    return this.confidence < 0.4;
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): SelectorCandidate {
    return {
      id: this.id,
      type: this.type,
      value: this.value,
      confidence: this.confidence,
      lastValidatedAt: this.lastValidatedAt
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: SelectorCandidate): SelectorCandidateEntity {
    const entity = Object.create(SelectorCandidateEntity.prototype);
    Object.assign(entity, data);
    return entity;
  }
}