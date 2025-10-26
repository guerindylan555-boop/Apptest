/**
 * XML Dump Normalization Utility
 *
 * Normalizes Android UIAutomator XML dumps for consistent processing.
 * Removes dynamic attributes while preserving structural information
 * needed for signature generation and selector extraction.
 */

import type { UIDumpElement } from '../types/graph';

export interface NormalizationOptions {
  /** Remove text content (can be dynamic) */
  removeText?: boolean;
  /** Remove bounds coordinates */
  removeBounds?: boolean;
  /** Remove content-desc attributes */
  removeContentDesc?: boolean;
  /** Keep resource-id even if dynamic */
  keepResourceId?: boolean;
  /** Normalize whitespace */
  normalizeWhitespace?: boolean;
}

export interface NormalizedUIDump {
  /** Normalized XML string */
  xml: string;
  /** Extracted elements with their properties */
  elements: UIDumpElement[];
  /** Activity name if detected */
  activity?: string;
  /** Package name if detected */
  package?: string;
}

export class XMLNormalizer {
  private defaultOptions: Required<NormalizationOptions> = {
    removeText: true,
    removeBounds: true,
    removeContentDesc: true,
    keepResourceId: false,
    normalizeWhitespace: true,
  };

  /**
   * Normalize a UIAutomator XML dump
   */
  async normalize(xmlContent: string, options: NormalizationOptions = {}): Promise<NormalizedUIDump> {
    const opts = { ...this.defaultOptions, ...options };

    try {
      // Parse XML and extract elements
      const parsed = await this.parseXML(xmlContent);

      // Extract metadata
      const activity = this.extractActivity(xmlContent);
      const package = this.extractPackage(xmlContent);

      // Normalize XML content
      const normalizedXML = this.normalizeXMLContent(xmlContent, opts);

      // Extract elements from normalized XML
      const elements = await this.extractElements(normalizedXML);

      return {
        xml: normalizedXML,
        elements,
        activity,
        package,
      };
    } catch (error) {
      console.error('Failed to normalize XML:', error);
      throw new Error(`XML normalization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Parse XML string into DOM-like structure
   */
  private async parseXML(xmlContent: string): Promise<Document> {
    // Use DOMParser if available (Node.js environment)
    if (typeof DOMParser !== 'undefined') {
      const parser = new DOMParser();
      return parser.parseFromString(xmlContent, 'text/xml');
    }

    // Fallback for Node.js - use xml2js or similar
    // For now, return a simple object structure
    throw new Error('XML parsing not implemented in this environment');
  }

  /**
   * Extract activity name from XML content
   */
  private extractActivity(xmlContent: string): string | undefined {
    const activityMatch = xmlContent.match(/activity=['"]([^'"]+)['"]/);
    return activityMatch?.[1];
  }

  /**
   * Extract package name from XML content
   */
  private extractPackage(xmlContent: string): string | undefined {
    const packageMatch = xmlContent.match(/package=['"]([^'"]+)['"]/);
    return packageMatch?.[1];
  }

  /**
   * Normalize XML content by removing dynamic attributes
   */
  private normalizeXMLContent(xmlContent: string, options: Required<NormalizationOptions>): string {
    let normalized = xmlContent;

    // Remove text content if requested
    if (options.removeText) {
      normalized = normalized.replace(/text=['"][^'"]*['"]/g, "text=''");
    }

    // Remove bounds if requested
    if (options.removeBounds) {
      normalized = normalized.replace(/bounds=['"][^'"]*['"]/g, '');
    }

    // Remove content-desc if requested
    if (options.removeContentDesc) {
      normalized = normalized.replace(/content-desc=['"][^'"]*['"]/g, "content-desc=''");
    }

    // Remove dynamic resource-ids unless explicitly kept
    if (!options.keepResourceId) {
      normalized = this.removeDynamicResourceIds(normalized);
    }

    // Normalize whitespace if requested
    if (options.normalizeWhitespace) {
      normalized = normalized.replace(/\s+/g, ' ').trim();
    }

    return normalized;
  }

  /**
   * Remove dynamic resource-ids while keeping stable ones
   */
  private removeDynamicResourceIds(xmlContent: string): string {
    return xmlContent.replace(/resource-id=['"]([^'"]+)['"]/g, (match, resourceId) => {
      if (this.isDynamicResourceId(resourceId)) {
        return "resource-id=''";
      }
      return match;
    });
  }

  /**
   * Check if a resource-id appears to be dynamically generated
   */
  private isDynamicResourceId(resourceId: string): boolean {
    const dynamicPatterns = [
      /\d+$/, // Ends with numbers
      /item_\d+/, // item_N pattern
      /row_\d+/, // row_N pattern
      /cell_\d+/, // cell_N pattern
      /btn_\d+/, // btn_N pattern
      /id\/\d+/, // id/N pattern
      /^[a-f0-9-]+$/i, // Hexadecimal IDs
    ];

    return dynamicPatterns.some(pattern => pattern.test(resourceId));
  }

  /**
   * Extract UI elements from normalized XML
   */
  private async extractElements(xmlContent: string): Promise<UIDumpElement[]> {
    const elements: UIDumpElement[] = [];

    // Simple regex-based extraction for now
    // In a production environment, use proper XML parsing
    const nodeRegex = /<node[^>]*>/g;
    let match;

    while ((match = nodeRegex.exec(xmlContent)) !== null) {
      const nodeXML = match[0];
      const element = this.parseNodeAttributes(nodeXML);

      // Only include elements with useful identifiers
      if (this.isUsefulElement(element)) {
        elements.push(element);
      }
    }

    return elements;
  }

  /**
   * Parse attributes from a node XML string
   */
  private parseNodeAttributes(nodeXML: string): UIDumpElement {
    const element: UIDumpElement = {
      index: '0',
      text: '',
      resource_id: '',
      content_desc: '',
      class: '',
      package: '',
      checkable: 'false',
      checked: 'false',
      clickable: 'false',
      enabled: 'true',
      focusable: 'false',
      focused: 'false',
      scrollable: 'false',
      long_clickable: 'false',
      password: 'false',
      selected: 'false',
      bounds: '',
    };

    // Extract all attributes
    const attributeRegexs = {
      index: /index=['"]([^'"]+)['"]/,
      text: /text=['"]([^'"]*)['"]/,
      resource_id: /resource-id=['"]([^'"]*)['"]/,
      content_desc: /content-desc=['"]([^'"]*)['"]/,
      class: /class=['"]([^'"]+)['"]/,
      package: /package=['"]([^'"]+)['"]/,
      checkable: /checkable=['"]([^'"]+)['"]/,
      checked: /checked=['"]([^'"]+)['"]/,
      clickable: /clickable=['"]([^'"]+)['"]/,
      enabled: /enabled=['"]([^'"]+)['"]/,
      focusable: /focusable=['"]([^'"]+)['"]/,
      focused: /focused=['"]([^'"]+)['"]/,
      scrollable: /scrollable=['"]([^'"]+)['"]/,
      long_clickable: /long-clickable=['"]([^'"]+)['"]/,
      password: /password=['"]([^'"]+)['"]/,
      selected: /selected=['"]([^'"]+)['"]/,
      bounds: /bounds=['"]([^'"]*)['"]/,
    };

    for (const [attr, regex] of Object.entries(attributeRegexs)) {
      const match = nodeXML.match(regex);
      if (match) {
        (element as any)[attr] = match[1];
      }
    }

    return element;
  }

  /**
   * Determine if an element is useful for UI automation
   */
  private isUsefulElement(element: UIDumpElement): boolean {
    // Element must be enabled
    if (element.enabled !== 'true') {
      return false;
    }

    // Element should be clickable, focusable, or have meaningful identifiers
    const isInteractive = element.clickable === 'true' ||
                         element.focusable === 'true' ||
                         element.long_clickable === 'true' ||
                         element.scrollable === 'true';

    const hasIdentifier = element.resource_id &&
                         element.resource_id.length > 0 &&
                         !element.resource_id.startsWith('id/');

    const hasText = element.text &&
                   element.text.length > 0 &&
                   element.text.length < 100; // Filter out very long text

    const hasContentDesc = element.content_desc &&
                          element.content_desc.length > 0 &&
                          element.content_desc.length < 100;

    return isInteractive || hasIdentifier || hasText || hasContentDesc;
  }

  /**
   * Extract resource-ids from normalized XML
   */
  extractResourceIds(xmlContent: string): string[] {
    const resourceIdPattern = /resource-id=['"]([^'"]+)['"]/g;
    const resourceIds: string[] = [];
    let match;

    while ((match = resourceIdPattern.exec(xmlContent)) !== null) {
      const resourceId = match[1];
      if (resourceId && !this.isDynamicResourceId(resourceId)) {
        resourceIds.push(resourceId.toLowerCase().trim());
      }
    }

    return [...new Set(resourceIds)].sort();
  }

  /**
   * Extract text content from normalized XML
   */
  extractTexts(xmlContent: string): string[] {
    const textPattern = /text=['"]([^'"]+)['"]/g;
    const texts: string[] = [];
    let match;

    while ((match = textPattern.exec(xmlContent)) !== null) {
      const text = match[1];
      if (text && this.isMeaningfulText(text)) {
        texts.push(text.toLowerCase().trim());
      }
    }

    return [...new Set(texts)].sort();
  }

  /**
   * Check if text is meaningful for identification
   */
  private isMeaningfulText(text: string): boolean {
    if (text.length < 2 || text.length > 100) {
      return false;
    }

    // Filter out common UI noise
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
   * Generate a layout fingerprint by analyzing XML structure
   */
  generateLayoutFingerprint(xmlContent: string): string {
    // Remove all attributes and content, keep only tag hierarchy
    const structure = xmlContent
      .replace(/<node[^>]*>/g, '<node>')
      .replace(/text=['"][^'"]*['"]/g, '')
      .replace(/resource-id=['"][^'"]*['"]/g, '')
      .replace(/content-desc=['"][^'"]*['"]/g, '')
      .replace(/bounds=['"][^'"]*['"]/g, '')
      .replace(/\s+/g, '')
      .trim();

    // Create hash of the structure
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(structure).digest('hex').substring(0, 16);
  }
}

export const xmlNormalizer = new XMLNormalizer();