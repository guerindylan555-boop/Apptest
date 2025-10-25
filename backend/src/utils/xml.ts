/**
 * XML Processing Utilities
 *
 * UI hierarchy XML normalization and selector extraction.
 * Optimized for stable state hashing and element identification.
 */

import { parseString } from 'xml2js';

// Type definitions for xml2js
interface XmlNode {
  [key: string]: any;
  $?: { [key: string]: string };
  $$?: XmlNode[];
  _?: string;
}

type Element = XmlNode;
type Node = XmlNode;
import { Selector } from '../types/graph';

export interface NormalizationOptions {
  /** Remove index attributes that change dynamically */
  removeIndexes: boolean;
  /** Remove timestamp attributes */
  removeTimestamps: boolean;
  /** Remove selection state attributes */
  removeSelectionStates: boolean;
  /** Remove dynamic ID attributes */
  removeDynamicIds: boolean;
}

export interface UIElement {
  node: Element;
  xpath: string;
  selector: Selector;
  text: string[];
  interactive: boolean;
}

/**
 * Default normalization options for stable hashing
 */
export const DEFAULT_NORMALIZATION_OPTIONS: NormalizationOptions = {
  removeIndexes: true,
  removeTimestamps: true,
  removeSelectionStates: true,
  removeDynamicIds: true
};

/**
 * Attribute patterns to normalize out
 */
const VOLATILE_ATTRIBUTES = [
  /^index$/i,
  /^focused/i,
  /^selected/i,
  /^checked/i,
  /^pressed/i,
  /^activated/i,
  /^scroll-?/i,
  /^timestamp$/i,
  /^time$/i,
  /^id-\d+/i,
  /^resourceId-\d+/i
];

/**
 * Interactive element classes
 */
const INTERACTIVE_CLASSES = [
  'android.widget.Button',
  'android.widget.EditText',
  'android.widget.TextView',
  'android.widget.ImageView',
  'android.widget.ImageButton',
  'android.widget.CheckBox',
  'android.widget.RadioButton',
  'android.widget.Switch',
  'android.widget.Spinner',
  'android.widget.ProgressBar',
  'android.widget.SeekBar',
  'android.widget.RatingBar',
  'android.widget.TabWidget',
  'android.widget.GridView',
  'android.widget.ListView',
  'android.widget.RecyclerView',
  'android.webkit.WebView',
  'androidx.recyclerview.widget.RecyclerView',
  'com.google.android.material.button.MaterialButton',
  'com.google.android.material.textfield.TextInputEditText',
  'com.google.android.material.textfield.TextInputLayout'
];

/**
 * Parse UI hierarchy XML string
 */
export function parseUIHierarchy(xml: string): Element | null {
  try {
    let document: any = null;
    parseString(xml, (err: Error, result: any) => {
      if (err) {
        throw err;
      }
      document = result;
    });
    return document;
  } catch (error) {
    throw new Error(`Failed to parse UI hierarchy XML: ${error}`);
  }
}

/**
 * Normalize XML for stable hashing
 */
export function normalizeXML(
  node: Element,
  options: NormalizationOptions = DEFAULT_NORMALIZATION_OPTIONS
): Element {
  if (!node) return node;

  const normalized = { ...node };

  // Normalize attributes
  if (normalized.$) {
    normalized.$ = normalizeAttributes(normalized.$, options);
  }

  // Normalize children recursively
  if (Array.isArray(normalized.$$)) {
    normalized.$$ = normalized.$$
      .map(child => normalizeXML(child, options))
      .filter(child => child !== null) as Element[];
  }

  return normalized;
}

/**
 * Normalize node attributes
 */
function normalizeAttributes(
  attributes: Record<string, string>,
  options: NormalizationOptions
): Record<string, string> {
  const normalized: Record<string, string> = {};

  Object.entries(attributes).forEach(([key, value]) => {
    let shouldKeep = true;

    // Remove indexes
    if (options.removeIndexes && key.toLowerCase().includes('index')) {
      shouldKeep = false;
    }

    // Remove timestamps
    if (options.removeTimestamps && VOLATILE_ATTRIBUTES.some(pattern =>
      pattern.test(key) && key.toLowerCase().includes('time')
    )) {
      shouldKeep = false;
    }

    // Remove selection states
    if (options.removeSelectionStates && VOLATILE_ATTRIBUTES.some(pattern =>
      pattern.test(key) && (key.toLowerCase().includes('focus') ||
                          key.toLowerCase().includes('select') ||
                          key.toLowerCase().includes('check') ||
                          key.toLowerCase().includes('press'))
    )) {
      shouldKeep = false;
    }

    // Remove dynamic IDs
    if (options.removeDynamicIds && VOLATILE_ATTRIBUTES.some(pattern =>
      pattern.test(key) && key.toLowerCase().includes('id')
    )) {
      shouldKeep = false;
    }

    if (shouldKeep) {
      normalized[key] = value;
    }
  });

  return normalized;
}

/**
 * Extract selectors from UI hierarchy
 */
export function extractSelectors(root: Element): Selector[] {
  const elements = extractUIElements(root);
  return elements
    .filter(element => element.interactive)
    .map(element => element.selector)
    .filter((selector, index, array) =>
      // Remove duplicates based on bounds
      array.findIndex(s =>
        s.bounds && selector.bounds &&
        arraysEqual(s.bounds, selector.bounds)
      ) === index
    );
}

/**
 * Extract UI elements with selectors
 */
export function extractUIElements(root: Element): UIElement[] {
  const elements: UIElement[] = [];

  function traverse(node: Element, xpath: string = ''): void {
    if (!node || !node.$) return;

    const element = processNode(node, xpath);
    if (element) {
      elements.push(element);
    }

    // Process children
    if (Array.isArray(node.$$)) {
      node.$$.forEach((child, index) => {
        const childXpath = `${xpath}/${node.$['class'] || 'node'}[${index + 1}]`;
        traverse(child, childXpath);
      });
    }
  }

  traverse(root);
  return elements;
}

/**
 * Process individual XML node into UI element
 */
function processNode(node: Element, xpath: string): UIElement | null {
  if (!node.$) return null;

  const attrs = node.$;
  const className = attrs['class'] || '';
  const textContent = extractTextContent(node);

  // Check if element is interactive
  const interactive = INTERACTIVE_CLASSES.some(cls =>
    className.includes(cls) ||
    cls.includes(className.split('.').pop() || '')
  );

  if (!interactive && !textContent) {
    return null;
  }

  // Extract bounds
  let bounds: [number, number, number, number] | undefined;
  if (attrs.bounds) {
    const match = attrs.bounds.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
    if (match) {
      bounds = [
        parseInt(match[1]),
        parseInt(match[2]),
        parseInt(match[3]),
        parseInt(match[4])
      ];
    }
  }

  // Build selector
  const selector: Selector = {
    rid: attrs['resource-id'] || attrs.resourceId,
    desc: attrs['content-desc'] || attrs.contentDescription,
    text: textContent || undefined,
    cls: className,
    bounds,
    xpath: xpath.length > 200 ? undefined : xpath // Limit xpath length
  };

  // Remove undefined values
  Object.keys(selector).forEach(key => {
    if (selector[key as keyof Selector] === undefined ||
        selector[key as keyof Selector] === '') {
      delete selector[key as keyof Selector];
    }
  });

  return {
    node,
    xpath,
    selector,
    text: textContent ? [textContent] : [],
    interactive
  };
}

/**
 * Extract text content from node and its children
 */
function extractTextContent(node: Element): string | null {
  if (!node) return null;

  let text = '';

  // Get text from text attribute
  if (node.$?.text) {
    text += node.$.text.trim();
  }

  // Get text from child nodes
  if (Array.isArray(node.$$)) {
    node.$$?.forEach(child => {
      const childText = extractTextContent(child);
      if (childText) {
        text += ' ' + childText;
      }
    });
  }

  return text.trim() || null;
}

/**
 * Generate normalized XML hash
 */
export function generateXMLHash(node: Element): string {
  const normalized = normalizeXML(node);
  const xmlString = nodeToXMLString(normalized);

  // Create SHA256 hash
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(xmlString).digest('hex');
}

/**
 * Convert XML node back to string (simplified)
 */
function nodeToXMLString(node: Element, indent: number = 0): string {
  if (!node || !node.$) return '';

  const indentStr = '  '.repeat(indent);
  const attrs = Object.entries(node.$)
    .map(([key, value]) => `${key}="${value}"`)
    .join(' ');

  let xml = `${indentStr}<${node.$['class'] || 'node'}`;
  if (attrs) {
    xml += ` ${attrs}`;
  }

  if (Array.isArray(node.$$) && node.$$.length > 0) {
    xml += '>\n';
    node.$$?.forEach(child => {
      xml += nodeToXMLString(child, indent + 1) + '\n';
    });
    xml += `${indentStr}</${node.$['class'] || 'node'}>`;
  } else {
    xml += ' />';
  }

  return xml;
}

/**
 * Check if two selectors are equivalent
 */
export function areSelectorsEqual(a: Selector, b: Selector): boolean {
  // Check bounds first (most specific)
  if (a.bounds && b.bounds) {
    return arraysEqual(a.bounds, b.bounds);
  }

  // Check resource ID
  if (a.rid && b.rid && a.rid === b.rid) {
    return true;
  }

  // Check content description
  if (a.desc && b.desc && a.desc === b.desc) {
    return true;
  }

  // Check text
  if (a.text && b.text && a.text === b.text) {
    return true;
  }

  // Check class
  if (a.cls && b.cls && a.cls === b.cls) {
    return true;
  }

  return false;
}

/**
 * Calculate Jaccard similarity between two selector sets
 */
export function calculateSelectorSimilarity(
  selectors1: Selector[],
  selectors2: Selector[]
): number {
  if (selectors1.length === 0 && selectors2.length === 0) {
    return 1.0;
  }

  if (selectors1.length === 0 || selectors2.length === 0) {
    return 0.0;
  }

  let matches = 0;
  selectors1.forEach(s1 => {
    if (selectors2.some(s2 => areSelectorsEqual(s1, s2))) {
      matches++;
    }
  });

  const intersection = matches;
  const union = selectors1.length + selectors2.length - matches;

  return intersection / union;
}

/**
 * Utility: Check if two arrays are equal
 */
function arraysEqual<T>(a: T[], b: T[]): boolean {
  return a.length === b.length && a.every((val, index) => val === b[index]);
}