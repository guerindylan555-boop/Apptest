/**
 * Semantic Selector Utilities
 *
 * Provides intelligent element identification using semantic properties,
 * content analysis, and AI-assisted selector generation for robust UI automation.
 */

import { Selector, StateRecord } from '../types/graph';

/**
 * Semantic selector with enhanced matching capabilities
 */
export interface SemanticSelector extends Selector {
  /** Semantic meaning of the element */
  semanticType?: 'button' | 'input' | 'link' | 'image' | 'text' | 'container' | 'navigation' | 'menu' | 'list' | 'unknown';

  /** Element purpose based on content and context */
  purpose?: string;

  /** Content-based signature */
  contentSignature?: string;

  /** Location hints */
  locationHint?: {
    position: 'header' | 'footer' | 'sidebar' | 'main' | 'center' | 'floating';
    area?: string;
  };

  /** Relational selectors */
  nearText?: string[];
  containsText?: string[];
  followsElement?: Selector;
  precedesElement?: Selector;

  /** Visual properties */
  visualHints?: {
    color?: string;
    size?: 'small' | 'medium' | 'large';
    prominence?: 'high' | 'medium' | 'low';
  };

  /** Interaction hints */
  interactionHints?: {
    clickable: boolean;
    editable: boolean;
    scrollable: boolean;
  };

  /** Fallback strategies */
  fallbackSelectors?: Selector[];

  /** Confidence score */
  confidence?: number;
}

/**
 * Element classification result
 */
export interface ElementClassification {
  element: Selector;
  semanticType: SemanticSelector['semanticType'];
  purpose: string;
  confidence: number;
  reasoning: string[];
  alternatives: SemanticSelector[];
}

/**
 * Selector generation options
 */
export interface SelectorGenerationOptions {
  /** Prefer semantic selectors over exact matches */
  preferSemantic: boolean;

  /** Include fallback strategies */
  includeFallbacks: boolean;

  /** Minimum confidence threshold */
  minConfidence: number;

  /** Generate multiple alternatives */
  generateAlternatives: boolean;

  /** Consider element context */
  useContext: boolean;

  /** Use content analysis */
  useContentAnalysis: boolean;
}

/**
 * Generate semantic selectors for a state's elements
 */
export function generateSemanticSelectors(
  state: StateRecord,
  options: Partial<SelectorGenerationOptions> = {}
): SemanticSelector[] {
  const opts: SelectorGenerationOptions = {
    preferSemantic: true,
    includeFallbacks: true,
    minConfidence: 0.7,
    generateAlternatives: true,
    useContext: true,
    useContentAnalysis: true,
    ...options
  };

  return state.selectors.map(selector =>
    enhanceSelectorWithSemantics(selector, state, opts)
  );
}

/**
 * Enhance a basic selector with semantic information
 */
export function enhanceSelectorWithSemantics(
  selector: Selector,
  state: StateRecord,
  options: SelectorGenerationOptions
): SemanticSelector {
  const enhanced: SemanticSelector = { ...selector };

  // Classify element type
  const classification = classifyElement(selector, state);
  enhanced.semanticType = classification.semanticType;
  enhanced.purpose = classification.purpose;
  enhanced.confidence = classification.confidence;

  // Generate content signature
  enhanced.contentSignature = generateContentSignature(selector, state);

  // Analyze location
  enhanced.locationHint = analyzeLocation(selector, state);

  // Extract content relationships
  if (options.useContext) {
    enhanced.nearText = findNearbyText(selector, state);
    enhanced.containsText = selector.text ? [selector.text] : [];
  }

  // Analyze visual properties
  enhanced.visualHints = analyzeVisualProperties(selector, state);

  // Determine interaction capabilities
  enhanced.interactionHints = analyzeInteractionCapabilities(selector, state);

  // Generate fallback selectors
  if (options.includeFallbacks) {
    enhanced.fallbackSelectors = generateFallbackSelectors(selector, state);
  }

  return enhanced;
}

/**
 * Classify element based on its properties and content
 */
function classifyElement(selector: Selector, state: StateRecord): ElementClassification {
  const reasoning: string[] = [];
  let semanticType: SemanticSelector['semanticType'] = 'unknown';
  let purpose = '';
  let confidence = 0.5;

  const className = selector.cls?.toLowerCase() || '';
  const text = selector.text?.toLowerCase() || '';
  const desc = selector.desc?.toLowerCase() || '';
  const resourceId = selector.rid?.toLowerCase() || '';

  // Button classification
  if (className.includes('button') ||
      text.includes('click') || text.includes('submit') || text.includes('login') ||
      desc.includes('button') || resourceId.includes('btn')) {
    semanticType = 'button';
    purpose = text || desc || 'Interactive button';
    confidence = 0.9;
    reasoning.push('Class name or content indicates button');
  }
  // Input classification
  else if (className.includes('edit') || className.includes('input') || className.includes('field') ||
           resourceId.includes('edit') || resourceId.includes('input')) {
    semanticType = 'input';
    purpose = desc || text || 'Text input field';
    confidence = 0.85;
    reasoning.push('Class name or resource ID indicates input field');
  }
  // Link classification
  else if (className.includes('link') || text.includes('http') ||
           (text && (text.includes('learn more') || text.includes('read more')))) {
    semanticType = 'link';
    purpose = text || desc || 'Navigation link';
    confidence = 0.8;
    reasoning.push('Content or class indicates link');
  }
  // Image classification
  else if (className.includes('image') || className.includes('img') || className.includes('photo')) {
    semanticType = 'image';
    purpose = desc || text || 'Image element';
    confidence = 0.75;
    reasoning.push('Class name indicates image');
  }
  // Navigation classification
  else if (className.includes('nav') || className.includes('menu') ||
           resourceId.includes('nav') || resourceId.includes('menu')) {
    semanticType = 'navigation';
    purpose = 'Navigation element';
    confidence = 0.8;
    reasoning.push('Class name indicates navigation');
  }
  // List classification
  else if (className.includes('list') || className.includes('item') ||
           resourceId.includes('list') || resourceId.includes('item')) {
    semanticType = 'list';
    purpose = 'List item';
    confidence = 0.75;
    reasoning.push('Class name indicates list item');
  }
  // Container classification
  else if (className.includes('container') || className.includes('layout') ||
           className.includes('panel') || className.includes('group')) {
    semanticType = 'container';
    purpose = desc || text || 'Layout container';
    confidence = 0.6;
    reasoning.push('Class name indicates container');
  }
  // Text classification
  else if (text && text.length > 0 && !className.includes('input')) {
    semanticType = 'text';
    purpose = text;
    confidence = 0.7;
    reasoning.push('Element contains display text');
  }

  return {
    element: selector,
    semanticType,
    purpose,
    confidence,
    reasoning,
    alternatives: []
  };
}

/**
 * Generate content signature for element matching
 */
function generateContentSignature(selector: Selector, state: StateRecord): string {
  const parts: string[] = [];

  if (selector.text) {
    parts.push(`text:${selector.text.toLowerCase().replace(/[^a-z0-9]/g, '')}`);
  }

  if (selector.desc) {
    parts.push(`desc:${selector.desc.toLowerCase().replace(/[^a-z0-9]/g, '')}`);
  }

  if (selector.rid) {
    parts.push(`id:${selector.rid.toLowerCase().replace(/[^a-z0-9]/g, '')}`);
  }

  const className = selector.cls?.split('.').pop()?.toLowerCase() || '';
  if (className) {
    parts.push(`class:${className}`);
  }

  return parts.join('|');
}

/**
 * Analyze element location within the screen
 */
function analyzeLocation(selector: Selector, state: StateRecord): SemanticSelector['locationHint'] {
  if (!selector.bounds) return undefined;

  const [left, top, right, bottom] = selector.bounds;
  const width = right - left;
  const height = bottom - top;
  const centerX = (left + right) / 2;
  const centerY = (top + bottom) / 2;

  // This would normally require screen dimensions, using normalized estimates
  const screenWidth = 1080; // Typical Android width
  const screenHeight = 1920; // Typical Android height

  let position: SemanticSelector['locationHint']['position'] = 'center';

  // Determine position
  if (top < screenHeight * 0.1) {
    position = 'header';
  } else if (bottom > screenHeight * 0.9) {
    position = 'footer';
  } else if (left < screenWidth * 0.2) {
    position = 'sidebar';
  } else if (centerX > screenWidth * 0.3 && centerX < screenWidth * 0.7 &&
             centerY > screenHeight * 0.3 && centerY < screenHeight * 0.7) {
    position = 'main';
  }

  let size: 'small' | 'medium' | 'large' = 'medium';
  const area = width * height;
  if (area < 10000) size = 'small';
  else if (area > 50000) size = 'large';

  return {
    position,
    area: `${Math.round(width)}x${Math.round(height)}`,
    size
  };
}

/**
 * Find nearby text elements for context
 */
function findNearbyText(selector: Selector, state: StateRecord): string[] {
  if (!selector.bounds) return [];

  const [left, top, right, bottom] = selector.bounds;
  const proximityThreshold = 100; // pixels

  const nearbyTexts: string[] = [];

  state.selectors.forEach(other => {
    if (other.id === selector.rid) return; // Skip self

    if (other.bounds) {
      const [otherLeft, otherTop, otherRight, otherBottom] = other.bounds;

      // Check if elements are nearby
      const horizontalDistance = Math.min(
        Math.abs(left - otherRight),
        Math.abs(right - otherLeft)
      );
      const verticalDistance = Math.min(
        Math.abs(top - otherBottom),
        Math.abs(bottom - otherTop)
      );

      if (horizontalDistance < proximityThreshold || verticalDistance < proximityThreshold) {
        if (other.text && other.text.trim().length > 0) {
          nearbyTexts.push(other.text.trim());
        }
        if (other.desc && other.desc.trim().length > 0) {
          nearbyTexts.push(other.desc.trim());
        }
      }
    }
  });

  return nearbyTexts.slice(0, 5); // Limit to 5 nearby texts
}

/**
 * Analyze visual properties based on class names and attributes
 */
function analyzeVisualProperties(selector: Selector, state: StateRecord): SemanticSelector['visualHints'] {
  const className = selector.cls?.toLowerCase() || '';
  const text = selector.text?.toLowerCase() || '';

  let prominence: 'high' | 'medium' | 'low' = 'medium';
  let size: 'small' | 'medium' | 'large' = 'medium';

  // Determine prominence from class names and content
  if (className.includes('important') || className.includes('primary') ||
      className.includes('large') || text.includes('important')) {
    prominence = 'high';
  } else if (className.includes('secondary') || className.includes('small') ||
             className.includes('subtle')) {
    prominence = 'low';
  }

  // Determine size from bounds if available
  if (selector.bounds) {
    const [left, top, right, bottom] = selector.bounds;
    const area = (right - left) * (bottom - top);
    if (area < 5000) size = 'small';
    else if (area > 20000) size = 'large';
  }

  return {
    size,
    prominence
  };
}

/**
 * Analyze interaction capabilities
 */
function analyzeInteractionCapabilities(selector: Selector, state: StateRecord): SemanticSelector['interactionHints'] {
  const className = selector.cls?.toLowerCase() || '';
  const resourceId = selector.rid?.toLowerCase() || '';

  // Determine clickability
  const clickable = className.includes('button') || className.includes('clickable') ||
                    resourceId.includes('btn') || selector.text !== undefined ||
                    selector.desc !== undefined;

  // Determine editability
  const editable = className.includes('edit') || className.includes('input') ||
                   className.includes('field') || resourceId.includes('edit');

  // Determine scrollability
  const scrollable = className.includes('scroll') || className.includes('list');

  return {
    clickable: clickable !== false,
    editable: editable !== false,
    scrollable: scrollable !== false
  };
}

/**
 * Generate fallback selectors for robustness
 */
function generateFallbackSelectors(selector: Selector, state: StateRecord): Selector[] {
  const fallbacks: Selector[] = [];

  // Original selector
  fallbacks.push({ ...selector });

  // Text-based fallback
  if (selector.text) {
    fallbacks.push({
      text: selector.text
    });
  }

  // Description-based fallback
  if (selector.desc) {
    fallbacks.push({
      desc: selector.desc
    });
  }

  // Resource ID fallback
  if (selector.rid) {
    fallbacks.push({
      rid: selector.rid
    });
  }

  // Class name fallback
  if (selector.cls) {
    fallbacks.push({
      cls: selector.cls
    });
  }

  // Partial resource ID fallback
  if (selector.rid && selector.rid.includes('/')) {
    const parts = selector.rid.split('/');
    if (parts.length > 1) {
      fallbacks.push({
        rid: parts[parts.length - 1] // Last part only
      });
    }
  }

  return fallbacks.filter((fb, index, arr) =>
    arr.findIndex(f => JSON.stringify(f) === JSON.stringify(fb)) === index
  );
}

/**
 * Match semantic selector against current state
 */
export function matchSemanticSelector(
  semanticSelector: SemanticSelector,
  currentState: StateRecord,
  threshold: number = 0.7
): Selector | null {
  const candidates = currentState.selectors;

  // Try exact matches first
  if (semanticSelector.rid) {
    const exactMatch = candidates.find(s => s.rid === semanticSelector.rid);
    if (exactMatch) return exactMatch;
  }

  // Try content-based matching
  if (semanticSelector.text || semanticSelector.desc) {
    const contentMatch = candidates.find(s =>
      (semanticSelector.text && s.text === semanticSelector.text) ||
      (semanticSelector.desc && s.desc === semanticSelector.desc)
    );
    if (contentMatch) return contentMatch;
  }

  // Try semantic matching
  const semanticMatches = candidates.map(candidate => ({
    candidate,
    score: calculateSemanticSimilarity(semanticSelector, candidate, currentState)
  }))
  .filter(match => match.score >= threshold)
  .sort((a, b) => b.score - a.score);

  return semanticMatches.length > 0 ? semanticMatches[0].candidate : null;
}

/**
 * Calculate semantic similarity between selector and candidate
 */
function calculateSemanticSimilarity(
  semanticSelector: SemanticSelector,
  candidate: Selector,
  state: StateRecord
): number {
  let score = 0;
  let factors = 0;

  // Class name similarity
  if (semanticSelector.cls && candidate.cls) {
    score += semanticSelector.cls === candidate.cls ? 1 : 0.3;
    factors++;
  }

  // Content similarity
  if (semanticSelector.text && candidate.text) {
    score += semanticSelector.text.toLowerCase() === candidate.text.toLowerCase() ? 1 : 0.5;
    factors++;
  }

  // Description similarity
  if (semanticSelector.desc && candidate.desc) {
    score += semanticSelector.desc.toLowerCase() === candidate.desc.toLowerCase() ? 1 : 0.5;
    factors++;
  }

  // Resource ID similarity
  if (semanticSelector.rid && candidate.rid) {
    score += semanticSelector.rid === candidate.rid ? 1 : 0.7;
    factors++;
  }

  // Semantic type matching
  const candidateSemantic = classifyElement(candidate, state);
  if (semanticSelector.semanticType === candidateSemantic.semanticType) {
    score += 0.8;
    factors++;
  }

  // Location similarity
  if (semanticSelector.locationHint && candidate.bounds) {
    // This would need screen dimensions for accurate comparison
    score += 0.3;
    factors++;
  }

  return factors > 0 ? score / factors : 0;
}

/**
 * Generate robust selector strategy for flow execution
 */
export function generateSelectorStrategy(
  targetSelector: SemanticSelector,
  currentState: StateRecord
): {
  primary: Selector;
  fallbacks: Selector[];
  strategy: 'exact' | 'semantic' | 'hybrid';
  confidence: number;
} {
  // Try to find exact match first
  const exactMatch = matchSemanticSelector(targetSelector, currentState, 1.0);

  if (exactMatch && targetSelector.confidence && targetSelector.confidence > 0.9) {
    return {
      primary: exactMatch,
      fallbacks: targetSelector.fallbackSelectors || [],
      strategy: 'exact',
      confidence: targetSelector.confidence
    };
  }

  // Use semantic matching
  const semanticMatch = matchSemanticSelector(targetSelector, currentState, 0.6);

  if (semanticMatch) {
    return {
      primary: semanticMatch,
      fallbacks: targetSelector.fallbackSelectors || [],
      strategy: 'semantic',
      confidence: targetSelector.confidence || 0.7
    };
  }

  // Use fallback strategy
  return {
    primary: targetSelector.fallbackSelectors?.[0] || targetSelector,
    fallbacks: targetSelector.fallbackSelectors?.slice(1) || [],
    strategy: 'hybrid',
    confidence: 0.5
  };
}