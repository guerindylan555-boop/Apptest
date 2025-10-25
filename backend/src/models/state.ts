/**
 * AutoApp UI Map & Intelligent Flow Engine - State Entity Model
 *
 * Comprehensive State entity implementation for UI state discovery and graph generation.
 * Provides selector normalization, validation, state digest calculation, and utility methods
 * for managing UI states captured from Android applications.
 *
 * Based on specs/001-ui-map-flow-engine/data-model.md and task T021 requirements.
 */

import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs/promises';
import * as path from 'path';

// Import types from the models definition
import {
  State as IState,
  Selector as ISelector,
  CreateStateRequest,
  UpdateStateRequest,
  StateError,
  ValidationError,
  ValidationResult,
  ValidationWarning,
  CaptureMethod,
  UUID,
  ISOTimestamp
} from '../types/models';

// Import utilities
import { hashObject } from '../utils/hash';

// ============================================================================
// Error Classes
// ============================================================================

/**
 * Custom error class for State validation failures
 */
export class StateValidationError extends Error {
  public readonly code: string;
  public readonly field?: string;
  public readonly value?: any;
  public readonly timestamp: string;

  constructor(message: string, code: string, field?: string, value?: any) {
    super(message);
    this.name = 'StateValidationError';
    this.code = code;
    this.field = field;
    this.value = value;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Custom error class for State-related operations
 */
export class StateOperationError extends Error {
  public readonly code: string;
  public readonly stateId?: string;
  public readonly timestamp: string;

  constructor(message: string, code: string, stateId?: string) {
    super(message);
    this.name = 'StateOperationError';
    this.code = code;
    this.stateId = stateId;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * Custom error class for selector validation failures
 */
export class SelectorValidationError extends StateValidationError {
  constructor(message: string, field?: string, value?: any) {
    super(message, 'SELECTOR_VALIDATION_ERROR', field, value);
    this.name = 'SelectorValidationError';
  }
}

// ============================================================================
// Selector Utilities
// ============================================================================

/**
 * Utility class for selector normalization and validation
 */
class SelectorUtilsInternal {
  /**
   * Normalizes a selector by cleaning and validating its properties
   *
   * @param selector - Raw selector to normalize
   * @returns Normalized selector
   * @throws SelectorValidationError if selector is invalid
   */
  static normalizeSelector(selector: ISelector): ISelector {
    const normalized: ISelector = {};

    // Normalize resource ID
    if (selector.rid) {
      const trimmedRid = selector.rid.trim();
      if (trimmedRid.length === 0) {
        throw new SelectorValidationError('Resource ID cannot be empty', 'rid', selector.rid);
      }
      // Remove common prefixes and clean up
      normalized.rid = trimmedRid.replace(/^id\//, '').replace(/^android:id\//, '');
    }

    // Normalize text content
    if (selector.text) {
      const trimmedText = selector.text.trim();
      if (trimmedText.length === 0) {
        throw new SelectorValidationError('Text cannot be empty', 'text', selector.text);
      }
      normalized.text = trimmedText;
    }

    // Normalize content description
    if (selector.desc) {
      const trimmedDesc = selector.desc.trim();
      if (trimmedDesc.length === 0) {
        throw new SelectorValidationError('Content description cannot be empty', 'desc', selector.desc);
      }
      normalized.desc = trimmedDesc;
    }

    // Normalize class name
    if (selector.cls) {
      const trimmedCls = selector.cls.trim();
      if (trimmedCls.length === 0) {
        throw new SelectorValidationError('Class name cannot be empty', 'cls', selector.cls);
      }
      normalized.cls = trimmedCls;
    }

    // Normalize and validate bounds
    if (selector.bounds) {
      if (!Array.isArray(selector.bounds) || selector.bounds.length !== 4) {
        throw new SelectorValidationError('Bounds must be an array of 4 numbers [left, top, right, bottom]', 'bounds', selector.bounds);
      }

      const [left, top, right, bottom] = selector.bounds;
      if (typeof left !== 'number' || typeof top !== 'number' || typeof right !== 'number' || typeof bottom !== 'number') {
        throw new SelectorValidationError('All bounds values must be numbers', 'bounds', selector.bounds);
      }

      if (left < 0 || top < 0 || right < 0 || bottom < 0) {
        throw new SelectorValidationError('Bounds values must be non-negative', 'bounds', selector.bounds);
      }

      if (left >= right || top >= bottom) {
        throw new SelectorValidationError('Invalid bounds geometry: left must be < right and top must be < bottom', 'bounds', selector.bounds);
      }

      normalized.bounds = [left, top, right, bottom];
    }

    // Normalize XPath
    if (selector.xpath) {
      const trimmedXpath = selector.xpath.trim();
      if (trimmedXpath.length === 0) {
        throw new SelectorValidationError('XPath cannot be empty', 'xpath', selector.xpath);
      }
      normalized.xpath = trimmedXpath;
    }

    return normalized;
  }

  /**
   * Validates that a selector has at least one identifying property
   *
   * @param selector - Selector to validate
   * @throws SelectorValidationError if selector is invalid
   */
  static validateSelectorHasProperties(selector: ISelector): void {
    const hasProperties = !!(selector.rid || selector.text || selector.desc || selector.cls || selector.xpath);
    if (!hasProperties) {
      throw new SelectorValidationError('Selector must have at least one identifying property (rid, text, desc, cls, or xpath)');
    }
  }

  /**
   * Deduplicates selectors within a state based on their normalized form
   *
   * @param selectors - Array of selectors to deduplicate
   * @returns Deduplicated array of unique selectors
   */
  static deduplicateSelectors(selectors: ISelector[]): ISelector[] {
    const seen = new Set<string>();
    const unique: ISelector[] = [];

    for (const selector of selectors) {
      const normalized = this.normalizeSelector(selector);
      const selectorKey = this.getSelectorKey(normalized);

      if (!seen.has(selectorKey)) {
        seen.add(selectorKey);
        unique.push(normalized);
      }
    }

    return unique;
  }

  /**
   * Creates a unique key for a selector based on its properties
   *
   * @param selector - Selector to create key for
   * @returns Unique string key for the selector
   */
  static getSelectorKey(selector: ISelector): string {
    const parts = [
      selector.rid || '',
      selector.text || '',
      selector.desc || '',
      selector.cls || '',
      selector.xpath || '',
      selector.bounds ? selector.bounds.join(',') : ''
    ];
    return parts.join('|');
  }

  /**
   * Determines if a selector represents an interactive element
   *
   * @param selector - Selector to check
   * @returns True if the selector appears to be interactive
   */
  static isInteractive(selector: ISelector): boolean {
    // Check for common interactive class patterns
    if (selector.cls) {
      const interactiveClasses = [
        'Button', 'ImageButton', 'EditText', 'CheckBox', 'RadioButton',
        'ToggleButton', 'Switch', 'SeekBar', 'Spinner', 'ListView',
        'RecyclerView', 'GridView', 'ScrollView', 'HorizontalScrollView',
        'ViewPager', 'TabHost', 'TabWidget', 'Menu', 'MenuItem'
      ];

      for (const cls of interactiveClasses) {
        if (selector.cls.includes(cls)) {
          return true;
        }
      }
    }

    // Check for common interactive resource ID patterns
    if (selector.rid) {
      const interactivePatterns = [
        'button', 'btn', 'edit', 'input', 'text', 'field', 'checkbox',
        'radio', 'switch', 'toggle', 'slider', 'seek', 'menu', 'item',
        'list', 'grid', 'scroll', 'tab', 'nav', 'close', 'back', 'next',
        'previous', 'submit', 'cancel', 'ok', 'yes', 'no', 'accept'
      ];

      const lowerRid = selector.rid.toLowerCase();
      for (const pattern of interactivePatterns) {
        if (lowerRid.includes(pattern)) {
          return true;
        }
      }
    }

    // Check for interactive content descriptions
    if (selector.desc) {
      const interactiveDescPatterns = [
        'button', 'tap', 'click', 'select', 'choose', 'enter', 'input',
        'navigate', 'go', 'back', 'close', 'dismiss', 'expand', 'collapse'
      ];

      const lowerDesc = selector.desc.toLowerCase();
      for (const pattern of interactiveDescPatterns) {
        if (lowerDesc.includes(pattern)) {
          return true;
        }
      }
    }

    // Check for interactive text patterns
    if (selector.text) {
      const interactiveTextPatterns = [
        'OK', 'Cancel', 'Yes', 'No', 'Submit', 'Save', 'Delete', 'Edit',
        'Add', 'Remove', 'Back', 'Next', 'Previous', 'Close', 'Done',
        'Continue', 'Finish', 'Start', 'Stop', 'Play', 'Pause'
      ];

      if (interactiveTextPatterns.includes(selector.text.trim())) {
        return true;
      }
    }

    return false;
  }

  /**
   * Calculates an importance score for a selector based on various factors
   *
   * @param selector - Selector to score
   * @returns Importance score (0-1, higher is more important)
   */
  static calculateSelectorImportance(selector: ISelector): number {
    let score = 0;

    // Resource ID is the most stable selector
    if (selector.rid) {
      score += 0.4;
      // Bonus for descriptive IDs
      if (selector.rid.length > 3 && !selector.rid.match(/^id\d+$/)) {
        score += 0.1;
      }
    }

    // Text content is valuable for user-recognizable elements
    if (selector.text) {
      score += 0.3;
      // Bonus for meaningful text
      if (selector.text.length > 2 && !selector.text.match(/^\d+$/)) {
        score += 0.1;
      }
    }

    // Content description is good for accessibility
    if (selector.desc) {
      score += 0.2;
    }

    // Class name provides context
    if (selector.cls) {
      score += 0.1;
      // Bonus for specific classes
      if (selector.cls.includes('Button') || selector.cls.includes('EditText')) {
        score += 0.1;
      }
    }

    // Interactive elements get bonus points
    if (this.isInteractive(selector)) {
      score += 0.2;
    }

    return Math.min(score, 1.0);
  }

  /**
   * Filters selectors by importance threshold
   *
   * @param selectors - Array of selectors to filter
   * @param threshold - Minimum importance score (0-1)
   * @returns Filtered array of selectors
   */
  static filterSelectorsByImportance(selectors: ISelector[], threshold: number = 0.3): ISelector[] {
    return selectors
      .map(selector => ({
        selector,
        importance: this.calculateSelectorImportance(selector)
      }))
      .filter(({ importance }) => importance >= threshold)
      .sort((a, b) => b.importance - a.importance)
      .map(({ selector }) => selector);
  }

  /**
   * Extracts text content from selectors for state matching
   *
   * @param selectors - Array of selectors
   * @returns Array of unique text content
   */
  static extractTextContent(selectors: ISelector[]): string[] {
    const textSet = new Set<string>();

    for (const selector of selectors) {
      if (selector.text) {
        textSet.add(selector.text.trim());
      }
      if (selector.desc) {
        textSet.add(selector.desc.trim());
      }
    }

    return Array.from(textSet).filter(text => text.length > 0);
  }
}

// ============================================================================
// State Entity Class
// ============================================================================

/**
 * State entity class representing a captured UI state
 *
 * Provides comprehensive functionality for state creation, validation, selector management,
 * and utility operations for UI state discovery and graph generation.
 */
export class State implements IState {
  // Core properties (from IState interface)
  public readonly id: UUID;
  public package: string;
  public activity: string;
  public digest: string;
  public selectors: ISelector[];
  public visibleText?: string[];
  public screenshot?: string;
  public tags?: string[];
  public metadata: {
    captureMethod: CaptureMethod;
    captureDuration: number;
    elementCount: number;
    hierarchyDepth: number;
  };
  public createdAt: ISOTimestamp;
  public updatedAt: ISOTimestamp;

  // Private validation cache
  private _validationCache?: ValidationResult;
  private _selectorImportanceCache?: Map<string, number>;

  /**
   * Creates a new State instance
   *
   * @param data - State creation data
   * @throws StateValidationError if validation fails
   */
  constructor(data: CreateStateRequest) {
    // Generate unique ID
    this.id = uuidv4();

    // Set timestamps
    this.createdAt = new Date().toISOString();
    this.updatedAt = this.createdAt;

    // Validate and set basic properties
    this.validateBasicStateData(data);
    this.package = data.package.trim();
    this.activity = data.activity.trim();

    // Process selectors
    this.selectors = SelectorUtilsInternal.deduplicateSelectors(data.selectors);
    this.validateSelectors(this.selectors);

    // Extract visible text if not provided
    this.visibleText = data.visibleText || SelectorUtilsInternal.extractTextContent(this.selectors);

    // Set metadata
    this.metadata = { ...data.metadata };

    // Set optional properties
    this.tags = data.tags || [];

    // Calculate state digest
    this.digest = this.calculateStateDigest();

    // Initialize caches
    this._selectorImportanceCache = new Map();
  }

  /**
   * Creates a State instance from existing data (for database reconstruction)
   *
   * @param data - Complete state data
   * @returns State instance
   */
  static fromExisting(data: IState): State {
    const state = Object.create(State.prototype);
    Object.assign(state, data);
    state._selectorImportanceCache = new Map();
    return state;
  }

  /**
   * Validates basic state data
   *
   * @param data - State data to validate
   * @throws StateValidationError if validation fails
   */
  private validateBasicStateData(data: CreateStateRequest): void {
    // Validate package name
    if (!data.package || typeof data.package !== 'string') {
      throw new StateValidationError('Package name is required and must be a string', 'MISSING_PACKAGE', 'package', data.package);
    }

    const trimmedPackage = data.package.trim();
    if (trimmedPackage.length === 0) {
      throw new StateValidationError('Package name cannot be empty', 'INVALID_PACKAGE', 'package', data.package);
    }

    // Validate Android package name format (basic validation)
    if (!trimmedPackage.match(/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/)) {
      throw new StateValidationError('Invalid Android package name format', 'INVALID_PACKAGE_FORMAT', 'package', trimmedPackage);
    }

    // Validate activity name
    if (!data.activity || typeof data.activity !== 'string') {
      throw new StateValidationError('Activity name is required and must be a string', 'MISSING_ACTIVITY', 'activity', data.activity);
    }

    const trimmedActivity = data.activity.trim();
    if (trimmedActivity.length === 0) {
      throw new StateValidationError('Activity name cannot be empty', 'INVALID_ACTIVITY', 'activity', data.activity);
    }

    // Validate activity name format (should be fully qualified)
    if (!trimmedActivity.match(/^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/)) {
      throw new StateValidationError('Activity name should be fully qualified (e.g., com.example.MainActivity)', 'INVALID_ACTIVITY_FORMAT', 'activity', trimmedActivity);
    }

    // Validate selectors array
    if (!Array.isArray(data.selectors)) {
      throw new StateValidationError('Selectors must be an array', 'INVALID_SELECTORS', 'selectors', data.selectors);
    }

    if (data.selectors.length === 0) {
      throw new StateValidationError('At least one selector is required', 'EMPTY_SELECTORS', 'selectors', data.selectors);
    }

    // Validate metadata
    if (!data.metadata) {
      throw new StateValidationError('Metadata is required', 'MISSING_METADATA', 'metadata', data.metadata);
    }

    this.validateMetadata(data.metadata);
  }

  /**
   * Validates metadata structure
   *
   * @param metadata - Metadata to validate
   * @throws StateValidationError if validation fails
   */
  private validateMetadata(metadata: CreateStateRequest['metadata']): void {
    // Validate capture method
    if (!metadata.captureMethod || !['adb', 'frida'].includes(metadata.captureMethod)) {
      throw new StateValidationError('Capture method must be either "adb" or "frida"', 'INVALID_CAPTURE_METHOD', 'captureMethod', metadata.captureMethod);
    }

    // Validate capture duration
    if (typeof metadata.captureDuration !== 'number' || metadata.captureDuration < 0) {
      throw new StateValidationError('Capture duration must be a non-negative number', 'INVALID_CAPTURE_DURATION', 'captureDuration', metadata.captureDuration);
    }

    // Validate element count
    if (typeof metadata.elementCount !== 'number' || metadata.elementCount < 0) {
      throw new StateValidationError('Element count must be a non-negative number', 'INVALID_ELEMENT_COUNT', 'elementCount', metadata.elementCount);
    }

    // Validate hierarchy depth
    if (typeof metadata.hierarchyDepth !== 'number' || metadata.hierarchyDepth < 0) {
      throw new StateValidationError('Hierarchy depth must be a non-negative number', 'INVALID_HIERARCHY_DEPTH', 'hierarchyDepth', metadata.hierarchyDepth);
    }
  }

  /**
   * Validates an array of selectors
   *
   * @param selectors - Selectors to validate
   * @throws StateValidationError if validation fails
   */
  private validateSelectors(selectors: ISelector[]): void {
    for (let i = 0; i < selectors.length; i++) {
      try {
        SelectorUtilsInternal.validateSelectorHasProperties(selectors[i]);
      } catch (error) {
        if (error instanceof SelectorValidationError) {
          throw new StateValidationError(`Selector at index ${i}: ${error.message}`, 'INVALID_SELECTOR', `selectors[${i}]`, selectors[i]);
        }
        throw error;
      }
    }
  }

  /**
   * Calculates the state digest for deduplication
   *
   * @returns SHA-256 hash of state content
   */
  private calculateStateDigest(): string {
    // Create canonical representation for hashing
    const canonicalData = {
      package: this.package,
      activity: this.activity,
      selectors: this.selectors.map(selector => SelectorUtilsInternal.normalizeSelector(selector)).sort((a, b) => {
        const keyA = SelectorUtilsInternal.getSelectorKey(a);
        const keyB = SelectorUtilsInternal.getSelectorKey(b);
        return keyA.localeCompare(keyB);
      }),
      visibleText: (this.visibleText || []).sort()
    };

    return hashObject(canonicalData);
  }

  /**
   * Updates the state with new data
   *
   * @param data - Update data
   * @throws StateValidationError if validation fails
   */
  public update(data: UpdateStateRequest): void {
    // Update selectors if provided
    if (data.selectors) {
      if (!Array.isArray(data.selectors)) {
        throw new StateValidationError('Selectors must be an array', 'INVALID_SELECTORS', 'selectors', data.selectors);
      }

      const newSelectors = SelectorUtilsInternal.deduplicateSelectors(data.selectors);
      this.validateSelectors(newSelectors);
      this.selectors = newSelectors;
    }

    // Update visible text if provided
    if (data.visibleText) {
      if (!Array.isArray(data.visibleText)) {
        throw new StateValidationError('Visible text must be an array', 'INVALID_VISIBLE_TEXT', 'visibleText', data.visibleText);
      }
      this.visibleText = data.visibleText;
    } else if (data.selectors) {
      // Re-extract visible text from selectors
      this.visibleText = SelectorUtilsInternal.extractTextContent(this.selectors);
    }

    // Update screenshot if provided
    if (data.screenshot !== undefined) {
      if (data.screenshot && typeof data.screenshot !== 'string') {
        throw new StateValidationError('Screenshot must be a string path', 'INVALID_SCREENSHOT', 'screenshot', data.screenshot);
      }
      this.screenshot = data.screenshot;
    }

    // Update tags if provided
    if (data.tags) {
      if (!Array.isArray(data.tags)) {
        throw new StateValidationError('Tags must be an array', 'INVALID_TAGS', 'tags', data.tags);
      }
      this.tags = data.tags;
    }

    // Update metadata if provided
    if (data.metadata) {
      this.metadata = { ...this.metadata, ...data.metadata };
      // Validate updated metadata
      this.validateMetadata(this.metadata as any);
    }

    // Update timestamp and recalculate digest
    this.updatedAt = new Date().toISOString();
    this.digest = this.calculateStateDigest();

    // Clear validation cache
    this._validationCache = undefined;
    this._selectorImportanceCache?.clear();
  }

  /**
   * Validates the state and returns validation result
   *
   * @returns Validation result with errors and warnings
   */
  public validate(): ValidationResult {
    // Return cached result if available
    if (this._validationCache) {
      return this._validationCache;
    }

    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    try {
      // Validate basic structure
      if (!this.id || typeof this.id !== 'string') {
        errors.push({
          field: 'id',
          message: 'State ID is required and must be a string',
          code: 'MISSING_ID',
          value: this.id,
          severity: 'error'
        });
      }

      if (!this.package || typeof this.package !== 'string') {
        errors.push({
          field: 'package',
          message: 'Package name is required and must be a string',
          code: 'MISSING_PACKAGE',
          value: this.package,
          severity: 'error'
        });
      }

      if (!this.activity || typeof this.activity !== 'string') {
        errors.push({
          field: 'activity',
          message: 'Activity name is required and must be a string',
          code: 'MISSING_ACTIVITY',
          value: this.activity,
          severity: 'error'
        });
      }

      if (!Array.isArray(this.selectors) || this.selectors.length === 0) {
        errors.push({
          field: 'selectors',
          message: 'At least one selector is required',
          code: 'EMPTY_SELECTORS',
          value: this.selectors,
          severity: 'error'
        });
      }

      // Validate individual selectors
      this.selectors.forEach((selector, index) => {
        try {
          SelectorUtilsInternal.normalizeSelector(selector);
          SelectorUtilsInternal.validateSelectorHasProperties(selector);
        } catch (error) {
          if (error instanceof SelectorValidationError) {
            errors.push({
              field: `selectors[${index}]`,
              message: error.message,
              code: error.code,
              value: error.value,
              severity: 'error'
            });
          }
        }
      });

      // Validate digest
      if (!this.digest || typeof this.digest !== 'string') {
        errors.push({
          field: 'digest',
          message: 'State digest is required and must be a string',
          code: 'MISSING_DIGEST',
          value: this.digest,
          severity: 'error'
        });
      }

      // Check for warnings
      if (this.selectors.length > 50) {
        warnings.push({
          field: 'selectors',
          message: 'Large number of selectors may impact performance',
          code: 'MANY_SELECTORS',
          value: this.selectors.length,
          severity: 'warning'
        });
      }

      if (!this.screenshot) {
        warnings.push({
          field: 'screenshot',
          message: 'No screenshot reference provided',
          code: 'MISSING_SCREENSHOT',
          value: this.screenshot,
          severity: 'warning'
        });
      }

      const interactiveCount = this.selectors.filter(s => SelectorUtilsInternal.isInteractive(s)).length;
      if (interactiveCount === 0) {
        warnings.push({
          field: 'selectors',
          message: 'No interactive elements detected',
          code: 'NO_INTERACTIVE_ELEMENTS',
          value: interactiveCount,
          severity: 'warning'
        });
      }

    } catch (error) {
      errors.push({
        field: 'state',
        message: `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        code: 'VALIDATION_FAILED',
        severity: 'error'
      });
    }

    const result: ValidationResult = {
      isValid: errors.length === 0,
      errors,
      warnings
    };

    // Cache the result
    this._validationCache = result;
    return result;
  }

  /**
   * Checks if this state is equivalent to another state
   *
   * @param other - Other state to compare with
   * @returns True if states are equivalent
   */
  public isEquivalentTo(other: State | IState): boolean {
    if (!(other instanceof State) && !('digest' in other)) {
      return false;
    }

    // Primary comparison using digest
    return this.digest === other.digest;
  }

  /**
   * Gets interactive selectors from this state
   *
   * @param minImportance - Minimum importance score (0-1)
   * @returns Array of interactive selectors
   */
  public getInteractiveSelectors(minImportance: number = 0.3): ISelector[] {
    return this.selectors.filter(selector => {
      const isInteractive = SelectorUtilsInternal.isInteractive(selector);
      const importance = this.getSelectorImportance(selector);
      return isInteractive && importance >= minImportance;
    });
  }

  /**
   * Gets selector importance score (cached)
   *
   * @param selector - Selector to score
   * @returns Importance score (0-1)
   */
  public getSelectorImportance(selector: ISelector): number {
    const selectorKey = SelectorUtilsInternal.getSelectorKey(selector);

    if (this._selectorImportanceCache?.has(selectorKey)) {
      return this._selectorImportanceCache.get(selectorKey)!;
    }

    const importance = SelectorUtilsInternal.calculateSelectorImportance(selector);
    this._selectorImportanceCache?.set(selectorKey, importance);

    return importance;
  }

  /**
   * Gets selectors sorted by importance
   *
   * @returns Array of selectors sorted by importance (highest first)
   */
  public getSelectorsByImportance(): ISelector[] {
    return [...this.selectors].sort((a, b) => {
      const importanceA = this.getSelectorImportance(a);
      const importanceB = this.getSelectorImportance(b);
      return importanceB - importanceA;
    });
  }

  /**
   * Filters selectors based on a predicate function
   *
   * @param predicate - Filter function
   * @returns Filtered array of selectors
   */
  public filterSelectors(predicate: (selector: ISelector, index: number) => boolean): ISelector[] {
    return this.selectors.filter(predicate);
  }

  /**
   * Gets selectors that match specific criteria
   *
   * @param criteria - Selection criteria
   * @returns Array of matching selectors
   */
  public getSelectorsByCriteria(criteria: {
    text?: string | RegExp;
    desc?: string | RegExp;
    rid?: string | RegExp;
    cls?: string | RegExp;
    interactive?: boolean;
    minImportance?: number;
  }): ISelector[] {
    return this.selectors.filter(selector => {
      // Check text criteria
      if (criteria.text !== undefined) {
        if (!selector.text) return false;
        if (criteria.text instanceof RegExp) {
          if (!criteria.text.test(selector.text)) return false;
        } else {
          if (!selector.text.includes(criteria.text)) return false;
        }
      }

      // Check description criteria
      if (criteria.desc !== undefined) {
        if (!selector.desc) return false;
        if (criteria.desc instanceof RegExp) {
          if (!criteria.desc.test(selector.desc)) return false;
        } else {
          if (!selector.desc.includes(criteria.desc)) return false;
        }
      }

      // Check resource ID criteria
      if (criteria.rid !== undefined) {
        if (!selector.rid) return false;
        if (criteria.rid instanceof RegExp) {
          if (!criteria.rid.test(selector.rid)) return false;
        } else {
          if (!selector.rid.includes(criteria.rid)) return false;
        }
      }

      // Check class criteria
      if (criteria.cls !== undefined) {
        if (!selector.cls) return false;
        if (criteria.cls instanceof RegExp) {
          if (!criteria.cls.test(selector.cls)) return false;
        } else {
          if (!selector.cls.includes(criteria.cls)) return false;
        }
      }

      // Check interactive criteria
      if (criteria.interactive !== undefined) {
        const isInteractive = SelectorUtilsInternal.isInteractive(selector);
        if (criteria.interactive !== isInteractive) return false;
      }

      // Check importance criteria
      if (criteria.minImportance !== undefined) {
        const importance = this.getSelectorImportance(selector);
        if (importance < criteria.minImportance) return false;
      }

      return true;
    });
  }

  /**
   * Gets text content available in this state
   *
   * @returns Array of unique text content
   */
  public getAvailableText(): string[] {
    if (this.visibleText) {
      return [...this.visibleText];
    }
    return SelectorUtilsInternal.extractTextContent(this.selectors);
  }

  /**
   * Checks if the state contains specific text
   *
   * @param searchText - Text to search for
   * @param caseSensitive - Whether search should be case sensitive
   * @returns True if text is found
   */
  public containsText(searchText: string, caseSensitive: boolean = false): boolean {
    const text = this.getAvailableText();
    const search = caseSensitive ? searchText : searchText.toLowerCase();

    return text.some(t => {
      const comparison = caseSensitive ? t : t.toLowerCase();
      return comparison.includes(search);
    });
  }

  /**
   * Adds tags to the state
   *
   * @param tags - Tags to add
   */
  public addTags(...tags: string[]): void {
    if (!this.tags) {
      this.tags = [];
    }

    for (const tag of tags) {
      const trimmedTag = tag.trim();
      if (trimmedTag && !this.tags.includes(trimmedTag)) {
        this.tags.push(trimmedTag);
      }
    }

    this.updatedAt = new Date().toISOString();
  }

  /**
   * Removes tags from the state
   *
   * @param tags - Tags to remove
   */
  public removeTags(...tags: string[]): void {
    if (!this.tags) return;

    this.tags = this.tags.filter(tag => !tags.includes(tag));
    this.updatedAt = new Date().toISOString();
  }

  /**
   * Checks if the state has a specific tag
   *
   * @param tag - Tag to check
   * @returns True if tag exists
   */
  public hasTag(tag: string): boolean {
    return this.tags?.includes(tag) || false;
  }

  /**
   * Gets the activity name without package prefix
   *
   * @returns Simple activity name
   */
  public getSimpleActivityName(): string {
    const lastDot = this.activity.lastIndexOf('.');
    return lastDot >= 0 ? this.activity.substring(lastDot + 1) : this.activity;
  }

  /**
   * Gets a summary of the state for logging/display
   *
   * @returns State summary object
   */
  public getSummary(): {
    id: string;
    package: string;
    activity: string;
    simpleActivity: string;
    selectorCount: number;
    interactiveCount: number;
    hasScreenshot: boolean;
    tags: string[];
    captureMethod: CaptureMethod;
    createdAt: string;
  } {
    const interactiveCount = this.selectors.filter(s => SelectorUtilsInternal.isInteractive(s)).length;

    return {
      id: this.id,
      package: this.package,
      activity: this.activity,
      simpleActivity: this.getSimpleActivityName(),
      selectorCount: this.selectors.length,
      interactiveCount,
      hasScreenshot: !!this.screenshot,
      tags: this.tags || [],
      captureMethod: this.metadata.captureMethod,
      createdAt: this.createdAt
    };
  }

  /**
   * Serializes the state to JSON
   *
   * @returns JSON string representation
   */
  public toJSON(): string {
    return JSON.stringify(this.toObject(), null, 2);
  }

  /**
   * Converts the state to a plain object
   *
   * @returns Plain object representation
   */
  public toObject(): IState {
    return {
      id: this.id,
      package: this.package,
      activity: this.activity,
      digest: this.digest,
      selectors: this.selectors,
      visibleText: this.visibleText,
      screenshot: this.screenshot,
      tags: this.tags,
      metadata: this.metadata,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };
  }

  /**
   * Validates that a screenshot file exists and is accessible
   *
   * @param basePath - Base path for relative screenshot paths
   * @returns True if screenshot is valid
   */
  public async validateScreenshot(basePath?: string): Promise<boolean> {
    if (!this.screenshot) {
      return false;
    }

    try {
      const screenshotPath = path.isAbsolute(this.screenshot)
        ? this.screenshot
        : path.join(basePath || '.', this.screenshot);

      await fs.access(screenshotPath, fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Creates a copy of the state with a new ID
   *
   * @returns New State instance with unique ID
   */
  public clone(): State {
    const cloneData = this.toObject();
    delete (cloneData as any).id;
    delete (cloneData as any).createdAt;
    delete (cloneData as any).updatedAt;

    return new State(cloneData as CreateStateRequest);
  }
}

// ============================================================================
// State Factory Functions
// ============================================================================

/**
 * Factory functions for creating State instances
 */
export class StateFactory {
  /**
   * Creates a new State instance from raw capture data
   *
   * @param rawData - Raw capture data from ADB or Frida
   * @param options - Creation options
   * @returns New State instance
   */
  static createFromCaptureData(
    rawData: {
      package: string;
      activity: string;
      xmlHierarchy: string;
      screenshotPath?: string;
      captureMethod: CaptureMethod;
      captureDuration: number;
    },
    options: {
      tags?: string[];
      elementCount?: number;
      hierarchyDepth?: number;
    } = {}
  ): State {
    // Parse XML hierarchy to extract selectors
    const selectors = this.extractSelectorsFromXML(rawData.xmlHierarchy);

    // Extract visible text
    const visibleText = this.extractVisibleTextFromXML(rawData.xmlHierarchy);

    // Create state
    const stateData: CreateStateRequest = {
      package: rawData.package,
      activity: rawData.activity,
      selectors,
      visibleText,
      tags: options.tags,
      metadata: {
        captureMethod: rawData.captureMethod,
        captureDuration: rawData.captureDuration,
        elementCount: options.elementCount || selectors.length,
        hierarchyDepth: options.hierarchyDepth || 1
      }
    };

    return new State(stateData);
  }

  /**
   * Extracts selectors from XML hierarchy (simplified implementation)
   *
   * @param xmlHierarchy - XML hierarchy string
   * @returns Array of selectors
   */
  private static extractSelectorsFromXML(xmlHierarchy: string): ISelector[] {
    // This is a simplified implementation
    // In practice, this would use the existing XML parsing utilities

    const selectors: ISelector[] = [];

    // Extract basic selectors from XML
    // Note: This is a placeholder - actual implementation would use proper XML parsing
    const resourceIds = xmlHierarchy.match(/resource-id="([^"]+)"/g) || [];
    const texts = xmlHierarchy.match(/text="([^"]+)"/g) || [];
    const descriptions = xmlHierarchy.match(/content-desc="([^"]+)"/g) || [];
    const classes = xmlHierarchy.match(/class="([^"]+)"/g) || [];
    const bounds = xmlHierarchy.match(/bounds="\[([^\]]+)\]"/g) || [];

    // Create selectors from extracted data
    for (let i = 0; i < Math.max(resourceIds.length, texts.length, descriptions.length, classes.length); i++) {
      const selector: ISelector = {};

      if (resourceIds[i]) {
        selector.rid = resourceIds[i].match(/resource-id="([^"]+)"/)?.[1];
      }

      if (texts[i]) {
        selector.text = texts[i].match(/text="([^"]+)"/)?.[1];
      }

      if (descriptions[i]) {
        selector.desc = descriptions[i].match(/content-desc="([^"]+)"/)?.[1];
      }

      if (classes[i]) {
        selector.cls = classes[i].match(/class="([^"]+)"/)?.[1];
      }

      if (bounds[i]) {
        const boundsMatch = bounds[i].match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
        if (boundsMatch) {
          selector.bounds = [
            parseInt(boundsMatch[1]),
            parseInt(boundsMatch[2]),
            parseInt(boundsMatch[3]),
            parseInt(boundsMatch[4])
          ];
        }
      }

      // Only add selector if it has identifying properties
      if (selector.rid || selector.text || selector.desc || selector.cls) {
        selectors.push(selector);
      }
    }

    return selectors;
  }

  /**
   * Extracts visible text from XML hierarchy
   *
   * @param xmlHierarchy - XML hierarchy string
   * @returns Array of visible text
   */
  private static extractVisibleTextFromXML(xmlHierarchy: string): string[] {
    const textSet = new Set<string>();

    // Extract text attributes
    const textMatches = xmlHierarchy.match(/text="([^"]+)"/g) || [];
    for (const match of textMatches) {
      const text = match.match(/text="([^"]+)"/)?.[1];
      if (text && text.trim().length > 0) {
        textSet.add(text.trim());
      }
    }

    // Extract content descriptions
    const descMatches = xmlHierarchy.match(/content-desc="([^"]+)"/g) || [];
    for (const match of descMatches) {
      const desc = match.match(/content-desc="([^"]+)"/)?.[1];
      if (desc && desc.trim().length > 0) {
        textSet.add(desc.trim());
      }
    }

    return Array.from(textSet);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Utility functions for state operations
 */
export class StateUtils {
  /**
   * Compares two states for equality
   *
   * @param state1 - First state
   * @param state2 - Second state
   * @returns True if states are equal
   */
  static areStatesEqual(state1: State | IState, state2: State | IState): boolean {
    if (state1 instanceof State) {
      return state1.isEquivalentTo(state2);
    }
    if (state2 instanceof State) {
      return state2.isEquivalentTo(state1);
    }
    return state1.digest === state2.digest;
  }

  /**
   * Groups states by package name
   *
   * @param states - Array of states
   * @returns Map of package name to states
   */
  static groupStatesByPackage(states: (State | IState)[]): Map<string, (State | IState)[]> {
    const groups = new Map<string, (State | IState)[]>();

    for (const state of states) {
      const packageName = state.package;
      if (!groups.has(packageName)) {
        groups.set(packageName, []);
      }
      groups.get(packageName)!.push(state);
    }

    return groups;
  }

  /**
   * Groups states by activity name
   *
   * @param states - Array of states
   * @returns Map of activity name to states
   */
  static groupStatesByActivity(states: (State | IState)[]): Map<string, (State | IState)[]> {
    const groups = new Map<string, (State | IState)[]>();

    for (const state of states) {
      const activityName = state.activity;
      if (!groups.has(activityName)) {
        groups.set(activityName, []);
      }
      groups.get(activityName)!.push(state);
    }

    return groups;
  }

  /**
   * Finds duplicate states in an array
   *
   * @param states - Array of states to check
   * @returns Array of duplicate state groups
   */
  static findDuplicateStates(states: (State | IState)[]): (State | IState)[][] {
    const digestMap = new Map<string, (State | IState)[]>();

    for (const state of states) {
      const digest = state.digest;
      if (!digestMap.has(digest)) {
        digestMap.set(digest, []);
      }
      digestMap.get(digest)!.push(state);
    }

    return Array.from(digestMap.values()).filter(group => group.length > 1);
  }

  /**
   * Creates a State from a JSON string
   *
   * @param json - JSON string representation
   * @returns State instance
   * @throws StateOperationError if parsing fails
   */
  static fromJSON(json: string): State {
    try {
      const data = JSON.parse(json) as IState;
      return State.fromExisting(data);
    } catch (error) {
      throw new StateOperationError(
        `Failed to parse State from JSON: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'JSON_PARSE_ERROR'
      );
    }
  }

  /**
   * Validates an array of states
   *
   * @param states - Array of states to validate
   * @returns Array of validation results
   */
  static validateStates(states: (State | IState)[]): ValidationResult[] {
    return states.map(state => {
      if (state instanceof State) {
        return state.validate();
      }

      // For plain IState objects, do basic validation
      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      if (!state.id) {
        errors.push({
          field: 'id',
          message: 'State ID is required',
          code: 'MISSING_ID',
          severity: 'error'
        });
      }

      if (!state.package) {
        errors.push({
          field: 'package',
          message: 'Package name is required',
          code: 'MISSING_PACKAGE',
          severity: 'error'
        });
      }

      if (!state.activity) {
        errors.push({
          field: 'activity',
          message: 'Activity name is required',
          code: 'MISSING_ACTIVITY',
          severity: 'error'
        });
      }

      return {
        isValid: errors.length === 0,
        errors,
        warnings
      };
    });
  }
}

// Export utilities for external use
export const SelectorUtils = {
  normalizeSelector: SelectorUtilsInternal.normalizeSelector.bind(SelectorUtilsInternal),
  validateSelectorHasProperties: SelectorUtilsInternal.validateSelectorHasProperties.bind(SelectorUtilsInternal),
  deduplicateSelectors: SelectorUtilsInternal.deduplicateSelectors.bind(SelectorUtilsInternal),
  getSelectorKey: SelectorUtilsInternal.getSelectorKey.bind(SelectorUtilsInternal),
  isInteractive: SelectorUtilsInternal.isInteractive.bind(SelectorUtilsInternal),
  calculateSelectorImportance: SelectorUtilsInternal.calculateSelectorImportance.bind(SelectorUtilsInternal),
  filterSelectorsByImportance: SelectorUtilsInternal.filterSelectorsByImportance.bind(SelectorUtilsInternal),
  extractTextContent: SelectorUtilsInternal.extractTextContent.bind(SelectorUtilsInternal)
};

// ============================================================================
// Exports
// ============================================================================

export default State;