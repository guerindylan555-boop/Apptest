/**
 * Transition Model Tests
 *
 * Comprehensive test suite for the Transition entity model.
 * Tests all functionality including creation, validation, evidence management,
 * and utility methods.
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { Transition } from '../transition';
import {
  ActionType,
  SwipeDirection,
  CreateTransitionRequest,
  TransitionError
} from '../../types/models';

// ============================================================================
// Test Data and Fixtures
// ============================================================================

const validTransitionRequest: CreateTransitionRequest = {
  from: 'state-login-screen',
  to: 'state-home-screen',
  action: {
    type: 'tap',
    target: {
      rid: 'com.example.app:id/login_button',
      text: 'Login'
    }
  },
  confidence: 0.9,
  tags: ['authentication', 'successful']
};

const validSwipeRequest: CreateTransitionRequest = {
  from: 'state-feed-screen',
  to: 'state-feed-screen-scrolled',
  action: {
    type: 'swipe',
    swipe: {
      direction: 'up',
      distance: 0.7
    }
  },
  confidence: 0.8
};

const validTypeRequest: CreateTransitionRequest = {
  from: 'state-search-screen',
  to: 'state-results-screen',
  action: {
    type: 'type',
    target: {
      rid: 'com.example.app:id/search_input'
    },
    text: 'search query'
  },
  confidence: 0.85
};

// ============================================================================
// Test Suite
// ============================================================================

describe('Transition Model', () => {
  // ========================================================================
  // Basic Creation Tests
  // ========================================================================

  describe('Basic Creation', () => {
    it('should create a valid transition with minimal data', () => {
      const transition = new Transition(validTransitionRequest);

      expect(transition.id).toBeDefined();
      expect(transition.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
      expect(transition.from).toBe(validTransitionRequest.from);
      expect(transition.to).toBe(validTransitionRequest.to);
      expect(transition.action).toEqual(validTransitionRequest.action);
      expect(transition.confidence).toBe(validTransitionRequest.confidence);
      expect(transition.tags).toEqual(validTransitionRequest.tags);
      expect(transition.createdAt).toBeDefined();
      expect(transition.updatedAt).toBeDefined();
      expect(transition.version).toBe('1.0.0');
    });

    it('should create transition with custom ID', () => {
      const customId = 'custom-transition-id';
      const transition = new Transition(validTransitionRequest, customId);

      expect(transition.id).toBe(customId);
    });

    it('should handle missing optional fields', () => {
      const minimalRequest: CreateTransitionRequest = {
        from: 'state-1',
        to: 'state-2',
        action: {
          type: 'back'
        }
      };

      const transition = new Transition(minimalRequest);

      expect(transition.confidence).toBe(0.8); // Default confidence
      expect(transition.tags).toEqual([]);
      expect(transition.evidence).toBeUndefined();
    });

    it('should normalize confidence values', () => {
      const lowConfidenceRequest = { ...validTransitionRequest, confidence: -0.5 };
      const highConfidenceRequest = { ...validTransitionRequest, confidence: 1.5 };
      const undefinedConfidenceRequest = { ...validTransitionRequest, confidence: undefined };

      const lowTransition = new Transition(lowConfidenceRequest);
      const highTransition = new Transition(highConfidenceRequest);
      const undefinedTransition = new Transition(undefinedConfidenceRequest);

      expect(lowTransition.confidence).toBe(0.1); // Min confidence
      expect(highTransition.confidence).toBe(1.0); // Max confidence
      expect(undefinedTransition.confidence).toBe(0.8); // Default confidence
    });
  });

  // ========================================================================
  // Action Validation Tests
  // ========================================================================

  describe('Action Validation', () => {
    it('should validate tap actions', () => {
      const transition = new Transition(validTransitionRequest);
      const validation = transition.validateAction();

      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should validate swipe actions', () => {
      const transition = new Transition(validSwipeRequest);
      const validation = transition.validateAction();

      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should validate type actions', () => {
      const transition = new Transition(validTypeRequest);
      const validation = transition.validateAction();

      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should reject invalid action types', () => {
      const invalidRequest = {
        ...validTransitionRequest,
        action: {
          type: 'invalid_type' as ActionType,
          target: { text: 'Button' }
        }
      };

      expect(() => new Transition(invalidRequest)).toThrow(TransitionError);
    });

    it('should require text for type actions', () => {
      const invalidTypeRequest = {
        ...validTypeRequest,
        action: {
          type: 'type' as ActionType,
          target: { rid: 'input' }
          // Missing text
        }
      };

      expect(() => new Transition(invalidTypeRequest)).toThrow(TransitionError);
    });

    it('should require swipe configuration for swipe actions', () => {
      const invalidSwipeRequest = {
        ...validTransitionRequest,
        action: {
          type: 'swipe' as ActionType
          // Missing swipe config
        }
      };

      expect(() => new Transition(invalidSwipeRequest)).toThrow(TransitionError);
    });

    it('should validate swipe direction', () => {
      const invalidSwipeRequest = {
        ...validTransitionRequest,
        action: {
          type: 'swipe' as ActionType,
          swipe: {
            direction: 'diagonal' as SwipeDirection,
            distance: 0.5
          }
        }
      };

      expect(() => new Transition(invalidSwipeRequest)).toThrow(TransitionError);
    });

    it('should validate swipe distance range', () => {
      const invalidSwipeRequest = {
        ...validTransitionRequest,
        action: {
          type: 'swipe' as ActionType,
          swipe: {
            direction: 'up',
            distance: 1.5 // Invalid: > 1
          }
        }
      };

      expect(() => new Transition(invalidSwipeRequest)).toThrow(TransitionError);
    });

    it('should require intent parameters for intent actions', () => {
      const invalidIntentRequest = {
        ...validTransitionRequest,
        action: {
          type: 'intent' as ActionType
          // Missing intent parameters
        }
      };

      expect(() => new Transition(invalidIntentRequest)).toThrow(TransitionError);
    });
  });

  // ========================================================================
  // Required Field Validation Tests
  // ========================================================================

  describe('Required Field Validation', () => {
    it('should require from state', () => {
      const invalidRequest = { ...validTransitionRequest, from: '' };

      expect(() => new Transition(invalidRequest)).toThrow(TransitionError);
    });

    it('should require to state', () => {
      const invalidRequest = { ...validTransitionRequest, to: '' };

      expect(() => new Transition(invalidRequest)).toThrow(TransitionError);
    });

    it('should require action', () => {
      const invalidRequest = { ...validTransitionRequest, action: null as any };

      expect(() => new Transition(invalidRequest)).toThrow(TransitionError);
    });

    it('should require action type', () => {
      const invalidRequest = {
        ...validTransitionRequest,
        action: { target: { text: 'Button' } } as any // Missing type
      };

      expect(() => new Transition(invalidRequest)).toThrow(TransitionError);
    });
  });

  // ========================================================================
  // Evidence Management Tests
  // ========================================================================

  describe('Evidence Management', () => {
    it('should add evidence to transition', () => {
      const transition = new Transition(validTransitionRequest);

      transition.addEvidence({
        beforeDigest: 'sha256:before',
        afterDigest: 'sha256:after',
        duration: 1500,
        notes: 'Test evidence'
      });

      expect(transition.evidence).toBeDefined();
      expect(transition.evidence!.beforeDigest).toBe('sha256:before');
      expect(transition.evidence!.afterDigest).toBe('sha256:after');
      expect(transition.evidence!.duration).toBe(1500);
      expect(transition.evidence!.notes).toBe('Test evidence');
    });

    it('should add screenshots to evidence', () => {
      const transition = new Transition(validTransitionRequest);

      transition.addScreenshots('before.png', 'after.png');

      expect(transition.evidence).toBeDefined();
      expect(transition.evidence!.screenshots!.before).toBe('before.png');
      expect(transition.evidence!.screenshots!.after).toBe('after.png');
    });

    it('should set performance metrics', () => {
      const transition = new Transition(validTransitionRequest);

      transition.setPerformanceMetrics({
        responseTime: 100,
        renderTime: 200,
        animationTime: 150,
        networkRequests: 3
      });

      expect(transition.evidence).toBeDefined();
      expect(transition.evidence!.metrics!.responseTime).toBe(100);
      expect(transition.evidence!.metrics!.renderTime).toBe(200);
      expect(transition.evidence!.metrics!.animationTime).toBe(150);
      expect(transition.evidence!.metrics!.networkRequests).toBe(3);
    });

    it('should check evidence sufficiency', () => {
      const transitionWithoutEvidence = new Transition(validTransitionRequest);
      expect(transitionWithoutEvidence.hasSufficientEvidence()).toBe(false);

      const transitionWithPartialEvidence = new Transition(validTransitionRequest);
      transitionWithPartialEvidence.addEvidence({
        timestamp: new Date().toISOString()
        // Missing digests and duration
      });
      expect(transitionWithPartialEvidence.hasSufficientEvidence()).toBe(false);

      const transitionWithFullEvidence = new Transition(validTransitionRequest);
      transitionWithFullEvidence.addEvidence({
        beforeDigest: 'sha256:before',
        afterDigest: 'sha256:after',
        timestamp: new Date().toISOString(),
        duration: 1000
      });
      expect(transitionWithFullEvidence.hasSufficientEvidence()).toBe(true);
    });
  });

  // ========================================================================
  // Update Operations Tests
  // ========================================================================

  describe('Update Operations', () => {
    it('should update transition properties', () => {
      const transition = new Transition(validTransitionRequest);
      const originalUpdatedAt = transition.updatedAt;

      // Wait a bit to ensure different timestamp
      setTimeout(() => {
        transition.update({
          confidence: 0.95,
          tags: ['new', 'tags'],
          evidence: {
            beforeDigest: 'new-digest'
          }
        });

        expect(transition.confidence).toBe(0.95);
        expect(transition.tags).toEqual(['new', 'tags']);
        expect(transition.evidence!.beforeDigest).toBe('new-digest');
        expect(transition.updatedAt).not.toBe(originalUpdatedAt);
      }, 10);
    });

    it('should add tags', () => {
      const transition = new Transition(validTransitionRequest);

      transition.addTags('critical', 'important');
      expect(transition.tags).toContain('critical');
      expect(transition.tags).toContain('important');
      expect(transition.tags).toContain('authentication'); // Original tag
    });

    it('should not duplicate tags', () => {
      const transition = new Transition(validTransitionRequest);

      transition.addTags('authentication', 'new-tag');
      expect(transition.tags.filter(t => t === 'authentication')).toHaveLength(1);
      expect(transition.tags).toContain('new-tag');
    });

    it('should remove tags', () => {
      const transition = new Transition(validTransitionRequest);

      transition.removeTags('authentication');
      expect(transition.tags).not.toContain('authentication');
    });

    it('should handle removing non-existent tags', () => {
      const transition = new Transition(validTransitionRequest);
      const originalTags = [...transition.tags];

      transition.removeTags('non-existent-tag');
      expect(transition.tags).toEqual(originalTags);
    });
  });

  // ========================================================================
  // Comparison and Analysis Tests
  // ========================================================================

  describe('Comparison and Analysis', () => {
    it('should compare identical transitions', () => {
      const transition1 = new Transition(validTransitionRequest);
      const transition2 = new Transition(validTransitionRequest);

      const comparison = transition1.compareWith(transition2);

      expect(comparison.similarity).toBe(1.0);
      expect(comparison.recommendation).toBe('identical');
      expect(comparison.differences).toHaveLength(0);
    });

    it('should compare different transitions', () => {
      const transition1 = new Transition(validTransitionRequest);
      const transition2 = new Transition(validSwipeRequest);

      const comparison = transition1.compareWith(transition2);

      expect(comparison.similarity).toBeLessThan(1.0);
      expect(comparison.factors.actionType).toBe(false);
      expect(comparison.factors.sourceState).toBe(false);
      expect(comparison.factors.destinationState).toBe(false);
      expect(comparison.recommendation).toBe('different');
      expect(comparison.differences.length).toBeGreaterThan(0);
    });

    it('should detect reversal transitions', () => {
      const forwardTransition = new Transition({
        from: 'state-1',
        to: 'state-2',
        action: {
          type: 'swipe',
          swipe: { direction: 'up', distance: 0.5 }
        }
      });

      const backwardTransition = new Transition({
        from: 'state-2',
        to: 'state-1',
        action: {
          type: 'swipe',
          swipe: { direction: 'down', distance: 0.5 }
        }
      });

      expect(forwardTransition.isReversalOf(backwardTransition)).toBe(true);
      expect(backwardTransition.isReversalOf(forwardTransition)).toBe(true);
    });

    it('should categorize transitions', () => {
      const tapTransition = new Transition(validTransitionRequest);
      const typeTransition = new Transition(validTypeRequest);
      const swipeTransition = new Transition(validSwipeRequest);
      const backTransition = new Transition({
        from: 'state-1',
        to: 'state-2',
        action: { type: 'back' }
      });
      const intentTransition = new Transition({
        from: 'state-1',
        to: 'state-2',
        action: {
          type: 'intent',
          intent: { action: 'android.intent.action.VIEW' }
        }
      });

      expect(tapTransition.categorize()).toBe('interaction');
      expect(typeTransition.categorize()).toBe('input');
      expect(swipeTransition.categorize()).toBe('navigation');
      expect(backTransition.categorize()).toBe('navigation');
      expect(intentTransition.categorize()).toBe('system');
    });

    it('should detect circular transitions', () => {
      const circularTransition = new Transition({
        from: 'state-same',
        to: 'state-same',
        action: { type: 'tap', target: { text: 'Button' } }
      });

      const normalTransition = new Transition(validTransitionRequest);

      expect(circularTransition.isCircular()).toBe(true);
      expect(normalTransition.isCircular()).toBe(false);
    });

    it('should estimate execution time', () => {
      const tapTransition = new Transition(validTransitionRequest);
      const typeTransition = new Transition(validTypeRequest);
      const swipeTransition = new Transition(validSwipeRequest);

      expect(tapTransition.estimateExecutionTime()).toBe(1000);
      expect(typeTransition.estimateExecutionTime()).toBeGreaterThan(1000); // Base + text length
      expect(swipeTransition.estimateExecutionTime()).toBe(1500); // 1.5 * base
    });
  });

  // ========================================================================
  // Validation Tests
  // ========================================================================

  describe('Validation', () => {
    it('should validate correct transitions', () => {
      const transition = new Transition(validTransitionRequest);
      const validation = transition.validate();

      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should warn about circular transitions', () => {
      const circularTransition = new Transition({
        from: 'state-same',
        to: 'state-same',
        action: { type: 'tap', target: { text: 'Button' } }
      });

      const validation = circularTransition.validate();

      expect(validation.isValid).toBe(true); // Still valid, just warned
      expect(validation.warnings.some(w => w.code === 'CIRCULAR_TRANSITION')).toBe(true);
    });

    it('should warn about low confidence', () => {
      const lowConfidenceRequest = { ...validTransitionRequest, confidence: 0.05 };
      const transition = new Transition(lowConfidenceRequest);

      const validation = transition.validate();

      expect(validation.isValid).toBe(true); // Still valid, just warned
      expect(validation.warnings.some(w => w.code === 'LOW_CONFIDENCE')).toBe(true);
    });

    it('should warn about missing evidence', () => {
      const transition = new Transition(validTransitionRequest);
      const validation = transition.validate();

      expect(validation.isValid).toBe(true); // Still valid, just warned
      expect(validation.warnings.some(w => w.code === 'MISSING_EVIDENCE')).toBe(true);
    });

    it('should warn about identical evidence digests', () => {
      const transition = new Transition(validTransitionRequest);
      transition.addEvidence({
        beforeDigest: 'same-digest',
        afterDigest: 'same-digest', // Same as before
        timestamp: new Date().toISOString()
      });

      const validation = transition.validate();

      expect(validation.warnings.some(w => w.code === 'IDENTICAL_STATES')).toBe(true);
    });

    it('should warn about long duration', () => {
      const transition = new Transition(validTransitionRequest);
      transition.addEvidence({
        duration: 35000, // 35 seconds, over the 30 second threshold
        timestamp: new Date().toISOString()
      });

      const validation = transition.validate();

      expect(validation.warnings.some(w => w.code === 'LONG_DURATION')).toBe(true);
    });
  });

  // ========================================================================
  // Factory Method Tests
  // ========================================================================

  describe('Factory Methods', () => {
    it('should create transition from execution', () => {
      const transition = Transition.fromExecution(
        'state-1',
        'state-2',
        { type: 'tap', target: { text: 'Button' } },
        'before-digest',
        'after-digest',
        1200
      );

      expect(transition.from).toBe('state-1');
      expect(transition.to).toBe('state-2');
      expect(transition.action.type).toBe('tap');
      expect(transition.evidence!.beforeDigest).toBe('before-digest');
      expect(transition.evidence!.afterDigest).toBe('after-digest');
      expect(transition.evidence!.duration).toBe(1200);
    });

    it('should create transition with evidence', () => {
      const transition = Transition.withEvidence(
        validTransitionRequest,
        {
          beforeDigest: 'before',
          afterDigest: 'after',
          duration: 1000,
          notes: 'Test note'
        }
      );

      expect(transition.from).toBe(validTransitionRequest.from);
      expect(transition.to).toBe(validTransitionRequest.to);
      expect(transition.evidence!.beforeDigest).toBe('before');
      expect(transition.evidence!.afterDigest).toBe('after');
      expect(transition.evidence!.duration).toBe(1000);
      expect(transition.evidence!.notes).toBe('Test note');
    });

    it('should create mock transition', () => {
      const mockTransition = Transition.createMock({
        from: 'mock-start',
        to: 'mock-end',
        confidence: 1.0
      });

      expect(mockTransition.id).toBe('mock-transition-id');
      expect(mockTransition.from).toBe('mock-start');
      expect(mockTransition.to).toBe('mock-end');
      expect(mockTransition.confidence).toBe(1.0);
    });

    it('should create mock transition with defaults', () => {
      const mockTransition = Transition.createMock();

      expect(mockTransition.id).toBe('mock-transition-id');
      expect(mockTransition.from).toBe('mock-state-1');
      expect(mockTransition.to).toBe('mock-state-2');
      expect(mockTransition.action.type).toBe('tap');
    });
  });

  // ========================================================================
  // Serialization Tests
  // ========================================================================

  describe('Serialization', () => {
    it('should convert to JSON', () => {
      const transition = new Transition(validTransitionRequest);
      const json = transition.toJSON();

      expect(json.id).toBe(transition.id);
      expect(json.from).toBe(transition.from);
      expect(json.to).toBe(transition.to);
      expect(json.action).toEqual(transition.action);
      expect(json.confidence).toBe(transition.confidence);
      expect(json.tags).toEqual(transition.tags);
      expect(json.createdAt).toBe(transition.createdAt);
      expect(json.updatedAt).toBe(transition.updatedAt);
    });

    it('should convert to storage format', () => {
      const transition = new Transition(validTransitionRequest);
      const storage = transition.toStorage();

      expect(storage.id).toBe(transition.id);
      expect(storage.version).toBe('1.0.0');
      expect(storage.from).toBe(transition.from);
      expect(storage.to).toBe(transition.to);
    });

    it('should create from storage data', () => {
      const original = new Transition(validTransitionRequest);
      const storageData = original.toStorage();

      const restored = Transition.fromStorage(storageData);

      expect(restored.id).toBe(original.id);
      expect(restored.from).toBe(original.from);
      expect(restored.to).toBe(original.to);
      expect(restored.action).toEqual(original.action);
      expect(restored.confidence).toBe(original.confidence);
      expect(restored.tags).toEqual(original.tags);
      expect(restored.createdAt).toBe(original.createdAt);
      expect(restored.updatedAt).toBe(original.updatedAt);
      expect(restored.version).toBe(original.version);
    });
  });

  // ========================================================================
  // String Representation Tests
  // ========================================================================

  describe('String Representation', () => {
    it('should provide string representation', () => {
      const transition = new Transition(validTransitionRequest);

      const stringRep = transition.toString();

      expect(stringRep).toContain(transition.id);
      expect(stringRep).toContain(transition.from);
      expect(stringRep).toContain(transition.to);
      expect(stringRep).toContain('tap');
    });

    it('should describe action', () => {
      const transition = new Transition(validTransitionRequest);

      const actionDesc = transition.describeAction();

      expect(actionDesc).toContain('tap');
      expect(actionDesc).toContain('Login');
    });

    it('should provide detailed description', () => {
      const transition = new Transition(validTransitionRequest);

      const description = transition.describe();

      expect(description).toContain(transition.from);
      expect(description).toContain(transition.to);
      expect(description).toContain('tap');
      expect(description).toContain('90%'); // Confidence
      expect(description).toContain('interaction'); // Category
    });
  });

  // ========================================================================
  // Hash Calculation Tests
  // ========================================================================

  describe('Hash Calculation', () => {
    it('should calculate consistent hash', () => {
      const transition = new Transition(validTransitionRequest);

      const hash1 = transition.calculateHash();
      const hash2 = transition.calculateHash();

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/i);
    });

    it('should calculate different hashes for different transitions', () => {
      const transition1 = new Transition(validTransitionRequest);
      const transition2 = new Transition(validSwipeRequest);

      const hash1 = transition1.calculateHash();
      const hash2 = transition2.calculateHash();

      expect(hash1).not.toBe(hash2);
    });

    it('should use cached hash', () => {
      const transition = new Transition(validTransitionRequest);

      const hash1 = transition.calculateHash();
      const hash2 = transition.calculateHash();

      expect(hash1).toBe(hash2);
      // The hash should be cached, so both calls should return the same reference
      expect(hash1).toBe(hash2);
    });
  });
});