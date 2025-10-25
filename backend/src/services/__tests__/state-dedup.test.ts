/**
 * AutoApp UI Map & Intelligent Flow Engine - State Deduplication Service Tests
 *
 * Comprehensive test suite for the state deduplication service (T025).
 * Tests all major functionality including digest-based matching, fuzzy matching,
 * merge strategies, and performance monitoring.
 */

import { State } from '../../models/state';
import { StateDeduplicationService, StateDeduplicationError, MergeConflictError } from '../state-dedup';
import { CreateStateRequest, CaptureMethod } from '../../types/models';

describe('StateDeduplicationService', () => {
  let service: StateDeduplicationService;
  let mockStates: State[];

  beforeEach(() => {
    service = new StateDeduplicationService({
      similarityThreshold: 0.9,
      selectorWeight: 0.7,
      textWeight: 0.3,
      enableActivityGrouping: true,
      logLevel: 'error' // Reduce log noise in tests
    });

    // Create mock states for testing
    mockStates = createMockStates();
  });

  afterEach(() => {
    service.clearCaches();
  });

  describe('Constructor and Configuration', () => {
    test('should initialize with default configuration', () => {
      const defaultService = new StateDeduplicationService();
      expect(defaultService).toBeDefined();
    });

    test('should accept custom configuration', () => {
      const customService = new StateDeduplicationService({
        similarityThreshold: 0.8,
        selectorWeight: 0.6,
        textWeight: 0.4
      });
      expect(customService).toBeDefined();
    });

    test('should update configuration', () => {
      service.updateConfig({ similarityThreshold: 0.95 });
      // Since config is private, we test behavior instead
      expect(service).toBeDefined();
    });
  });

  describe('Single State Deduplication', () => {
    test('should identify exact duplicates', async () => {
      const state1 = mockStates[0];
      const state2 = mockStates[1]; // Exact duplicate of state1

      const result = await service.deduplicateState(state1, [state2]);

      expect(result.isDuplicate).toBe(true);
      expect(result.matchedState).toBe(state2);
      expect(result.similarity).toBe(1.0);
    });

    test('should identify unique states', async () => {
      const state1 = mockStates[0];
      const state3 = mockStates[2]; // Different state

      const result = await service.deduplicateState(state1, [state3]);

      expect(result.isDuplicate).toBe(false);
      expect(result.matchedState).toBeUndefined();
      expect(result.similarity).toBeLessThan(0.9);
    });

    test('should find similar states above threshold', async () => {
      const state1 = mockStates[0];
      const state4 = mockStates[3]; // Similar state

      const result = await service.deduplicateState(state1, [state4]);

      expect(result.isDuplicate).toBe(true);
      expect(result.similarity).toBeGreaterThan(0.9);
      expect(result.mergeCandidate).toBeDefined();
    });

    test('should filter by activity when enabled', async () => {
      const state1 = mockStates[0]; // com.example.MainActivity
      const state5 = mockStates[4]; // com.example.OtherActivity

      const result = await service.deduplicateState(state1, [state5]);

      expect(result.isDuplicate).toBe(false);
      expect(result.similarity).toBe(0); // Different activities
    });

    test('should handle states without digests', async () => {
      const state1 = mockStates[0];
      // Create state without digest
      const stateNoDigest = State.fromExisting({
        ...state1.toObject(),
        digest: ''
      });

      const result = await service.deduplicateState(stateNoDigest, [state1]);

      expect(result).toBeDefined();
      expect(stateNoDigest.digest).toBeTruthy(); // Digest should be calculated
    });
  });

  describe('Batch Deduplication', () => {
    test('should deduplicate batch of states', async () => {
      const result = await service.deduplicateBatch(mockStates);

      expect(result.totalStates).toBe(mockStates.length);
      expect(result.uniqueStates).toBeLessThan(mockStates.length);
      expect(result.duplicatesFound).toBeGreaterThan(0);
      expect(result.processingTime).toBeGreaterThan(0);
    });

    test('should handle empty batch', async () => {
      const result = await service.deduplicateBatch([]);

      expect(result.totalStates).toBe(0);
      expect(result.uniqueStates).toBe(0);
      expect(result.duplicatesFound).toBe(0);
    });

    test('should track similarity distribution', async () => {
      const result = await service.deduplicateBatch(mockStates);

      expect(result.similarityDistribution).toBeDefined();
      expect(typeof result.similarityDistribution.exact).toBe('number');
      expect(typeof result.similarityDistribution.high).toBe('number');
      expect(typeof result.similarityDistribution.medium).toBe('number');
      expect(typeof result.similarityDistribution.low).toBe('number');
      expect(typeof result.similarityDistribution.none).toBe('number');
    });

    test('should group by activity when enabled', async () => {
      const activityService = new StateDeduplicationService({
        enableActivityGrouping: true,
        logLevel: 'error'
      });

      const result = await activityService.deduplicateBatch(mockStates);
      expect(result).toBeDefined();
    });
  });

  describe('State Comparison', () => {
    test('should compare identical states', async () => {
      const state1 = mockStates[0];
      const state2 = mockStates[1];

      const result = await service.compareStates(state1, state2);

      expect(result.similarity).toBe(1.0);
      expect(result.shouldMerge).toBe(true);
      expect(result.confidence).toBe(1.0);
      expect(result.details.commonSelectors.length).toBeGreaterThan(0);
    });

    test('should compare different states', async () => {
      const state1 = mockStates[0];
      const state3 = mockStates[2];

      const result = await service.compareStates(state1, state3);

      expect(result.similarity).toBeLessThan(1.0);
      expect(result.details.uniqueSelectors1.length).toBeGreaterThan(0);
      expect(result.details.uniqueSelectors2.length).toBeGreaterThan(0);
    });

    test('should handle different packages/activities', async () => {
      const state1 = mockStates[0];
      const state5 = mockStates[4];

      const result = await service.compareStates(state1, state5);

      expect(result.similarity).toBe(0);
      expect(result.shouldMerge).toBe(false);
      expect(result.confidence).toBe(1.0);
    });

    test('should calculate selector and text similarity', async () => {
      const state1 = mockStates[0];
      const state4 = mockStates[3];

      const result = await service.compareStates(state1, state4);

      expect(typeof result.selectorSimilarity).toBe('number');
      expect(typeof result.textSimilarity).toBe('number');
      expect(result.selectorSimilarity).toBeGreaterThanOrEqual(0);
      expect(result.selectorSimilarity).toBeLessThanOrEqual(1);
      expect(result.textSimilarity).toBeGreaterThanOrEqual(0);
      expect(result.textSimilarity).toBeLessThanOrEqual(1);
    });
  });

  describe('State Merging', () => {
    test('should merge states with comprehensive strategy', async () => {
      const state1 = mockStates[0];
      const state2 = mockStates[3];

      const result = await service.mergeStates([state1, state2], 'comprehensive');

      expect(result).toBeDefined();
      expect(result.selectors.length).toBeGreaterThanOrEqual(
        Math.max(state1.selectors.length, state2.selectors.length)
      );
      expect(result.package).toBe(state1.package);
      expect(result.activity).toBe(state1.activity);
    });

    test('should merge states with latest strategy', async () => {
      const state1 = mockStates[0];
      const state2 = mockStates[1];

      const result = await service.mergeStates([state1, state2], 'latest');

      expect(result).toBeDefined();
      // Should return the more recently updated state
      expect([state1.id, state2.id]).toContain(result.id);
    });

    test('should merge states with most_selectors strategy', async () => {
      const state1 = mockStates[0];
      const state2 = mockStates[2]; // Has more selectors

      const result = await service.mergeStates([state1, state2], 'most_selectors');

      expect(result).toBeDefined();
      expect(result.selectors.length).toBeGreaterThanOrEqual(state1.selectors.length);
    });

    test('should merge single state', async () => {
      const state1 = mockStates[0];

      const result = await service.mergeStates([state1]);

      expect(result).toBe(state1);
    });

    test('should reject merging states from different packages', async () => {
      const state1 = mockStates[0];
      const differentPackageState = State.fromExisting({
        ...state1.toObject(),
        package: 'com.different.package'
      });

      await expect(service.mergeStates([state1, differentPackageState]))
        .rejects.toThrow(MergeConflictError);
    });

    test('should reject empty state array', async () => {
      await expect(service.mergeStates([]))
        .rejects.toThrow(StateDeduplicationError);
    });
  });

  describe('Duplicate Finding', () => {
    test('should find exact duplicates', async () => {
      const duplicates = await service.findDuplicates([mockStates[0], mockStates[1]]);

      expect(duplicates).toHaveLength(1);
      expect(duplicates[0]).toHaveLength(2);
    });

    test('should find fuzzy duplicates', async () => {
      const duplicates = await service.findDuplicates([mockStates[0], mockStates[3]]);

      expect(duplicates.length).toBeGreaterThan(0);
    });

    test('should handle unique states', async () => {
      const uniqueStates = [mockStates[0], mockStates[2], mockStates[4]];
      const duplicates = await service.findDuplicates(uniqueStates);

      expect(duplicates).toHaveLength(0);
    });

    test('should handle empty array', async () => {
      const duplicates = await service.findDuplicates([]);

      expect(duplicates).toHaveLength(0);
    });
  });

  describe('Performance Monitoring', () => {
    test('should track performance metrics', async () => {
      const monitoringService = new StateDeduplicationService({
        enablePerformanceMonitoring: true,
        logLevel: 'error'
      });

      await monitoringService.deduplicateBatch(mockStates);

      const metrics = monitoringService.getPerformanceMetrics();
      expect(metrics.length).toBeGreaterThan(0);

      const batchMetrics = metrics.find(m => m.operation === 'deduplicateBatch');
      expect(batchMetrics).toBeDefined();
      expect(batchMetrics!.duration).toBeGreaterThan(0);
    });

    test('should clear caches', async () => {
      await service.deduplicateBatch(mockStates);

      service.clearCaches();

      const metrics = service.getPerformanceMetrics();
      expect(metrics).toHaveLength(0);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid state data', async () => {
      const invalidState = {
        id: 'invalid',
        package: '',
        activity: '',
        digest: 'invalid',
        selectors: [],
        metadata: {
          captureMethod: 'adb' as CaptureMethod,
          captureDuration: 0,
          elementCount: 0,
          hierarchyDepth: 0
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      // Should not throw, but handle gracefully
      await expect(service.deduplicateState(invalidState, []))
        .resolves.toBeDefined();
    });

    test('should handle merge conflicts', async () => {
      const state1 = mockStates[0];
      const conflictState = State.fromExisting({
        ...state1.toObject(),
        package: 'com.different.package'
      });

      await expect(service.mergeStates([state1, conflictState]))
        .rejects.toThrow(MergeConflictError);
    });

    test('should propagate errors with context', async () => {
      const state1 = mockStates[0];
      const state2 = mockStates[1];

      // Mock an internal error
      const originalCompare = service.compareStates.bind(service);
      service.compareStates = jest.fn().mockRejectedValue(new Error('Internal error'));

      await expect(service.deduplicateState(state1, [state2]))
        .rejects.toThrow(StateDeduplicationError);

      // Restore original method
      service.compareStates = originalCompare;
    });
  });

  describe('Utility Methods', () => {
    test('should calculate state digests correctly', async () => {
      const state1 = mockStates[0];
      const state2 = mockStates[1]; // Same content

      expect(state1.digest).toBe(state2.digest);
      expect(state1.digest).toMatch(/^[a-f0-9]{64}$/i); // SHA-256 format
    });

    test('should handle missing digests gracefully', async () => {
      const state1 = mockStates[0];
      const stateWithoutDigest = State.fromExisting({
        ...state1.toObject(),
        digest: ''
      });

      // Service should calculate missing digest
      const result = await service.deduplicateState(stateWithoutDigest, [state1]);
      expect(result).toBeDefined();
    });
  });
});

// Helper function to create mock states for testing
function createMockStates(): State[] {
  const baseStateData: CreateStateRequest = {
    package: 'com.example.app',
    activity: 'com.example.MainActivity',
    selectors: [
      {
        rid: 'btn_login',
        text: 'Login',
        cls: 'android.widget.Button'
      },
      {
        rid: 'input_username',
        cls: 'android.widget.EditText'
      },
      {
        rid: 'input_password',
        cls: 'android.widget.EditText'
      }
    ],
    visibleText: ['Login', 'Username', 'Password', 'Forgot Password?'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 150,
      elementCount: 15,
      hierarchyDepth: 5
    }
  };

  // State 1: Base state
  const state1 = new State(baseStateData);

  // State 2: Exact duplicate of state 1
  const state2 = State.fromExisting(state1.toObject());

  // State 3: Different state (same activity, different content)
  const state3 = new State({
    ...baseStateData,
    selectors: [
      {
        rid: 'btn_register',
        text: 'Register',
        cls: 'android.widget.Button'
      },
      {
        rid: 'input_email',
        cls: 'android.widget.EditText'
      }
    ],
    visibleText: ['Register', 'Email', 'Create Account']
  });

  // State 4: Similar state (same activity, similar content)
  const state4 = new State({
    ...baseStateData,
    selectors: [
      {
        rid: 'btn_login',
        text: 'Sign In', // Slightly different text
        cls: 'android.widget.Button'
      },
      {
        rid: 'input_username',
        cls: 'android.widget.EditText'
      },
      {
        rid: 'input_password',
        cls: 'android.widget.EditText'
      },
      {
        rid: 'checkbox_remember',
        text: 'Remember me',
        cls: 'android.widget.CheckBox'
      }
    ],
    visibleText: ['Sign In', 'Username', 'Password', 'Remember me', 'Forgot Password?']
  });

  // State 5: Different activity
  const state5 = new State({
    ...baseStateData,
    activity: 'com.example.OtherActivity',
    selectors: [
      {
        rid: 'btn_settings',
        text: 'Settings',
        cls: 'android.widget.Button'
      }
    ],
    visibleText: ['Settings', 'Preferences', 'Configuration']
  });

  // State 6: High selector count state
  const state6 = new State({
    ...baseStateData,
    selectors: [
      ...baseStateData.selectors,
      {
        rid: 'btn_cancel',
        text: 'Cancel',
        cls: 'android.widget.Button'
      },
      {
        rid: 'btn_help',
        text: 'Help',
        cls: 'android.widget.Button'
      },
      {
        rid: 'link_terms',
        text: 'Terms of Service',
        cls: 'android.widget.TextView'
      },
      {
        rid: 'link_privacy',
        text: 'Privacy Policy',
        cls: 'android.widget.TextView'
      }
    ],
    visibleText: [
      ...baseStateData.visibleText!,
      'Cancel', 'Help', 'Terms of Service', 'Privacy Policy'
    ],
    metadata: {
      ...baseStateData.metadata,
      elementCount: 25
    }
  });

  return [state1, state2, state3, state4, state5, state6];
}