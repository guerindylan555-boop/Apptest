/**
 * AutoApp UI Map & Intelligent Flow Engine - Flow Validator Tests
 *
 * Integration tests for the comprehensive flow validation service.
 * Tests all validation categories, predicate resolution, caching,
 * and performance characteristics.
 */

import { FlowValidator } from '../flowValidator';
import { GraphService } from '../graphService';
import { FlowDefinition } from '../../models/flow-definition';
import { FlowStep } from '../../models/flow-step';
import { StatePredicate } from '../../models/state-predicate';
import { StateRecord } from '../../types/graph';
import { v4 as uuidv4 } from 'uuid';

// Mock data setup
const mockStates: StateRecord[] = [
  {
    id: 'state1',
    activity: 'com.example.app.MainActivity',
    package: 'com.example.app',
    visibleText: ['Welcome', 'Login', 'Sign Up'],
    selectors: [
      { rid: 'login_button', text: 'Login', desc: 'Login button' },
      { rid: 'signup_button', text: 'Sign Up', desc: 'Sign up button' },
      { rid: 'username_field', text: 'Username', desc: 'Username input field' }
    ],
    screenshot: 'screenshot1.png',
    createdAt: '2023-01-01T00:00:00.000Z',
    updatedAt: '2023-01-01T00:00:00.000Z',
    digest: 'digest1'
  },
  {
    id: 'state2',
    activity: 'com.example.app.HomeActivity',
    package: 'com.example.app',
    visibleText: ['Home', 'Dashboard', 'Settings'],
    selectors: [
      { rid: 'menu_button', text: 'Menu', desc: 'Menu button' },
      { rid: 'settings_button', text: 'Settings', desc: 'Settings button' }
    ],
    screenshot: 'screenshot2.png',
    createdAt: '2023-01-01T00:01:00.000Z',
    updatedAt: '2023-01-01T00:01:00.000Z',
    digest: 'digest2'
  },
  {
    id: 'state3',
    activity: 'com.example.app.SettingsActivity',
    package: 'com.example.app',
    visibleText: ['Settings', 'Profile', 'Notifications'],
    selectors: [
      { rid: 'profile_item', text: 'Profile', desc: 'Profile settings' },
      { rid: 'notifications_item', text: 'Notifications', desc: 'Notification settings' }
    ],
    screenshot: 'screenshot3.png',
    createdAt: '2023-01-01T00:02:00.000Z',
    updatedAt: '2023-01-01T00:02:00.000Z',
    digest: 'digest3'
  }
];

// Mock GraphService
class MockGraphService {
  private states: StateRecord[] = [];

  constructor(states: StateRecord[] = []) {
    this.states = states;
  }

  async getGraph() {
    return {
      states: this.states,
      transitions: [],
      version: '1.0.0',
      createdAt: '2023-01-01T00:00:00.000Z',
      updatedAt: '2023-01-01T00:00:00.000Z',
      packageName: 'com.example.app',
      stats: {
        stateCount: this.states.length,
        transitionCount: 0,
        averageDegree: 0,
        isolatedStates: this.states.length
      },
      metadata: {}
    };
  }

  async loadGraph() {
    return this.getGraph();
  }
}

describe('FlowValidator', () => {
  let validator: FlowValidator;
  let mockGraphService: MockGraphService;

  beforeEach(() => {
    mockGraphService = new MockGraphService(mockStates);
    validator = new FlowValidator(mockGraphService as any);
  });

  afterEach(() => {
    validator.clearCache();
    validator.resetMetrics();
  });

  describe('Structural Validation', () => {
    test('should validate a well-formed flow', async () => {
      const flow = createValidFlow();
      const result = await validator.validateFlow(flow);

      expect(result.isValid).toBe(true);
      expect(result.categoryResults.structural.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    test('should detect missing required fields', async () => {
      const flow = {
        // Missing required fields
        steps: [],
        entryPoint: StatePredicate.exactState('state1'),
        config: {
          defaultTimeout: 30,
          retryAttempts: 3,
          allowParallel: false,
          priority: 'medium' as const
        }
      } as any;

      const result = await validator.validateFlow(flow);

      expect(result.isValid).toBe(false);
      expect(result.categoryResults.structural.isValid).toBe(false);

      const requiredFieldErrors = result.errors.filter(e =>
        ['MISSING_FLOW_ID', 'MISSING_FLOW_NAME', 'MISSING_PACKAGE', 'MISSING_STEPS'].includes(e.code)
      );
      expect(requiredFieldErrors.length).toBeGreaterThan(0);
    });

    test('should validate step structure', async () => {
      const flow = new FlowDefinition({
        name: 'Test Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Invalid Step',
            preconditions: [],
            action: {
              type: 'tap'
              // Missing target selector
            }
          },
          {
            name: 'Another Invalid Step',
            preconditions: [],
            action: {
              type: 'type'
              // Missing text
            }
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      expect(result.isValid).toBe(false);
      expect(result.categoryResults.structural.isValid).toBe(false);

      const targetWarnings = result.warnings.filter(w => w.code === 'NO_TARGET_SELECTOR');
      const textErrors = result.errors.filter(e => e.code === 'MISSING_TYPE_TEXT');

      expect(targetWarnings.length).toBe(1);
      expect(textErrors.length).toBe(1);
    });

    test('should detect invalid package names', async () => {
      const flow = new FlowDefinition({
        name: 'Test Flow',
        packageName: 'invalid-package-name', // Should be in Java format
        steps: [createValidStep()],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      expect(result.isValid).toBe(false);
      const packageErrors = result.errors.filter(e => e.code === 'INVALID_PACKAGE_FORMAT');
      expect(packageErrors.length).toBe(1);
    });
  });

  describe('Semantic Validation', () => {
    test('should detect circular dependencies', async () => {
      const flow = new FlowDefinition({
        name: 'Circular Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Step 1',
            preconditions: [StatePredicate.exactState('state1')],
            action: { type: 'tap', target: { text: 'Button 1' } },
            expectedState: StatePredicate.exactState('state2')
          },
          {
            name: 'Step 2',
            preconditions: [StatePredicate.exactState('state2')],
            action: { type: 'tap', target: { text: 'Button 2' } },
            expectedState: StatePredicate.exactState('state3')
          },
          {
            name: 'Step 3',
            preconditions: [StatePredicate.exactState('state3')],
            action: { type: 'tap', target: { text: 'Button 3' } },
            expectedState: StatePredicate.exactState('state1') // Creates cycle
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      expect(result.categoryResults.semantic.isValid).toBe(false);
      const cycleErrors = result.errors.filter(e => e.code === 'CIRCULAR_DEPENDENCY');
      expect(cycleErrors.length).toBeGreaterThan(0);
    });

    test('should detect unreachable steps', async () => {
      const flow = new FlowDefinition({
        name: 'Flow with Unreachable Step',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Reachable Step',
            preconditions: [StatePredicate.exactState('state1')],
            action: { type: 'tap', target: { text: 'Button' } },
            expectedState: StatePredicate.exactState('state2')
          },
          {
            name: 'Unreachable Step',
            preconditions: [StatePredicate.exactState('nonexistent_state')], // Can't be reached
            action: { type: 'tap', target: { text: 'Button' } }
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      const unreachableWarnings = result.warnings.filter(w => w.code === 'UNREACHABLE_STEP');
      expect(unreachableWarnings.length).toBe(1);
      expect(unreachableWarnings[0].field).toContain('steps[1]');
    });

    test('should validate predicate resolvability', async () => {
      const flow = new FlowDefinition({
        name: 'Flow with Unresolvable Predicates',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Step with Bad Precondition',
            preconditions: [StatePredicate.exactState('nonexistent_state')], // Doesn't exist
            action: { type: 'tap', target: { text: 'Button' } }
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      const unresolvableErrors = result.errors.filter(e => e.code === 'UNRESOLVABLE_PRECONDITION');
      expect(unresolvableErrors.length).toBe(1);
    });
  });

  describe('Execution Validation', () => {
    test('should validate action feasibility', async () => {
      const flow = new FlowDefinition({
        name: 'Flow with Complex Actions',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Swipe Step',
            preconditions: [StatePredicate.exactState('state1')],
            action: {
              type: 'swipe',
              swipe: { direction: 'invalid_direction', distance: 1.5 } // Invalid
            }
          },
          {
            name: 'Intent Step',
            preconditions: [StatePredicate.exactState('state2')],
            action: {
              type: 'intent'
              // Missing intent configuration
            }
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      expect(result.categoryResults.execution.isValid).toBe(false);

      const swipeErrors = result.errors.filter(e => e.code === 'INVALID_SWIPE_DIRECTION');
      const intentErrors = result.errors.filter(e => e.code === 'MISSING_INTENT_CONFIG');

      expect(swipeErrors.length).toBe(1);
      expect(intentErrors.length).toBe(1);
    });

    test('should analyze performance characteristics', async () => {
      const flow = new FlowDefinition({
        name: 'Performance Test Flow',
        packageName: 'com.example.app',
        steps: Array(50).fill(null).map((_, i) => ({
          name: `Step ${i}`,
          preconditions: [StatePredicate.exactState(`state${(i % 3) + 1}`)],
          action: { type: 'tap', target: { text: `Button ${i}` } },
          timeout: 120 // Very long timeout
        })),
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      expect(result.performance.estimatedDuration).toBeGreaterThan(60000); // > 1 minute
      expect(result.performance.impact).toBe('high');

      const longExecutionWarnings = result.warnings.filter(w => w.code === 'LONG_EXECUTION_TIME');
      expect(longExecutionWarnings.length).toBe(1);
    });

    test('should validate timeout configurations', async () => {
      const flow = new FlowDefinition({
        name: 'Timeout Test Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Step with High Timeout',
            preconditions: [StatePredicate.exactState('state1')],
            action: { type: 'tap', target: { text: 'Button' } },
            timeout: 500 // Exceeds max
          }
        ],
        entryPoint: StatePredicate.exactState('state1'),
        config: {
          defaultTimeout: 30,
          retryAttempts: 10, // Excessive retries
          allowParallel: false,
          priority: 'medium' as const
        }
      });

      const result = await validator.validateFlow(flow, {
        maxTimeout: 300,
        maxRetryAttempts: 5
      });

      const timeoutWarnings = result.warnings.filter(w => w.code === 'TIMEOUT_EXCEEDS_MAXIMUM');
      const retryWarnings = result.warnings.filter(w => w.code === 'HIGH_RETRY_COUNT');

      expect(timeoutWarnings.length).toBe(1);
      expect(retryWarnings.length).toBe(1);
    });
  });

  describe('Security Validation', () => {
    test('should detect sensitive permissions', async () => {
      const flow = new FlowDefinition({
        name: 'Security Test Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Call Intent Step',
            preconditions: [StatePredicate.exactState('state1')],
            action: {
              type: 'intent',
              intent: {
                action: 'android.intent.action.CALL',
                data: 'tel:1234567890'
              }
            }
          },
          {
            name: 'Camera Intent Step',
            preconditions: [StatePredicate.exactState('state2')],
            action: {
              type: 'intent',
              intent: {
                action: 'android.media.action.IMAGE_CAPTURE'
              }
            }
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      const permissionWarnings = result.warnings.filter(w => w.code === 'SENSITIVE_PERMISSION');
      expect(permissionWarnings.length).toBeGreaterThan(0);
    });

    test('should detect sensitive data input', async () => {
      const flow = new FlowDefinition({
        name: 'Sensitive Data Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Credit Card Input',
            preconditions: [StatePredicate.exactState('state1')],
            action: {
              type: 'type',
              target: { text: 'Card Number' },
              text: '4111-1111-1111-1111' // Credit card pattern
            }
          },
          {
            name: 'Email Input',
            preconditions: [StatePredicate.exactState('state2')],
            action: {
              type: 'type',
              target: { text: 'Email' },
              text: 'test@example.com' // Email pattern
            }
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      const sensitiveDataWarnings = result.warnings.filter(w => w.code === 'SENSITIVE_DATA_INPUT');
      expect(sensitiveDataWarnings.length).toBe(2);
    });

    test('should detect potential injection attacks', async () => {
      const flow = new FlowDefinition({
        name: 'Injection Test Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Script Injection Step',
            preconditions: [StatePredicate.exactState('state1')],
            action: {
              type: 'type',
              target: { text: 'Input' },
              text: '<script>alert("xss")</script>' // Script pattern
            }
          },
          {
            name: 'SQL Injection Step',
            preconditions: [StatePredicate.exactState('state2')],
            action: {
              type: 'type',
              target: { text: 'Query' },
              text: "SELECT * FROM users WHERE id = 1 OR 1=1" // SQL pattern
            }
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      const scriptWarnings = result.warnings.filter(w => w.code === 'POTENTIAL_SCRIPT_INJECTION');
      const sqlWarnings = result.warnings.filter(w => w.code === 'POTENTIAL_SQL_INJECTION');

      expect(scriptWarnings.length).toBe(1);
      expect(sqlWarnings.length).toBe(1);
    });
  });

  describe('Integration Validation', () => {
    test('should validate graph state compatibility', async () => {
      const flow = new FlowDefinition({
        name: 'Integration Test Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Valid Step',
            preconditions: [StatePredicate.exactState('state1')], // Exists in graph
            action: { type: 'tap', target: { text: 'Login' } },
            expectedState: StatePredicate.exactState('state2') // Exists in graph
          }
        ],
        entryPoint: StatePredicate.exactState('state1') // Exists in graph
      });

      const result = await validator.validateFlow(flow, {
        availableStates: mockStates
      });

      expect(result.categoryResults.integration.isValid).toBe(true);
      expect(result.predicateResolutions.every(r => r.resolved)).toBe(true);
    });

    test('should detect incompatible entry point', async () => {
      const flow = new FlowDefinition({
        name: 'Incompatible Flow',
        packageName: 'com.example.app',
        steps: [createValidStep()],
        entryPoint: StatePredicate.exactState('nonexistent_state') // Doesn't exist
      });

      const result = await validator.validateFlow(flow, {
        availableStates: mockStates
      });

      expect(result.categoryResults.integration.isValid).toBe(false);
      const noMatchErrors = result.errors.filter(e => e.code === 'ENTRY_POINT_NO_MATCH');
      expect(noMatchErrors.length).toBe(1);
    });

    test('should validate package compatibility', async () => {
      const flow = new FlowDefinition({
        name: 'Wrong Package Flow',
        packageName: 'com.different.app',
        steps: [createValidStep()],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow, {
        availablePackages: ['com.example.app', 'com.another.app']
      });

      const packageErrors = result.errors.filter(e => e.code === 'PACKAGE_NOT_AVAILABLE');
      expect(packageErrors.length).toBe(1);
    });
  });

  describe('Predicate Resolution', () => {
    test('should resolve exact state predicates', async () => {
      const flow = new FlowDefinition({
        name: 'Exact Predicate Flow',
        packageName: 'com.example.app',
        steps: [createValidStep()],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow, {
        availableStates: mockStates
      });

      const entryResolution = result.predicateResolutions.find(r =>
        r.predicate.type === 'exact' && r.predicate.stateId === 'state1'
      );

      expect(entryResolution).toBeDefined();
      expect(entryResolution!.resolved).toBe(true);
      expect(entryResolution!.confidence).toBe(1);
      expect(entryResolution!.matchingStates).toHaveLength(1);
      expect(entryResolution!.matchingStates[0].id).toBe('state1');
    });

    test('should resolve contains predicates', async () => {
      const flow = new FlowDefinition({
        name: 'Contains Predicate Flow',
        packageName: 'com.example.app',
        steps: [createValidStep()],
        entryPoint: StatePredicate.textContent(['Welcome', 'Login'])
      });

      const result = await validator.validateFlow(flow, {
        availableStates: mockStates
      });

      const entryResolution = result.predicateResolutions.find(r =>
        r.predicate.type === 'contains'
      );

      expect(entryResolution).toBeDefined();
      expect(entryResolution!.resolved).toBe(true);
      expect(entryResolution!.confidence).toBeGreaterThan(0);
      expect(entryResolution!.matchingStates.length).toBeGreaterThan(0);
    });

    test('should handle unresolvable predicates', async () => {
      const flow = new FlowDefinition({
        name: 'Unresolvable Predicate Flow',
        packageName: 'com.example.app',
        steps: [createValidStep()],
        entryPoint: StatePredicate.textContent(['Nonexistent Text'])
      });

      const result = await validator.validateFlow(flow, {
        availableStates: mockStates
      });

      const entryResolution = result.predicateResolutions.find(r =>
        r.predicate.type === 'contains'
      );

      expect(entryResolution).toBeDefined();
      expect(entryResolution!.resolved).toBe(false);
      expect(entryResolution!.confidence).toBe(0);
      expect(entryResolution!.matchingStates).toHaveLength(0);
    });
  });

  describe('Performance and Caching', () => {
    test('should cache validation results', async () => {
      const flow = createValidFlow();

      // First validation
      const result1 = await validator.validateFlow(flow, {
        enableCaching: true
      });

      // Second validation should hit cache
      const result2 = await validator.validateFlow(flow, {
        enableCaching: true
      });

      expect(result1.metadata.cacheHit).toBe(false);
      expect(result2.metadata.cacheHit).toBe(true);
      expect(result1).toEqual(result2);

      const metrics = validator.getMetrics();
      expect(metrics.cacheHits).toBe(1);
      expect(metrics.cacheHitRate).toBeGreaterThan(0);
    });

    test('should meet performance requirements', async () => {
      // Create a flow with 50 states worth of complexity
      const flow = new FlowDefinition({
        name: 'Performance Test Flow',
        packageName: 'com.example.app',
        steps: Array(50).fill(null).map((_, i) => ({
          name: `Step ${i}`,
          preconditions: [
            StatePredicate.textContent([`Text ${i}`]),
            StatePredicate.exactState(`state${(i % 3) + 1}`)
          ],
          action: { type: 'tap', target: { text: `Button ${i}` } },
          expectedState: StatePredicate.exactState(`state${((i + 1) % 3) + 1}`)
        })),
        entryPoint: StatePredicate.exactState('state1')
      });

      const startTime = performance.now();
      const result = await validator.validateFlow(flow, {
        availableStates: mockStates
      });
      const duration = performance.now() - startTime;

      // Should complete in under 2 seconds for ≤50 states
      expect(duration).toBeLessThan(2000);
      expect(result.performance.totalTime).toBeLessThan(2000);
      expect(result.performance.impact).toBe('low');
    });

    test('should handle batch validation efficiently', async () => {
      const flows = Array(5).fill(null).map((_, i) =>
        createValidFlow(`Batch Flow ${i}`)
      );

      const startTime = performance.now();
      const results = await validator.validateFlowsBatch(flows);
      const duration = performance.now() - startTime;

      expect(results).toHaveLength(5);
      expect(results.every(r => r.isValid)).toBe(true);

      // Batch validation should be more efficient than individual validations
      expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
    });

    test('should track validation metrics', async () => {
      const flows = [
        createValidFlow('Flow 1'),
        createValidFlow('Flow 2'),
        createValidFlow('Flow 3')
      ];

      // Validate flows
      for (const flow of flows) {
        await validator.validateFlow(flow);
      }

      const metrics = validator.getMetrics();
      expect(metrics.totalValidations).toBe(3);
      expect(metrics.averageValidationTime).toBeGreaterThan(0);

      validator.resetMetrics();
      const resetMetrics = validator.getMetrics();
      expect(resetMetrics.totalValidations).toBe(0);
    });
  });

  describe('Error Reporting and Suggestions', () => {
    test('should provide detailed error information', async () => {
      const flow = new FlowDefinition({
        name: 'Error Test Flow',
        packageName: 'invalid-package',
        steps: [
          {
            name: 'Invalid Step',
            preconditions: [],
            action: {
              type: 'swipe',
              swipe: { direction: 'invalid', distance: -1 }
            },
            timeout: -10
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      expect(result.errors.length).toBeGreaterThan(0);

      // Check enhanced error properties
      const enhancedErrors = result.errors as any;
      enhancedErrors.forEach((error: any) => {
        expect(error.category).toBeDefined();
        expect(error.severity).toBeDefined();
        expect(error.suggestions).toBeDefined();
        expect(Array.isArray(error.suggestions)).toBe(true);
      });
    });

    test('should provide actionable suggestions', async () => {
      const flow = new FlowDefinition({
        name: 'Suggestion Test Flow',
        packageName: 'com.example.app',
        steps: [
          {
            name: 'Step without target',
            preconditions: [StatePredicate.exactState('state1')],
            action: { type: 'tap' } // Missing target
          },
          {
            name: 'Critical step without validation',
            preconditions: [],
            action: { type: 'tap', target: { text: 'Button' } },
            critical: true
          }
        ],
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      const suggestions = result.analysis.suggestions;
      expect(suggestions.length).toBeGreaterThan(0);

      // Should suggest adding targets and validation
      const hasTargetSuggestion = suggestions.some(s =>
        s.toLowerCase().includes('target')
      );
      const hasValidationSuggestion = suggestions.some(s =>
        s.toLowerCase().includes('validation')
      );

      expect(hasTargetSuggestion).toBe(true);
      expect(hasValidationSuggestion).toBe(true);
    });

    test('should provide risk factor analysis', async () => {
      const flow = new FlowDefinition({
        name: 'Risk Analysis Flow',
        packageName: 'com.example.app',
        steps: Array(25).fill(null).map((_, i) => ({
          name: `Risk Step ${i}`,
          preconditions: [], // No preconditions = risky
          action: { type: 'tap', target: { text: `Button ${i}` } },
          critical: i % 5 === 0 // Some critical steps
        })),
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(flow);

      const riskFactors = result.analysis.riskFactors;
      expect(riskFactors.length).toBeGreaterThan(0);

      // Should identify complexity and reliability risks
      const hasComplexityRisk = riskFactors.some(r => r.includes('complexity'));
      const hasReliabilityRisk = riskFactors.some(r => r.includes('reliability'));

      expect(hasComplexityRisk).toBe(true);
      expect(hasReliabilityRisk).toBe(true);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle malformed flow definitions gracefully', async () => {
      const malformedFlow = {
        // Completely malformed
        invalid: 'data',
        steps: 'not an array',
        entryPoint: null
      } as any;

      const result = await validator.validateFlow(malformedFlow);

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.categoryResults.structural.isValid).toBe(false);
    });

    test('should handle empty flows', async () => {
      const emptyFlow = {
        name: 'Empty Flow',
        packageName: 'com.example.app',
        steps: [],
        entryPoint: StatePredicate.exactState('state1'),
        config: {
          defaultTimeout: 30,
          retryAttempts: 3,
          allowParallel: false,
          priority: 'medium' as const
        }
      };

      const result = await validator.validateFlow(emptyFlow);

      expect(result.isValid).toBe(false);
      const emptyStepErrors = result.errors.filter(e => e.code === 'EMPTY_STEPS');
      expect(emptyStepErrors.length).toBe(1);
    });

    test('should handle very large flows', async () => {
      const largeFlow = new FlowDefinition({
        name: 'Large Flow',
        packageName: 'com.example.app',
        steps: Array(150).fill(null).map((_, i) => createValidStep(`Step ${i}`)),
        entryPoint: StatePredicate.exactState('state1')
      });

      const result = await validator.validateFlow(largeFlow, {
        maxSteps: 100
      });

      expect(result.isValid).toBe(false);
      const manyStepWarnings = result.warnings.filter(w => w.code === 'MANY_STEPS');
      expect(manyStepWarnings.length).toBe(1);
    });

    test('should handle concurrent validations', async () => {
      const flows = Array(10).fill(null).map((_, i) => createValidFlow(`Concurrent Flow ${i}`));

      // Run validations concurrently
      const promises = flows.map(flow => validator.validateFlow(flow));
      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      expect(results.every(r => r.isValid)).toBe(true);

      // Metrics should track all validations
      const metrics = validator.getMetrics();
      expect(metrics.totalValidations).toBe(10);
    });
  });
});

// Helper functions
function createValidFlow(name = 'Test Flow'): FlowDefinition {
  return new FlowDefinition({
    name,
    packageName: 'com.example.app',
    steps: [createValidStep()],
    entryPoint: StatePredicate.exactState('state1')
  });
}

function createValidStep(name = 'Test Step'): any {
  return {
    name,
    preconditions: [StatePredicate.exactState('state1')],
    action: {
      type: 'tap',
      target: { text: 'Test Button' }
    },
    timeout: 30,
    critical: false
  };
}