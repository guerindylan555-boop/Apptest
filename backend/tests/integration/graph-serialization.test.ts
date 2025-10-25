/**
 * Graph JSON Serialization Integration Tests
 *
 * Comprehensive test suite for UI Graph (UTG) JSON serialization, persistence,
 * and validation. Tests graph creation, state management, transition recording,
 * serialization/deserialization, version management, and performance benchmarks.
 *
 * This test validates the graph persistence layer that stores all discovered
 * UI states and transitions for the Discovery system.
 */

import { promises as fs } from 'fs';
import { join, resolve } from 'path';
import { createHash } from 'crypto';
import {
  UIGraph,
  StateRecord,
  TransitionRecord,
  UserAction,
  Selector,
  GraphConfig
} from '../../src/types/graph';
import { GraphService } from '../../src/services/graphService';
import { JsonStorageService, StorageError, ConflictError, ValidationError } from '../../src/services/json-storage';
import {
  generateStateId,
  generateTransitionId,
  generateDigest,
  calculateStateSimilarity,
  shouldMergeStates,
  isValidSHA256,
  hashObject
} from '../../src/utils/hash';
import { getGraphConfig } from '../../src/config/discovery';

// ============================================================================
// TEST CONFIGURATION AND UTILITIES
// ============================================================================

/**
 * Test configuration interface
 */
interface TestConfig {
  testDir: string;
  testDataDir: string;
  tempDir: string;
  performanceEnabled: boolean;
  verboseLogging: boolean;
  cleanupAfterTest: boolean;
}

/**
 * Test result interface
 */
interface TestResult {
  testName: string;
  passed: boolean;
  duration: number;
  error?: string;
  details?: any;
  performance?: {
    memoryUsage: number;
    cpuTime: number;
    fileSize: number;
  };
}

/**
 * Graph test data generator
 */
class GraphTestDataGenerator {
  private testConfig: TestConfig;

  constructor(testConfig: TestConfig) {
    this.testConfig = testConfig;
  }

  /**
   * Generate a test state with realistic data
   */
  generateTestState(overrides: Partial<StateRecord> = {}): StateRecord {
    const packageName = 'com.example.testapp';
    const activity = '.MainActivity';
    const xmlHash = createHash('sha256').update(`test_xml_${Date.now()}`).digest('hex');

    const selectors: Selector[] = [
      {
        rid: 'btn_login',
        desc: 'Login button',
        text: 'Login',
        cls: 'android.widget.Button',
        bounds: [100, 200, 300, 400]
      },
      {
        rid: 'input_username',
        desc: 'Username input field',
        cls: 'android.widget.EditText',
        bounds: [100, 100, 300, 150]
      }
    ];

    const visibleText = ['Login', 'Username', 'Password', 'Welcome'];

    const digest = generateDigest(xmlHash, selectors, visibleText);
    const stateId = generateStateId(packageName, activity, digest);
    const now = new Date().toISOString();

    return {
      id: stateId,
      package: packageName,
      activity,
      digest,
      selectors,
      visibleText,
      screenshot: `${stateId}.png`,
      tags: ['login', 'main'],
      createdAt: now,
      updatedAt: now,
      metadata: {
        captureMethod: 'adb',
        captureDuration: 500,
        elementCount: selectors.length,
        hierarchyDepth: 5
      },
      ...overrides
    };
  }

  /**
   * Generate a test transition
   */
  generateTestTransition(
    fromStateId: string,
    toStateId: string,
    overrides: Partial<TransitionRecord> = {}
  ): TransitionRecord {
    const action: UserAction = {
      type: 'tap',
      target: {
        rid: 'btn_login',
        desc: 'Login button'
      },
      semanticSelector: {
        semanticType: 'button',
        purpose: 'login',
        contentSignature: 'login_btn',
        confidence: 0.95
      }
    };

    const actionStr = JSON.stringify(action);
    const transitionId = generateTransitionId(fromStateId, toStateId, actionStr);
    const now = new Date().toISOString();

    return {
      id: transitionId,
      from: fromStateId,
      to: toStateId,
      action,
      evidence: {
        beforeDigest: 'before_digest_hash',
        afterDigest: 'after_digest_hash',
        timestamp: now,
        notes: 'Successful login transition'
      },
      confidence: 0.95,
      createdAt: now,
      tags: ['login', 'success'],
      ...overrides
    };
  }

  /**
   * Generate a test graph with specified number of states and transitions
   */
  generateTestGraph(
    stateCount: number = 10,
    transitionCount: number = 15,
    overrides: Partial<UIGraph> = {}
  ): UIGraph {
    const states: StateRecord[] = [];
    const transitions: TransitionRecord[] = [];
    const now = new Date().toISOString();

    // Generate states
    for (let i = 0; i < stateCount; i++) {
      const state = this.generateTestState({
        id: generateStateId(
          'com.example.testapp',
          `.Activity${i}`,
          generateDigest(`xml_${i}`, [], [`Activity ${i}`])
        ),
        activity: `.Activity${i}`,
        visibleText: [`Activity ${i}`, 'Button', 'Text'],
        tags: [`activity_${i}`, 'test']
      });
      states.push(state);
    }

    // Generate transitions
    for (let i = 0; i < Math.min(transitionCount, stateCount * (stateCount - 1)); i++) {
      const fromIndex = i % stateCount;
      const toIndex = (i + 1) % stateCount;

      const transition = this.generateTestTransition(
        states[fromIndex].id,
        states[toIndex].id,
        {
          action: {
            type: ['tap', 'type', 'swipe', 'back'][i % 4] as UserAction['type'],
            target: states[toIndex].selectors[0]
          }
        }
      );
      transitions.push(transition);
    }

    // Calculate graph statistics
    const stateIds = new Set(states.map(s => s.id));
    const statesWithTransitions = new Set([
      ...transitions.map(t => t.from),
      ...transitions.map(t => t.to)
    ]);
    const isolatedStates = stateCount - statesWithTransitions.size;

    return {
      version: '1.0.0',
      createdAt: now,
      updatedAt: now,
      packageName: 'com.example.testapp',
      states,
      transitions,
      stats: {
        stateCount,
        transitionCount: transitions.length,
        averageDegree: stateCount > 0 ? (transitions.length * 2) / stateCount : 0,
        isolatedStates,
        lastCapture: now
      },
      metadata: {
        captureTool: 'AutoApp Discovery Test',
        androidVersion: '11',
        appVersion: '1.0.0',
        deviceInfo: 'test_emulator',
        totalCaptureTime: stateCount * 500,
        totalSessions: 1
      },
      ...overrides
    };
  }

  /**
   * Generate corrupted JSON data for testing error handling
   */
  generateCorruptedGraphData(): string[] {
    return [
      // Invalid JSON syntax
      '{ "states": [ { "id": "test" ',

      // Missing required fields
      JSON.stringify({
        version: '1.0.0',
        // Missing packageName
        states: [],
        transitions: []
      }),

      // Invalid data types
      JSON.stringify({
        version: '1.0.0',
        packageName: 'test.app',
        states: 'not an array',  // Should be array
        transitions: []
      }),

      // Invalid state IDs
      JSON.stringify({
        version: '1.0.0',
        packageName: 'test.app',
        states: [{ id: 'invalid_hash' }],  // Invalid SHA256
        transitions: []
      }),

      // Circular reference (simulated)
      JSON.stringify({
        version: '1.0.0',
        packageName: 'test.app',
        states: [],
        transitions: [{
          from: 'nonexistent',
          to: 'also_nonexistent'
        }]
      })
    ];
  }
}

/**
 * Performance monitor for tracking test metrics
 */
class PerformanceMonitor {
  private startTime: number = 0;
  private startMemory: number = 0;

  start(): void {
    this.startTime = Date.now();
    this.startMemory = process.memoryUsage().heapUsed;
  }

  getMetrics(): { duration: number; memoryUsed: number; memoryDelta: number } {
    const endTime = Date.now();
    const endMemory = process.memoryUsage().heapUsed;

    return {
      duration: endTime - this.startTime,
      memoryUsed: endMemory,
      memoryDelta: endMemory - this.startMemory
    };
  }
}

/**
 * JSON schema validator for graph structures
 */
class GraphSchemaValidator {
  private requiredGraphFields = ['version', 'createdAt', 'updatedAt', 'packageName', 'states', 'transitions', 'stats', 'metadata'];
  private requiredStateFields = ['id', 'package', 'activity', 'digest', 'selectors', 'visibleText', 'createdAt', 'updatedAt'];
  private requiredTransitionFields = ['id', 'from', 'to', 'action', 'createdAt'];
  private requiredStatsFields = ['stateCount', 'transitionCount', 'averageDegree', 'isolatedStates'];
  private requiredMetadataFields = ['captureTool', 'totalCaptureTime', 'totalSessions'];

  /**
   * Validate UIGraph structure
   */
  validateGraph(graph: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!graph || typeof graph !== 'object') {
      errors.push('Graph must be an object');
      return { isValid: false, errors };
    }

    // Check required fields
    for (const field of this.requiredGraphFields) {
      if (!(field in graph)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Validate field types
    if (graph.states && !Array.isArray(graph.states)) {
      errors.push('Graph states must be an array');
    }

    if (graph.transitions && !Array.isArray(graph.transitions)) {
      errors.push('Graph transitions must be an array');
    }

    if (graph.stats && typeof graph.stats !== 'object') {
      errors.push('Graph stats must be an object');
    }

    if (graph.metadata && typeof graph.metadata !== 'object') {
      errors.push('Graph metadata must be an object');
    }

    // Validate version format
    if (graph.version && typeof graph.version !== 'string') {
      errors.push('Graph version must be a string');
    }

    // Validate timestamp formats
    const timestampFields = ['createdAt', 'updatedAt'];
    for (const field of timestampFields) {
      if (graph[field] && !this.isValidTimestamp(graph[field])) {
        errors.push(`Invalid timestamp format for ${field}`);
      }
    }

    // Validate states
    if (Array.isArray(graph.states)) {
      for (let i = 0; i < graph.states.length; i++) {
        const stateValidation = this.validateState(graph.states[i]);
        if (!stateValidation.isValid) {
          errors.push(`State ${i}: ${stateValidation.errors.join(', ')}`);
        }
      }
    }

    // Validate transitions
    if (Array.isArray(graph.transitions)) {
      for (let i = 0; i < graph.transitions.length; i++) {
        const transitionValidation = this.validateTransition(graph.transitions[i]);
        if (!transitionValidation.isValid) {
          errors.push(`Transition ${i}: ${transitionValidation.errors.join(', ')}`);
        }
      }
    }

    // Validate stats
    if (graph.stats) {
      const statsValidation = this.validateStats(graph.stats);
      if (!statsValidation.isValid) {
        errors.push(`Stats: ${statsValidation.errors.join(', ')}`);
      }
    }

    // Validate metadata
    if (graph.metadata) {
      const metadataValidation = this.validateMetadata(graph.metadata);
      if (!metadataValidation.isValid) {
        errors.push(`Metadata: ${metadataValidation.errors.join(', ')}`);
      }
    }

    // Validate transition references
    if (Array.isArray(graph.states) && Array.isArray(graph.transitions)) {
      const stateIds = new Set(graph.states.map((s: StateRecord) => s.id));

      for (let i = 0; i < graph.transitions.length; i++) {
        const transition = graph.transitions[i];
        if (!stateIds.has(transition.from)) {
          errors.push(`Transition ${i}: references non-existent source state ${transition.from}`);
        }
        if (!stateIds.has(transition.to)) {
          errors.push(`Transition ${i}: references non-existent target state ${transition.to}`);
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate StateRecord structure
   */
  private validateState(state: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!state || typeof state !== 'object') {
      errors.push('State must be an object');
      return { isValid: false, errors };
    }

    // Check required fields
    for (const field of this.requiredStateFields) {
      if (!(field in state)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Validate state ID format
    if (state.id && !isValidSHA256(state.id)) {
      errors.push('Invalid state ID format (must be SHA256)');
    }

    // Validate arrays
    if (state.selectors && !Array.isArray(state.selectors)) {
      errors.push('State selectors must be an array');
    }

    if (state.visibleText && !Array.isArray(state.visibleText)) {
      errors.push('State visibleText must be an array');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate TransitionRecord structure
   */
  private validateTransition(transition: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!transition || typeof transition !== 'object') {
      errors.push('Transition must be an object');
      return { isValid: false, errors };
    }

    // Check required fields
    for (const field of this.requiredTransitionFields) {
      if (!(field in transition)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Validate transition ID format
    if (transition.id && !isValidSHA256(transition.id)) {
      errors.push('Invalid transition ID format (must be SHA256)');
    }

    // Validate action
    if (transition.action && typeof transition.action !== 'object') {
      errors.push('Transition action must be an object');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate graph statistics
   */
  private validateStats(stats: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!stats || typeof stats !== 'object') {
      errors.push('Stats must be an object');
      return { isValid: false, errors };
    }

    // Check required fields
    for (const field of this.requiredStatsFields) {
      if (!(field in stats)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Validate numeric fields
    const numericFields = ['stateCount', 'transitionCount', 'averageDegree', 'isolatedStates'];
    for (const field of numericFields) {
      if (stats[field] !== undefined && typeof stats[field] !== 'number') {
        errors.push(`Stats field ${field} must be a number`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate graph metadata
   */
  private validateMetadata(metadata: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!metadata || typeof metadata !== 'object') {
      errors.push('Metadata must be an object');
      return { isValid: false, errors };
    }

    // Check required fields
    for (const field of this.requiredMetadataFields) {
      if (!(field in metadata)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate ISO timestamp format
   */
  private isValidTimestamp(timestamp: string): boolean {
    const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
    return iso8601Regex.test(timestamp);
  }
}

// ============================================================================
// MAIN TEST SUITE
// ============================================================================

/**
 * Main graph serialization test suite
 */
class GraphSerializationTestSuite {
  private testConfig: TestConfig;
  private dataGenerator: GraphTestDataGenerator;
  private storageService: JsonStorageService;
  private schemaValidator: GraphSchemaValidator;
  private testResults: TestResult[] = [];
  private testGraphPath: string;

  constructor() {
    // Setup test configuration
    this.testConfig = {
      testDir: resolve(__dirname, '..'),
      testDataDir: resolve(__dirname, 'data'),
      tempDir: resolve(__dirname, 'temp'),
      performanceEnabled: process.env.ENABLE_PERFORMANCE_TESTS !== 'false',
      verboseLogging: process.env.VERBOSE_TESTS === 'true',
      cleanupAfterTest: process.env.CLEANUP_AFTER_TEST !== 'false'
    };

    this.dataGenerator = new GraphTestDataGenerator(this.testConfig);
    this.storageService = new JsonStorageService();
    this.schemaValidator = new GraphSchemaValidator();
    this.testGraphPath = join(this.testConfig.tempDir, 'test-graph.json');
  }

  /**
   * Run complete test suite
   */
  async runCompleteTestSuite(): Promise<{
    summary: {
      totalTests: number;
      passedTests: number;
      failedTests: number;
      successRate: number;
      totalDuration: number;
    };
    results: TestResult[];
  }> {
    console.log('='.repeat(80));
    console.log('GRAPH JSON SERIALIZATION INTEGRATION TESTS');
    console.log('='.repeat(80));

    const suiteStartTime = Date.now();

    try {
      // Setup test environment
      await this.setupTestEnvironment();

      // Run test categories
      await this.runGraphCreationTests();
      await this.runStateManagementTests();
      await this.runTransitionTests();
      await this.runSerializationTests();
      await this.runVersionManagementTests();
      await this.runPerformanceTests();
      await this.runErrorHandlingTests();
      await this.runEdgeCaseTests();
      await this.runConcurrencyTests();

      // Cleanup test environment
      if (this.testConfig.cleanupAfterTest) {
        await this.cleanupTestEnvironment();
      }

      const suiteDuration = Date.now() - suiteStartTime;
      const summary = this.calculateTestSummary(suiteDuration);

      console.log('='.repeat(80));
      console.log('TEST RESULTS SUMMARY');
      console.log('='.repeat(80));
      console.log(`Total Tests: ${summary.totalTests}`);
      console.log(`Passed: ${summary.passedTests}`);
      console.log(`Failed: ${summary.failedTests}`);
      console.log(`Success Rate: ${summary.successRate}%`);
      console.log(`Duration: ${summary.totalDuration}ms`);

      // Log failed tests
      const failedTests = this.testResults.filter(r => !r.passed);
      if (failedTests.length > 0) {
        console.log('\nFAILED TESTS:');
        failedTests.forEach(test => {
          console.log(`  ❌ ${test.testName}: ${test.error}`);
        });
      }

      return { summary, results: this.testResults };

    } catch (error) {
      console.error('Test suite execution failed:', error);
      throw error;
    }
  }

  /**
   * Setup test environment
   */
  private async setupTestEnvironment(): Promise<void> {
    console.log('Setting up test environment...');

    // Create test directories
    await fs.mkdir(this.testConfig.testDataDir, { recursive: true });
    await fs.mkdir(this.testConfig.tempDir, { recursive: true });

    // Create sample test data files
    await this.createSampleTestData();

    console.log('Test environment setup complete.');
  }

  /**
   * Create sample test data files
   */
  private async createSampleTestData(): Promise<void> {
    // Create small test graph
    const smallGraph = this.dataGenerator.generateTestGraph(5, 8);
    await fs.writeFile(
      join(this.testConfig.testDataDir, 'small-graph.json'),
      JSON.stringify(smallGraph, null, 2)
    );

    // Create medium test graph
    const mediumGraph = this.dataGenerator.generateTestGraph(50, 100);
    await fs.writeFile(
      join(this.testConfig.testDataDir, 'medium-graph.json'),
      JSON.stringify(mediumGraph, null, 2)
    );

    // Create corrupted test files
    const corruptedData = this.dataGenerator.generateCorruptedGraphData();
    for (let i = 0; i < corruptedData.length; i++) {
      await fs.writeFile(
        join(this.testConfig.testDataDir, `corrupted-${i}.json`),
        corruptedData[i]
      );
    }
  }

  /**
   * Run graph creation and initialization tests
   */
  private async runGraphCreationTests(): Promise<void> {
    console.log('\n🔧 Running graph creation tests...');

    await this.runTest('Create empty graph', async () => {
      const graph = this.dataGenerator.generateTestGraph(0, 0);

      const validation = this.schemaValidator.validateGraph(graph);
      if (!validation.isValid) {
        throw new Error(`Graph validation failed: ${validation.errors.join(', ')}`);
      }

      // Test JSON serialization
      const serialized = JSON.stringify(graph);
      const deserialized = JSON.parse(serialized);

      const revalidation = this.schemaValidator.validateGraph(deserialized);
      if (!revalidation.isValid) {
        throw new Error(`Deserialized graph validation failed: ${revalidation.errors.join(', ')}`);
      }

      return { graphSize: serialized.length };
    });

    await this.runTest('Create graph with single state', async () => {
      const graph = this.dataGenerator.generateTestGraph(1, 0);

      if (graph.states.length !== 1) {
        throw new Error('Expected exactly 1 state');
      }

      if (graph.transitions.length !== 0) {
        throw new Error('Expected no transitions');
      }

      const state = graph.states[0];
      if (!state.id || !state.package || !state.activity) {
        throw new Error('State missing required fields');
      }

      return { stateId: state.id, packageName: state.package };
    });

    await this.runTest('Create graph with multiple states', async () => {
      const stateCount = 10;
      const graph = this.dataGenerator.generateTestGraph(stateCount, 0);

      if (graph.states.length !== stateCount) {
        throw new Error(`Expected ${stateCount} states, got ${graph.states.length}`);
      }

      // Verify all state IDs are unique
      const stateIds = graph.states.map(s => s.id);
      const uniqueIds = new Set(stateIds);
      if (uniqueIds.size !== stateCount) {
        throw new Error('State IDs are not unique');
      }

      // Verify all states have valid SHA256 IDs
      for (const state of graph.states) {
        if (!isValidSHA256(state.id)) {
          throw new Error(`Invalid state ID: ${state.id}`);
        }
      }

      return { stateCount, uniqueIds: uniqueIds.size };
    });

    await this.runTest('Graph statistics calculation', async () => {
      const stateCount = 10;
      const transitionCount = 15;
      const graph = this.dataGenerator.generateTestGraph(stateCount, transitionCount);

      // Verify statistics
      if (graph.stats.stateCount !== stateCount) {
        throw new Error(`Expected state count ${stateCount}, got ${graph.stats.stateCount}`);
      }

      if (graph.stats.transitionCount !== transitionCount) {
        throw new Error(`Expected transition count ${transitionCount}, got ${graph.stats.transitionCount}`);
      }

      // Verify average degree calculation
      const expectedAverageDegree = stateCount > 0 ? (transitionCount * 2) / stateCount : 0;
      const actualAverageDegree = graph.stats.averageDegree;
      const degreeDiff = Math.abs(expectedAverageDegree - actualAverageDegree);

      if (degreeDiff > 0.1) {
        throw new Error(`Expected average degree ~${expectedAverageDegree}, got ${actualAverageDegree}`);
      }

      return {
        stateCount: graph.stats.stateCount,
        transitionCount: graph.stats.transitionCount,
        averageDegree: graph.stats.averageDegree
      };
    });
  }

  /**
   * Run state management tests
   */
  private async runStateManagementTests(): Promise<void> {
    console.log('\n📊 Running state management tests...');

    await this.runTest('Add state to empty graph', async () => {
      const graph = this.dataGenerator.generateTestGraph(0, 0);
      const newState = this.dataGenerator.generateTestState();

      graph.states.push(newState);
      graph.updatedAt = new Date().toISOString();
      graph.stats.stateCount = 1;

      const validation = this.schemaValidator.validateGraph(graph);
      if (!validation.isValid) {
        throw new Error(`Graph validation failed: ${validation.errors.join(', ')}`);
      }

      return { stateId: newState.id, totalStates: graph.states.length };
    });

    await this.runTest('State deduplication', async () => {
      const graph = this.dataGenerator.generateTestGraph(0, 0);
      const baseState = this.dataGenerator.generateTestState();

      // Add identical state
      graph.states.push(baseState);
      graph.states.push({ ...baseState }); // Clone but same content

      // Test similarity detection
      const similarity = calculateStateSimilarity(baseState, baseState);
      if (similarity !== 1.0) {
        throw new Error(`Expected similarity 1.0, got ${similarity}`);
      }

      // Test merge decision
      const shouldMerge = shouldMergeStates(baseState, baseState, 0.9);
      if (!shouldMerge) {
        throw new Error('Identical states should be merged');
      }

      return { similarity, shouldMerge, duplicateCount: graph.states.length };
    });

    await this.runTest('State metadata validation', async () => {
      const state = this.dataGenerator.generateTestState({
        metadata: {
          captureMethod: 'adb',
          captureDuration: 500,
          elementCount: 10,
          hierarchyDepth: 5
        }
      });

      if (!state.metadata) {
        throw new Error('State metadata is missing');
      }

      if (state.metadata.captureMethod !== 'adb' && state.metadata.captureMethod !== 'frida') {
        throw new Error(`Invalid capture method: ${state.metadata.captureMethod}`);
      }

      if (typeof state.metadata.captureDuration !== 'number' || state.metadata.captureDuration <= 0) {
        throw new Error('Invalid capture duration');
      }

      return {
        captureMethod: state.metadata.captureMethod,
        captureDuration: state.metadata.captureDuration,
        elementCount: state.metadata.elementCount
      };
    });

    await this.runTest('State selector validation', async () => {
      const state = this.dataGenerator.generateTestState();

      if (!Array.isArray(state.selectors) || state.selectors.length === 0) {
        throw new Error('State must have selectors array');
      }

      for (const selector of state.selectors) {
        if (!selector.rid && !selector.desc && !selector.text && !selector.cls) {
          throw new Error('Selector must have at least one identifier');
        }

        if (selector.bounds && (!Array.isArray(selector.bounds) || selector.bounds.length !== 4)) {
          throw new Error('Selector bounds must be array of 4 numbers');
        }
      }

      return { selectorCount: state.selectors.length, firstSelector: state.selectors[0] };
    });
  }

  /**
   * Run transition management tests
   */
  private async runTransitionTests(): Promise<void> {
    console.log('\n🔄 Running transition tests...');

    await this.runTest('Create transition between states', async () => {
      const state1 = this.dataGenerator.generateTestState();
      const state2 = this.dataGenerator.generateTestState();
      const transition = this.dataGenerator.generateTestTransition(state1.id, state2.id);

      const graph = this.dataGenerator.generateTestGraph(0, 0);
      graph.states = [state1, state2];
      graph.transitions = [transition];
      graph.stats.stateCount = 2;
      graph.stats.transitionCount = 1;

      const validation = this.schemaValidator.validateGraph(graph);
      if (!validation.isValid) {
        throw new Error(`Graph validation failed: ${validation.errors.join(', ')}`);
      }

      return {
        transitionId: transition.id,
        fromState: transition.from,
        toState: transition.to,
        actionType: transition.action.type
      };
    });

    await this.runTest('Transition action validation', async () => {
      const actions: UserAction[] = [
        { type: 'tap', target: { rid: 'button' } },
        { type: 'type', target: { rid: 'input' }, text: 'test input' },
        { type: 'swipe', target: { cls: 'view' }, swipe: { direction: 'up', distance: 100 } },
        { type: 'back' },
        { type: 'intent', intent: { action: 'android.intent.action.VIEW' } }
      ];

      const results = [];
      for (const action of actions) {
        const transition = this.dataGenerator.generateTestTransition('state1', 'state2', { action });

        if (!transition.action || transition.action.type !== action.type) {
          throw new Error(`Action type mismatch for ${action.type}`);
        }

        results.push({ type: action.type, valid: true });
      }

      return { validatedActions: results };
    });

    await this.runTest('Transition evidence tracking', async () => {
      const transition = this.dataGenerator.generateTestTransition('state1', 'state2', {
        evidence: {
          beforeDigest: 'before_hash_123',
          afterDigest: 'after_hash_456',
          timestamp: new Date().toISOString(),
          notes: 'Test transition evidence',
          beforeScreenshot: 'before.png',
          afterScreenshot: 'after.png'
        }
      });

      if (!transition.evidence) {
        throw new Error('Transition evidence is missing');
      }

      const evidence = transition.evidence;
      if (!evidence.beforeDigest || !evidence.afterDigest) {
        throw new Error('Evidence missing required digests');
      }

      if (!evidence.timestamp) {
        throw new Error('Evidence missing timestamp');
      }

      return {
        hasEvidence: !!transition.evidence,
        hasDigests: !!(evidence.beforeDigest && evidence.afterDigest),
        hasTimestamp: !!evidence.timestamp,
        hasScreenshots: !!(evidence.beforeScreenshot && evidence.afterScreenshot)
      };
    });

    await this.runTest('Transition confidence scoring', async () => {
      const confidenceLevels = [0.5, 0.7, 0.9, 1.0];
      const results = [];

      for (const confidence of confidenceLevels) {
        const transition = this.dataGenerator.generateTestTransition('state1', 'state2', {
          confidence
        });

        if (transition.confidence !== confidence) {
          throw new Error(`Confidence mismatch: expected ${confidence}, got ${transition.confidence}`);
        }

        results.push({ confidence, valid: true });
      }

      return { confidenceLevels: results };
    });
  }

  /**
   * Run JSON serialization/deserialization tests
   */
  private async runSerializationTests(): Promise<void> {
    console.log('\n💾 Running serialization tests...');

    await this.runTest('Graph JSON serialization', async () => {
      const originalGraph = this.dataGenerator.generateTestGraph(10, 15);

      // Serialize to JSON
      const serialized = JSON.stringify(originalGraph, null, 2);

      // Verify it's valid JSON
      let parsedGraph: UIGraph;
      try {
        parsedGraph = JSON.parse(serialized);
      } catch (error) {
        throw new Error(`JSON parsing failed: ${error}`);
      }

      // Validate structure
      const validation = this.schemaValidator.validateGraph(parsedGraph);
      if (!validation.isValid) {
        throw new Error(`Deserialized graph validation failed: ${validation.errors.join(', ')}`);
      }

      // Compare key properties
      if (parsedGraph.version !== originalGraph.version) {
        throw new Error('Version mismatch after serialization');
      }

      if (parsedGraph.packageName !== originalGraph.packageName) {
        throw new Error('Package name mismatch after serialization');
      }

      if (parsedGraph.states.length !== originalGraph.states.length) {
        throw new Error('State count mismatch after serialization');
      }

      if (parsedGraph.transitions.length !== originalGraph.transitions.length) {
        throw new Error('Transition count mismatch after serialization');
      }

      return {
        serializedSize: serialized.length,
        stateCount: parsedGraph.states.length,
        transitionCount: parsedGraph.transitions.length
      };
    });

    await this.runTest('Compact vs pretty JSON serialization', async () => {
      const graph = this.dataGenerator.generateTestGraph(5, 8);

      // Compact serialization
      const compactJson = JSON.stringify(graph);

      // Pretty serialization
      const prettyJson = JSON.stringify(graph, null, 2);

      // Both should be valid JSON
      const compactParsed = JSON.parse(compactJson);
      const prettyParsed = JSON.parse(prettyJson);

      // Should have same content
      if (compactParsed.states.length !== prettyParsed.states.length) {
        throw new Error('State count mismatch between compact and pretty serialization');
      }

      // Pretty should be larger
      if (prettyJson.length <= compactJson.length) {
        throw new Error('Pretty JSON should be larger than compact JSON');
      }

      return {
        compactSize: compactJson.length,
        prettySize: prettyJson.length,
        sizeRatio: prettyJson.length / compactJson.length
      };
    });

    await this.runTest('File system serialization', async () => {
      const graph = this.dataGenerator.generateTestGraph(8, 12);
      const filePath = join(this.testConfig.tempDir, 'fs-test-graph.json');

      // Write to file
      await fs.writeFile(filePath, JSON.stringify(graph, null, 2));

      // Read from file
      const fileContent = await fs.readFile(filePath, 'utf-8');
      const loadedGraph = JSON.parse(fileContent);

      // Validate loaded graph
      const validation = this.schemaValidator.validateGraph(loadedGraph);
      if (!validation.isValid) {
        throw new Error(`Loaded graph validation failed: ${validation.errors.join(', ')}`);
      }

      // Verify file stats
      const stats = await fs.stat(filePath);
      if (stats.size === 0) {
        throw new Error('File is empty');
      }

      return {
        filePath,
        fileSize: stats.size,
        stateCount: loadedGraph.states.length,
        transitionCount: loadedGraph.transitions.length
      };
    });

    await this.runTest('Binary data handling', async () => {
      // Create graph with screenshot references
      const graph = this.dataGenerator.generateTestGraph(3, 5, {
        states: [
          { ...this.dataGenerator.generateTestState(), screenshot: 'screenshot1.png' },
          { ...this.dataGenerator.generateTestState(), screenshot: 'screenshot2.png' },
          { ...this.dataGenerator.generateTestState(), screenshot: undefined }
        ]
      });

      // Serialize and deserialize
      const serialized = JSON.stringify(graph);
      const deserialized = JSON.parse(serialized);

      // Check screenshot references are preserved
      const screenshotStates = deserialized.states.filter((s: StateRecord) => s.screenshot);
      if (screenshotStates.length !== 2) {
        throw new Error('Screenshot references not preserved correctly');
      }

      return {
        totalStates: deserialized.states.length,
        statesWithScreenshots: screenshotStates.length,
        serializedSize: serialized.length
      };
    });
  }

  /**
   * Run version management tests
   */
  private async runVersionManagementTests(): Promise<void> {
    console.log('\n🏷️ Running version management tests...');

    await this.runTest('Graph version tracking', async () => {
      const graph = this.dataGenerator.generateTestGraph(5, 8, {
        version: '1.0.0',
        createdAt: '2023-01-01T00:00:00.000Z',
        updatedAt: '2023-01-01T00:00:00.000Z'
      });

      // Simulate graph update
      const updatedGraph = {
        ...graph,
        version: '1.0.1',
        updatedAt: new Date().toISOString(),
        states: [...graph.states, this.dataGenerator.generateTestState()]
      };

      // Verify version progression
      if (updatedGraph.version === graph.version) {
        throw new Error('Version should change after update');
      }

      if (updatedGraph.updatedAt === graph.updatedAt) {
        throw new Error('Updated timestamp should change after update');
      }

      if (updatedGraph.states.length <= graph.states.length) {
        throw new Error('State count should increase after adding state');
      }

      return {
        oldVersion: graph.version,
        newVersion: updatedGraph.version,
        oldStateCount: graph.states.length,
        newStateCount: updatedGraph.states.length
      };
    });

    await this.runTest('Version compatibility', async () => {
      const versions = ['1.0.0', '1.0.1', '1.1.0', '2.0.0'];
      const results = [];

      for (const version of versions) {
        const graph = this.dataGenerator.generateTestGraph(3, 5, { version });

        const validation = this.schemaValidator.validateGraph(graph);
        if (!validation.isValid) {
          throw new Error(`Version ${version} compatibility failed: ${validation.errors.join(', ')}`);
        }

        results.push({ version, compatible: true });
      }

      return { compatibleVersions: results };
    });

    await this.runTest('Migration scenario', async () => {
      // Simulate old version format
      const oldFormatGraph = {
        version: '0.9.0',
        created: '2023-01-01T00:00:00.000Z', // Old field name
        packageName: 'com.example.app',
        states: [
          {
            id: generateStateId('com.example.app', '.MainActivity', 'test_digest'),
            package: 'com.example.app',
            activity: '.MainActivity',
            selectors: [],
            visibleText: []
          }
        ],
        transitions: []
        // Missing stats and metadata fields
      };

      // Migration function
      const migrateGraph = (oldGraph: any): UIGraph => {
        const now = new Date().toISOString();
        return {
          version: '1.0.0',
          createdAt: oldGraph.created || now,
          updatedAt: now,
          packageName: oldGraph.packageName,
          states: oldGraph.states || [],
          transitions: oldGraph.transitions || [],
          stats: {
            stateCount: oldGraph.states?.length || 0,
            transitionCount: oldGraph.transitions?.length || 0,
            averageDegree: 0,
            isolatedStates: 0
          },
          metadata: {
            captureTool: 'AutoApp Discovery',
            totalCaptureTime: 0,
            totalSessions: 1
          }
        };
      };

      const migratedGraph = migrateGraph(oldFormatGraph);
      const validation = this.schemaValidator.validateGraph(migratedGraph);

      if (!validation.isValid) {
        throw new Error(`Migration failed: ${validation.errors.join(', ')}`);
      }

      return {
        originalVersion: oldFormatGraph.version,
        migratedVersion: migratedGraph.version,
        migrationSuccessful: validation.isValid
      };
    });
  }

  /**
   * Run performance benchmark tests
   */
  private async runPerformanceTests(): Promise<void> {
    if (!this.testConfig.performanceEnabled) {
      console.log('\n⚡ Skipping performance tests (disabled)');
      return;
    }

    console.log('\n⚡ Running performance tests...');

    await this.runTest('Small graph performance (< 2s)', async () => {
      const monitor = new PerformanceMonitor();
      monitor.start();

      const graph = this.dataGenerator.generateTestGraph(50, 100);
      const serialized = JSON.stringify(graph, null, 2);
      const deserialized = JSON.parse(serialized);

      const metrics = monitor.getMetrics();

      if (metrics.duration > 2000) {
        throw new Error(`Small graph processing took ${metrics.duration}ms, expected < 2000ms`);
      }

      return {
        stateCount: graph.states.length,
        transitionCount: graph.transitions.length,
        processingTime: metrics.duration,
        serializedSize: serialized.length,
        memoryDelta: metrics.memoryDelta
      };
    });

    await this.runTest('Large graph performance', async () => {
      const monitor = new PerformanceMonitor();
      monitor.start();

      const graph = this.dataGenerator.generateTestGraph(500, 1000);
      const serialized = JSON.stringify(graph);
      const deserialized = JSON.parse(serialized);

      const metrics = monitor.getMetrics();

      // Validate large graph processing completes
      if (deserialized.states.length !== 500) {
        throw new Error('Large graph state count mismatch');
      }

      return {
        stateCount: graph.states.length,
        transitionCount: graph.transitions.length,
        processingTime: metrics.duration,
        serializedSize: serialized.length,
        memoryDelta: metrics.memoryDelta,
        performanceRatio: metrics.duration / 500 // ms per state
      };
    });

    await this.runTest('Serialization size benchmarks', async () => {
      const sizes = [10, 50, 100, 200];
      const results = [];

      for (const size of sizes) {
        const graph = this.dataGenerator.generateTestGraph(size, size * 2);
        const compactJson = JSON.stringify(graph);
        const prettyJson = JSON.stringify(graph, null, 2);

        results.push({
          stateCount: size,
          compactSize: compactJson.length,
          prettySize: prettyJson.length,
          bytesPerState: compactJson.length / size
        });
      }

      // Verify size scales reasonably
      const firstSize = results[0];
      const lastSize = results[results.length - 1];
      const sizeRatio = lastSize.compactSize / firstSize.compactSize;
      const expectedRatio = lastSize.stateCount / firstSize.stateCount;

      if (sizeRatio > expectedRatio * 2) {
        throw new Error('Size scaling is inefficient');
      }

      return { sizeBenchmarks: results };
    });
  }

  /**
   * Run error handling tests
   */
  private async runErrorHandlingTests(): Promise<void> {
    console.log('\n🚨 Running error handling tests...');

    await this.runTest('Invalid JSON handling', async () => {
      const corruptedData = this.dataGenerator.generateCorruptedGraphData();
      const results = [];

      for (let i = 0; i < corruptedData.length; i++) {
        try {
          JSON.parse(corruptedData[i]);
          results.push({ index: i, shouldHaveFailed: true, actualResult: 'success' });
        } catch (error) {
          results.push({ index: i, shouldHaveFailed: true, actualResult: 'error', error: (error as Error).message });
        }
      }

      // All corrupted data should fail to parse
      const parseFailures = results.filter(r => r.actualResult === 'error');
      if (parseFailures.length !== corruptedData.length) {
        throw new Error('Some corrupted data was incorrectly parsed as valid');
      }

      return { corruptedDataTests: results };
    });

    await this.runTest('Missing required fields', async () => {
      const incompleteGraphs = [
        { version: '1.0.0' }, // Missing most fields
        { version: '1.0.0', packageName: 'test.app', states: [] }, // Missing transitions
        { version: '1.0.0', packageName: 'test.app', transitions: [] }, // Missing states
        { version: '1.0.0', packageName: 'test.app', states: [], transitions: [], stats: {} } // Missing metadata
      ];

      const validationResults = [];
      for (const incompleteGraph of incompleteGraphs) {
        const validation = this.schemaValidator.validateGraph(incompleteGraph);
        validationResults.push({
          hasErrors: !validation.isValid,
          errorCount: validation.errors.length,
          errors: validation.errors
        });
      }

      // All incomplete graphs should have validation errors
      const allHaveErrors = validationResults.every(r => r.hasErrors);
      if (!allHaveErrors) {
        throw new Error('Some incomplete graphs passed validation incorrectly');
      }

      return { validationResults };
    });

    await this.runTest('Invalid state IDs', async () => {
      const graphWithInvalidIds = this.dataGenerator.generateTestGraph(0, 0, {
        states: [
          {
            id: 'invalid_short_hash',
            package: 'com.test.app',
            activity: '.MainActivity',
            digest: 'test_digest',
            selectors: [],
            visibleText: [],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
          }
        ]
      });

      const validation = this.schemaValidator.validateGraph(graphWithInvalidIds);
      if (validation.isValid) {
        throw new Error('Graph with invalid state IDs should fail validation');
      }

      if (!validation.errors.some(e => e.includes('Invalid state ID'))) {
        throw new Error('Validation should detect invalid state ID format');
      }

      return {
        validationFailed: !validation.isValid,
        errorCount: validation.errors.length,
        errors: validation.errors
      };
    });

    await this.runTest('Broken transition references', async () => {
      const graphWithBrokenRefs = this.dataGenerator.generateTestGraph(1, 0, {
        transitions: [
          {
            id: generateTransitionId('nonexistent1', 'nonexistent2', '{}'),
            from: 'nonexistent1',
            to: 'nonexistent2',
            action: { type: 'tap' },
            createdAt: new Date().toISOString()
          }
        ]
      });

      const validation = this.schemaValidator.validateGraph(graphWithBrokenRefs);
      if (validation.isValid) {
        throw new Error('Graph with broken references should fail validation');
      }

      const refErrors = validation.errors.filter(e => e.includes('non-existent'));
      if (refErrors.length === 0) {
        throw new Error('Validation should detect broken state references');
      }

      return {
        validationFailed: !validation.isValid,
        referenceErrors: refErrors.length,
        allErrors: validation.errors
      };
    });
  }

  /**
   * Run edge case tests
   */
  private async runEdgeCaseTests(): Promise<void> {
    console.log('\n🔍 Running edge case tests...');

    await this.runTest('Empty graph handling', async () => {
      const emptyGraph = this.dataGenerator.generateTestGraph(0, 0);

      const validation = this.schemaValidator.validateGraph(emptyGraph);
      if (!validation.isValid) {
        throw new Error(`Empty graph validation failed: ${validation.errors.join(', ')}`);
      }

      // Test serialization
      const serialized = JSON.stringify(emptyGraph);
      const deserialized = JSON.parse(serialized);

      if (deserialized.states.length !== 0 || deserialized.transitions.length !== 0) {
        throw new Error('Empty graph should remain empty after serialization');
      }

      return {
        stateCount: emptyGraph.states.length,
        transitionCount: emptyGraph.transitions.length,
        serializedSize: serialized.length
      };
    });

    await this.runTest('Single state graph', async () => {
      const singleStateGraph = this.dataGenerator.generateTestGraph(1, 0);

      if (singleStateGraph.states.length !== 1) {
        throw new Error('Expected exactly 1 state');
      }

      if (singleStateGraph.stats.isolatedStates !== 1) {
        throw new Error('Single state should be counted as isolated');
      }

      if (singleStateGraph.stats.averageDegree !== 0) {
        throw new Error('Single state graph should have average degree 0');
      }

      return {
        stateCount: 1,
        isolatedStates: singleStateGraph.stats.isolatedStates,
        averageDegree: singleStateGraph.stats.averageDegree
      };
    });

    await this.runTest('Graph with no transitions', async () => {
      const stateCount = 10;
      const graphWithoutTransitions = this.dataGenerator.generateTestGraph(stateCount, 0);

      if (graphWithoutTransitions.transitions.length !== 0) {
        throw new Error('Expected no transitions');
      }

      if (graphWithoutTransitions.stats.isolatedStates !== stateCount) {
        throw new Error('All states should be isolated without transitions');
      }

      return {
        stateCount,
        transitionCount: 0,
        isolatedStates: graphWithoutTransitions.stats.isolatedStates,
        averageDegree: graphWithoutTransitions.stats.averageDegree
      };
    });

    await this.runTest('Maximum field lengths', async () => {
      const longText = 'a'.repeat(1000);
      const manySelectors = Array(100).fill(null).map((_, i) => ({
        rid: `selector_${i}`,
        text: longText
      }));

      const graphWithLongFields = this.dataGenerator.generateTestGraph(1, 0, {
        states: [{
          ...this.dataGenerator.generateTestState(),
          selectors: manySelectors,
          visibleText: Array(50).fill(longText)
        }]
      });

      const validation = this.schemaValidator.validateGraph(graphWithLongFields);
      if (!validation.isValid) {
        throw new Error(`Graph with long fields failed validation: ${validation.errors.join(', ')}`);
      }

      // Test serialization can handle large data
      const serialized = JSON.stringify(graphWithLongFields);
      const deserialized = JSON.parse(serialized);

      if (deserialized.states[0].selectors.length !== manySelectors.length) {
        throw new Error('Long selector array not preserved');
      }

      return {
        selectorCount: manySelectors.length,
        textLength: longText.length,
        serializedSize: serialized.length
      };
    });

    await this.runTest('Special characters handling', async () => {
      const specialChars = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \n\t\r\u00A0\u2603';
      const unicodeChars = '🚀 🎉 ✨ 💻 📱 🎮 🌟 💡 🔥 💯';

      const graphWithSpecialChars = this.dataGenerator.generateTestGraph(2, 1, {
        states: [
          {
            ...this.dataGenerator.generateTestState(),
            visibleText: [specialChars, unicodeChars, 'Normal text'],
            selectors: [{
              text: specialChars,
              desc: unicodeChars
            }]
          }
        ],
        transitions: [{
          ...this.dataGenerator.generateTestTransition('state1', 'state2'),
          action: {
            type: 'type',
            text: specialChars
          }
        }]
      });

      const validation = this.schemaValidator.validateGraph(graphWithSpecialChars);
      if (!validation.isValid) {
        throw new Error(`Graph with special characters failed validation: ${validation.errors.join(', ')}`);
      }

      // Test JSON serialization preserves special characters
      const serialized = JSON.stringify(graphWithSpecialChars);
      const deserialized = JSON.parse(serialized);

      const preservedText = deserialized.states[0].visibleText.includes(specialChars);
      const preservedUnicode = deserialized.states[0].visibleText.includes(unicodeChars);

      if (!preservedText || !preservedUnicode) {
        throw new Error('Special characters not preserved in serialization');
      }

      return {
        specialCharsPreserved: preservedText,
        unicodePreserved: preservedUnicode,
        serializedSize: serialized.length
      };
    });
  }

  /**
   * Run concurrency tests
   */
  private async runConcurrencyTests(): Promise<void> {
    console.log('\n🔄 Running concurrency tests...');

    await this.runTest('Concurrent graph access', async () => {
      const sharedGraphPath = join(this.testConfig.tempDir, 'concurrent-test-graph.json');
      const graph = this.dataGenerator.generateTestGraph(5, 8);

      // Write initial graph
      await fs.writeFile(sharedGraphPath, JSON.stringify(graph, null, 2));

      // Simulate concurrent access
      const concurrentOperations = Array(5).fill(null).map(async (_, index) => {
        try {
          const currentContent = await fs.readFile(sharedGraphPath, 'utf-8');
          const currentGraph = JSON.parse(currentContent);

          // Add a new state
          const newState = this.dataGenerator.generateTestState({
            id: generateStateId('com.example.app', `.Activity${index}`, `digest_${index}`)
          });

          currentGraph.states.push(newState);
          currentGraph.updatedAt = new Date().toISOString();
          currentGraph.stats.stateCount = currentGraph.states.length;

          // Write back
          await fs.writeFile(sharedGraphPath, JSON.stringify(currentGraph, null, 2));

          return { success: true, index, stateAdded: newState.id };
        } catch (error) {
          return { success: false, index, error: (error as Error).message };
        }
      });

      const results = await Promise.all(concurrentOperations);
      const successfulOperations = results.filter(r => r.success);
      const failedOperations = results.filter(r => !r.success);

      // At least some operations should succeed
      if (successfulOperations.length === 0) {
        throw new Error('All concurrent operations failed');
      }

      // Verify final graph integrity
      const finalContent = await fs.readFile(sharedGraphPath, 'utf-8');
      const finalGraph = JSON.parse(finalContent);
      const validation = this.schemaValidator.validateGraph(finalGraph);

      if (!validation.isValid) {
        throw new Error(`Final graph validation failed: ${validation.errors.join(', ')}`);
      }

      return {
        totalOperations: results.length,
        successful: successfulOperations.length,
        failed: failedOperations.length,
        finalStateCount: finalGraph.states.length
      };
    });

    await this.runTest('Optimistic locking simulation', async () => {
      // This test simulates optimistic locking behavior
      const graphPath = join(this.testConfig.tempDir, 'optimistic-lock-test.json');
      const originalGraph = this.dataGenerator.generateTestGraph(3, 5);

      await fs.writeFile(graphPath, JSON.stringify(originalGraph, null, 2));

      // Simulate two concurrent updates
      const update1 = async () => {
        const content = await fs.readFile(graphPath, 'utf-8');
        const graph = JSON.parse(content);

        // Simulate processing delay
        await new Promise(resolve => setTimeout(resolve, 100));

        graph.states.push(this.dataGenerator.generateTestState());
        graph.updatedAt = new Date().toISOString();

        try {
          await fs.writeFile(graphPath, JSON.stringify(graph, null, 2));
          return { success: true, stateCount: graph.states.length };
        } catch (error) {
          return { success: false, error: (error as Error).message };
        }
      };

      const [result1, result2] = await Promise.all([update1(), update1()]);

      // At least one update should succeed
      if (!result1.success && !result2.success) {
        throw new Error('Both concurrent updates failed');
      }

      // Verify final graph is valid
      const finalContent = await fs.readFile(graphPath, 'utf-8');
      const finalGraph = JSON.parse(finalContent);
      const validation = this.schemaValidator.validateGraph(finalGraph);

      if (!validation.isValid) {
        throw new Error(`Final graph validation failed: ${validation.errors.join(', ')}`);
      }

      return {
        update1Result: result1,
        update2Result: result2,
        finalStateCount: finalGraph.states.length
      };
    });
  }

  /**
   * Run a single test with error handling and timing
   */
  private async runTest(testName: string, testFn: () => Promise<any>): Promise<void> {
    const startTime = Date.now();
    const startMemory = process.memoryUsage().heapUsed;

    try {
      const result = await testFn();
      const duration = Date.now() - startTime;
      const endMemory = process.memoryUsage().heapUsed;

      this.testResults.push({
        testName,
        passed: true,
        duration,
        details: result,
        performance: {
          memoryUsage: endMemory,
          cpuTime: duration,
          fileSize: JSON.stringify(result).length
        }
      });

      if (this.testConfig.verboseLogging) {
        console.log(`  ✅ ${testName} (${duration}ms)`);
      }

    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      this.testResults.push({
        testName,
        passed: false,
        duration,
        error: errorMessage
      });

      console.log(`  ❌ ${testName} (${duration}ms): ${errorMessage}`);
    }
  }

  /**
   * Calculate test suite summary
   */
  private calculateTestSummary(totalDuration: number): {
    totalTests: number;
    passedTests: number;
    failedTests: number;
    successRate: number;
    totalDuration: number;
  } {
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(r => r.passed).length;
    const failedTests = totalTests - passedTests;
    const successRate = totalTests > 0 ? Math.round((passedTests / totalTests) * 100) : 0;

    return {
      totalTests,
      passedTests,
      failedTests,
      successRate,
      totalDuration
    };
  }

  /**
   * Cleanup test environment
   */
  private async cleanupTestEnvironment(): Promise<void> {
    console.log('\nCleaning up test environment...');

    try {
      // Remove temp directory
      await fs.rm(this.testConfig.tempDir, { recursive: true, force: true });

      // Remove test data directory (optional, keep for debugging)
      // await fs.rm(this.testConfig.testDataDir, { recursive: true, force: true });

      console.log('Test environment cleanup complete.');
    } catch (error) {
      console.warn('Warning: Failed to cleanup test environment:', error);
    }
  }
}

// ============================================================================
// TEST EXECUTION
// ============================================================================

/**
 * Main test execution function
 */
async function runGraphSerializationTests(): Promise<{
  summary: any;
  results: TestResult[];
}> {
  console.log('Starting Graph JSON Serialization Integration Tests...');

  const testSuite = new GraphSerializationTestSuite();

  try {
    const results = await testSuite.runCompleteTestSuite();
    return results;
  } catch (error) {
    console.error('Test execution failed:', error);
    throw error;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  // Main test suite
  GraphSerializationTestSuite,
  runGraphSerializationTests,

  // Test utilities
  GraphTestDataGenerator,
  PerformanceMonitor,
  GraphSchemaValidator,

  // Types
  TestConfig,
  TestResult
};

// ============================================================================
// SELF-EXECUTION
// ============================================================================

// Run tests if this file is executed directly
if (require.main === module) {
  runGraphSerializationTests()
    .then(({ summary, results }) => {
      process.exit(summary.failedTests > 0 ? 1 : 0);
    })
    .catch((error) => {
      console.error('Test execution failed:', error);
      process.exit(1);
    });
}