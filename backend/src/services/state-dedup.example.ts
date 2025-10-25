/**
 * AutoApp UI Map & Intelligent Flow Engine - State Deduplication Service Usage Examples
 *
 * This file demonstrates practical usage of the StateDeduplicationService for various
 * scenarios including real-time deduplication, batch processing, and performance monitoring.
 */

import { State } from '../models/state';
import { StateDeduplicationService } from './state-dedup';
import { CreateStateRequest, CaptureMethod } from '../types/models';

// ============================================================================
// Example 1: Basic Single State Deduplication
// ============================================================================

/**
 * Example 1: Basic single state deduplication
 * Demonstrates how to check if a newly captured state is a duplicate
 */
export async function example1_basicDeduplication() {
  console.log('\n=== Example 1: Basic Single State Deduplication ===');

  // Initialize the deduplication service
  const dedupService = new StateDeduplicationService({
    similarityThreshold: 0.9, // 90% similarity threshold
    selectorWeight: 0.7,
    textWeight: 0.3,
    enableActivityGrouping: true,
    logLevel: 'info'
  });

  // Create some existing states (simulating a database of captured states)
  const existingStates = createSampleStates();

  // Create a new state to check for duplicates
  const newState = new State({
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
      }
    ],
    visibleText: ['Login', 'Username', 'Password'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 150,
      elementCount: 12,
      hierarchyDepth: 4
    }
  });

  // Check if the new state is a duplicate
  const result = await dedupService.deduplicateState(newState, existingStates);

  console.log('Deduplication Result:');
  console.log(`- Is Duplicate: ${result.isDuplicate}`);
  console.log(`- Similarity: ${result.similarity?.toFixed(3) || 'N/A'}`);
  console.log(`- Matched State ID: ${result.matchedState?.id || 'None'}`);
  console.log(`- Merge Candidate Available: ${!!result.mergeCandidate}`);

  if (result.isDuplicate && result.mergeCandidate) {
    console.log('\nMerged State Details:');
    console.log(`- Selector Count: ${result.mergeCandidate.selectors.length}`);
    console.log(`- Visible Text Count: ${result.mergeCandidate.visibleText?.length || 0}`);
    console.log(`- Tags: ${result.mergeCandidate.tags?.join(', ') || 'None'}`);
  }
}

// ============================================================================
// Example 2: Batch State Processing
// ============================================================================

/**
 * Example 2: Batch deduplication of multiple states
 * Demonstrates how to process a large collection of states efficiently
 */
export async function example2_batchDeduplication() {
  console.log('\n=== Example 2: Batch State Deduplication ===');

  // Initialize service with batch-optimized settings
  const dedupService = new StateDeduplicationService({
    similarityThreshold: 0.95,
    batchSize: 50,
    enablePerformanceMonitoring: true,
    logLevel: 'warn' // Reduce log noise for batch processing
  });

  // Create a large collection of states (simulating bulk import)
  const largeStateCollection = createLargeStateCollection(200);

  console.log(`Processing ${largeStateCollection.length} states...`);

  // Perform batch deduplication
  const batchResult = await dedupService.deduplicateBatch(largeStateCollection);

  console.log('\nBatch Deduplication Results:');
  console.log(`- Total States Processed: ${batchResult.totalStates}`);
  console.log(`- Unique States Remaining: ${batchResult.uniqueStates}`);
  console.log(`- Duplicates Found: ${batchResult.duplicatesFound}`);
  console.log(`- States Merged: ${batchResult.statesMerged}`);
  console.log(`- Processing Time: ${batchResult.processingTime}ms`);
  console.log(`- Throughput: ${(batchResult.totalStates / batchResult.processingTime * 1000).toFixed(2)} states/sec`);

  console.log('\nSimilarity Distribution:');
  console.log(`- Exact Matches: ${batchResult.similarityDistribution.exact}`);
  console.log(`- High Similarity (90-100%): ${batchResult.similarityDistribution.high}`);
  console.log(`- Medium Similarity (70-90%): ${batchResult.similarityDistribution.medium}`);
  console.log(`- Low Similarity (50-70%): ${batchResult.similarityDistribution.low}`);
  console.log(`- No Similarity (<50%): ${batchResult.similarityDistribution.none}`);

  if (batchResult.errors.length > 0) {
    console.log(`\nErrors Encountered: ${batchResult.errors.length}`);
    batchResult.errors.slice(0, 3).forEach(error => {
      console.log(`- ${error.stateId}: ${error.error}`);
    });
  }

  // Get performance metrics
  const metrics = dedupService.getPerformanceMetrics();
  const batchMetrics = metrics.find(m => m.operation === 'deduplicateBatch');
  if (batchMetrics) {
    console.log('\nPerformance Metrics:');
    console.log(`- Memory Usage: ${(batchMetrics.memoryUsage / 1024 / 1024).toFixed(2)} MB`);
    console.log(`- Cache Hit Rate: ${(batchMetrics.cacheHitRate * 100).toFixed(1)}%`);
  }
}

// ============================================================================
// Example 3: Advanced State Comparison
// ============================================================================

/**
 * Example 3: Detailed state comparison and analysis
 * Demonstrates how to analyze differences between states
 */
export async function example3_stateComparison() {
  console.log('\n=== Example 3: Advanced State Comparison ===');

  const dedupService = new StateDeduplicationService({
    similarityThreshold: 0.8,
    logLevel: 'info'
  });

  // Create two similar but different states
  const state1 = new State({
    package: 'com.example.app',
    activity: 'com.example.LoginActivity',
    selectors: [
      { rid: 'btn_login', text: 'Login', cls: 'android.widget.Button' },
      { rid: 'input_username', cls: 'android.widget.EditText' },
      { rid: 'input_password', cls: 'android.widget.EditText' },
      { rid: 'checkbox_remember', text: 'Remember me', cls: 'android.widget.CheckBox' }
    ],
    visibleText: ['Login', 'Username', 'Password', 'Remember me', 'Forgot Password?'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 200,
      elementCount: 18,
      hierarchyDepth: 5
    }
  });

  const state2 = new State({
    package: 'com.example.app',
    activity: 'com.example.LoginActivity',
    selectors: [
      { rid: 'btn_signin', text: 'Sign In', cls: 'android.widget.Button' }, // Different text/ID
      { rid: 'input_email', cls: 'android.widget.EditText' }, // Different ID
      { rid: 'input_password', cls: 'android.widget.EditText' },
      { rid: 'link_forgot', text: 'Forgot Password?', cls: 'android.widget.TextView' }
    ],
    visibleText: ['Sign In', 'Email', 'Password', 'Forgot Password?', 'Create Account'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 180,
      elementCount: 16,
      hierarchyDepth: 4
    }
  });

  // Perform detailed comparison
  const comparison = await dedupService.compareStates(state1, state2);

  console.log('State Comparison Results:');
  console.log(`- Overall Similarity: ${(comparison.similarity * 100).toFixed(1)}%`);
  console.log(`- Selector Similarity: ${(comparison.selectorSimilarity * 100).toFixed(1)}%`);
  console.log(`- Text Similarity: ${(comparison.textSimilarity * 100).toFixed(1)}%`);
  console.log(`- Should Merge: ${comparison.shouldMerge}`);
  console.log(`- Confidence: ${(comparison.confidence * 100).toFixed(1)}%`);

  console.log('\nCommon Elements:');
  console.log(`- Common Selectors: ${comparison.details.commonSelectors.length}`);
  console.log(`- Common Text: ${comparison.details.commonText.join(', ')}`);

  console.log('\nUnique Elements:');
  console.log(`- State 1 Unique Selectors: ${comparison.details.uniqueSelectors1.length}`);
  console.log(`- State 2 Unique Selectors: ${comparison.details.uniqueSelectors2.length}`);
  console.log(`- State 1 Unique Text: ${comparison.details.uniqueText1.join(', ') || 'None'}`);
  console.log(`- State 2 Unique Text: ${comparison.details.uniqueText2.join(', ') || 'None'}`);
}

// ============================================================================
// Example 4: State Merging Strategies
// ============================================================================

/**
 * Example 4: Different state merging strategies
 * Demonstrates how to use different merge approaches
 */
export async function example4_mergeStrategies() {
  console.log('\n=== Example 4: State Merging Strategies ===');

  const dedupService = new StateDeduplicationService({
    logLevel: 'info'
  });

  // Create states that could be merged
  const baseState = new State({
    package: 'com.example.app',
    activity: 'com.example.MainActivity',
    selectors: [
      { rid: 'btn_action', text: 'Action', cls: 'android.widget.Button' },
      { rid: 'input_data', cls: 'android.widget.EditText' }
    ],
    visibleText: ['Action', 'Enter Data'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 150,
      elementCount: 10,
      hierarchyDepth: 3
    }
  });

  const additionalState = new State({
    package: 'com.example.app',
    activity: 'com.example.MainActivity',
    selectors: [
      { rid: 'btn_submit', text: 'Submit', cls: 'android.widget.Button' },
      { rid: 'btn_cancel', text: 'Cancel', cls: 'android.widget.Button' },
      { rid: 'checkbox_terms', text: 'I agree to terms', cls: 'android.widget.CheckBox' }
    ],
    visibleText: ['Submit', 'Cancel', 'Terms and Conditions'],
    tags: ['form', 'validation'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 200,
      elementCount: 15,
      hierarchyDepth: 4
    }
  });

  const statesToMerge = [baseState, additionalState];

  // Test different merge strategies
  const strategies = ['comprehensive', 'latest', 'most_selectors', 'most_interactive'] as const;

  for (const strategy of strategies) {
    console.log(`\n--- ${strategy.toUpperCase()} Strategy ---`);

    try {
      const mergedState = await dedupService.mergeStates(statesToMerge, strategy);

      console.log(`Merge Result (${strategy}):`);
      console.log(`- Final Selector Count: ${mergedState.selectors.length}`);
      console.log(`- Final Text Count: ${mergedState.visibleText?.length || 0}`);
      console.log(`- Final Tags: ${mergedState.tags?.join(', ') || 'None'}`);
      console.log(`- Element Count: ${mergedState.metadata.elementCount}`);
      console.log(`- Hierarchy Depth: ${mergedState.metadata.hierarchyDepth}`);

      // Show some sample selectors
      console.log('- Sample Selectors:');
      mergedState.selectors.slice(0, 3).forEach((selector, idx) => {
        console.log(`  ${idx + 1}. ${selector.rid || 'N/A'} - ${selector.text || 'N/A'} (${selector.cls})`);
      });

    } catch (error) {
      console.log(`Merge failed with ${strategy} strategy: ${error}`);
    }
  }
}

// ============================================================================
// Example 5: Finding Duplicates in Large Dataset
// ============================================================================

/**
 * Example 5: Finding duplicate groups in a large dataset
 * Demonstrates how to identify clusters of similar states
 */
export async function example5_findDuplicates() {
  console.log('\n=== Example 5: Finding Duplicates in Large Dataset ===');

  const dedupService = new StateDeduplicationService({
    similarityThreshold: 0.9,
    enableActivityGrouping: true,
    logLevel: 'warn'
  });

  // Create a dataset with intentional duplicates
  const dataset = createDatasetWithDuplicates(100);

  console.log(`Analyzing ${dataset.length} states for duplicates...`);

  // Find all duplicate groups
  const duplicateGroups = await dedupService.findDuplicates(dataset);

  console.log(`\nFound ${duplicateGroups.length} duplicate groups:`);

  let totalDuplicates = 0;
  duplicateGroups.forEach((group, index) => {
    totalDuplicates += group.length;
    console.log(`\nGroup ${index + 1}: ${group.length} states`);

    // Show details for the first few groups
    if (index < 3) {
      const firstState = group[0];
      console.log(`  Package: ${firstState.package}`);
      console.log(`  Activity: ${firstState.activity}`);
      console.log(`  Selector Count: ${firstState.selectors.length}`);
      console.log(`  State IDs: ${group.map(s => s.id.substring(0, 8)).join(', ')}`);
    }
  });

  console.log(`\nTotal states in duplicate groups: ${totalDuplicates}`);
  console.log(`Unique states that could be created: ${duplicateGroups.length}`);

  // Calculate potential storage savings
  const originalSize = dataset.length;
  const deduplicatedSize = originalSize - (totalDuplicates - duplicateGroups.length);
  const savingsPercent = ((originalSize - deduplicatedSize) / originalSize * 100).toFixed(1);

  console.log(`Storage optimization potential: ${savingsPercent}% reduction`);
}

// ============================================================================
// Helper Functions for Creating Sample Data
// ============================================================================

/**
 * Creates a set of sample states for testing
 */
function createSampleStates(): State[] {
  const states: State[] = [];

  // Login page state
  states.push(new State({
    package: 'com.example.app',
    activity: 'com.example.MainActivity',
    selectors: [
      { rid: 'btn_login', text: 'Login', cls: 'android.widget.Button' },
      { rid: 'input_username', cls: 'android.widget.EditText' },
      { rid: 'input_password', cls: 'android.widget.EditText' }
    ],
    visibleText: ['Login', 'Username', 'Password'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 150,
      elementCount: 12,
      hierarchyDepth: 4
    }
  }));

  // Dashboard state
  states.push(new State({
    package: 'com.example.app',
    activity: 'com.example.DashboardActivity',
    selectors: [
      { rid: 'btn_profile', text: 'Profile', cls: 'android.widget.Button' },
      { rid: 'btn_settings', text: 'Settings', cls: 'android.widget.Button' },
      { rid: 'text_welcome', text: 'Welcome, User!', cls: 'android.widget.TextView' }
    ],
    visibleText: ['Welcome, User!', 'Profile', 'Settings', 'Logout'],
    metadata: {
      captureMethod: 'adb',
      captureDuration: 200,
      elementCount: 20,
      hierarchyDepth: 6
    }
  }));

  return states;
}

/**
 * Creates a large collection of states for batch processing
 */
function createLargeStateCollection(count: number): State[] {
  const states: State[] = [];
  const packages = ['com.example.app', 'com.test.app', 'com.demo.app'];
  const activities = ['MainActivity', 'DashboardActivity', 'SettingsActivity'];

  for (let i = 0; i < count; i++) {
    const packageIdx = i % packages.length;
    const activityIdx = i % activities.length;

    // Create some intentional duplicates
    const shouldDuplicate = i % 10 === 0 && i > 0;
    const baseIndex = shouldDuplicate ? i - 10 : i;

    states.push(new State({
      package: packages[packageIdx],
      activity: `${packages[packageIdx]}.${activities[activityIdx]}`,
      selectors: [
        { rid: `btn_action_${baseIndex % 5}`, text: `Button ${baseIndex % 3}`, cls: 'android.widget.Button' },
        { rid: `input_data_${baseIndex % 3}`, cls: 'android.widget.EditText' }
      ],
      visibleText: [`Button ${baseIndex % 3}`, 'Input Field', 'Label'],
      metadata: {
        captureMethod: 'adb',
        captureDuration: 150 + (i % 100),
        elementCount: 10 + (i % 20),
        hierarchyDepth: 3 + (i % 4)
      }
    }));
  }

  return states;
}

/**
 * Creates a dataset with intentional duplicates for testing
 */
function createDatasetWithDuplicates(count: number): State[] {
  const states: State[] = [];
  const baseStates = createSampleStates();

  // Add base states multiple times to create duplicates
  for (let i = 0; i < count; i++) {
    const baseState = baseStates[i % baseStates.length];

    // Create slight variations for some duplicates
    if (i % 15 === 0) {
      // Create a slightly different version
      const variedState = State.fromExisting(baseState.toObject());
      variedState.selectors.push({
        rid: `additional_element_${i}`,
        text: 'Additional Element',
        cls: 'android.widget.TextView'
      });
      states.push(variedState);
    } else {
      // Exact duplicate
      states.push(State.fromExisting(baseState.toObject()));
    }
  }

  return states;
}

// ============================================================================
// Main Runner Function
// ============================================================================

/**
 * Runs all examples sequentially
 */
export async function runAllExamples() {
  console.log('State Deduplication Service - Usage Examples');
  console.log('==============================================');

  try {
    await example1_basicDeduplication();
    await example2_batchDeduplication();
    await example3_stateComparison();
    await example4_mergeStrategies();
    await example5_findDuplicates();

    console.log('\n✅ All examples completed successfully!');
  } catch (error) {
    console.error('\n❌ Error running examples:', error);
  }
}

// Run examples if this file is executed directly
if (require.main === module) {
  runAllExamples();
}