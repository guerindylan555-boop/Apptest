/**
 * Simple test for the State Deduplication Service
 */

import { State } from '../models/state';
import { StateDeduplicationService } from './state-dedup-simplified';
import { CreateStateRequest, CaptureMethod } from '../types/models';

async function testDeduplicationService() {
  console.log('Testing State Deduplication Service');
  console.log('===================================');

  try {
    // Initialize the service
    const service = new StateDeduplicationService({
      similarityThreshold: 0.9,
      logLevel: 'info'
    });

    console.log('✅ Service initialized successfully');

    // Create test states
    const state1 = new State({
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
    });

    // Create exact duplicate
    const state2 = State.fromExisting(state1.toObject());

    // Create similar state
    const state3 = new State({
      package: 'com.example.app',
      activity: 'com.example.MainActivity',
      selectors: [
        { rid: 'btn_signin', text: 'Sign In', cls: 'android.widget.Button' }, // Slightly different
        { rid: 'input_username', cls: 'android.widget.EditText' },
        { rid: 'input_password', cls: 'android.widget.EditText' },
        { rid: 'checkbox_remember', text: 'Remember me', cls: 'android.widget.CheckBox' }
      ],
      visibleText: ['Sign In', 'Username', 'Password', 'Remember me'],
      metadata: {
        captureMethod: 'adb',
        captureDuration: 160,
        elementCount: 15,
        hierarchyDepth: 4
      }
    });

    // Create different state
    const state4 = new State({
      package: 'com.example.app',
      activity: 'com.example.DashboardActivity',
      selectors: [
        { rid: 'btn_profile', text: 'Profile', cls: 'android.widget.Button' }
      ],
      visibleText: ['Dashboard', 'Profile'],
      metadata: {
        captureMethod: 'adb',
        captureDuration: 120,
        elementCount: 8,
        hierarchyDepth: 3
      }
    });

    console.log('✅ Test states created');

    // Test 1: Exact duplicate detection
    console.log('\n--- Test 1: Exact Duplicate Detection ---');
    const result1 = await service.deduplicateState(state1, [state2]);
    console.log(`Is duplicate: ${result1.isDuplicate}`);
    console.log(`Similarity: ${result1.similarity}`);
    console.log(`Expected: true, 1.0`);
    console.log(`Result: ${result1.isDuplicate === true && result1.similarity === 1.0 ? '✅ PASS' : '❌ FAIL'}`);

    // Test 2: Similar state detection
    console.log('\n--- Test 2: Similar State Detection ---');
    const result2 = await service.deduplicateState(state1, [state3]);
    console.log(`Is duplicate: ${result2.isDuplicate}`);
    console.log(`Similarity: ${result2.similarity?.toFixed(3)}`);
    console.log(`Expected: true, > 0.9`);
    console.log(`Result: ${result2.isDuplicate === true && (result2.similarity || 0) > 0.9 ? '✅ PASS' : '❌ FAIL'}`);

    // Test 3: Different state detection
    console.log('\n--- Test 3: Different State Detection ---');
    const result3 = await service.deduplicateState(state1, [state4]);
    console.log(`Is duplicate: ${result3.isDuplicate}`);
    console.log(`Similarity: ${result3.similarity?.toFixed(3)}`);
    console.log(`Expected: false, 0`);
    console.log(`Result: ${result3.isDuplicate === false && result3.similarity === 0 ? '✅ PASS' : '❌ FAIL'}`);

    // Test 4: State comparison
    console.log('\n--- Test 4: State Comparison ---');
    const comparison = await service.compareStates(state1, state3);
    console.log(`Similarity: ${comparison.similarity.toFixed(3)}`);
    console.log(`Should merge: ${comparison.shouldMerge}`);
    console.log(`Common selectors: ${comparison.details.commonSelectors.length}`);
    console.log(`Result: ${comparison.similarity > 0.8 ? '✅ PASS' : '❌ FAIL'}`);

    // Test 5: State merging
    console.log('\n--- Test 5: State Merging ---');
    const mergedState = await service.mergeStates([state1, state3], 'comprehensive');
    console.log(`Original selectors: ${state1.selectors.length + state3.selectors.length}`);
    console.log(`Merged selectors: ${mergedState.selectors.length}`);
    console.log(`Result: ${mergedState.selectors.length >= Math.max(state1.selectors.length, state3.selectors.length) ? '✅ PASS' : '❌ FAIL'}`);

    // Test 6: Batch processing
    console.log('\n--- Test 6: Batch Processing ---');
    const batchResult = await service.deduplicateBatch([state1, state2, state3, state4]);
    console.log(`Total states: ${batchResult.totalStates}`);
    console.log(`Unique states: ${batchResult.uniqueStates}`);
    console.log(`Duplicates found: ${batchResult.duplicatesFound}`);
    console.log(`Processing time: ${batchResult.processingTime}ms`);
    console.log(`Result: ${batchResult.uniqueStates < batchResult.totalStates ? '✅ PASS' : '❌ FAIL'}`);

    // Test 7: Finding duplicates
    console.log('\n--- Test 7: Finding Duplicates ---');
    const duplicates = await service.findDuplicates([state1, state2, state3]);
    console.log(`Duplicate groups found: ${duplicates.length}`);
    console.log(`Total duplicates: ${duplicates.reduce((sum, group) => sum + group.length, 0)}`);
    console.log(`Result: ${duplicates.length > 0 ? '✅ PASS' : '❌ FAIL'}`);

    console.log('\n🎉 All tests completed!');

    // Performance summary
    console.log('\n--- Performance Summary ---');
    const metrics = service.getPerformanceMetrics();
    if (metrics.length > 0) {
      metrics.forEach(metric => {
        console.log(`${metric.operation}: ${metric.duration}ms`);
      });
    }

  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Run the test
testDeduplicationService();