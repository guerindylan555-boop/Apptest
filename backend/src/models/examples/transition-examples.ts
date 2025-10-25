/**
 * Transition Model Usage Examples
 *
 * Comprehensive examples demonstrating how to use the Transition entity
 * for various scenarios in the AutoApp UI Map & Intelligent Flow Engine.
 */

import { Transition } from '../transition';
import {
  ActionType,
  SwipeDirection,
  CreateTransitionRequest,
  TransitionEvidence
} from '../../types/models';

// ============================================================================
// Basic Transition Creation Examples
// ============================================================================

/**
 * Example 1: Create a simple tap transition
 */
export function createSimpleTapTransition(): Transition {
  const request: CreateTransitionRequest = {
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

  return new Transition(request);
}

/**
 * Example 2: Create a text input transition
 */
export function createTextInputTransition(): Transition {
  const request: CreateTransitionRequest = {
    from: 'state-search-screen',
    to: 'state-results-screen',
    action: {
      type: 'type',
      target: {
        rid: 'com.example.app:id/search_input',
        desc: 'Search input field'
      },
      text: 'search query here'
    },
    confidence: 0.85,
    tags: ['search', 'input']
  };

  return new Transition(request);
}

/**
 * Example 3: Create a swipe transition
 */
export function createSwipeTransition(): Transition {
  const request: CreateTransitionRequest = {
    from: 'state-feed-screen',
    to: 'state-feed-screen-scrolled',
    action: {
      type: 'swipe',
      swipe: {
        direction: 'up',
        distance: 0.7
      }
    },
    confidence: 0.8,
    tags: ['navigation', 'scroll']
  };

  return new Transition(request);
}

/**
 * Example 4: Create a back navigation transition
 */
export function createBackTransition(): Transition {
  const request: CreateTransitionRequest = {
    from: 'state-details-screen',
    to: 'state-list-screen',
    action: {
      type: 'back'
    },
    confidence: 0.95,
    tags: ['navigation', 'back']
  };

  return new Transition(request);
}

// ============================================================================
// Advanced Transition Creation Examples
// ============================================================================

/**
 * Example 5: Create transition with comprehensive evidence
 */
export function createTransitionWithEvidence(): Transition {
  const evidence: TransitionEvidence = {
    beforeDigest: 'sha256:abc123...',
    afterDigest: 'sha256:def456...',
    timestamp: '2024-01-15T10:30:45.123Z',
    duration: 2500,
    screenshots: {
      before: 'screenshots/before_state.png',
      after: 'screenshots/after_state.png'
    },
    metrics: {
      responseTime: 150,
      renderTime: 200,
      animationTime: 300,
      networkRequests: 2
    },
    notes: 'User tapped login button, successful authentication'
  };

  const request: CreateTransitionRequest = {
    from: 'state-login-form',
    to: 'state-dashboard',
    action: {
      type: 'tap',
      target: {
        rid: 'com.example.app:id/submit_button',
        text: 'Submit',
        cls: 'android.widget.Button'
      },
      metadata: {
        duration: 100,
        confidence: 0.9
      }
    },
    evidence,
    confidence: 0.95,
    tags: ['authentication', 'success', 'critical-path']
  };

  return new Transition(request);
}

/**
 * Example 6: Create transition with semantic selector
 */
export function createSemanticSelectorTransition(): Transition {
  const request: CreateTransitionRequest = {
    from: 'state-product-list',
    to: 'state-product-details',
    action: {
      type: 'tap',
      target: {
        text: 'Product Title'
      },
      semanticSelector: {
        type: 'product-item',
        purpose: 'navigate-to-details',
        nearText: ['Add to Cart', '$29.99']
      }
    },
    confidence: 0.75,
    tags: ['navigation', 'e-commerce']
  };

  return new Transition(request);
}

/**
 * Example 7: Create long press transition
 */
export function createLongPressTransition(): Transition {
  const request: CreateTransitionRequest = {
    from: 'state-file-list',
    to: 'state-context-menu',
    action: {
      type: 'long_press',
      target: {
        rid: 'com.example.app:id/file_item',
        text: 'document.pdf'
      },
      metadata: {
        duration: 2000 // 2 seconds long press
      }
    },
    confidence: 0.85,
    tags: ['interaction', 'context-menu']
  };

  return new Transition(request);
}

/**
 * Example 8: Create intent-based transition
 */
export function createIntentTransition(): Transition {
  const request: CreateTransitionRequest = {
    from: 'state-main-app',
    to: 'state-camera-app',
    action: {
      type: 'intent',
      intent: {
        action: 'android.media.action.IMAGE_CAPTURE',
        package: 'com.android.camera',
        extras: {
          'android.intent.extras.CAMERA_FACING': 0
        }
      }
    },
    confidence: 0.9,
    tags: ['system', 'camera', 'intent']
  };

  return new Transition(request);
}

// ============================================================================
// Factory Method Examples
// ============================================================================

/**
 * Example 9: Create transition from execution data
 */
export function createTransitionFromExecution(): Transition {
  return Transition.fromExecution(
    'state-screen-1',
    'state-screen-2',
    {
      type: 'tap',
      target: { text: 'Next' }
    },
    'sha256:digest-before',
    'sha256:digest-after',
    1800 // 1.8 seconds
  );
}

/**
 * Example 10: Create transition with evidence using factory method
 */
export function createTransitionWithEvidenceFactory(): Transition {
  return Transition.withEvidence(
    {
      from: 'state-form-page-1',
      to: 'state-form-page-2',
      action: {
        type: 'tap',
        target: { text: 'Next Step' }
      }
    },
    {
      beforeDigest: 'sha256:before-form',
      afterDigest: 'sha256:after-form',
      duration: 1200,
      notes: 'Form validation passed'
    }
  );
}

/**
 * Example 11: Create mock transition for testing
 */
export function createMockTransition(): Transition {
  return Transition.createMock({
    from: 'mock-start',
    to: 'mock-end',
    action: {
      type: 'swipe',
      swipe: { direction: 'left', distance: 0.5 }
    },
    confidence: 1.0,
    tags: ['test', 'mock']
  });
}

// ============================================================================
// Transition Manipulation Examples
// ============================================================================

/**
 * Example 12: Update transition properties
 */
export function updateTransitionExample(): Transition {
  const transition = createSimpleTapTransition();

  // Update the transition
  transition.update({
    confidence: 0.95,
    tags: ['authentication', 'successful', 'updated'],
    evidence: {
      beforeDigest: 'sha256:new-before',
      afterDigest: 'sha256:new-after',
      notes: 'Updated with better evidence'
    }
  });

  return transition;
}

/**
 * Example 13: Add evidence to existing transition
 */
export function addEvidenceExample(): Transition {
  const transition = createSimpleTapTransition();

  // Add screenshots
  transition.addScreenshots(
    'screenshots/login-before.png',
    'screenshots/home-after.png'
  );

  // Add performance metrics
  transition.setPerformanceMetrics({
    responseTime: 200,
    renderTime: 150,
    animationTime: 100,
    networkRequests: 3
  });

  // Add notes
  transition.addEvidence({
    notes: 'Transition completed successfully with good performance'
  });

  return transition;
}

/**
 * Example 14: Manage tags
 */
export function manageTagsExample(): Transition {
  const transition = createSimpleTapTransition();

  // Add tags
  transition.addTags('critical', 'user-flow', 'authentication');

  // Remove tags
  transition.removeTags('successful');

  return transition;
}

// ============================================================================
// Transition Analysis Examples
// ============================================================================

/**
 * Example 15: Compare transitions for similarity
 */
export function compareTransitionsExample(): void {
  const transition1 = createSimpleTapTransition();
  const transition2 = createTextInputTransition();

  const comparison = transition1.compareWith(transition2);

  console.log('Similarity:', comparison.similarity);
  console.log('Factors:', comparison.factors);
  console.log('Differences:', comparison.differences);
  console.log('Recommendation:', comparison.recommendation);
}

/**
 * Example 16: Check for reversal transitions
 */
export function checkReversalExample(): void {
  const forwardTransition = createSwipeTransition();
  const backwardTransition = new Transition({
    from: 'state-feed-screen-scrolled',
    to: 'state-feed-screen',
    action: {
      type: 'swipe',
      swipe: { direction: 'down', distance: 0.7 }
    }
  });

  const isReversal = forwardTransition.isReversalOf(backwardTransition);
  console.log('Is reversal:', isReversal);
}

/**
 * Example 17: Transition categorization
 */
export function categorizeTransitionExample(): void {
  const transitions = [
    createSimpleTapTransition(),
    createTextInputTransition(),
    createSwipeTransition(),
    createBackTransition(),
    createIntentTransition()
  ];

  transitions.forEach(transition => {
    console.log(`Transition ${transition.id}: ${transition.categorize()}`);
  });
}

// ============================================================================
// Validation Examples
// ============================================================================

/**
 * Example 18: Validate transition
 */
export function validateTransitionExample(): void {
  const transition = createTransitionWithEvidence();

  const validation = transition.validate();

  console.log('Is valid:', validation.isValid);
  console.log('Errors:', validation.errors.length);
  console.log('Warnings:', validation.warnings.length);

  if (validation.errors.length > 0) {
    console.log('Validation errors:');
    validation.errors.forEach(error => {
      console.log(`- ${error.field}: ${error.message}`);
    });
  }

  if (validation.warnings.length > 0) {
    console.log('Validation warnings:');
    validation.warnings.forEach(warning => {
      console.log(`- ${warning.field}: ${warning.message}`);
    });
  }
}

/**
 * Example 19: Validate actions
 */
export function validateActionExample(): void {
  const transition = createSemanticSelectorTransition();

  const actionValidation = transition.validateAction();

  console.log('Action is valid:', actionValidation.isValid);
  console.log('Estimated confidence:', actionValidation.estimatedConfidence);

  if (actionValidation.errors.length > 0) {
    console.log('Action errors:', actionValidation.errors);
  }

  if (actionValidation.warnings.length > 0) {
    console.log('Action warnings:', actionValidation.warnings);
  }
}

// ============================================================================
// Performance and Analysis Examples
// ============================================================================

/**
 * Example 20: Estimate execution time
 */
export function estimateExecutionTimeExample(): void {
  const transitions = [
    createSimpleTapTransition(),
    createTextInputTransition(),
    createSwipeTransition(),
    createLongPressTransition(),
    createIntentTransition()
  ];

  transitions.forEach(transition => {
    const estimatedTime = transition.estimateExecutionTime();
    console.log(`${transition.describeAction()}: ~${estimatedTime}ms`);
  });
}

/**
 * Example 21: Check circular transitions
 */
export function checkCircularExample(): void {
  // Create circular transition
  const circularTransition = new Transition({
    from: 'state-same-screen',
    to: 'state-same-screen',
    action: {
      type: 'tap',
      target: { text: 'Refresh' }
    }
  });

  console.log('Is circular:', circularTransition.isCircular());

  const validation = circularTransition.validate();
  console.log('Circular warning:',
    validation.warnings.some(w => w.code === 'CIRCULAR_TRANSITION')
  );
}

/**
 * Example 22: Hash calculation for deduplication
 */
export function calculateHashExample(): void {
  const transition1 = createSimpleTapTransition();
  const transition2 = createSimpleTapTransition(); // Same data

  const hash1 = transition1.calculateHash();
  const hash2 = transition2.calculateHash();

  console.log('Hash 1:', hash1);
  console.log('Hash 2:', hash2);
  console.log('Hashes match:', hash1 === hash2);
}

// ============================================================================
// Export Examples for Testing
// ============================================================================

/**
 * Example 23: Export to different formats
 */
export function exportFormatsExample(): void {
  const transition = createTransitionWithEvidence();

  // JSON format
  const jsonFormat = transition.toJSON();
  console.log('JSON format:', JSON.stringify(jsonFormat, null, 2));

  // Storage format
  const storageFormat = transition.toStorage();
  console.log('Storage format:', JSON.stringify(storageFormat, null, 2));

  // String representation
  console.log('String:', transition.toString());
  console.log('Description:', transition.describe());
}

// ============================================================================
// Error Handling Examples
// ============================================================================

/**
 * Example 24: Handle invalid transitions
 */
export function handleInvalidTransitionExample(): void {
  try {
    // This should throw an error due to invalid action
    const invalidTransition = new Transition({
      from: 'state-1',
      to: 'state-2',
      action: {
        type: 'invalid_type' as ActionType, // Invalid action type
        target: { text: 'Button' }
      }
    });
  } catch (error) {
    console.log('Caught error:', error.message);
    console.log('Error code:', error.code);
    console.log('Error details:', error.details);
  }
}

/**
 * Example 25: Handle missing required fields
 */
export function handleMissingFieldsExample(): void {
  try {
    // This should throw an error due to missing destination
    const incompleteTransition = new Transition({
      from: 'state-1',
      to: '', // Empty destination
      action: {
        type: 'tap',
        target: { text: 'Button' }
      }
    });
  } catch (error) {
    console.log('Missing field error:', error.message);
    console.log('Required field:', error.details?.field);
  }
}