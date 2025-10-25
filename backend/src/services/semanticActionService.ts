/**
 * Semantic Action Service
 *
 * Enhanced action execution with semantic selector resolution and intelligent fallback strategies.
 */

import { UserAction, StateRecord } from '../types/graph';
import { SemanticSelector, generateSelectorStrategy, matchSemanticSelector } from '../utils/semanticSelectors';

/**
 * Enhanced action with semantic selector information
 */
export interface EnhancedUserAction extends UserAction {
  /** Semantic selector information */
  semanticSelector?: SemanticSelector;

  /** Selector matching strategy */
  selectorStrategy?: {
    primary: any;
    fallbacks: any[];
    strategy: 'exact' | 'semantic' | 'fallback';
    confidence: number;
  };

  /** Action execution context */
  context?: {
    sourceState: string;
    targetState?: string;
    previousActions: UserAction[];
    elementContext?: any;
  };

  /** Execution preferences */
  preferences?: {
    allowMultipleMatches: boolean;
    requireVisible: boolean;
    waitForElement: boolean;
    timeout: number;
  };
}

/**
 * Action execution result with semantic information
 */
export interface ActionResult {
  /** Whether action was successful */
  success: boolean;

  /** Final action that was executed */
  executedAction: UserAction;

  /** Which selector strategy worked */
  usedStrategy: 'exact' | 'semantic' | 'fallback';

  /** Matched element information */
  matchedElement?: any;

  /** Execution duration */
  duration: number;

  /** Error information if failed */
  error?: {
    type: string;
    message: string;
    details?: any;
  };

  /** Semantic confidence score */
  confidence: number;

  /** Additional context */
  context?: {
    alternatives: any[];
    reasoning: string[];
    suggestions: string[];
  };
}

/**
 * Semantic Action Service
 */
export class SemanticActionService {
  constructor(
    private adbService: any,
    private stateService: any
  ) {}

  /**
   * Execute action with semantic selector resolution
   */
  async executeAction(
    action: EnhancedUserAction,
    currentState: StateRecord,
    context?: any
  ): Promise<ActionResult> {
    const startTime = Date.now();

    try {
      // Resolve semantic selector if present
      let resolvedAction = action;
      let usedStrategy: 'exact' | 'semantic' | 'fallback' = 'exact';
      let matchedElement: any;
      let confidence = 1.0;

      if (action.semanticSelector) {
        const strategy = generateSelectorStrategy(action.semanticSelector, currentState);

        // Try primary selector
        const primaryResult = await this.executeActionWithSelector(
          { ...action, target: strategy.primary },
          currentState
        );

        if (primaryResult.success) {
          resolvedAction = primaryResult.executedAction;
          matchedElement = primaryResult.matchedElement;
          usedStrategy = strategy.strategy;
          confidence = strategy.confidence;
        } else {
          // Try fallback selectors
          for (const fallback of strategy.fallbacks) {
            const fallbackResult = await this.executeActionWithSelector(
              { ...action, target: fallback },
              currentState
            );

            if (fallbackResult.success) {
              resolvedAction = fallbackResult.executedAction;
              matchedElement = fallbackResult.matchedElement;
              usedStrategy = 'fallback';
              confidence = strategy.confidence * 0.8; // Lower confidence for fallback
              break;
            }
          }

          if (!matchedElement) {
            return {
              success: false,
              executedAction: action,
              usedStrategy: 'semantic',
              duration: Date.now() - startTime,
              confidence: 0,
              error: {
                type: 'selector_not_found',
                message: `No matching element found for semantic selector: ${action.semanticSelector?.purpose}`,
                details: { strategy, semanticSelector: action.semanticSelector }
              },
              context: {
                alternatives: strategy.fallbacks,
                reasoning: ['Primary selector failed', 'All fallback selectors failed'],
                suggestions: this.generateSuggestions(action.semanticSelector, currentState)
              }
            };
          }
        }
      }

      // Execute the resolved action
      const executionResult = await this.performActionExecution(resolvedAction, currentState);

      return {
        success: executionResult.success,
        executedAction: resolvedAction,
        usedStrategy,
        matchedElement,
        duration: Date.now() - startTime,
        error: executionResult.error,
        confidence,
        context: {
          alternatives: [],
          reasoning: [`Used ${usedStrategy} selector strategy`],
          suggestions: []
        }
      };

    } catch (error) {
      return {
        success: false,
        executedAction: action,
        usedStrategy: 'exact',
        duration: Date.now() - startTime,
        confidence: 0,
        error: {
          type: 'execution_error',
          message: error instanceof Error ? error.message : 'Unknown error',
          details: error
        }
      };
    }
  }

  /**
   * Execute action with specific selector
   */
  private async executeActionWithSelector(
    action: EnhancedUserAction,
    currentState: StateRecord
  ): Promise<ActionResult> {
    try {
      const result = await this.performActionExecution(action, currentState);

      return {
        success: result.success,
        executedAction: action,
        usedStrategy: 'exact',
        matchedElement: action.target,
        duration: 0,
        error: result.error,
        confidence: 1.0
      };
    } catch (error) {
      return {
        success: false,
        executedAction: action,
        usedStrategy: 'exact',
        duration: 0,
        confidence: 0,
        error: {
          type: 'selector_execution_failed',
          message: error instanceof Error ? error.message : 'Selector execution failed',
          details: error
        }
      };
    }
  }

  /**
   * Perform the actual action execution
   */
  private async performActionExecution(
    action: UserAction,
    currentState: StateRecord
  ): Promise<{ success: boolean; error?: any }> {
    switch (action.type) {
      case 'tap':
        return await this.executeTap(action, currentState);
      case 'type':
        return await this.executeType(action, currentState);
      case 'swipe':
        return await this.executeSwipe(action, currentState);
      case 'back':
        return await this.executeBack(currentState);
      case 'intent':
        return await this.executeIntent(action, currentState);
      case 'long_press':
        return await this.executeLongPress(action, currentState);
      default:
        return {
          success: false,
          error: {
            type: 'unsupported_action',
            message: `Unsupported action type: ${action.type}`
          }
        };
    }
  }

  /**
   * Execute tap action
   */
  private async executeTap(action: UserAction, currentState: StateRecord): Promise<{ success: boolean; error?: any }> {
    if (!action.target || !action.target.bounds) {
      return {
        success: false,
        error: {
          type: 'invalid_target',
          message: 'Tap action requires target with bounds'
        }
      };
    }

    try {
      const [left, top, right, bottom] = action.target.bounds;
      const centerX = Math.round((left + right) / 2);
      const centerY = Math.round((top + bottom) / 2);

      const command = `adb shell input tap ${centerX} ${centerY}`;
      await this.adbService.executeCommand(command);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: {
          type: 'tap_execution_failed',
          message: error instanceof Error ? error.message : 'Tap execution failed'
        }
      };
    }
  }

  /**
   * Execute type action
   */
  private async executeType(action: UserAction, currentState: StateRecord): Promise<{ success: boolean; error?: any }> {
    if (!action.text) {
      return {
        success: false,
        error: {
          type: 'invalid_text',
          message: 'Type action requires text to type'
        }
      };
    }

    try {
      // First focus on the target if specified
      if (action.target && action.target.bounds) {
        const tapResult = await this.executeTap(action, currentState);
        if (!tapResult.success) {
          return tapResult;
        }

        // Wait a moment for focus
        await this.sleep(500);
      }

      // Type the text
      const escapedText = action.text.replace(/ /g, '%s');
      const command = `adb shell input text "${escapedText}"`;
      await this.adbService.executeCommand(command);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: {
          type: 'type_execution_failed',
          message: error instanceof Error ? error.message : 'Type execution failed'
        }
      };
    }
  }

  /**
   * Execute swipe action
   */
  private async executeSwipe(action: UserAction, currentState: StateRecord): Promise<{ success: boolean; error?: any }> {
    if (!action.swipe) {
      return {
        success: false,
        error: {
          type: 'invalid_swipe',
          message: 'Swipe action requires swipe configuration'
        }
      };
    }

    try {
      // Get screen dimensions (would normally get from device)
      const screenWidth = 1080;
      const screenHeight = 1920;

      // Calculate swipe coordinates based on direction
      let startX = screenWidth / 2;
      let startY = screenHeight / 2;
      let endX = startX;
      let endY = startY;

      const distance = action.swipe.distance || 200;

      switch (action.swipe.direction) {
        case 'up':
          endY -= distance;
          break;
        case 'down':
          endY += distance;
          break;
        case 'left':
          endX -= distance;
          break;
        case 'right':
          endX += distance;
          break;
      }

      const command = `adb shell input swipe ${startX} ${startY} ${endX} ${endY}`;
      await this.adbService.executeCommand(command);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: {
          type: 'swipe_execution_failed',
          message: error instanceof Error ? error.message : 'Swipe execution failed'
        }
      };
    }
  }

  /**
   * Execute back action
   */
  private async executeBack(currentState: StateRecord): Promise<{ success: boolean; error?: any }> {
    try {
      const command = 'adb shell input keyevent KEYCODE_BACK';
      await this.adbService.executeCommand(command);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: {
          type: 'back_execution_failed',
          message: error instanceof Error ? error.message : 'Back execution failed'
        }
      };
    }
  }

  /**
   * Execute intent action
   */
  private async executeIntent(action: UserAction, currentState: StateRecord): Promise<{ success: boolean; error?: any }> {
    if (!action.intent) {
      return {
        success: false,
        error: {
          type: 'invalid_intent',
          message: 'Intent action requires intent configuration'
        }
      };
    }

    try {
      let command = `adb shell am start`;

      if (action.intent.action) {
        command += ` -a ${action.intent.action}`;
      }

      if (action.intent.package) {
        command += ` ${action.intent.package}`;
      }

      if (action.intent.component) {
        command += `/${action.intent.component}`;
      }

      if (action.intent.extras) {
        for (const [key, value] of Object.entries(action.intent.extras)) {
          command += ` --es ${key} "${value}"`;
        }
      }

      await this.adbService.executeCommand(command);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: {
          type: 'intent_execution_failed',
          message: error instanceof Error ? error.message : 'Intent execution failed'
        }
      };
    }
  }

  /**
   * Execute long press action
   */
  private async executeLongPress(action: UserAction, currentState: StateRecord): Promise<{ success: boolean; error?: any }> {
    if (!action.target || !action.target.bounds) {
      return {
        success: false,
        error: {
          type: 'invalid_target',
          message: 'Long press action requires target with bounds'
        }
      };
    }

    try {
      const [left, top, right, bottom] = action.target.bounds;
      const centerX = Math.round((left + right) / 2);
      const centerY = Math.round((top + bottom) / 2);

      const duration = action.metadata?.duration || 1000;

      const command = `adb shell input swipe ${centerX} ${centerY} ${centerX} ${centerY} ${duration}`;
      await this.adbService.executeCommand(command);

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: {
          type: 'long_press_execution_failed',
          message: error instanceof Error ? error.message : 'Long press execution failed'
        }
      };
    }
  }

  /**
   * Generate suggestions for failed selector matching
   */
  private generateSuggestions(
    semanticSelector: SemanticSelector | undefined,
    currentState: StateRecord
  ): string[] {
    if (!semanticSelector) return [];

    const suggestions: string[] = [];

    // Suggest similar elements based on text
    if (semanticSelector.text) {
      const similarTexts = currentState.selectors
        .filter(s => s.text && s.text.toLowerCase().includes(semanticSelector.text!.toLowerCase()))
        .map(s => s.text);

      if (similarTexts.length > 0) {
        suggestions.push(`Try elements with similar text: ${similarTexts.join(', ')}`);
      }
    }

    // Suggest elements of the same semantic type
    if (semanticSelector.semanticType) {
      const sameTypeElements = currentState.selectors.filter(s => {
        const classification = this.classifyElement(s, currentState);
        return classification.semanticType === semanticSelector.semanticType;
      });

      if (sameTypeElements.length > 0) {
        suggestions.push(`Consider these ${semanticSelector.semanticType} elements: ${
          sameTypeElements.slice(0, 3).map(s => s.text || s.desc || 'unnamed').join(', ')
        }`);
      }
    }

    // Suggest checking different areas of the screen
    if (semanticSelector.locationHint) {
      suggestions.push(`Try looking in the ${semanticSelector.locationHint.position} area of the screen`);
    }

    return suggestions;
  }

  /**
   * Simple element classification (would normally use semanticSelectors utility)
   */
  private classifyElement(selector: any, state: StateRecord): { semanticType: string } {
    const className = selector.cls?.toLowerCase() || '';

    if (className.includes('button')) return { semanticType: 'button' };
    if (className.includes('input') || className.includes('edit')) return { semanticType: 'input' };
    if (className.includes('image')) return { semanticType: 'image' };
    if (className.includes('text')) return { semanticType: 'text' };

    return { semanticType: 'unknown' };
  }

  /**
   * Utility sleep function
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Validate action semantics before execution
   */
  validateAction(action: EnhancedUserAction): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate action type
    if (!['tap', 'type', 'swipe', 'back', 'intent', 'long_press'].includes(action.type)) {
      errors.push(`Invalid action type: ${action.type}`);
    }

    // Validate required fields based on action type
    switch (action.type) {
      case 'tap':
      case 'long_press':
        if (!action.target && !action.semanticSelector) {
          errors.push('Tap and long press actions require a target');
        }
        break;

      case 'type':
        if (!action.text) {
          errors.push('Type action requires text to type');
        }
        if (!action.target && !action.semanticSelector) {
          errors.push('Type action requires a target element');
        }
        break;

      case 'swipe':
        if (!action.swipe) {
          errors.push('Swipe action requires swipe configuration');
        }
        break;

      case 'intent':
        if (!action.intent || !action.intent.action) {
          errors.push('Intent action requires intent configuration with action');
        }
        break;
    }

    // Validate semantic selector if present
    if (action.semanticSelector) {
      if (!action.semanticSelector.semanticType && !action.semanticSelector.purpose) {
        errors.push('Semantic selector should have semantic type or purpose');
      }

      if (action.semanticSelector.confidence !== undefined &&
          (action.semanticSelector.confidence < 0 || action.semanticSelector.confidence > 1)) {
        errors.push('Semantic selector confidence must be between 0 and 1');
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Enhance regular action with semantic information
   */
  enhanceAction(action: UserAction, currentState: StateRecord): EnhancedUserAction {
    const enhanced: EnhancedUserAction = { ...action };

    if (action.target) {
      // Add semantic information to existing selector
      // This would integrate with the semanticSelectors utility
      enhanced.semanticSelector = {
        ...action.target,
        semanticType: 'unknown',
        purpose: action.target.text || action.target.desc || 'Interactive element',
        confidence: 0.8
      };
    }

    enhanced.preferences = {
      allowMultipleMatches: false,
      requireVisible: true,
      waitForElement: true,
      timeout: 5000
    };

    return enhanced;
  }
}