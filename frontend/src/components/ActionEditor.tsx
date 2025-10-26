/**
 * Action Editor Component
 *
 * UI for defining actions with selector and action-type selection.
 * Supports all action types: tap, type, wait, back, intent.
 * Integrates with selector ranking and validation.
 */

import React, { useState, useEffect } from 'react';
// Define local types to avoid permission issues
export interface SelectorCandidate {
  id: string;
  type: 'resource-id' | 'content-desc' | 'text' | 'accessibility' | 'xpath' | 'coords';
  value: string;
  confidence: number;
  lastValidatedAt: string;
}

export interface ActionDefinition {
  kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
  selectorId?: string;
  text?: string;
  keycode?: number;
  delayMs?: number;
  intent?: {
    action: string;
    package?: string;
    component?: string;
  };
}

export interface GuardCondition {
  mustMatchSignatureHash?: string;
  requiredTexts?: string[];
}

export interface ActionEditorProps {
  /** Available selectors from the current node */
  availableSelectors: SelectorCandidate[];
  /** Initial action definition */
  initialAction?: ActionDefinition;
  /** Initial guard conditions */
  initialGuard?: GuardCondition;
  /** Whether to show advanced options */
  showAdvanced?: boolean;
  /** Callback when action changes */
  onActionChange?: (action: ActionDefinition) => void;
  /** Callback when guard changes */
  onGuardChange?: (guard: GuardCondition) => void;
  /** Callback when validation state changes */
  onValidationChange?: (isValid: boolean, errors: string[]) => void;
  /** Disabled state */
  disabled?: boolean;
}

export const ActionEditor: React.FC<ActionEditorProps> = ({
  availableSelectors = [],
  initialAction,
  initialGuard,
  showAdvanced = false,
  onActionChange,
  onGuardChange,
  onValidationChange,
  disabled = false,
}) => {
  const [action, setAction] = useState<ActionDefinition>(
    initialAction || { kind: 'tap' }
  );
  const [guard, setGuard] = useState<GuardCondition>(initialGuard || {});
  const [errors, setErrors] = useState<string[]>([]);

  // Validate action whenever it changes
  useEffect(() => {
    const validationErrors = validateAction(action, guard);
    setErrors(validationErrors);
    onValidationChange?.(validationErrors.length === 0, validationErrors);
  }, [action, guard, onValidationChange]);

  // Notify parent of changes
  useEffect(() => {
    onActionChange?.(action);
  }, [action, onActionChange]);

  useEffect(() => {
    onGuardChange?.(guard);
  }, [guard, onGuardChange]);

  const validateAction = (actionDef: ActionDefinition, guardDef: GuardCondition): string[] => {
    const newErrors: string[] = [];

    // Action kind validation
    if (!actionDef.kind) {
      newErrors.push('Action type is required');
    }

    // Action-specific validation
    switch (actionDef.kind) {
      case 'tap':
        if (!actionDef.selectorId) {
          newErrors.push('Selector is required for tap action');
        }
        break;

      case 'type':
        if (!actionDef.selectorId) {
          newErrors.push('Selector is required for type action');
        }
        if (!actionDef.text || actionDef.text.trim().length === 0) {
          newErrors.push('Text is required for type action');
        }
        break;

      case 'intent':
        if (!actionDef.intent?.action) {
          newErrors.push('Intent action is required');
        }
        break;

      case 'wait':
        if (actionDef.delayMs && actionDef.delayMs < 0) {
          newErrors.push('Wait delay must be positive');
        }
        break;
    }

    // Guard validation
    if (guardDef.mustMatchSignatureHash && !/^[a-f0-9]{32}$/.test(guardDef.mustMatchSignatureHash)) {
      newErrors.push('Guard signature hash must be a 16-byte hex string');
    }

    return newErrors;
  };

  const handleActionKindChange = (kind: ActionDefinition['kind']) => {
    setAction({ kind });
  };

  const handleSelectorChange = (selectorId: string) => {
    setAction(prev => ({ ...prev, selectorId: selectorId || undefined }));
  };

  const handleTextChange = (text: string) => {
    setAction(prev => ({ ...prev, text: text || undefined }));
  };

  const handleDelayChange = (delayMs: number) => {
    setAction(prev => ({ ...prev, delayMs: delayMs || undefined }));
  };

  const handleKeycodeChange = (keycode: number) => {
    setAction(prev => ({ ...prev, keycode: keycode || undefined }));
  };

  const handleIntentChange = (intent: ActionDefinition['intent']) => {
    setAction(prev => ({ ...prev, intent }));
  };

  const handleGuardChange = (newGuard: GuardCondition) => {
    setGuard(newGuard);
  };

  const getConfidenceColor = (confidence: number): string => {
    if (confidence >= 0.8) return 'text-green-600';
    if (confidence >= 0.6) return 'text-yellow-600';
    return 'text-red-600';
  };

  const getActionIcon = (kind: ActionDefinition['kind']): string => {
    switch (kind) {
      case 'tap': return '👆';
      case 'type': return '⌨️';
      case 'wait': return '⏱️';
      case 'back': return '⬅️';
      case 'intent': return '🚀';
      default: return '❓';
    }
  };

  const selectedSelector = availableSelectors.find(s => s.id === action.selectorId);

  return (
    <div className="space-y-6">
      {/* Action Type Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-3">
          Action Type
        </label>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {(['tap', 'type', 'wait', 'back', 'intent'] as const).map((kind) => (
            <button
              key={kind}
              type="button"
              onClick={() => handleActionKindChange(kind)}
              disabled={disabled}
              className={`p-3 rounded-lg border-2 text-center transition-all ${
                action.kind === kind
                  ? 'border-blue-500 bg-blue-50 text-blue-700'
                  : 'border-gray-200 hover:border-gray-300 text-gray-600'
              } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <div className="text-2xl mb-1">{getActionIcon(kind)}</div>
              <div className="text-sm font-medium capitalize">{kind}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Action Configuration */}
      <div className="space-y-4">
        {/* Selector Selection (for tap and type actions) */}
        {(['tap', 'type'].includes(action.kind)) && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Target Selector {action.kind === 'tap' ? '' : '(for typing)'}
            </label>
            <select
              value={action.selectorId || ''}
              onChange={(e) => handleSelectorChange(e.target.value)}
              disabled={disabled}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">Select a selector...</option>
              {availableSelectors.map((selector) => (
                <option key={selector.id} value={selector.id}>
                  {selector.type}: {selector.value} ({Math.round(selector.confidence * 100)}%)
                </option>
              ))}
            </select>

            {/* Selected Selector Details */}
            {selectedSelector && (
              <div className="mt-2 p-2 bg-gray-50 rounded text-sm">
                <div className="flex justify-between items-center">
                  <span className="font-mono text-gray-700">{selectedSelector.value}</span>
                  <span className={`text-xs font-medium ${getConfidenceColor(selectedSelector.confidence)}`}>
                    {Math.round(selectedSelector.confidence * 100)}% confidence
                  </span>
                </div>
                <div className="flex items-center space-x-2 mt-1">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                    selectedSelector.type === 'resource-id' ? 'bg-green-100 text-green-800' :
                    selectedSelector.type === 'text' ? 'bg-blue-100 text-blue-800' :
                    selectedSelector.type === 'content-desc' ? 'bg-purple-100 text-purple-800' :
                    'bg-gray-100 text-gray-800'
                  }`}>
                    {selectedSelector.type}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Text Input (for type action) */}
        {action.kind === 'type' && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Text to Type
            </label>
            <input
              type="text"
              value={action.text || ''}
              onChange={(e) => handleTextChange(e.target.value)}
              disabled={disabled}
              placeholder="Enter text to type..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">
              Use {'${variableName}'} for placeholders that will be resolved during flow execution.
            </p>
          </div>
        )}

        {/* Delay Input (for wait action) */}
        {action.kind === 'wait' && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Wait Duration (milliseconds)
            </label>
            <input
              type="number"
              value={action.delayMs || 1000}
              onChange={(e) => handleDelayChange(parseInt(e.target.value, 10))}
              disabled={disabled}
              min="0"
              step="100"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
        )}

        {/* Keycode Input (for back action) */}
        {action.kind === 'back' && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Keycode (optional)
            </label>
            <input
              type="number"
              value={action.keycode || ''}
              onChange={(e) => handleKeycodeChange(parseInt(e.target.value, 10))}
              disabled={disabled}
              placeholder="4 for BACK key"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-500 mt-1">
              Leave empty for default BACK key (4). See Android KeyEvent constants for other values.
            </p>
          </div>
        )}

        {/* Intent Configuration (for intent action) */}
        {action.kind === 'intent' && (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Intent Action
              </label>
              <input
                type="text"
                value={action.intent?.action || ''}
                onChange={(e) => handleIntentChange({ ...action.intent, action: e.target.value })}
                disabled={disabled}
                placeholder="e.g., android.intent.action.VIEW"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Package (optional)
              </label>
              <input
                type="text"
                value={action.intent?.package || ''}
                onChange={(e) => handleIntentChange({ ...action.intent, action: action.intent?.action || '', package: e.target.value })}
                disabled={disabled}
                placeholder="e.g., com.mayndrive.app"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Component (optional)
              </label>
              <input
                type="text"
                value={action.intent?.component || ''}
                onChange={(e) => handleIntentChange({ ...action.intent, action: action.intent?.action || '', component: e.target.value })}
                disabled={disabled}
                placeholder="e.g., com.mayndrive.app/.MainActivity"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>
        )}
      </div>

      {/* Advanced Options */}
      {showAdvanced && (
        <div className="border-t border-gray-200 pt-4">
          <h3 className="text-sm font-medium text-gray-700 mb-3">Advanced Options</h3>

          {/* Guard Conditions */}
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Guard Conditions
              </label>
              <p className="text-xs text-gray-500 mb-2">
                Conditions that must be true for this action to execute.
              </p>

              <div className="space-y-2">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">
                    Must Match Signature Hash
                  </label>
                  <input
                    type="text"
                    value={guard.mustMatchSignatureHash || ''}
                    onChange={(e) => handleGuardChange({ ...guard, mustMatchSignatureHash: e.target.value || undefined })}
                    disabled={disabled}
                    placeholder="16-byte hex hash"
                    className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">
                    Required Texts
                  </label>
                  <input
                    type="text"
                    value={guard.requiredTexts?.join(', ') || ''}
                    onChange={(e) => handleGuardChange({
                      ...guard,
                      requiredTexts: e.target.value ? e.target.value.split(',').map(t => t.trim()) : undefined
                    })}
                    disabled={disabled}
                    placeholder="text1, text2, text3"
                    className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Validation Errors */}
      {errors.length > 0 && (
        <div className="rounded-md bg-red-50 p-3">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Validation Errors</h3>
              <div className="mt-2 text-sm text-red-700">
                <ul className="list-disc list-inside space-y-1">
                  {errors.map((error, index) => (
                    <li key={index}>{error}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Action Summary */}
      <div className="bg-gray-50 rounded-lg p-3">
        <h4 className="text-sm font-medium text-gray-700 mb-2">Action Summary</h4>
        <div className="text-sm text-gray-600">
          <div className="flex items-center space-x-2">
            <span>{getActionIcon(action.kind)}</span>
            <span className="font-medium capitalize">{action.kind}</span>
            {action.selectorId && selectedSelector && (
              <>
                <span>→</span>
                <span className="font-mono text-xs">{selectedSelector.value}</span>
                <span className={`text-xs ${getConfidenceColor(selectedSelector.confidence)}`}>
                  ({Math.round(selectedSelector.confidence * 100)}%)
                </span>
              </>
            )}
            {action.text && (
              <>
                <span>→</span>
                <span className="italic">"{action.text}"</span>
              </>
            )}
            {action.delayMs && (
              <>
                <span>→</span>
                <span>{action.delayMs}ms</span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ActionEditor;