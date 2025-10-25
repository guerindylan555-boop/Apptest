/**
 * Flow Editor Modal Component
 *
 * Modal interface for creating and editing flow definitions with state predicate selection.
 */

import React, { useState, useEffect } from 'react';
import {
  XMarkIcon,
  PlusIcon,
  TrashIcon,
  ChevronUpIcon,
  ChevronDownIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
  DocumentArrowDownIcon,
  DocumentArrowUpIcon,
  PlayIcon,
  StopIcon
} from '@heroicons/react/24/outline';

// Re-use the same types as DiscoveryPanel
interface Selector {
  rid?: string;
  desc?: string;
  text?: string;
  cls?: string;
  bounds?: [number, number, number, number];
  xpath?: string;
}

interface UserAction {
  type: 'tap' | 'type' | 'swipe' | 'back' | 'intent' | 'long_press';
  target?: Selector;
  text?: string;
  swipe?: {
    direction: 'up' | 'down' | 'left' | 'right';
    distance: number;
  };
  intent?: {
    action: string;
    package?: string;
    component?: string;
    extras?: Record<string, any>;
  };
  metadata?: {
    duration?: number;
    confidence?: number;
  };
  semanticSelector?: {
    semanticType?: 'button' | 'input' | 'link' | 'image' | 'text' | 'container' | 'navigation' | 'menu' | 'list' | 'unknown';
    purpose?: string;
    contentSignature?: string;
    nearText?: string[];
    confidence?: number;
  };
}

interface StateRecord {
  id: string;
  package: string;
  activity: string;
  digest: string;
  selectors: Selector[];
  visibleText: string[];
  screenshot?: string;
  tags?: string[];
  createdAt: string;
  updatedAt: string;
  metadata?: {
    captureMethod: 'adb' | 'frida';
    captureDuration: number;
    elementCount: number;
    hierarchyDepth: number;
  };
}

interface UIGraph {
  version: string;
  createdAt: string;
  updatedAt: string;
  packageName: string;
  states: StateRecord[];
  transitions: any[];
  stats: {
    stateCount: number;
    transitionCount: number;
    averageDegree: number;
    isolatedStates: number;
    lastCapture?: string;
  };
  metadata: {
    captureTool: string;
    androidVersion?: string;
    appVersion?: string;
    deviceInfo?: string;
    totalCaptureTime: number;
    totalSessions: number;
  };
}

interface StatePredicate {
  type: 'exact' | 'contains' | 'matches' | 'fuzzy';
  stateId?: string;
  activity?: string;
  containsText?: string[];
  matches?: {
    activity?: string;
    text?: string;
    selectors?: string;
  };
  fuzzyThreshold?: number;
  hasSelectors?: Array<{
    rid?: string;
    text?: string;
    desc?: string;
  }>;
}

interface FlowStep {
  id: string;
  name: string;
  description?: string;
  preconditions: StatePredicate[];
  action: UserAction;
  expectedState?: StatePredicate;
  timeout?: number;
  critical?: boolean;
  metadata?: {
    confidence?: number;
    notes?: string;
    tags?: string[];
  };
}

interface FlowDefinition {
  id: string;
  name: string;
  description?: string;
  version: string;
  packageName: string;
  steps: FlowStep[];
  entryPoint: StatePredicate;
  exitPoint?: StatePredicate;
  metadata: {
    createdAt: string;
    updatedAt: string;
    author?: string;
    tags?: string[];
    estimatedDuration?: number;
    complexity?: number;
    executionCount?: number;
    successRate?: number;
  };
  config?: {
    defaultTimeout: number;
    retryAttempts: number;
    allowParallel: boolean;
    priority: 'low' | 'medium' | 'high';
  };
}

interface FlowEditorProps {
  flow?: FlowDefinition | null;
  graph?: UIGraph | null;
  isVisible: boolean;
  onClose: () => void;
  onSave: (flow: FlowDefinition) => void;
  onValidate?: (flow: FlowDefinition) => { isValid: boolean; errors: string[] };
}

export const FlowEditor: React.FC<FlowEditorProps> = ({
  flow,
  graph,
  isVisible,
  onClose,
  onSave,
  onValidate
}) => {
  // Form state
  const [flowData, setFlowData] = useState<FlowDefinition>({
    id: '',
    name: '',
    description: '',
    version: '1.0.0',
    packageName: '',
    steps: [],
    entryPoint: {
      type: 'contains',
      containsText: ['']
    },
    metadata: {
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      tags: [],
      estimatedDuration: 0,
      complexity: 0,
      executionCount: 0,
      successRate: 0
    },
    config: {
      defaultTimeout: 5000,
      retryAttempts: 3,
      allowParallel: false,
      priority: 'medium'
    }
  });

  const [selectedStepIndex, setSelectedStepIndex] = useState<number | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [validationWarnings, setValidationWarnings] = useState<string[]>([]);
  const [validationSuggestions, setValidationSuggestions] = useState<string[]>([]);
  const [completenessScore, setCompletenessScore] = useState<number>(100);
  const [isDirty, setIsDirty] = useState(false);
  const [showPredicateBuilder, setShowPredicateBuilder] = useState(false);
  const [predicateTarget, setPredicateTarget] = useState<'entry' | 'exit' | 'precondition' | 'expected' | null>(null);
  const [selectedStepForPredicate, setSelectedStepForPredicate] = useState<number | null>(null);

  // Initialize form data when flow changes
  useEffect(() => {
    if (flow) {
      setFlowData({
        ...flow,
        metadata: {
          ...flow.metadata,
          updatedAt: new Date().toISOString()
        }
      });
    } else {
      // Create new flow template
      const newFlow: FlowDefinition = {
        id: `flow-${Date.now()}`,
        name: 'New Flow',
        description: '',
        version: '1.0.0',
        packageName: graph?.packageName || 'unknown',
        steps: [],
        entryPoint: {
          type: 'contains',
          containsText: ['']
        },
        metadata: {
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          tags: [],
          estimatedDuration: 0,
          complexity: 0,
          executionCount: 0,
          successRate: 0
        },
        config: {
          defaultTimeout: 5000,
          retryAttempts: 3,
          allowParallel: false,
          priority: 'medium'
        }
      };
      setFlowData(newFlow);
    }
  }, [flow, graph]);

  // Mark as dirty when form data changes and run validation
  useEffect(() => {
    setIsDirty(true);
    validateFlow();
  }, [flowData]);

  // Validate flow
  const validateFlow = () => {
    const errors: string[] = [];
    const warnings: string[] = [];
    const suggestions: string[] = [];
    let score = 100;

    // Basic validation
    if (!flowData.name.trim()) {
      errors.push('Flow name is required');
      score -= 20;
    }

    if (!flowData.packageName.trim()) {
      errors.push('Package name is required');
      score -= 20;
    }

    if (flowData.steps.length === 0) {
      errors.push('Flow must have at least one step');
      score -= 30;
    }

    // Validate entry point
    if (!isValidPredicate(flowData.entryPoint)) {
      errors.push('Entry point predicate is invalid');
      score -= 15;
    } else if (flowData.entryPoint.type === 'contains' && (!flowData.entryPoint.containsText || flowData.entryPoint.containsText.length === 0)) {
      warnings.push('Entry point is too generic - consider adding more specific text content');
      score -= 5;
    }

    // Validate steps
    flowData.steps.forEach((step, index) => {
      let stepScore = 0;

      if (!step.name.trim()) {
        errors.push(`Step ${index + 1} name is required`);
        score -= 10;
        stepScore -= 10;
      }

      if (!step.action.type) {
        errors.push(`Step ${index + 1} action type is required`);
        score -= 10;
        stepScore -= 10;
      }

      // Action validation
      switch (step.action.type) {
        case 'tap':
        case 'long_press':
          if (!step.action.target && !step.action.semanticSelector) {
            errors.push(`Step ${index + 1} ${step.action.type} action requires a target`);
            score -= 10;
            stepScore -= 10;
          } else if (step.action.semanticSelector && !step.action.semanticSelector.purpose) {
            warnings.push(`Step ${index + 1} semantic selector lacks purpose description`);
            score -= 3;
            stepScore -= 3;
          }
          break;

        case 'type':
          if (!step.action.text) {
            errors.push(`Step ${index + 1} type action requires text to type`);
            score -= 10;
            stepScore -= 10;
          }
          if (!step.action.target && !step.action.semanticSelector) {
            errors.push(`Step ${index + 1} type action requires a target`);
            score -= 10;
            stepScore -= 10;
          }
          break;

        case 'swipe':
          if (!step.action.swipe || !step.action.swipe.direction) {
            errors.push(`Step ${index + 1} swipe action requires direction`);
            score -= 10;
            stepScore -= 10;
          } else if (step.action.swipe.distance < 50) {
            warnings.push(`Step ${index + 1} swipe distance might be too short for reliable detection`);
            score -= 3;
            stepScore -= 3;
          }
          break;

        case 'intent':
          if (!step.action.intent || !step.action.intent.action) {
            errors.push(`Step ${index + 1} intent action requires intent configuration`);
            score -= 10;
            stepScore -= 10;
          }
          break;
      }

      // Preconditions validation
      step.preconditions.forEach((pred, predIndex) => {
        if (!isValidPredicate(pred)) {
          errors.push(`Step ${index + 1} precondition ${predIndex + 1} is invalid`);
          score -= 5;
          stepScore -= 5;
        } else if (pred.type === 'contains' && (!pred.containsText || pred.containsText.length === 0)) {
          warnings.push(`Step ${index + 1} precondition ${predIndex + 1} is too generic`);
          score -= 2;
          stepScore -= 2;
        }
      });

      // Expected state validation
      if (step.expectedState) {
        if (!isValidPredicate(step.expectedState)) {
          errors.push(`Step ${index + 1} expected state predicate is invalid`);
          score -= 5;
          stepScore -= 5;
        }
      } else {
        suggestions.push(`Consider adding expected state verification for step ${index + 1}`);
        score -= 2;
        stepScore -= 2;
      }

      // Critical step validation
      if (step.critical && !step.expectedState) {
        warnings.push(`Step ${index + 1} is marked as critical but has no expected state verification`);
        score -= 5;
        stepScore -= 5;
      }

      // Timeout validation
      if (step.timeout && (step.timeout < 1000 || step.timeout > 60000)) {
        warnings.push(`Step ${index + 1} has an unusual timeout: ${step.timeout}ms`);
        score -= 2;
        stepScore -= 2;
      }

      // Step description
      if (!step.description || step.description.trim().length === 0) {
        suggestions.push(`Add description to step ${index + 1} for better documentation`);
        score -= 1;
        stepScore -= 1;
      }
    });

    // Flow-level suggestions
    if (!flowData.description || flowData.description.trim().length === 0) {
      suggestions.push('Add a flow description to explain its purpose');
      score -= 3;
    }

    if (!flowData.exitPoint) {
      suggestions.push('Consider adding an exit point to verify flow completion');
      score -= 5;
    }

    if (flowData.steps.length > 15) {
      warnings.push(`Flow has ${flowData.steps.length} steps - consider breaking into smaller flows`);
      score -= 5;
    }

    // Complexity analysis
    const criticalSteps = flowData.steps.filter(s => s.critical).length;
    const stepsWithPreconditions = flowData.steps.filter(s => s.preconditions.length > 0).length;
    const stepsWithExpectedStates = flowData.steps.filter(s => s.expectedState).length;

    const complexityScore = flowData.steps.length * 2 + criticalSteps * 1 + stepsWithPreconditions * 3 + stepsWithExpectedStates * 2;
    if (complexityScore > 50) {
      warnings.push(`Flow has high complexity score (${complexityScore}) - may be difficult to maintain`);
      score -= 5;
    }

    setValidationErrors(errors);
    setValidationWarnings(warnings);
    setValidationSuggestions(suggestions);
    setCompletenessScore(Math.max(0, Math.min(100, score)));

    return { errors, warnings, suggestions, score };
  };

  const isValidPredicate = (predicate: StatePredicate): boolean => {
    if (predicate.type === 'exact' && !predicate.stateId) {
      return false;
    }
    if (predicate.type === 'contains' && (!predicate.containsText || predicate.containsText.length === 0)) {
      return false;
    }
    if (predicate.type === 'matches' && !predicate.matches) {
      return false;
    }
    if (predicate.type === 'fuzzy' && !predicate.fuzzyThreshold) {
      return false;
    }
    return true;
  };

  // Handle save
  const handleSave = () => {
    const validation = validateFlow();

    if (validation.errors.length === 0) {
      onSave(flowData);
      setIsDirty(false);
    }
  };

  // Add new step
  const addStep = () => {
    const newStep: FlowStep = {
      id: `step-${Date.now()}`,
      name: `Step ${flowData.steps.length + 1}`,
      description: '',
      preconditions: [],
      action: { type: 'tap' },
      timeout: 5000,
      critical: false,
      metadata: {
        confidence: 0.8,
        notes: '',
        tags: []
      }
    };

    setFlowData({
      ...flowData,
      steps: [...flowData.steps, newStep]
    });
    setSelectedStepIndex(flowData.steps.length);
  };

  // Remove step
  const removeStep = (index: number) => {
    const newSteps = flowData.steps.filter((_, i) => i !== index);
    setFlowData({
      ...flowData,
      steps: newSteps
    });
    if (selectedStepIndex === index) {
      setSelectedStepIndex(null);
    } else if (selectedStepIndex !== null && selectedStepIndex > index) {
      setSelectedStepIndex(selectedStepIndex - 1);
    }
  };

  // Move step up
  const moveStepUp = (index: number) => {
    if (index === 0) return;
    const newSteps = [...flowData.steps];
    [newSteps[index - 1], newSteps[index]] = [newSteps[index], newSteps[index - 1]];
    setFlowData({
      ...flowData,
      steps: newSteps
    });
    if (selectedStepIndex === index) {
      setSelectedStepIndex(index - 1);
    } else if (selectedStepIndex === index - 1) {
      setSelectedStepIndex(index);
    }
  };

  // Move step down
  const moveStepDown = (index: number) => {
    if (index === flowData.steps.length - 1) return;
    const newSteps = [...flowData.steps];
    [newSteps[index], newSteps[index + 1]] = [newSteps[index + 1], newSteps[index]];
    setFlowData({
      ...flowData,
      steps: newSteps
    });
    if (selectedStepIndex === index) {
      setSelectedStepIndex(index + 1);
    } else if (selectedStepIndex === index + 1) {
      setSelectedStepIndex(index);
    }
  };

  // Update step
  const updateStep = (index: number, updates: Partial<FlowStep>) => {
    const newSteps = [...flowData.steps];
    newSteps[index] = { ...newSteps[index], ...updates };
    setFlowData({
      ...flowData,
      steps: newSteps
    });
  };

  // Open predicate builder
  const openPredicateBuilder = (
    target: 'entry' | 'exit' | 'precondition' | 'expected',
    stepIndex?: number
  ) => {
    setPredicateTarget(target);
    setSelectedStepForPredicate(stepIndex || null);
    setShowPredicateBuilder(true);
  };

  // Set predicate from builder
  const setPredicate = (predicate: StatePredicate) => {
    if (predicateTarget === 'entry') {
      setFlowData({
        ...flowData,
        entryPoint: predicate
      });
    } else if (predicateTarget === 'exit') {
      setFlowData({
        ...flowData,
        exitPoint: predicate
      });
    } else if (predicateTarget === 'precondition' && selectedStepForPredicate !== null) {
      const newSteps = [...flowData.steps];
      newSteps[selectedStepForPredicate] = {
        ...newSteps[selectedStepForPredicate],
        preconditions: [...newSteps[selectedStepForPredicate].preconditions, predicate]
      };
      setFlowData({
        ...flowData,
        steps: newSteps
      });
    } else if (predicateTarget === 'expected' && selectedStepForPredicate !== null) {
      updateStep(selectedStepForPredicate, { expectedState: predicate });
    }

    setShowPredicateBuilder(false);
    setPredicateTarget(null);
    setSelectedStepForPredicate(null);
  };

  // Remove precondition
  const removePrecondition = (stepIndex: number, preconditionIndex: number) => {
    const newSteps = [...flowData.steps];
    newSteps[stepIndex].preconditions = newSteps[stepIndex].preconditions.filter((_, i) => i !== preconditionIndex);
    setFlowData({
      ...flowData,
      steps: newSteps
    });
  };

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="fixed inset-0 bg-gray-500 bg-opacity-75" onClick={onClose} />

        <div className="relative bg-white rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200">
            <div>
              <h2 className="text-xl font-semibold text-gray-900">
                {flow ? 'Edit Flow' : 'Create New Flow'}
              </h2>
              <p className="text-sm text-gray-500 mt-1">
                Define automated UI interaction sequences with state predicates
              </p>
            </div>
            <div className="flex items-center space-x-3">
              {/* Validation Status */}
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${
                  validationErrors.length > 0 ? 'bg-red-500' :
                  validationWarnings.length > 0 ? 'bg-yellow-500' :
                  completenessScore === 100 ? 'bg-green-500' : 'bg-blue-500'
                }`}></div>
                <span className="text-sm text-gray-600">
                  {completenessScore}% Complete
                </span>
              </div>

              {isDirty && (
                <span className="flex items-center text-sm text-amber-600">
                  <ExclamationTriangleIcon className="w-4 h-4 mr-1" />
                  Unsaved changes
                </span>
              )}

              <button
                onClick={onClose}
                className="p-2 text-gray-400 hover:text-gray-600"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex h-[calc(90vh-200px)]">
            {/* Left Panel - Flow Details */}
            <div className="w-1/3 border-r border-gray-200 overflow-y-auto p-6">
              <div className="space-y-6">
                {/* Basic Information */}
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-3">Basic Information</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Flow Name *
                      </label>
                      <input
                        type="text"
                        value={flowData.name}
                        onChange={(e) => setFlowData({ ...flowData, name: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="e.g., Login Flow"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Description
                      </label>
                      <textarea
                        value={flowData.description}
                        onChange={(e) => setFlowData({ ...flowData, description: e.target.value })}
                        rows={3}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="Describe what this flow does..."
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Package Name *
                      </label>
                      <input
                        type="text"
                        value={flowData.packageName}
                        onChange={(e) => setFlowData({ ...flowData, packageName: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="e.g., com.example.app"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Version
                      </label>
                      <input
                        type="text"
                        value={flowData.version}
                        onChange={(e) => setFlowData({ ...flowData, version: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="1.0.0"
                      />
                    </div>
                  </div>
                </div>

                {/* Entry/Exit Points */}
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-3">Entry & Exit Points</h3>
                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="block text-sm font-medium text-gray-700">
                          Entry Point *
                        </label>
                        <button
                          onClick={() => openPredicateBuilder('entry')}
                          className="text-xs text-blue-600 hover:text-blue-800"
                        >
                          Edit
                        </button>
                      </div>
                      <div className="p-3 bg-gray-50 rounded-md text-xs">
                        <div className="font-medium text-gray-700">Type: {flowData.entryPoint.type}</div>
                        {flowData.entryPoint.stateId && (
                          <div className="text-gray-600">State: {flowData.entryPoint.stateId.substring(0, 8)}...</div>
                        )}
                        {flowData.entryPoint.activity && (
                          <div className="text-gray-600">Activity: {flowData.entryPoint.activity}</div>
                        )}
                        {flowData.entryPoint.containsText && (
                          <div className="text-gray-600">Contains: {flowData.entryPoint.containsText.join(', ')}</div>
                        )}
                      </div>
                    </div>

                    {flowData.exitPoint && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <label className="block text-sm font-medium text-gray-700">
                            Exit Point
                          </label>
                          <button
                            onClick={() => openPredicateBuilder('exit')}
                            className="text-xs text-blue-600 hover:text-blue-800"
                          >
                            Edit
                          </button>
                        </div>
                        <div className="p-3 bg-gray-50 rounded-md text-xs">
                          <div className="font-medium text-gray-700">Type: {flowData.exitPoint.type}</div>
                          {flowData.exitPoint.stateId && (
                            <div className="text-gray-600">State: {flowData.exitPoint.stateId.substring(0, 8)}...</div>
                          )}
                          {flowData.exitPoint.activity && (
                            <div className="text-gray-600">Activity: {flowData.exitPoint.activity}</div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Configuration */}
                <div>
                  <h3 className="text-sm font-medium text-gray-900 mb-3">Configuration</h3>
                  <div className="space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Default Timeout (ms)
                      </label>
                      <input
                        type="number"
                        value={flowData.config?.defaultTimeout || 5000}
                        onChange={(e) => setFlowData({
                          ...flowData,
                          config: { ...flowData.config!, defaultTimeout: parseInt(e.target.value) }
                        })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Retry Attempts
                      </label>
                      <input
                        type="number"
                        value={flowData.config?.retryAttempts || 3}
                        onChange={(e) => setFlowData({
                          ...flowData,
                          config: { ...flowData.config!, retryAttempts: parseInt(e.target.value) }
                        })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Priority
                      </label>
                      <select
                        value={flowData.config?.priority || 'medium'}
                        onChange={(e) => setFlowData({
                          ...flowData,
                          config: { ...flowData.config!, priority: e.target.value as 'low' | 'medium' | 'high' }
                        })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                      </select>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Right Panel - Steps */}
            <div className="flex-1 overflow-y-auto">
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-medium text-gray-900">Flow Steps</h3>
                  <button
                    onClick={addStep}
                    className="flex items-center px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-700"
                  >
                    <PlusIcon className="w-3 h-3 mr-1" />
                    Add Step
                  </button>
                </div>

                {flowData.steps.length === 0 ? (
                  <div className="text-center py-12 bg-gray-50 rounded-lg">
                    <InformationCircleIcon className="w-12 h-12 text-gray-400 mx-auto mb-3" />
                    <p className="text-sm text-gray-600 mb-2">No steps defined yet</p>
                    <p className="text-xs text-gray-500 mb-4">
                      Add steps to define the sequence of actions for this flow
                    </p>
                    <button
                      onClick={addStep}
                      className="inline-flex items-center px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
                    >
                      <PlusIcon className="w-4 h-4 mr-2" />
                      Add First Step
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {flowData.steps.map((step, index) => (
                      <div
                        key={step.id}
                        className={`border rounded-lg transition-colors ${
                          selectedStepIndex === index
                            ? 'border-blue-300 bg-blue-50'
                            : 'border-gray-200 bg-white'
                        }`}
                      >
                        <div
                          className="flex items-center justify-between p-4 cursor-pointer"
                          onClick={() => setSelectedStepIndex(selectedStepIndex === index ? null : index)}
                        >
                          <div className="flex items-center space-x-3">
                            <span className="flex items-center justify-center w-6 h-6 bg-gray-100 text-gray-600 text-xs font-medium rounded-full">
                              {index + 1}
                            </span>
                            <div>
                              <h4 className="text-sm font-medium text-gray-900">{step.name}</h4>
                              <p className="text-xs text-gray-500">
                                {step.action.type}
                                {step.critical && ' • Critical'}
                                {step.timeout && ` • ${step.timeout}ms timeout`}
                              </p>
                            </div>
                          </div>

                          <div className="flex items-center space-x-1">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                moveStepUp(index);
                              }}
                              disabled={index === 0}
                              className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-50"
                            >
                              <ChevronUpIcon className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                moveStepDown(index);
                              }}
                              disabled={index === flowData.steps.length - 1}
                              className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-50"
                            >
                              <ChevronDownIcon className="w-4 h-4" />
                            </button>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                removeStep(index);
                              }}
                              className="p-1 text-red-400 hover:text-red-600"
                            >
                              <TrashIcon className="w-4 h-4" />
                            </button>
                          </div>
                        </div>

                        {selectedStepIndex === index && (
                          <div className="border-t border-gray-200 p-4 bg-gray-50">
                            <div className="space-y-4">
                              {/* Step Name and Description */}
                              <div className="grid grid-cols-2 gap-4">
                                <div>
                                  <label className="block text-xs font-medium text-gray-700 mb-1">
                                    Step Name *
                                  </label>
                                  <input
                                    type="text"
                                    value={step.name}
                                    onChange={(e) => updateStep(index, { name: e.target.value })}
                                    onClick={(e) => e.stopPropagation()}
                                    className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                  />
                                </div>
                                <div>
                                  <label className="block text-xs font-medium text-gray-700 mb-1">
                                    Timeout (ms)
                                  </label>
                                  <input
                                    type="number"
                                    value={step.timeout || 5000}
                                    onChange={(e) => updateStep(index, { timeout: parseInt(e.target.value) })}
                                    onClick={(e) => e.stopPropagation()}
                                    className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                  />
                                </div>
                              </div>

                              <div>
                                <label className="block text-xs font-medium text-gray-700 mb-1">
                                  Description
                                </label>
                                <textarea
                                  value={step.description}
                                  onChange={(e) => updateStep(index, { description: e.target.value })}
                                  onClick={(e) => e.stopPropagation()}
                                  rows={2}
                                  className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                />
                              </div>

                              {/* Action Configuration */}
                              <div>
                                <label className="block text-xs font-medium text-gray-700 mb-2">
                                  Action Configuration
                                </label>
                                <div className="grid grid-cols-2 gap-4">
                                  <div>
                                    <label className="block text-xs text-gray-600 mb-1">Action Type</label>
                                    <select
                                      value={step.action.type}
                                      onChange={(e) => updateStep(index, {
                                        action: { ...step.action, type: e.target.value as UserAction['type'] }
                                      })}
                                      onClick={(e) => e.stopPropagation()}
                                      className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                    >
                                      <option value="tap">Tap</option>
                                      <option value="type">Type</option>
                                      <option value="swipe">Swipe</option>
                                      <option value="back">Back</option>
                                      <option value="intent">Intent</option>
                                      <option value="long_press">Long Press</option>
                                    </select>
                                  </div>

                                  {step.action.type === 'type' && (
                                    <div>
                                      <label className="block text-xs text-gray-600 mb-1">Text to Type</label>
                                      <input
                                        type="text"
                                        value={step.action.text || ''}
                                        onChange={(e) => updateStep(index, {
                                          action: { ...step.action, text: e.target.value }
                                        })}
                                        onClick={(e) => e.stopPropagation()}
                                        className="w-full px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                      />
                                    </div>
                                  )}
                                </div>

                                {/* Semantic Selector Configuration */}
                                {(step.action.type === 'tap' || step.action.type === 'type' || step.action.type === 'long_press') && (
                                  <div className="mt-4 p-3 bg-blue-50 rounded border border-blue-200">
                                    <div className="flex items-center justify-between mb-2">
                                      <label className="block text-xs font-medium text-blue-900">
                                        Semantic Selector (Enhanced Targeting)
                                      </label>
                                      <button
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          updateStep(index, {
                                            action: {
                                              ...step.action,
                                              semanticSelector: {
                                                semanticType: 'unknown',
                                                purpose: '',
                                                confidence: 0.8
                                              }
                                            }
                                          });
                                        }}
                                        className="text-xs text-blue-600 hover:text-blue-800"
                                      >
                                        {step.action.semanticSelector ? 'Edit' : 'Add'} Semantic Info
                                      </button>
                                    </div>

                                    {step.action.semanticSelector && (
                                      <div className="space-y-2">
                                        <div className="grid grid-cols-2 gap-2">
                                          <div>
                                            <label className="block text-xs text-blue-700 mb-1">Semantic Type</label>
                                            <select
                                              value={step.action.semanticSelector.semanticType || 'unknown'}
                                              onChange={(e) => updateStep(index, {
                                                action: {
                                                  ...step.action,
                                                  semanticSelector: {
                                                    ...step.action.semanticSelector!,
                                                    semanticType: e.target.value as any
                                                  }
                                                }
                                              })}
                                              onClick={(e) => e.stopPropagation()}
                                              className="w-full px-2 py-1 text-xs border border-blue-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                            >
                                              <option value="unknown">Unknown</option>
                                              <option value="button">Button</option>
                                              <option value="input">Input Field</option>
                                              <option value="link">Link</option>
                                              <option value="image">Image</option>
                                              <option value="text">Text</option>
                                              <option value="container">Container</option>
                                              <option value="navigation">Navigation</option>
                                              <option value="menu">Menu</option>
                                              <option value="list">List Item</option>
                                            </select>
                                          </div>

                                          <div>
                                            <label className="block text-xs text-blue-700 mb-1">Confidence</label>
                                            <input
                                              type="number"
                                              min="0"
                                              max="1"
                                              step="0.1"
                                              value={step.action.semanticSelector.confidence || 0.8}
                                              onChange={(e) => updateStep(index, {
                                                action: {
                                                  ...step.action,
                                                  semanticSelector: {
                                                    ...step.action.semanticSelector!,
                                                    confidence: parseFloat(e.target.value)
                                                  }
                                                }
                                              })}
                                              onClick={(e) => e.stopPropagation()}
                                              className="w-full px-2 py-1 text-xs border border-blue-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                            />
                                          </div>
                                        </div>

                                        <div>
                                          <label className="block text-xs text-blue-700 mb-1">Purpose/Description</label>
                                          <input
                                            type="text"
                                            value={step.action.semanticSelector.purpose || ''}
                                            onChange={(e) => updateStep(index, {
                                              action: {
                                                ...step.action,
                                                semanticSelector: {
                                                  ...step.action.semanticSelector!,
                                                  purpose: e.target.value
                                                }
                                              }
                                            })}
                                            onClick={(e) => e.stopPropagation()}
                                            className="w-full px-2 py-1 text-xs border border-blue-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                            placeholder="e.g., Login button, Username field, Menu item"
                                          />
                                        </div>

                                        <div>
                                          <label className="block text-xs text-blue-700 mb-1">Nearby Text (comma separated)</label>
                                          <input
                                            type="text"
                                            value={(step.action.semanticSelector.nearText || []).join(', ')}
                                            onChange={(e) => updateStep(index, {
                                              action: {
                                                ...step.action,
                                                semanticSelector: {
                                                  ...step.action.semanticSelector!,
                                                  nearText: e.target.value.split(',').map(t => t.trim()).filter(t => t)
                                                }
                                              }
                                            })}
                                            onClick={(e) => e.stopPropagation()}
                                            className="w-full px-2 py-1 text-xs border border-blue-300 rounded focus:outline-none focus:ring-1 focus:ring-blue-500"
                                            placeholder="e.g., Login, Password, Submit"
                                          />
                                        </div>

                                        <div className="text-xs text-blue-600">
                                          💡 Semantic selectors help find elements even if their exact properties change
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                )}
                              </div>

                              {/* Preconditions */}
                              <div>
                                <div className="flex items-center justify-between mb-2">
                                  <label className="block text-xs font-medium text-gray-700">
                                    Preconditions ({step.preconditions.length})
                                  </label>
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      openPredicateBuilder('precondition', index);
                                    }}
                                    className="text-xs text-blue-600 hover:text-blue-800"
                                  >
                                    Add Precondition
                                  </button>
                                </div>
                                {step.preconditions.length > 0 && (
                                  <div className="space-y-2">
                                    {step.preconditions.map((precondition, predIndex) => (
                                      <div key={predIndex} className="flex items-center justify-between p-2 bg-white rounded border">
                                        <div className="text-xs">
                                          <span className="font-medium">Type:</span> {precondition.type}
                                          {precondition.activity && <span> • {precondition.activity}</span>}
                                          {precondition.containsText && (
                                            <span> • Contains: {precondition.containsText.join(', ')}</span>
                                          )}
                                        </div>
                                        <button
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            removePrecondition(index, predIndex);
                                          }}
                                          className="p-1 text-red-400 hover:text-red-600"
                                        >
                                          <TrashIcon className="w-3 h-3" />
                                        </button>
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>

                              {/* Expected State */}
                              <div>
                                <div className="flex items-center justify-between mb-2">
                                  <label className="block text-xs font-medium text-gray-700">
                                    Expected State
                                  </label>
                                  {step.expectedState ? (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        openPredicateBuilder('expected', index);
                                      }}
                                      className="text-xs text-blue-600 hover:text-blue-800"
                                    >
                                      Edit
                                    </button>
                                  ) : (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        openPredicateBuilder('expected', index);
                                      }}
                                      className="text-xs text-green-600 hover:text-green-800"
                                    >
                                      Add Expected State
                                    </button>
                                  )}
                                </div>
                                {step.expectedState && (
                                  <div className="p-2 bg-white rounded border">
                                    <div className="text-xs">
                                      <span className="font-medium">Type:</span> {step.expectedState.type}
                                      {step.expectedState.activity && <span> • {step.expectedState.activity}</span>}
                                      {step.expectedState.containsText && (
                                        <span> • Contains: {step.expectedState.containsText.join(', ')}</span>
                                      )}
                                    </div>
                                  </div>
                                )}
                              </div>

                              {/* Options */}
                              <div className="flex items-center space-x-4">
                                <label className="flex items-center text-xs">
                                  <input
                                    type="checkbox"
                                    checked={step.critical || false}
                                    onChange={(e) => updateStep(index, { critical: e.target.checked })}
                                    onClick={(e) => e.stopPropagation()}
                                    className="mr-1"
                                  />
                                  Critical step
                                </label>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Validation Errors */}
          {validationErrors.length > 0 && (
            <div className="border-t border-gray-200 p-4 bg-red-50">
              <div className="flex items-start">
                <ExclamationTriangleIcon className="w-5 h-5 text-red-500 mt-0.5 mr-2" />
                <div>
                  <h4 className="text-sm font-medium text-red-900">Validation Errors</h4>
                  <ul className="mt-1 text-xs text-red-700 list-disc list-inside">
                    {validationErrors.map((error, index) => (
                      <li key={index}>{error}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Validation Summary */}
          {(validationWarnings.length > 0 || validationSuggestions.length > 0) && (
            <div className="border-t border-gray-200 p-4 bg-blue-50">
              <div className="space-y-3">
                {validationWarnings.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-blue-900 mb-2">Warnings</h4>
                    <ul className="space-y-1">
                      {validationWarnings.map((warning, index) => (
                        <li key={index} className="flex items-start text-xs text-blue-700">
                          <ExclamationTriangleIcon className="w-3 h-3 mr-1 mt-0.5 flex-shrink-0" />
                          <span>{warning}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {validationSuggestions.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-blue-900 mb-2">Suggestions</h4>
                    <ul className="space-y-1">
                      {validationSuggestions.map((suggestion, index) => (
                        <li key={index} className="flex items-start text-xs text-blue-700">
                          <InformationCircleIcon className="w-3 h-3 mr-1 mt-0.5 flex-shrink-0" />
                          <span>{suggestion}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Footer Actions */}
          <div className="border-t border-gray-200 p-4 bg-gray-50">
            <div className="flex items-center justify-between">
              <div className="text-xs text-gray-500">
                {flowData.steps.length} step{flowData.steps.length !== 1 ? 's' : ''} •
                Complexity: {flowData.metadata.complexity || 0} •
                {validationWarnings.length} warning{validationWarnings.length !== 1 ? 's' : ''}
              </div>

              <div className="flex items-center space-x-3">
                <button
                  onClick={onClose}
                  className="px-4 py-2 text-sm text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSave}
                  disabled={validationErrors.length > 0}
                  className="flex items-center px-4 py-2 text-sm text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  title={validationErrors.length > 0 ? 'Fix validation errors before saving' : 'Save flow'}
                >
                  <CheckCircleIcon className="w-4 h-4 mr-2" />
                  Save Flow
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Predicate Builder Modal */}
      {showPredicateBuilder && (
        <PredicateBuilder
          isVisible={showPredicateBuilder}
          onClose={() => {
            setShowPredicateBuilder(false);
            setPredicateTarget(null);
            setSelectedStepForPredicate(null);
          }}
          onSave={setPredicate}
          graph={graph}
          predicateType={predicateTarget}
        />
      )}
    </div>
  );
};

// Predicate Builder Component
interface PredicateBuilderProps {
  isVisible: boolean;
  onClose: () => void;
  onSave: (predicate: StatePredicate) => void;
  graph?: UIGraph | null;
  predicateType?: 'entry' | 'exit' | 'precondition' | 'expected' | null;
}

const PredicateBuilder: React.FC<PredicateBuilderProps> = ({
  isVisible,
  onClose,
  onSave,
  graph,
  predicateType
}) => {
  const [predicate, setPredicate] = useState<StatePredicate>({
    type: 'contains',
    containsText: ['']
  });

  const handleSave = () => {
    onSave(predicate);
  };

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="fixed inset-0 bg-gray-500 bg-opacity-75" onClick={onClose} />

        <div className="relative bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">
              Build State Predicate
            </h3>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-600"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          <div className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Predicate Type
              </label>
              <select
                value={predicate.type}
                onChange={(e) => setPredicate({
                  ...predicate,
                  type: e.target.value as StatePredicate['type']
                })}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="exact">Exact State Match</option>
                <option value="contains">Contains Text</option>
                <option value="matches">Pattern Match</option>
                <option value="fuzzy">Fuzzy Match</option>
              </select>
            </div>

            {predicate.type === 'exact' && graph && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Select State
                </label>
                <select
                  value={predicate.stateId || ''}
                  onChange={(e) => setPredicate({
                    ...predicate,
                    stateId: e.target.value
                  })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Choose a state...</option>
                  {graph.states.map((state) => (
                    <option key={state.id} value={state.id}>
                      {state.activity} ({state.selectors.length} elements)
                    </option>
                  ))}
                </select>
              </div>
            )}

            {predicate.type === 'contains' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Text to Match (one per line)
                </label>
                <textarea
                  value={predicate.containsText?.join('\n') || ''}
                  onChange={(e) => setPredicate({
                    ...predicate,
                    containsText: e.target.value.split('\n').filter(t => t.trim())
                  })}
                  rows={4}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Enter text that should be present in the state..."
                />
              </div>
            )}

            {predicate.type === 'matches' && (
              <div className="space-y-3">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Activity Pattern
                  </label>
                  <input
                    type="text"
                    value={predicate.matches?.activity || ''}
                    onChange={(e) => setPredicate({
                      ...predicate,
                      matches: { ...predicate.matches!, activity: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="e.g., .*Activity"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Text Pattern
                  </label>
                  <input
                    type="text"
                    value={predicate.matches?.text || ''}
                    onChange={(e) => setPredicate({
                      ...predicate,
                      matches: { ...predicate.matches!, text: e.target.value }
                    })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="e.g., Login|Sign In"
                  />
                </div>
              </div>
            )}

            {predicate.type === 'fuzzy' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Similarity Threshold (0-1)
                </label>
                <input
                  type="number"
                  min="0"
                  max="1"
                  step="0.1"
                  value={predicate.fuzzyThreshold || 0.8}
                  onChange={(e) => setPredicate({
                    ...predicate,
                    fuzzyThreshold: parseFloat(e.target.value)
                  })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Higher values require more exact matches (0.8 = 80% similarity)
                </p>
              </div>
            )}

            {graph && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Selectors (optional)
                </label>
                <div className="max-h-40 overflow-y-auto border border-gray-200 rounded-md p-2">
                  {graph.states.slice(0, 5).map((state) => (
                    <div key={state.id} className="mb-2">
                      <div className="text-xs font-medium text-gray-700 mb-1">
                        {state.activity}
                      </div>
                      <div className="space-y-1">
                        {state.selectors.slice(0, 3).map((selector, idx) => (
                          <label key={idx} className="flex items-center text-xs">
                            <input
                              type="checkbox"
                              className="mr-1"
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setPredicate({
                                    ...predicate,
                                    hasSelectors: [...(predicate.hasSelectors || []), {
                                      rid: selector.rid,
                                      text: selector.text,
                                      desc: selector.desc
                                    }]
                                  });
                                } else {
                                  setPredicate({
                                    ...predicate,
                                    hasSelectors: predicate.hasSelectors?.filter(s =>
                                      !(s.rid === selector.rid && s.text === selector.text)
                                    )
                                  });
                                }
                              }}
                            />
                            {selector.rid || selector.text || selector.desc || 'unnamed'}
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="border-t border-gray-200 p-4 bg-gray-50">
            <div className="flex justify-end space-x-3">
              <button
                onClick={onClose}
                className="px-4 py-2 text-sm text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                className="px-4 py-2 text-sm text-white bg-blue-600 rounded-md hover:bg-blue-700"
              >
                Save Predicate
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FlowEditor;