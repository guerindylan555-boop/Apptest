/**
 * Discovery Panel Component
 *
 * Main UI for manual state discovery, graph building, and transition recording.
 * Replaces GPS panel in the application layout.
 */

import React, { useState, useEffect } from 'react';
import {
  CameraIcon,
  ArrowRightIcon,
  ArrowPathIcon,
  DocumentArrowDownIcon,
  Squares2X2Icon,
  EyeIcon,
  PencilIcon,
  ArrowsRightLeftIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
  PlayIcon,
  PlusIcon,
  DocumentTextIcon,
  FolderIcon,
  Cog6ToothIcon,
  ChevronRightIcon,
  StopIcon
} from '@heroicons/react/24/outline';
import { useDiscovery } from '../../hooks/useDiscovery';
import { useFlow } from '../../hooks/useFlow';
import FlowEditor from './FlowEditor';
// Type definitions for the UI Discovery system
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

interface TransitionRecord {
  id: string;
  from: string;
  to: string;
  action: UserAction;
  evidence?: {
    beforeDigest?: string;
    afterDigest?: string;
    timestamp?: string;
    notes?: string;
    beforeScreenshot?: string;
    afterScreenshot?: string;
  };
  confidence?: number;
  createdAt: string;
  tags?: string[];
}

interface UIGraph {
  version: string;
  createdAt: string;
  updatedAt: string;
  packageName: string;
  states: StateRecord[];
  transitions: TransitionRecord[];
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

// Flow-related types
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

interface FlowExecution {
  executionId: string;
  flowId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused' | 'cancelled';
  startedAt: string;
  completedAt?: string;
  duration?: number;
  currentStep?: number;
  stepHistory: any[];
  summary?: {
    totalSteps: number;
    successfulSteps: number;
    failedSteps: number;
    skippedSteps: number;
    averageStepDuration: number;
  };
  logs?: Array<{
    id: string;
    timestamp: string;
    level: 'debug' | 'info' | 'warn' | 'error';
    message: string;
    stepId?: string;
    data?: any;
  }>;
}

interface DiscoveryPanelProps {
  className?: string;
}

export const DiscoveryPanel: React.FC<DiscoveryPanelProps> = ({ className = '' }) => {
  const {
    graph,
    currentState,
    isCapturing,
    isLoading,
    error,
    captureState,
    getCurrentState,
    createTransition,
    mergeStates,
    refreshGraph,
    clearError
  } = useDiscovery(30000); // Refresh every 30 seconds

  const {
    flows,
    executions,
    flowLoading,
    flowError,
    createFlow,
    updateFlow,
    deleteFlow,
    executeFlow,
    getFlowExecutionStatus,
    getFlowExecutionResult,
    refreshFlows,
    clearFlowError
  } = useFlow(15000); // Refresh every 15 seconds

  // Discovery state
  const [selectedState, setSelectedState] = useState<StateRecord | null>(null);
  const [transitionMode, setTransitionMode] = useState(false);
  const [transitionStart, setTransitionStart] = useState<StateRecord | null>(null);
  const [mergeMode, setMergeMode] = useState(false);
  const [mergeTarget, setMergeTarget] = useState<StateRecord | null>(null);
  const [showGraphMini, setShowGraphMini] = useState(true);

  // Flow state
  const [activeTab, setActiveTab] = useState<'discovery' | 'flows'>('discovery');
  const [selectedFlow, setSelectedFlow] = useState<FlowDefinition | null>(null);
  const [selectedExecution, setSelectedExecution] = useState<FlowExecution | null>(null);
  const [showFlowEditor, setShowFlowEditor] = useState(false);
  const [showFlowExecutor, setShowFlowExecutor] = useState(false);

  // Handle state capture
  const handleCaptureState = async () => {
    try {
      await captureState();
      if (transitionMode && transitionStart) {
        // Complete transition
        await createTransition({
          fromStateId: transitionStart.id,
          action: { type: 'tap' } // Default action
        });
        setTransitionMode(false);
        setTransitionStart(null);
      }
    } catch (error) {
      console.error('Capture failed:', error);
    }
  };

  // Handle transition mode toggle
  const handleTransitionMode = async () => {
    if (transitionMode) {
      // Cancel transition mode
      setTransitionMode(false);
      setTransitionStart(null);
    } else {
      // Start transition mode
      if (currentState) {
        setTransitionMode(true);
        setTransitionStart(currentState);
      } else {
        // Capture current state first
        try {
          const result = await captureState();
          setTransitionMode(true);
          setTransitionStart(result.state);
        } catch (error) {
          console.error('Failed to start transition mode:', error);
        }
      }
    }
  };

  // Handle merge states
  const handleMergeStates = async () => {
    if (!selectedState || !mergeTarget) return;

    try {
      await mergeStates({
        sourceId: selectedState.id,
        targetId: mergeTarget.id
      });
      setMergeMode(false);
      setMergeTarget(null);
      setSelectedState(null);
    } catch (error) {
      console.error('Merge failed:', error);
    }
  };

  // Format duration
  const formatDuration = (ms?: number): string => {
    if (!ms) return 'Unknown';
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  };

  // Format date
  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString();
  };

  // Flow handlers
  const handleCreateFlow = async () => {
    try {
      // Create a temporary flow to open in editor
      const tempFlow: Partial<FlowDefinition> = {
        name: `New Flow ${new Date().toISOString().split('T')[0]}`,
        description: 'Created from current UI state',
        packageName: graph?.packageName || 'unknown',
        steps: [
          {
            id: 'step-1',
            name: 'Initial Action',
            description: 'Starting step',
            preconditions: currentState ? [{
              type: 'exact',
              stateId: currentState.id
            }] : [{
              type: 'contains',
              containsText: ['']
            }],
            action: { type: 'tap' },
            critical: true
          }
        ],
        entryPoint: currentState ? {
          type: 'exact',
          stateId: currentState.id
        } : {
          type: 'contains',
          containsText: ['']
        }
      };

      setSelectedFlow(tempFlow as FlowDefinition);
      setShowFlowEditor(true);
    } catch (error) {
      console.error('Failed to create flow:', error);
    }
  };

  const handleSaveFlow = async (flowData: FlowDefinition) => {
    try {
      if (flowData.id.startsWith('flow-') && !flows?.find(f => f.id === flowData.id)) {
        // New flow - create it
        const createdFlow = await createFlow(flowData);
        setSelectedFlow(createdFlow);
      } else {
        // Existing flow - update it
        await updateFlow(flowData.id, flowData);
        setSelectedFlow(flowData);
      }
      setShowFlowEditor(false);
      refreshFlows();
    } catch (error) {
      console.error('Failed to save flow:', error);
    }
  };

  const handleExecuteFlow = async (flowId: string) => {
    try {
      const executionId = await executeFlow(flowId);
      // Refresh executions after a short delay
      setTimeout(() => refreshFlows(), 1000);
    } catch (error) {
      console.error('Failed to execute flow:', error);
    }
  };

  const handleDeleteFlow = async (flowId: string) => {
    if (!confirm('Are you sure you want to delete this flow?')) return;

    try {
      await deleteFlow(flowId);
      if (selectedFlow?.id === flowId) {
        setSelectedFlow(null);
      }
      refreshFlows();
    } catch (error) {
      console.error('Failed to delete flow:', error);
    }
  };

  const getFlowStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
        return <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500"></div>;
      case 'completed':
        return <CheckCircleIcon className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <XCircleIcon className="w-4 h-4 text-red-500" />;
      case 'pending':
        return <div className="w-4 h-4 bg-yellow-400 rounded-full"></div>;
      default:
        return <div className="w-4 h-4 bg-gray-300 rounded-full"></div>;
    }
  };

  // Get status icon
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'capturing':
      case 'loading':
        return (
          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500"></div>
        );
      case 'success':
        return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'warning':
        return <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" />;
      case 'error':
        return <XCircleIcon className="w-5 h-5 text-red-500" />;
      default:
        return <EyeIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  return (
    <div className={`h-full flex flex-col bg-gray-900 ${className}`}>
      {/* Header with Tabs */}
      <div className="border-b border-gray-700">
        <div className="flex items-center justify-between p-4 border-b border-gray-800">
          <h2 className="text-lg font-semibold text-gray-100">Discovery & Flows</h2>
          <div className="flex items-center space-x-2">
            {getStatusIcon(isCapturing ? 'capturing' : flowError ? 'error' : 'success')}
            <button
              onClick={() => activeTab === 'discovery' ? refreshGraph() : refreshFlows()}
              disabled={isLoading || flowLoading}
              className="p-1 text-gray-400 hover:text-gray-200 disabled:opacity-50 transition-colors"
              title="Refresh"
            >
              <ArrowPathIcon className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex bg-gray-800">
          <button
            onClick={() => setActiveTab('discovery')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'discovery'
                ? 'border-blue-500 text-blue-400 bg-gray-700'
                : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
            }`}
          >
            <div className="flex items-center space-x-2">
              <Squares2X2Icon className="w-4 h-4" />
              <span>Discovery</span>
            </div>
          </button>
          <button
            onClick={() => setActiveTab('flows')}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === 'flows'
                ? 'border-blue-500 text-blue-400 bg-gray-700'
                : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
            }`}
          >
            <div className="flex items-center space-x-2">
              <DocumentTextIcon className="w-4 h-4" />
              <span>Flows</span>
              {flows && flows.length > 0 && (
                <span className="bg-blue-900 text-blue-300 px-2 py-0.5 rounded-full text-xs">
                  {flows.length}
                </span>
              )}
            </div>
          </button>
        </div>
      </div>

      {/* Error Display */}
      {(error || flowError) && (
        <div className="mx-4 mt-4 p-3 bg-red-900 border border-red-700 rounded-md">
          <div className="flex items-start">
            <XCircleIcon className="w-5 h-5 text-red-400 mt-0.5 mr-2" />
            <div className="flex-1">
              <p className="text-sm text-red-200">
                {activeTab === 'discovery' ? error : flowError}
              </p>
              <button
                onClick={() => activeTab === 'discovery' ? clearError() : clearFlowError()}
                className="mt-1 text-xs text-red-300 hover:text-red-100 transition-colors"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="p-4 border-b border-gray-700">
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={handleCaptureState}
            disabled={isCapturing}
            className={`flex items-center justify-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
              isCapturing
                ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50'
            }`}
          >
            <CameraIcon className="w-4 h-4 mr-2" />
            {transitionMode ? 'Complete Transition' : 'Snapshot State'}
          </button>

          <button
            onClick={handleTransitionMode}
            className={`flex items-center justify-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
              transitionMode
                ? 'bg-orange-600 text-white hover:bg-orange-700'
                : 'bg-gray-600 text-white hover:bg-gray-700'
            }`}
          >
            <ArrowRightIcon className="w-4 h-4 mr-2" />
            {transitionMode ? 'Cancel Transition' : 'Mark Transition'}
          </button>

          {!mergeMode ? (
            <button
              onClick={() => setMergeMode(true)}
              disabled={!graph || graph.states.length < 2}
              className="flex items-center justify-center px-3 py-2 text-sm font-medium bg-purple-600 text-white rounded-md hover:bg-purple-700 disabled:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <ArrowsRightLeftIcon className="w-4 h-4 mr-2" />
              Merge States
            </button>
          ) : (
            <>
              <button
                onClick={handleMergeStates}
                disabled={!mergeTarget || !selectedState}
                className="flex items-center justify-center px-3 py-2 text-sm font-medium bg-green-600 text-white rounded-md hover:bg-green-700 disabled:bg-gray-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <CheckCircleIcon className="w-4 h-4 mr-2" />
                Confirm Merge
              </button>
              <button
                onClick={() => {
                  setMergeMode(false);
                  setMergeTarget(null);
                  setSelectedState(null);
                }}
                className="flex items-center justify-center px-3 py-2 text-sm font-medium bg-gray-600 text-white rounded-md hover:bg-gray-700"
              >
                Cancel
              </button>
            </>
          )}

          <button
            onClick={() => setShowGraphMini(!showGraphMini)}
            className="flex items-center justify-center px-3 py-2 text-sm font-medium bg-gray-600 text-white rounded-md hover:bg-gray-700"
          >
            <Squares2X2Icon className="w-4 h-4 mr-2" />
            {showGraphMini ? 'Hide' : 'Show'} Graph
          </button>
        </div>

        {/* Mode Indicators */}
        {transitionMode && transitionStart && (
          <div className="mt-3 p-2 bg-orange-900 border border-orange-700 rounded-md">
            <p className="text-xs text-orange-200">
              Transition mode: From {transitionStart.activity}
            </p>
          </div>
        )}

        {mergeMode && (
          <div className="mt-3 p-2 bg-purple-900 border border-purple-700 rounded-md">
            <p className="text-xs text-purple-200">
              Merge mode: Select target state to merge {selectedState?.activity || 'selected state'} into
            </p>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-y-auto">
        {activeTab === 'discovery' ? (
          <>
            {/* Current State Display */}
            {currentState && (
          <div className="p-4 border-b border-gray-700">
            <h3 className="text-sm font-semibold text-gray-100 mb-2">Current State</h3>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-400">Activity:</span>
                <span className="font-mono text-gray-200">{currentState.activity}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Package:</span>
                <span className="font-mono text-xs truncate ml-2 text-gray-200">{currentState.package}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Elements:</span>
                <span className="text-gray-200">{currentState.selectors.length}</span>
              </div>
              {currentState.metadata?.captureDuration && (
                <div className="flex justify-between">
                  <span className="text-gray-400">Capture Time:</span>
                  <span className="text-gray-200">{formatDuration(currentState.metadata.captureDuration)}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-gray-400">Captured:</span>
                <span className="text-gray-200">{formatDate(currentState.createdAt)}</span>
              </div>
            </div>

            {/* Screenshot */}
            {currentState.screenshot && (
              <div className="mt-3">
                <img
                  src={`/api/state/${currentState.id}/screenshot`}
                  alt="Current state screenshot"
                  className="w-full h-32 object-cover border border-gray-600 rounded"
                />
              </div>
            )}
          </div>
        )}

        {/* Interactive Elements */}
        {currentState && currentState.selectors.length > 0 && (
          <div className="p-4 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900 mb-2">Interactive Elements</h3>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {currentState.selectors.slice(0, 10).map((selector: Selector, index: number) => (
                <div key={index} className="p-2 bg-gray-50 rounded text-xs">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      {selector.rid && (
                        <div className="font-mono text-blue-600 truncate">
                          {selector.rid}
                        </div>
                      )}
                      {selector.text && (
                        <div className="text-gray-700 truncate">
                          "{selector.text}"
                        </div>
                      )}
                      {selector.desc && (
                        <div className="text-gray-500 truncate">
                          {selector.desc}
                        </div>
                      )}
                      <div className="text-gray-400">
                        {selector.cls?.split('.').pop()}
                      </div>
                    </div>
                    {selector.bounds && (
                      <div className="ml-2 text-gray-400 text-xs">
                        [{selector.bounds[0]}, {selector.bounds[1]}]
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {currentState.selectors.length > 10 && (
                <p className="text-xs text-gray-500 text-center">
                  ... and {currentState.selectors.length - 10} more
                </p>
              )}
            </div>
          </div>
        )}

        {/* Graph Mini-Map */}
        {showGraphMini && graph && (
          <div className="p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-gray-900">Graph Overview</h3>
              <span className="text-xs text-gray-500">
                {graph.states.length} states, {graph.transitions.length} transitions
              </span>
            </div>

            {/* Simple graph visualization */}
            <div className="bg-gray-50 rounded p-3 min-h-32">
              {graph.states.length === 0 ? (
                <p className="text-xs text-gray-500 text-center">
                  No states captured yet. Take your first snapshot!
                </p>
              ) : (
                <div className="space-y-2">
                  {/* Group states by activity */}
                  {Array.from(new Set(graph.states.map(s => s.activity))).map(activity => {
                    const activityStates = graph.states.filter(s => s.activity === activity);
                    return (
                      <div key={activity} className="text-xs">
                        <div className="font-medium text-gray-700 mb-1 truncate">
                          {activity}
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {activityStates.map((state: StateRecord) => (
                            <div
                              key={state.id}
                              onClick={() => {
                                if (mergeMode && selectedState && selectedState.id !== state.id) {
                                  setMergeTarget(state);
                                } else if (!mergeMode) {
                                  setSelectedState(state);
                                }
                              }}
                              className={`px-2 py-1 rounded cursor-pointer transition-colors ${
                                selectedState?.id === state.id
                                  ? 'bg-blue-100 border-blue-300'
                                  : mergeTarget?.id === state.id
                                  ? 'bg-purple-100 border-purple-300'
                                  : currentState?.id === state.id
                                  ? 'bg-green-100 border-green-300'
                                  : 'bg-white border-gray-300'
                              } border text-xs`}
                              title={`${state.activity}\n${state.selectors.length} elements`}
                            >
                              {state.selectors.length}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Export buttons */}
            <div className="mt-3 flex space-x-2">
              <button
                onClick={() => {
                  const dataStr = JSON.stringify(graph, null, 2);
                  const dataBlob = new Blob([dataStr], { type: 'application/json' });
                  const url = URL.createObjectURL(dataBlob);
                  const link = document.createElement('a');
                  link.href = url;
                  link.download = `graph-${new Date().toISOString().split('T')[0]}.json`;
                  link.click();
                  URL.revokeObjectURL(url);
                }}
                className="flex items-center px-2 py-1 text-xs bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                <DocumentArrowDownIcon className="w-3 h-3 mr-1" />
                Export Graph
              </button>
            </div>
          </div>
        )}
          </>
        ) : (
          <>
            {/* Flow Management UI */}
            <div className="p-4 border-b border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-gray-900">Flow Management</h3>
                <button
                  onClick={handleCreateFlow}
                  disabled={flowLoading}
                  className="flex items-center px-3 py-1.5 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                >
                  <PlusIcon className="w-3 h-3 mr-1" />
                  Create Flow
                </button>
              </div>

              {/* Flow List */}
              <div className="space-y-2">
                {flows && flows.length > 0 ? (
                  flows.map((flow: FlowDefinition) => (
                    <div
                      key={flow.id}
                      className="border border-gray-600 rounded-lg p-3 hover:bg-gray-700 cursor-pointer transition-colors"
                      onClick={() => setSelectedFlow(flow)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2">
                            <h4 className="text-sm font-medium text-gray-100 truncate">{flow.name}</h4>
                            <span className="text-xs text-gray-400">v{flow.version}</span>
                          </div>
                          {flow.description && (
                            <p className="text-xs text-gray-300 mt-1 line-clamp-2">{flow.description}</p>
                          )}
                          <div className="flex items-center space-x-4 mt-2 text-xs text-gray-400">
                            <span>{flow.steps.length} steps</span>
                            <span>Complexity: {flow.metadata.complexity || 0}</span>
                            {flow.metadata.executionCount !== undefined && (
                              <span>Runs: {flow.metadata.executionCount}</span>
                            )}
                            {flow.metadata.successRate !== undefined && (
                              <span>Success: {Math.round(flow.metadata.successRate * 100)}%</span>
                            )}
                          </div>
                          {flow.metadata.tags && flow.metadata.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {flow.metadata.tags.map((tag, index) => (
                                <span
                                  key={index}
                                  className="px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded text-xs"
                                >
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="flex items-center space-x-1 ml-3">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleExecuteFlow(flow.id);
                            }}
                            disabled={flowLoading}
                            className="p-1 text-green-600 hover:text-green-800 disabled:opacity-50"
                            title="Execute Flow"
                          >
                            <PlayIcon className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setShowFlowEditor(true);
                            }}
                            className="p-1 text-blue-600 hover:text-blue-800"
                            title="Edit Flow"
                          >
                            <PencilIcon className="w-4 h-4" />
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteFlow(flow.id);
                            }}
                            className="p-1 text-red-600 hover:text-red-800"
                            title="Delete Flow"
                          >
                            <XCircleIcon className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8">
                    <FolderIcon className="w-12 h-12 text-gray-500 mx-auto mb-3" />
                    <p className="text-sm text-gray-400 mb-4">No flows created yet</p>
                    <button
                      onClick={handleCreateFlow}
                      disabled={flowLoading}
                      className="inline-flex items-center px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                    >
                      <PlusIcon className="w-4 h-4 mr-2" />
                      Create Your First Flow
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Flow Details */}
            {selectedFlow && (
              <div className="p-4 border-b border-gray-200">
                <h3 className="text-sm font-semibold text-gray-900 mb-3">Flow Details</h3>
                <div className="space-y-3">
                  <div className="bg-gray-50 rounded p-3">
                    <h4 className="text-xs font-medium text-gray-700 mb-2">Entry Point</h4>
                    <div className="text-xs text-gray-600">
                      <span className="font-medium">Type:</span> {selectedFlow.entryPoint.type}
                      {selectedFlow.entryPoint.stateId && (
                        <div>
                          <span className="font-medium">State:</span>
                          <span className="font-mono ml-1">{selectedFlow.entryPoint.stateId.substring(0, 8)}...</span>
                        </div>
                      )}
                      {selectedFlow.entryPoint.activity && (
                        <div>
                          <span className="font-medium">Activity:</span> {selectedFlow.entryPoint.activity}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="bg-gray-800 rounded p-3 border border-gray-700">
                    <h4 className="text-xs font-medium text-gray-200 mb-2">Steps ({selectedFlow.steps.length})</h4>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {selectedFlow.steps.map((step, index) => (
                        <div key={step.id} className="flex items-center space-x-2 text-xs">
                          <span className="text-gray-400">#{index + 1}</span>
                          <span className="font-medium">{step.name}</span>
                          <ChevronRightIcon className="w-3 h-3 text-gray-400" />
                          <span className="text-gray-300">{step.action.type}</span>
                          {step.critical && (
                            <span className="px-1 py-0.5 bg-red-100 text-red-600 rounded">Critical</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="flex space-x-2">
                    <button
                      onClick={() => handleExecuteFlow(selectedFlow.id)}
                      disabled={flowLoading}
                      className="flex items-center px-3 py-1.5 text-xs bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
                    >
                      <PlayIcon className="w-3 h-3 mr-1" />
                      Execute Flow
                    </button>
                    <button
                      onClick={() => setShowFlowEditor(true)}
                      className="flex items-center px-3 py-1.5 text-xs bg-gray-600 text-white rounded hover:bg-gray-700"
                    >
                      <PencilIcon className="w-3 h-3 mr-1" />
                      Edit Flow
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Flow Executions */}
            {executions && executions.length > 0 && (
              <div className="p-4 border-b border-gray-700">
                <h3 className="text-sm font-semibold text-gray-100 mb-3">Recent Executions</h3>
                <div className="space-y-2">
                  {executions.slice(0, 5).map((execution: FlowExecution) => (
                    <div
                      key={execution.executionId}
                      className="flex items-center justify-between p-2 bg-gray-800 rounded border border-gray-700"
                    >
                      <div className="flex items-center space-x-2">
                        {getFlowStatusIcon(execution.status)}
                        <div>
                          <div className="text-xs font-medium text-gray-200">{execution.executionId.substring(0, 8)}...</div>
                          <div className="text-xs text-gray-400">
                            {formatDate(execution.startedAt)}
                            {execution.duration && ` • ${formatDuration(execution.duration)}`}
                          </div>
                        </div>
                      </div>
                      {execution.summary && (
                        <div className="text-xs text-gray-400">
                          {execution.summary.successfulSteps}/{execution.summary.totalSteps} steps
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Flow Library Info */}
            <div className="p-4">
              <h3 className="text-sm font-semibold text-gray-100 mb-3">Flow Library</h3>
              <div className="bg-blue-900 border border-blue-700 rounded p-3">
                <div className="flex items-center space-x-2 mb-2">
                  <DocumentTextIcon className="w-4 h-4 text-blue-400" />
                  <span className="text-xs font-medium text-blue-200">Flow Management</span>
                </div>
                <p className="text-xs text-blue-300">
                  Create and manage reusable UI automation flows. Flows capture sequences of actions and state transitions
                  that can be executed automatically for testing and navigation.
                </p>
                <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-blue-400">
                  <div>• {flows?.length || 0} flows created</div>
                  <div>• {executions?.length || 0} executions</div>
                </div>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Flow Editor Modal */}
      <FlowEditor
        flow={selectedFlow}
        graph={graph}
        isVisible={showFlowEditor}
        onClose={() => setShowFlowEditor(false)}
        onSave={handleSaveFlow}
      />
    </div>
  );
};

export default DiscoveryPanel;