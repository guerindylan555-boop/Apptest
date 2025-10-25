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
  XCircleIcon
} from '@heroicons/react/24/outline';
import { useDiscovery } from '../../hooks/useDiscovery';
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

  const [selectedState, setSelectedState] = useState<StateRecord | null>(null);
  const [transitionMode, setTransitionMode] = useState(false);
  const [transitionStart, setTransitionStart] = useState<StateRecord | null>(null);
  const [mergeMode, setMergeMode] = useState(false);
  const [mergeTarget, setMergeTarget] = useState<StateRecord | null>(null);
  const [showGraphMini, setShowGraphMini] = useState(true);

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
    <div className={`h-full flex flex-col bg-white border-l border-gray-200 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <h2 className="text-lg font-semibold text-gray-900">UI Discovery</h2>
        <div className="flex items-center space-x-2">
          {getStatusIcon(isCapturing ? 'capturing' : error ? 'error' : 'success')}
          <button
            onClick={refreshGraph}
            disabled={isLoading}
            className="p-1 text-gray-500 hover:text-gray-700 disabled:opacity-50"
            title="Refresh"
          >
            <ArrowPathIcon className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="mx-4 mt-4 p-3 bg-red-50 border border-red-200 rounded-md">
          <div className="flex items-start">
            <XCircleIcon className="w-5 h-5 text-red-500 mt-0.5 mr-2" />
            <div className="flex-1">
              <p className="text-sm text-red-700">{error}</p>
              <button
                onClick={clearError}
                className="mt-1 text-xs text-red-600 hover:text-red-800"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="p-4 border-b border-gray-200">
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={handleCaptureState}
            disabled={isCapturing}
            className={`flex items-center justify-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
              isCapturing
                ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700'
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
              className="flex items-center justify-center px-3 py-2 text-sm font-medium bg-purple-600 text-white rounded-md hover:bg-purple-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
            >
              <ArrowsRightLeftIcon className="w-4 h-4 mr-2" />
              Merge States
            </button>
          ) : (
            <>
              <button
                onClick={handleMergeStates}
                disabled={!mergeTarget || !selectedState}
                className="flex items-center justify-center px-3 py-2 text-sm font-medium bg-green-600 text-white rounded-md hover:bg-green-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
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
          <div className="mt-3 p-2 bg-orange-50 border border-orange-200 rounded-md">
            <p className="text-xs text-orange-700">
              Transition mode: From {transitionStart.activity}
            </p>
          </div>
        )}

        {mergeMode && (
          <div className="mt-3 p-2 bg-purple-50 border border-purple-200 rounded-md">
            <p className="text-xs text-purple-700">
              Merge mode: Select target state to merge {selectedState?.activity || 'selected state'} into
            </p>
          </div>
        )}
      </div>

      {/* Current State Display */}
      <div className="flex-1 overflow-y-auto">
        {currentState && (
          <div className="p-4 border-b border-gray-200">
            <h3 className="text-sm font-semibold text-gray-900 mb-2">Current State</h3>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-gray-600">Activity:</span>
                <span className="font-mono">{currentState.activity}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Package:</span>
                <span className="font-mono text-xs truncate ml-2">{currentState.package}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600">Elements:</span>
                <span>{currentState.selectors.length}</span>
              </div>
              {currentState.metadata?.captureDuration && (
                <div className="flex justify-between">
                  <span className="text-gray-600">Capture Time:</span>
                  <span>{formatDuration(currentState.metadata.captureDuration)}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-gray-600">Captured:</span>
                <span>{formatDate(currentState.createdAt)}</span>
              </div>
            </div>

            {/* Screenshot */}
            {currentState.screenshot && (
              <div className="mt-3">
                <img
                  src={`/api/state/${currentState.id}/screenshot`}
                  alt="Current state screenshot"
                  className="w-full h-32 object-cover border border-gray-300 rounded"
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
      </div>
    </div>
  );
};

export default DiscoveryPanel;