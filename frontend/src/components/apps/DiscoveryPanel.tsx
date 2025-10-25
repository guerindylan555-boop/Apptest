/**
 * Discovery Panel Component
 *
 * Main UI for manual state discovery, graph building, and transition recording.
 * Replaces GPS panel in the application layout.
 */

import React, { useState, useEffect, useMemo } from 'react';
import clsx from 'clsx';
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
  TrashIcon,
  ChevronRightIcon
} from '@heroicons/react/24/outline';
import { useDiscovery } from '../../hooks/useDiscovery';
import { useFlow } from '../../hooks/useFlow';
import FlowEditor from './FlowEditor';
import '../../styles/discovery-panel.css';
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
    extras?: Record<string, unknown>;
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

// eslint-disable-next-line @typescript-eslint/no-unused-vars
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
  stepHistory: unknown[];
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
    data?: unknown;
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
  const [showFlowEditor, setShowFlowEditor] = useState(false);

  const stateList = useMemo(() => graph?.states ?? [], [graph]);
  const flowsList = useMemo(() => flows ?? [], [flows]);
  const executionsList: FlowExecution[] = useMemo(() => executions ?? [], [executions]);
  const transitionsPreview = useMemo(
    () => (graph?.transitions ?? []).slice(0, 6),
    [graph]
  );

  const activityGroups = useMemo(() => {
    if (!graph) return [];
    const groups = graph.states.reduce<Record<string, StateRecord[]>>((acc, state) => {
      acc[state.activity] = acc[state.activity] ? [...acc[state.activity], state] : [state];
      return acc;
    }, {});
    return Object.entries(groups)
      .map(([activity, states]) => ({
        activity,
        states,
        count: states.length
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 4);
  }, [graph]);

  const discoveryStats = useMemo(() => {
    const statesCount = graph?.stats?.stateCount ?? graph?.states?.length ?? 0;
    const transitionsCount = graph?.stats?.transitionCount ?? graph?.transitions?.length ?? 0;
    return {
      states: statesCount,
      transitions: transitionsCount,
      averageDegree: graph?.stats?.averageDegree ?? 0,
      isolatedStates: graph?.stats?.isolatedStates ?? 0,
      lastCapture: graph?.stats?.lastCapture ?? graph?.updatedAt
    };
  }, [graph]);

  const selectorPreview = useMemo(() => {
    const source = selectedState ?? currentState;
    return source?.selectors.slice(0, 10) ?? [];
  }, [selectedState, currentState]);

  useEffect(() => {
    if (!selectedState && currentState) {
      setSelectedState(currentState);
    }
  }, [currentState, selectedState]);

  useEffect(() => {
    if (!selectedFlow && flowsList.length > 0) {
      setSelectedFlow(flowsList[0]);
    }
  }, [flowsList, selectedFlow]);

  const handleStateSelection = (state: StateRecord) => {
    if (mergeMode && selectedState && selectedState.id !== state.id) {
      setMergeTarget(state);
      return;
    }
    setSelectedState(state);
  };

  const handleExportGraph = () => {
    if (!graph) return;
    const data = JSON.stringify(graph, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `graph-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const renderStateLibrary = () => {
    if (!stateList.length) {
      return (
        <p className="discovery-panel__empty">
          Capture at least one screen to build the discovery graph.
        </p>
      );
    }

    return (
      <ul className="discovery-panel__state-list">
        {stateList.map((state) => {
          const isSelected = selectedState?.id === state.id;
          const isCurrent = currentState?.id === state.id;
          const isTarget = mergeTarget?.id === state.id;

          return (
            <li
              key={state.id}
              className={clsx('discovery-panel__state-row', {
                'is-selected': isSelected,
                'is-current': isCurrent,
                'is-target': isTarget
              })}
              onClick={() => handleStateSelection(state)}
            >
              <div>
                <p className="discovery-panel__state-name">{state.activity}</p>
                <p className="discovery-panel__state-meta">
                  {new Date(state.updatedAt).toLocaleTimeString()}
                </p>
              </div>
              <div className="discovery-panel__state-tags">
                <span className="discovery-panel__chip">
                  {state.selectors.length} nodes
                </span>
                {isCurrent && (
                  <span className="discovery-panel__chip discovery-panel__chip--accent">
                    live
                  </span>
                )}
                {isTarget && (
                  <span className="discovery-panel__chip discovery-panel__chip--warning">
                    target
                  </span>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    );
  };

  const renderSelectorList = () => {
    if (!selectorPreview.length) {
      return (
        <p className="discovery-panel__empty">
          No interactive elements recorded for this state yet.
        </p>
      );
    }

    return (
      <ul className="discovery-panel__selector-list">
        {selectorPreview.map((selector, index) => (
          <li key={selector.rid ?? selector.text ?? index} className="discovery-panel__selector-row">
            <div>
              {selector.rid && (
                <p className="discovery-panel__mono">{selector.rid}</p>
              )}
              {selector.text && (
                <p className="discovery-panel__selector-text">&ldquo;{selector.text}&rdquo;</p>
              )}
              {selector.desc && (
                <p className="discovery-panel__selector-desc">{selector.desc}</p>
              )}
              {selector.cls && (
                <p className="discovery-panel__selector-meta">
                  {selector.cls.split('.').pop()}
                </p>
              )}
            </div>
            {selector.bounds && (
              <span className="discovery-panel__chip discovery-panel__chip--outline">
                [{selector.bounds[0]}, {selector.bounds[1]}]
              </span>
            )}
          </li>
        ))}
      </ul>
    );
  };

  const renderGraphOverview = () => {
    if (!graph) {
      return (
        <p className="discovery-panel__empty">
          Graph data is not available yet.
        </p>
      );
    }

    return (
      <>
        <div className="discovery-panel__stat-grid discovery-panel__stat-grid--compact">
          <div className="discovery-panel__stat">
            <p className="discovery-panel__stat-label">States</p>
            <p className="discovery-panel__stat-value">{discoveryStats.states}</p>
          </div>
          <div className="discovery-panel__stat">
            <p className="discovery-panel__stat-label">Transitions</p>
            <p className="discovery-panel__stat-value">{discoveryStats.transitions}</p>
          </div>
          <div className="discovery-panel__stat">
            <p className="discovery-panel__stat-label">Avg Degree</p>
            <p className="discovery-panel__stat-value">
              {discoveryStats.averageDegree.toFixed(1)}
            </p>
          </div>
          <div className="discovery-panel__stat">
            <p className="discovery-panel__stat-label">Isolated</p>
            <p className="discovery-panel__stat-value">{discoveryStats.isolatedStates}</p>
          </div>
        </div>

        <div className="discovery-panel__activity-groups">
          {activityGroups.map((group) => (
            <div key={group.activity} className="discovery-panel__activity-card">
              <p className="discovery-panel__activity-name">{group.activity}</p>
              <p className="discovery-panel__activity-count">
                {group.count} state{group.count === 1 ? '' : 's'}
              </p>
            </div>
          ))}
          {!activityGroups.length && (
            <p className="discovery-panel__empty">
              Capture a few screens to build activity clusters.
            </p>
          )}
        </div>

        {transitionsPreview.length > 0 && (
          <div className="discovery-panel__timeline">
            {transitionsPreview.map((transition) => (
              <div key={transition.id} className="discovery-panel__timeline-row">
                <div>
                  <p className="discovery-panel__timeline-label">{transition.action.type}</p>
                  <p className="discovery-panel__timeline-meta">
                    {formatDate(transition.createdAt)}
                  </p>
                </div>
                <div className="discovery-panel__timeline-state">
                  <span>{transition.from.slice(0, 6)}</span>
                  <ChevronRightIcon className="discovery-panel__icon discovery-panel__icon--muted" />
                  <span>{transition.to.slice(0, 6)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </>
    );
  };

  const renderDiscoveryContent = () => {
    if (isLoading && !stateList.length) {
      return (
        <div className="discovery-panel__placeholder">
          <span className="discovery-panel__spinner" aria-hidden />
          <p>Loading discovery data…</p>
        </div>
      );
    }

    if (!graph || (!stateList.length && !currentState)) {
      return (
        <div className="discovery-panel__placeholder">
          <div className="discovery-panel__placeholder-icon">
            <Squares2X2Icon className="discovery-panel__icon discovery-panel__icon--muted" />
          </div>
          <p className="discovery-panel__placeholder-title">No states captured yet</p>
          <p className="discovery-panel__placeholder-text">
            Take your first snapshot to start building the UI map.
          </p>
        </div>
      );
    }

    const referenceState = selectedState ?? currentState;

    return (
      <div className="discovery-panel__layout">
        <div className="discovery-panel__column discovery-panel__column--primary">
          <section className="discovery-panel__card discovery-panel__card--highlight">
            <div className="discovery-panel__card-header">
              <div>
                <p className="discovery-panel__eyebrow">Current Snapshot</p>
                <h3 className="discovery-panel__card-title">
                  {currentState?.activity ?? 'No active state'}
                </h3>
              </div>
              <button
                type="button"
                className="discovery-panel__button discovery-panel__button--ghost discovery-panel__button--small"
                onClick={() => {
                  void getCurrentState?.();
                }}
              >
                <ArrowPathIcon className="discovery-panel__icon" />
                Sync
              </button>
            </div>
            <div className="discovery-panel__meta-grid">
              <div>
                <p className="discovery-panel__meta-label">Package</p>
                <p className="discovery-panel__meta-value">
                  {currentState?.package ?? graph?.packageName ?? 'unknown'}
                </p>
              </div>
              <div>
                <p className="discovery-panel__meta-label">Captured</p>
                <p className="discovery-panel__meta-value">
                  {currentState?.updatedAt ? formatDate(currentState.updatedAt) : 'Not captured'}
                </p>
              </div>
              <div>
                <p className="discovery-panel__meta-label">Element Count</p>
                <p className="discovery-panel__meta-value">
                  {currentState?.metadata?.elementCount ?? '—'}
                </p>
              </div>
            </div>
          </section>

          <section className="discovery-panel__card">
            <div className="discovery-panel__card-header">
              <div>
                <p className="discovery-panel__eyebrow">Focused State</p>
                <h3 className="discovery-panel__card-title">
                  {referenceState ? referenceState.activity : 'Select a state'}
                </h3>
              </div>
              {referenceState && (
                <span className="discovery-panel__chip discovery-panel__chip--outline">
                  {referenceState.selectors.length} selectors
                </span>
              )}
            </div>

            {referenceState ? (
              <>
                <div className="discovery-panel__meta-grid">
                  <div>
                    <p className="discovery-panel__meta-label">Digest</p>
                    <p className="discovery-panel__meta-value discovery-panel__mono">
                      {referenceState.digest.slice(0, 8)}
                    </p>
                  </div>
                  <div>
                    <p className="discovery-panel__meta-label">Captured</p>
                    <p className="discovery-panel__meta-value">
                      {formatDate(referenceState.updatedAt)}
                    </p>
                  </div>
                  <div>
                    <p className="discovery-panel__meta-label">Capture Method</p>
                    <p className="discovery-panel__meta-value">
                      {referenceState.metadata?.captureMethod ?? 'n/a'}
                    </p>
                  </div>
                </div>

                {referenceState.tags && referenceState.tags.length > 0 && (
                  <div className="discovery-panel__tags">
                    {referenceState.tags.map((tag) => (
                      <span key={tag} className="discovery-panel__chip discovery-panel__chip--accent">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}

                <h4 className="discovery-panel__section-title">Interactive elements</h4>
                {renderSelectorList()}
              </>
            ) : (
              <p className="discovery-panel__empty">
                Select a state from the library to inspect it.
              </p>
            )}
          </section>

          {showGraphMini && (
            <section className="discovery-panel__card">
              <div className="discovery-panel__card-header">
                <div>
                  <p className="discovery-panel__eyebrow">Graph Overview</p>
                  <h3 className="discovery-panel__card-title">State coverage</h3>
                </div>
                <button
                  type="button"
                  className="discovery-panel__button discovery-panel__button--ghost discovery-panel__button--small"
                  onClick={handleExportGraph}
                >
                  <DocumentArrowDownIcon className="discovery-panel__icon" />
                  Export
                </button>
              </div>
              {renderGraphOverview()}
            </section>
          )}
        </div>

        <div className="discovery-panel__column discovery-panel__column--secondary">
          <section className="discovery-panel__card">
            <div className="discovery-panel__card-header">
              <div>
                <p className="discovery-panel__eyebrow">Discovery Stats</p>
                <h3 className="discovery-panel__card-title">Coverage snapshot</h3>
              </div>
              {discoveryStats.lastCapture && (
                <span className="discovery-panel__meta-label">
                  Updated {formatDate(discoveryStats.lastCapture)}
                </span>
              )}
            </div>
            <div className="discovery-panel__stat-grid">
              <div className="discovery-panel__stat">
                <p className="discovery-panel__stat-label">States</p>
                <p className="discovery-panel__stat-value">{discoveryStats.states}</p>
              </div>
              <div className="discovery-panel__stat">
                <p className="discovery-panel__stat-label">Transitions</p>
                <p className="discovery-panel__stat-value">{discoveryStats.transitions}</p>
              </div>
              <div className="discovery-panel__stat">
                <p className="discovery-panel__stat-label">Avg Degree</p>
                <p className="discovery-panel__stat-value">
                  {discoveryStats.averageDegree.toFixed(1)}
                </p>
              </div>
              <div className="discovery-panel__stat">
                <p className="discovery-panel__stat-label">Isolated</p>
                <p className="discovery-panel__stat-value">{discoveryStats.isolatedStates}</p>
              </div>
            </div>
          </section>

          <section className="discovery-panel__card discovery-panel__card--scroll">
            <div className="discovery-panel__card-header">
              <div>
                <p className="discovery-panel__eyebrow">State Library</p>
                <h3 className="discovery-panel__card-title">{stateList.length} captured</h3>
              </div>
            </div>
            {renderStateLibrary()}
          </section>
        </div>
      </div>
    );
  };

  const renderFlowView = () => {
    return (
      <div className="discovery-panel__layout discovery-panel__layout--flow">
        <div className="discovery-panel__column discovery-panel__column--secondary">
          <section className="discovery-panel__card">
            <div className="discovery-panel__card-header">
              <div>
                <p className="discovery-panel__eyebrow">Flow Library</p>
                <h3 className="discovery-panel__card-title">Automation blueprints</h3>
              </div>
              <button
                type="button"
                className="discovery-panel__button discovery-panel__button--primary discovery-panel__button--small"
                onClick={handleCreateFlow}
                disabled={flowLoading}
              >
                <PlusIcon className="discovery-panel__icon" />
                New flow
              </button>
            </div>
            {flowLoading ? (
              <div className="discovery-panel__placeholder discovery-panel__placeholder--dense">
                <span className="discovery-panel__spinner" aria-hidden />
                <p>Loading flows…</p>
              </div>
            ) : flowsList.length ? (
              <ul className="discovery-panel__flow-list">
                {flowsList.map((flow) => (
                  <li
                    key={flow.id}
                    className={clsx('discovery-panel__flow-row', {
                      'is-active': selectedFlow?.id === flow.id
                    })}
                    onClick={() => setSelectedFlow(flow)}
                  >
                    <div>
                      <p className="discovery-panel__flow-name">{flow.name}</p>
                      {flow.description && (
                        <p className="discovery-panel__flow-description">{flow.description}</p>
                      )}
                      <div className="discovery-panel__flow-meta">
                        <span>{flow.steps.length} steps</span>
                        <span>v{flow.version}</span>
                        {typeof flow.metadata?.successRate === 'number' && (
                          <span>{Math.round(flow.metadata.successRate * 100)}% success</span>
                        )}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="discovery-panel__button discovery-panel__button--ghost discovery-panel__button--icon"
                      onClick={(event) => {
                        event.stopPropagation();
                        handleExecuteFlow(flow.id);
                      }}
                      disabled={flowLoading}
                      title="Execute flow"
                    >
                      <PlayIcon className="discovery-panel__icon" />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="discovery-panel__empty">
                No flows defined. Create one to automate this UI.
              </p>
            )}
          </section>

          <section className="discovery-panel__card">
            <div className="discovery-panel__card-header">
              <div>
                <p className="discovery-panel__eyebrow">Recent activity</p>
                <h3 className="discovery-panel__card-title">Flow executions</h3>
              </div>
            </div>
            {executionsList.length > 0 ? (
              <ul className="discovery-panel__execution-list">
                {executionsList.slice(0, 5).map((execution) => (
                  <li key={execution.executionId} className="discovery-panel__execution-row">
                    <div className="discovery-panel__execution-status">
                      {getFlowStatusIcon(execution.status)}
                      <div>
                        <p className="discovery-panel__execution-id">
                          {execution.executionId.substring(0, 8)}…
                        </p>
                        <p className="discovery-panel__execution-meta">
                          {formatDate(execution.startedAt)}
                          {execution.duration && ` • ${formatDuration(execution.duration)}`}
                        </p>
                      </div>
                    </div>
                    {execution.summary && (
                      <span className="discovery-panel__chip discovery-panel__chip--outline">
                        {execution.summary.successfulSteps}/{execution.summary.totalSteps} steps
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="discovery-panel__empty">
                No execution history available.
              </p>
            )}
          </section>
        </div>

        <div className="discovery-panel__column discovery-panel__column--primary">
          <section className="discovery-panel__card discovery-panel__card--highlight">
            {selectedFlow ? (
              <>
                <div className="discovery-panel__card-header">
                  <div>
                    <p className="discovery-panel__eyebrow">Flow details</p>
                    <h3 className="discovery-panel__card-title">{selectedFlow.name}</h3>
                    {selectedFlow.description && (
                      <p className="discovery-panel__card-subtitle">{selectedFlow.description}</p>
                    )}
                  </div>
                  <div className="discovery-panel__button-group">
                    <button
                      type="button"
                      className="discovery-panel__button discovery-panel__button--ghost discovery-panel__button--icon"
                      onClick={() => setShowFlowEditor(true)}
                      title="Edit flow"
                    >
                      <PencilIcon className="discovery-panel__icon" />
                    </button>
                    <button
                      type="button"
                      className="discovery-panel__button discovery-panel__button--ghost discovery-panel__button--icon"
                      onClick={() => handleDeleteFlow(selectedFlow.id)}
                      title="Delete flow"
                    >
                      <TrashIcon className="discovery-panel__icon discovery-panel__icon--danger" />
                    </button>
                  </div>
                </div>

                <div className="discovery-panel__meta-grid">
                  <div>
                    <p className="discovery-panel__meta-label">Package</p>
                    <p className="discovery-panel__meta-value">{selectedFlow.packageName}</p>
                  </div>
                  <div>
                    <p className="discovery-panel__meta-label">Last updated</p>
                    <p className="discovery-panel__meta-value">
                      {formatDate(selectedFlow.metadata.updatedAt)}
                    </p>
                  </div>
                  <div>
                    <p className="discovery-panel__meta-label">Complexity</p>
                    <p className="discovery-panel__meta-value">
                      {selectedFlow.metadata.complexity ?? 0}
                    </p>
                  </div>
                </div>

                {selectedFlow.metadata.tags && selectedFlow.metadata.tags.length > 0 && (
                  <div className="discovery-panel__tags discovery-panel__tags--wrap">
                    {selectedFlow.metadata.tags.map((tag) => (
                      <span key={tag} className="discovery-panel__chip discovery-panel__chip--accent">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}

                <div className="discovery-panel__flow-actions">
                  <button
                    type="button"
                    className="discovery-panel__button discovery-panel__button--positive"
                    onClick={() => handleExecuteFlow(selectedFlow.id)}
                    disabled={flowLoading}
                  >
                    <PlayIcon className="discovery-panel__icon" />
                    Execute flow
                  </button>
                  <button
                    type="button"
                    className="discovery-panel__button discovery-panel__button--ghost"
                    onClick={() => setShowFlowEditor(true)}
                  >
                    <PencilIcon className="discovery-panel__icon" />
                    Edit
                  </button>
                </div>

                <h4 className="discovery-panel__section-title">
                  Steps ({selectedFlow.steps.length})
                </h4>
                <ul className="discovery-panel__steps">
                  {selectedFlow.steps.map((step, index) => (
                    <li key={step.id} className="discovery-panel__step-row">
                      <div className="discovery-panel__step-index">#{index + 1}</div>
                      <div>
                        <p className="discovery-panel__step-name">{step.name}</p>
                        <p className="discovery-panel__step-meta">
                          {step.action.type}
                          {step.critical && ' • critical'}
                        </p>
                        {step.description && (
                          <p className="discovery-panel__step-desc">{step.description}</p>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <div className="discovery-panel__placeholder discovery-panel__placeholder--dense">
                <DocumentTextIcon className="discovery-panel__icon discovery-panel__icon--muted" />
                <p className="discovery-panel__placeholder-title">Select a flow</p>
                <p className="discovery-panel__placeholder-text">
                  Choose a flow from the list to inspect steps, or create a new one.
                </p>
              </div>
            )}
          </section>
        </div>
      </div>
    );
  };

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
        },
        metadata: {
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          author: 'autoapp',
          tags: [],
          estimatedDuration: 0,
          complexity: 0,
          executionCount: 0,
          successRate: 0
        },
        config: {
          defaultTimeout: 30,
          retryAttempts: 0,
          allowParallel: false,
          priority: 'low'
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
      await executeFlow(flowId);
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
        return <span className="discovery-panel__spinner discovery-panel__spinner--small" aria-hidden />;
      case 'completed':
        return <CheckCircleIcon className="discovery-panel__icon discovery-panel__icon--success" />;
      case 'failed':
        return <XCircleIcon className="discovery-panel__icon discovery-panel__icon--danger" />;
      case 'pending':
        return <span className="discovery-panel__dot discovery-panel__dot--warning" />;
      default:
        return <span className="discovery-panel__dot" />;
    }
  };

  const getStatusIcon = (status?: 'capturing' | 'loading' | 'success' | 'warning' | 'error') => {
    switch (status) {
      case 'capturing':
      case 'loading':
        return <span className="discovery-panel__spinner discovery-panel__spinner--small" aria-hidden />;
      case 'success':
        return <CheckCircleIcon className="discovery-panel__icon discovery-panel__icon--success" />;
      case 'warning':
        return <ExclamationTriangleIcon className="discovery-panel__icon discovery-panel__icon--warning" />;
      case 'error':
        return <XCircleIcon className="discovery-panel__icon discovery-panel__icon--danger" />;
      default:
        return <EyeIcon className="discovery-panel__icon discovery-panel__icon--muted" />;
    }
  };

  return (
    <section className={clsx('discovery-panel', className)}>
      <header className="discovery-panel__header">
        <div>
          <h2 className="discovery-panel__title">Discovery & Flows</h2>
          <p className="discovery-panel__subtitle">
            Inspect live UI states and promote them into reusable automation flows.
          </p>
        </div>
        <div className="discovery-panel__header-actions">
          <div className="discovery-panel__status-pill">
            {getStatusIcon(isCapturing ? 'capturing' : isLoading ? 'loading' : undefined)}
            <span>{isCapturing ? 'Capturing…' : isLoading ? 'Syncing' : 'Idle'}</span>
          </div>
          <div className="discovery-panel__status-pill discovery-panel__status-pill--muted">
            <DocumentTextIcon className="discovery-panel__icon discovery-panel__icon--muted" />
            <span>{flowsList.length} flows</span>
          </div>
          <button
            type="button"
            className="discovery-panel__button discovery-panel__button--ghost discovery-panel__button--small"
            onClick={() => (activeTab === 'discovery' ? refreshGraph() : refreshFlows())}
            disabled={activeTab === 'discovery' ? isLoading : flowLoading}
          >
            <ArrowPathIcon className="discovery-panel__icon" />
            Refresh
          </button>
        </div>
      </header>

      <div className="discovery-panel__tabs">
        <button
          type="button"
          className={clsx('discovery-panel__tab', { 'is-active': activeTab === 'discovery' })}
          onClick={() => setActiveTab('discovery')}
        >
          <Squares2X2Icon className="discovery-panel__icon" />
          Discovery
        </button>
        <button
          type="button"
          className={clsx('discovery-panel__tab', { 'is-active': activeTab === 'flows' })}
          onClick={() => setActiveTab('flows')}
        >
          <DocumentTextIcon className="discovery-panel__icon" />
          Flows
          {flowsList.length > 0 && (
            <span className="discovery-panel__badge">{flowsList.length}</span>
          )}
        </button>
      </div>

      {(error || flowError) && (
        <div className="discovery-panel__alert">
          <div className="discovery-panel__alert-content">
            <XCircleIcon className="discovery-panel__icon discovery-panel__icon--danger" />
            <span>{activeTab === 'discovery' ? error : flowError}</span>
          </div>
          <button
            type="button"
            className="discovery-panel__link"
            onClick={() => (activeTab === 'discovery' ? clearError() : clearFlowError())}
          >
            Dismiss
          </button>
        </div>
      )}

      <div className="discovery-panel__actions">
        <button
          type="button"
          className="discovery-panel__button discovery-panel__button--primary"
          onClick={handleCaptureState}
          disabled={isCapturing}
        >
          <CameraIcon className="discovery-panel__icon" />
          {transitionMode ? 'Complete Transition' : 'Snapshot State'}
        </button>

        <button
          type="button"
          className={clsx(
            'discovery-panel__button',
            transitionMode ? 'discovery-panel__button--warning' : 'discovery-panel__button--ghost'
          )}
          onClick={handleTransitionMode}
        >
          <ArrowRightIcon className="discovery-panel__icon" />
          {transitionMode ? 'Cancel Transition' : 'Mark Transition'}
        </button>

        {mergeMode ? (
          <>
            <button
              type="button"
              className="discovery-panel__button discovery-panel__button--positive"
              onClick={handleMergeStates}
              disabled={!mergeTarget || !selectedState}
            >
              <CheckCircleIcon className="discovery-panel__icon" />
              Confirm Merge
            </button>
            <button
              type="button"
              className="discovery-panel__button discovery-panel__button--ghost"
              onClick={() => {
                setMergeMode(false);
                setMergeTarget(null);
                setSelectedState(null);
              }}
            >
              <XCircleIcon className="discovery-panel__icon" />
              Cancel
            </button>
          </>
        ) : (
          <button
            type="button"
            className="discovery-panel__button discovery-panel__button--ghost"
            onClick={() => setMergeMode(true)}
            disabled={!graph || stateList.length < 2}
          >
            <ArrowsRightLeftIcon className="discovery-panel__icon" />
            Merge States
          </button>
        )}

        <button
          type="button"
          className="discovery-panel__button discovery-panel__button--ghost"
          onClick={() => setShowGraphMini((value) => !value)}
        >
          <Squares2X2Icon className="discovery-panel__icon" />
          {showGraphMini ? 'Hide Graph' : 'Show Graph'}
        </button>
      </div>

      {transitionMode && transitionStart && (
        <div className="discovery-panel__mode-banner discovery-panel__mode-banner--warning">
          Transition mode enabled. Starting from <strong>{transitionStart.activity}</strong>
        </div>
      )}

      {mergeMode && (
        <div className="discovery-panel__mode-banner discovery-panel__mode-banner--purple">
          Select the destination state to merge <strong>{selectedState?.activity ?? 'source state'}</strong> into.
        </div>
      )}

      <div className="discovery-panel__content">
        {activeTab === 'discovery' ? renderDiscoveryContent() : renderFlowView()}
      </div>

      <FlowEditor
        flow={selectedFlow}
        graph={graph}
        isVisible={showFlowEditor}
        onClose={() => setShowFlowEditor(false)}
        onSave={handleSaveFlow}
      />
    </section>
  );
};

export default DiscoveryPanel;
