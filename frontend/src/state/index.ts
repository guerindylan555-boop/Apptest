import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
// Simple UUID generation for browser environment
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Re-export existing stores
export { useAppStore } from './useAppStore';
export { useAppsLibraryStore, useSelectedEntry, useFilteredEntries } from './appsLibraryStore';
export {
  useFeatureFlagsStore,
  useFridaEnabled,
  useDiscoveryPanel,
  useGpsPanel
} from './featureFlagsStore';

// ===== Type Definitions =====

/**
 * UI State representation captured from the Android emulator
 */
export interface UIState {
  id: string;
  timestamp: string;
  screenshot?: string; // base64 encoded image
  elements: UIElement[];
  metadata: {
    packageName?: string;
    activityName?: string;
    deviceInfo?: DeviceInfo;
    captureMethod: 'automation' | 'manual' | 'scheduled';
  };
}

/**
 * Individual UI element within a captured state
 */
export interface UIElement {
  id: string;
  type: 'view' | 'button' | 'text' | 'image' | 'input' | 'list' | 'container';
  bounds: {
    left: number;
    top: number;
    right: number;
    bottom: number;
  };
  text?: string;
  description?: string;
  resourceId?: string;
  className?: string;
  packageName?: string;
  enabled: boolean;
  clickable: boolean;
  focusable: boolean;
  focused: boolean;
  selected: boolean;
  children: string[]; // child element IDs
  parent?: string; // parent element ID
  properties: Record<string, any>;
}

/**
 * Device information at time of capture
 */
export interface DeviceInfo {
  model: string;
  androidVersion: string;
  sdkVersion: number;
  screenWidth: number;
  screenHeight: number;
  density: number;
  orientation: 'portrait' | 'landscape';
}

/**
 * Screenshot information and metadata
 */
export interface ScreenshotInfo {
  id: string;
  filename: string;
  dataUrl: string;
  timestamp: string;
  stateId: string;
  fileSize: number;
  dimensions: {
    width: number;
    height: number;
  };
}

/**
 * UI Graph representing relationships between states
 */
export interface UIGraph {
  id: string;
  name: string;
  states: UIState[];
  transitions: Transition[];
  metadata: {
    createdAt: string;
    updatedAt: string;
    packageName?: string;
    version?: string;
    totalStates: number;
    totalTransitions: number;
  };
}

/**
 * Transition between UI states
 */
export interface Transition {
  id: string;
  fromStateId: string;
  toStateId: string;
  trigger: {
    type: 'click' | 'swipe' | 'back' | 'menu' | 'home' | 'intent' | 'unknown';
    elementId?: string;
    action?: string;
  };
  metadata: {
    timestamp: string;
    duration?: number;
    confidence?: number;
  };
}

/**
 * Flow definition for automated testing
 */
export interface FlowDefinition {
  id: string;
  name: string;
  description?: string;
  steps: FlowStep[];
  metadata: {
    createdAt: string;
    updatedAt: string;
    createdBy: string;
    version: string;
    tags: string[];
    category?: string;
  };
  settings: {
    timeoutMs: number;
    retryCount: number;
    screenshotOnStep: boolean;
    allowPartialMatch: boolean;
  };
}

/**
 * Individual step within a flow
 */
export interface FlowStep {
  id: string;
  order: number;
  type: 'navigate' | 'action' | 'verify' | 'wait' | 'condition' | 'loop';
  description: string;
  target?: {
    stateId?: string;
    elementId?: string;
    text?: string;
    resourceId?: string;
  };
  action?: {
    type: 'click' | 'input' | 'swipe' | 'back' | 'menu' | 'home';
    value?: string;
    direction?: 'up' | 'down' | 'left' | 'right';
    duration?: number;
  };
  verification?: {
    type: 'element_exists' | 'text_present' | 'state_match' | 'custom';
    expected?: any;
    timeoutMs?: number;
  };
  condition?: {
    type: 'if' | 'while' | 'until';
    expression: string;
    thenSteps: string[]; // step IDs
    elseSteps?: string[]; // step IDs
  };
  loop?: {
    type: 'for' | 'while' | 'until';
    iterations?: number;
    condition?: string;
    bodySteps: string[]; // step IDs
  };
  wait?: {
    durationMs?: number;
    condition?: string;
    timeoutMs?: number;
  };
}

/**
 * Flow execution status and results
 */
export interface FlowExecution {
  id: string;
  flowId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: string;
  endTime?: string;
  currentStep?: string;
  completedSteps: string[];
  results: StepResult[];
  logs: ExecutionLog[];
  metadata: {
    deviceId?: string;
    packageName?: string;
    environment: 'emulator' | 'device';
    testRunId?: string;
  };
}

/**
 * Result of individual step execution
 */
export interface StepResult {
  stepId: string;
  status: 'success' | 'failed' | 'skipped' | 'timeout';
  startTime: string;
  endTime?: string;
  duration?: number;
  screenshot?: string;
  error?: string;
  details?: Record<string, any>;
}

/**
 * Execution log entry
 */
export interface ExecutionLog {
  id: string;
  timestamp: string;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  stepId?: string;
  metadata?: Record<string, any>;
}

/**
 * WebRTC connection status and metrics
 */
export interface WebRTCStatus {
  connectionState: 'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'failed';
  iceConnectionState: 'new' | 'checking' | 'connected' | 'completed' | 'failed' | 'disconnected' | 'closed';
  iceGatheringState: 'new' | 'gathering' | 'complete';
  signalingState: 'stable' | 'have-local-offer' | 'have-remote-offer' | 'have-local-pranswer' | 'have-remote-pranswer' | 'closed';
}

/**
 * Stream quality metrics
 */
export interface StreamMetrics {
  resolution: {
    width: number;
    height: number;
  };
  frameRate: number;
  bitrate: number;
  packetsLost: number;
  rtt: number; // Round trip time in ms
  jitter: number;
  qualityLevel: 'low' | 'medium' | 'high' | 'excellent';
}

/**
 * WebRTC connection configuration
 */
export interface WebRTCConfig {
  servers: RTCIceServer[];
  videoConstraints: MediaTrackConstraints;
  audioConstraints: MediaTrackConstraints;
  dataChannels: {
    enabled: boolean;
    ordered: boolean;
    maxRetransmits?: number;
  };
}

/**
 * User settings and preferences
 */
export interface UserSettings {
  ui: {
    theme: 'light' | 'dark' | 'system';
    language: string;
    compactMode: boolean;
    showGrid: boolean;
    showElementBounds: boolean;
    screenshotQuality: 'low' | 'medium' | 'high';
  };
  capture: {
    autoCapture: boolean;
    captureInterval: number; // seconds
    maxHistorySize: number;
    captureOnInteraction: boolean;
    includeHiddenElements: boolean;
    timeoutMs: number;
  };
  debugging: {
    enableLogs: boolean;
    logLevel: 'debug' | 'info' | 'warn' | 'error';
    showPerformanceMetrics: boolean;
    enableConsoleDebug: boolean;
  };
  performance: {
    maxConcurrentFlows: number;
    stepTimeoutMs: number;
    flowRetryCount: number;
    enableCaching: boolean;
    cacheSize: number;
  };
  notifications: {
    enableSounds: boolean;
    enableDesktop: boolean;
    flowCompletion: boolean;
    errors: boolean;
    connectionStatus: boolean;
  };
}

/**
 * Validation result for flows
 */
export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  summary: {
    totalSteps: number;
    validSteps: number;
    invalidSteps: number;
    warnings: number;
  };
}

/**
 * Validation error
 */
export interface ValidationError {
  stepId?: string;
  type: 'syntax' | 'logic' | 'reference' | 'configuration';
  message: string;
  severity: 'error' | 'warning';
  line?: number;
  column?: number;
}

/**
 * Validation warning
 */
export interface ValidationWarning {
  stepId?: string;
  type: 'performance' | 'best_practice' | 'deprecated';
  message: string;
  suggestion?: string;
}

/**
 * Flow template
 */
export interface FlowTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  steps: Omit<FlowStep, 'id'>[];
  tags: string[];
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime: number; // minutes
  author: string;
  version: string;
}

// ===== Store Interfaces =====

/**
 * Discovery Store Interface
 */
export interface DiscoveryState {
  // State
  currentGraph: UIGraph | null;
  capturedStates: UIState[];
  selectedState: UIState | null;
  isCapturing: boolean;
  connectionStatus: 'connected' | 'disconnected' | 'connecting';
  screenshots: Record<string, ScreenshotInfo>;
  captureHistory: string[]; // state IDs
  isLoading: boolean;
  error: string | null;

  // Actions
  setCurrentGraph: (graph: UIGraph | null) => void;
  addCapturedState: (state: UIState) => void;
  updateCapturedState: (id: string, updates: Partial<UIState>) => void;
  removeCapturedState: (id: string) => void;
  selectState: (state: UIState | null) => void;
  setCapturing: (capturing: boolean) => void;
  setConnectionStatus: (status: DiscoveryState['connectionStatus']) => void;
  addScreenshot: (screenshot: ScreenshotInfo) => void;
  removeScreenshot: (id: string) => void;
  clearGraph: () => void;
  clearHistory: () => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;

  // Async actions
  captureState: () => Promise<void>;
  captureElementScreenshot: (elementId: string) => Promise<ScreenshotInfo>;
  analyzeCurrentScreen: () => Promise<UIState>;
}

/**
 * Flow Store Interface
 */
export interface FlowState {
  // State
  flows: FlowDefinition[];
  selectedFlowId: string | null;
  executions: FlowExecution[];
  selectedExecutionId: string | null;
  templates: FlowTemplate[];
  validationResult: ValidationResult | null;
  isExecuting: boolean;
  isCreating: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  setFlows: (flows: FlowDefinition[]) => void;
  addFlow: (flow: FlowDefinition) => void;
  updateFlow: (id: string, updates: Partial<FlowDefinition>) => void;
  removeFlow: (id: string) => void;
  selectFlow: (id: string | null) => void;
  setExecutions: (executions: FlowExecution[]) => void;
  addExecution: (execution: FlowExecution) => void;
  updateExecution: (id: string, updates: Partial<FlowExecution>) => void;
  selectExecution: (id: string | null) => void;
  setTemplates: (templates: FlowTemplate[]) => void;
  setValidationResult: (result: ValidationResult | null) => void;
  setExecuting: (executing: boolean) => void;
  setCreating: (creating: boolean) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;

  // Async actions
  createFlow: (template?: FlowTemplate) => Promise<FlowDefinition>;
  executeFlow: (flowId: string, options?: Record<string, any>) => Promise<FlowExecution>;
  stopExecution: (executionId: string) => Promise<void>;
  validateFlow: (flow: FlowDefinition) => Promise<ValidationResult>;
  duplicateFlow: (flowId: string) => Promise<FlowDefinition>;
  exportFlow: (flowId: string) => Promise<string>;
  importFlow: (flowData: string) => Promise<FlowDefinition>;
  loadTemplates: () => Promise<void>;
}

/**
 * WebRTC Store Interface
 */
export interface WebRTCState {
  // State
  status: WebRTCStatus;
  metrics: StreamMetrics | null;
  config: WebRTCConfig;
  isConnected: boolean;
  isReconnecting: boolean;
  connectionQuality: 'poor' | 'fair' | 'good' | 'excellent';
  lastError: string | null;
  reconnectAttempts: number;
  maxReconnectAttempts: number;

  // Actions
  setStatus: (status: Partial<WebRTCStatus>) => void;
  setMetrics: (metrics: StreamMetrics | null) => void;
  setConfig: (config: Partial<WebRTCConfig>) => void;
  setConnected: (connected: boolean) => void;
  setReconnecting: (reconnecting: boolean) => void;
  setConnectionQuality: (quality: WebRTCState['connectionQuality']) => void;
  setLastError: (error: string | null) => void;
  incrementReconnectAttempts: () => void;
  resetReconnectAttempts: () => void;

  // Async actions
  connect: (config?: Partial<WebRTCConfig>) => Promise<void>;
  disconnect: () => Promise<void>;
  reconnect: () => Promise<void>;
  updateConfig: (config: Partial<WebRTCConfig>) => Promise<void>;
  getConnectionStats: () => Promise<RTCStatsReport>;
}

/**
 * Settings Store Interface
 */
export interface SettingsState {
  // State
  settings: UserSettings;
  isLoading: boolean;
  error: string | null;
  lastSaved: string | null;

  // Actions
  updateSettings: (updates: Partial<UserSettings>) => void;
  resetSettings: () => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setLastSaved: (timestamp: string) => void;

  // Async actions
  saveSettings: () => Promise<void>;
  loadSettings: () => Promise<void>;
  exportSettings: () => Promise<string>;
  importSettings: (settingsData: string) => Promise<void>;
  resetToDefaults: () => Promise<void>;
}

// ===== Store Implementations =====

/**
 * Discovery Store - manages UI state discovery and graph building
 */
export const useDiscoveryStore = create<DiscoveryState>()(
  devtools(
    (set, get) => ({
      // Initial state
      currentGraph: null,
      capturedStates: [],
      selectedState: null,
      isCapturing: false,
      connectionStatus: 'disconnected',
      screenshots: {},
      captureHistory: [],
      isLoading: false,
      error: null,

      // Actions
      setCurrentGraph: (graph) => set({ currentGraph: graph }),

      addCapturedState: (state) => set((prev) => ({
        capturedStates: [...prev.capturedStates, state],
        captureHistory: [...prev.captureHistory, state.id]
      })),

      updateCapturedState: (id, updates) => set((prev) => ({
        capturedStates: prev.capturedStates.map(state =>
          state.id === id ? { ...state, ...updates } : state
        )
      })),

      removeCapturedState: (id) => set((prev) => ({
        capturedStates: prev.capturedStates.filter(state => state.id !== id),
        captureHistory: prev.captureHistory.filter(stateId => stateId !== id),
        selectedState: prev.selectedState?.id === id ? null : prev.selectedState
      })),

      selectState: (state) => set({ selectedState: state }),

      setCapturing: (capturing) => set({ isCapturing: capturing }),

      setConnectionStatus: (status) => set({ connectionStatus: status }),

      addScreenshot: (screenshot) => set((prev) => ({
        screenshots: { ...prev.screenshots, [screenshot.id]: screenshot }
      })),

      removeScreenshot: (id) => set((prev) => {
        const newScreenshots = { ...prev.screenshots };
        delete newScreenshots[id];
        return { screenshots: newScreenshots };
      }),

      clearGraph: () => set({
        currentGraph: null,
        capturedStates: [],
        selectedState: null,
        screenshots: {},
        captureHistory: []
      }),

      clearHistory: () => set({
        capturedStates: [],
        selectedState: null,
        screenshots: {},
        captureHistory: []
      }),

      setLoading: (loading) => set({ isLoading: loading }),

      setError: (error) => set({ error }),

      // Async actions
      captureState: async () => {
        const { isCapturing, connectionStatus } = get();
        if (isCapturing || connectionStatus !== 'connected') {
          return;
        }

        set({ isCapturing: true, error: null });

        try {
          // This would integrate with the actual capture service
          const newState: UIState = {
            id: generateUUID(),
            timestamp: new Date().toISOString(),
            elements: [],
            metadata: {
              captureMethod: 'manual'
            }
          };

          get().addCapturedState(newState);
        } catch (error) {
          set({ error: error instanceof Error ? error.message : 'Failed to capture state' });
        } finally {
          set({ isCapturing: false });
        }
      },

      captureElementScreenshot: async (elementId: string) => {
        // Implementation would capture specific element screenshot
        const screenshot: ScreenshotInfo = {
          id: generateUUID(),
          filename: `element_${elementId}_${Date.now()}.png`,
          dataUrl: '', // Would contain actual screenshot data
          timestamp: new Date().toISOString(),
          stateId: get().selectedState?.id || '',
          fileSize: 0,
          dimensions: { width: 0, height: 0 }
        };

        get().addScreenshot(screenshot);
        return screenshot;
      },

      analyzeCurrentScreen: async () => {
        set({ isLoading: true, error: null });

        try {
          // Implementation would analyze current screen
          const state: UIState = {
            id: generateUUID(),
            timestamp: new Date().toISOString(),
            elements: [],
            metadata: {
              captureMethod: 'automation'
            }
          };

          return state;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to analyze screen';
          set({ error: errorMessage });
          throw error;
        } finally {
          set({ isLoading: false });
        }
      }
    }),
    { name: 'discovery-store' }
  )
);

/**
 * Flow Store - manages flow definitions and executions
 */
export const useFlowStore = create<FlowState>()(
  devtools(
    (set, get) => ({
      // Initial state
      flows: [],
      selectedFlowId: null,
      executions: [],
      selectedExecutionId: null,
      templates: [],
      validationResult: null,
      isExecuting: false,
      isCreating: false,
      isLoading: false,
      error: null,

      // Actions
      setFlows: (flows) => set({ flows }),

      addFlow: (flow) => set((prev) => ({
        flows: [...prev.flows, flow]
      })),

      updateFlow: (id, updates) => set((prev) => ({
        flows: prev.flows.map(flow =>
          flow.id === id ? { ...flow, ...updates, metadata: { ...flow.metadata, updatedAt: new Date().toISOString() } } : flow
        )
      })),

      removeFlow: (id) => set((prev) => ({
        flows: prev.flows.filter(flow => flow.id !== id),
        selectedFlowId: prev.selectedFlowId === id ? null : prev.selectedFlowId
      })),

      selectFlow: (id) => set({ selectedFlowId: id }),

      setExecutions: (executions) => set({ executions }),

      addExecution: (execution) => set((prev) => ({
        executions: [...prev.executions, execution]
      })),

      updateExecution: (id, updates) => set((prev) => ({
        executions: prev.executions.map(execution =>
          execution.id === id ? { ...execution, ...updates } : execution
        )
      })),

      selectExecution: (id) => set({ selectedExecutionId: id }),

      setTemplates: (templates) => set({ templates }),

      setValidationResult: (result) => set({ validationResult: result }),

      setExecuting: (executing) => set({ isExecuting: executing }),

      setCreating: (creating) => set({ isCreating: creating }),

      setLoading: (loading) => set({ isLoading: loading }),

      setError: (error) => set({ error }),

      // Async actions
      createFlow: async (template) => {
        set({ isCreating: true, error: null });

        try {
          const newFlow: FlowDefinition = {
            id: generateUUID(),
            name: template?.name || 'New Flow',
            description: template?.description,
            steps: template?.steps.map((step, index) => ({
              ...step,
              id: generateUUID(),
              order: index
            })) || [],
            metadata: {
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
              createdBy: 'user',
              version: '1.0.0',
              tags: template?.tags || [],
              category: template?.category
            },
            settings: {
              timeoutMs: 30000,
              retryCount: 3,
              screenshotOnStep: true,
              allowPartialMatch: false
            }
          };

          get().addFlow(newFlow);
          get().selectFlow(newFlow.id);

          return newFlow;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to create flow';
          set({ error: errorMessage });
          throw error;
        } finally {
          set({ isCreating: false });
        }
      },

      executeFlow: async (flowId, options = {}) => {
        set({ isExecuting: true, error: null });

        try {
          const execution: FlowExecution = {
            id: generateUUID(),
            flowId,
            status: 'pending',
            startTime: new Date().toISOString(),
            completedSteps: [],
            results: [],
            logs: [],
            metadata: {
              environment: 'emulator',
              ...options
            }
          };

          get().addExecution(execution);
          get().selectExecution(execution.id);

          // Update status to running
          get().updateExecution(execution.id, { status: 'running' });

          return execution;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to execute flow';
          set({ error: errorMessage });
          throw error;
        } finally {
          set({ isExecuting: false });
        }
      },

      stopExecution: async (executionId) => {
        try {
          get().updateExecution(executionId, {
            status: 'cancelled',
            endTime: new Date().toISOString()
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to stop execution';
          set({ error: errorMessage });
          throw error;
        }
      },

      validateFlow: async (flow) => {
        set({ isLoading: true, error: null });

        try {
          const result: ValidationResult = {
            isValid: true,
            errors: [],
            warnings: [],
            summary: {
              totalSteps: flow.steps.length,
              validSteps: flow.steps.length,
              invalidSteps: 0,
              warnings: 0
            }
          };

          get().setValidationResult(result);
          return result;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to validate flow';
          set({ error: errorMessage });
          throw error;
        } finally {
          set({ isLoading: false });
        }
      },

      duplicateFlow: async (flowId) => {
        const originalFlow = get().flows.find(f => f.id === flowId);
        if (!originalFlow) {
          throw new Error('Flow not found');
        }

        const duplicatedFlow: FlowDefinition = {
          ...originalFlow,
          id: generateUUID(),
          name: `${originalFlow.name} (Copy)`,
          metadata: {
            ...originalFlow.metadata,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            createdBy: 'user'
          }
        };

        get().addFlow(duplicatedFlow);
        return duplicatedFlow;
      },

      exportFlow: async (flowId) => {
        const flow = get().flows.find(f => f.id === flowId);
        if (!flow) {
          throw new Error('Flow not found');
        }

        return JSON.stringify(flow, null, 2);
      },

      importFlow: async (flowData) => {
        try {
          const flow = JSON.parse(flowData) as FlowDefinition;
          flow.id = generateUUID(); // Generate new ID to avoid conflicts
          flow.metadata.updatedAt = new Date().toISOString();

          get().addFlow(flow);
          return flow;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to import flow';
          set({ error: errorMessage });
          throw error;
        }
      },

      loadTemplates: async () => {
        set({ isLoading: true, error: null });

        try {
          // This would load templates from server or local storage
          const templates: FlowTemplate[] = [];
          get().setTemplates(templates);
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Failed to load templates';
          set({ error: errorMessage });
          throw error;
        } finally {
          set({ isLoading: false });
        }
      }
    }),
    { name: 'flow-store' }
  )
);

/**
 * WebRTC Store - manages WebRTC connections and streaming
 */
export const useWebRTCStore = create<WebRTCState>()(
  devtools(
    (set, get) => ({
      // Initial state
      status: {
        connectionState: 'disconnected',
        iceConnectionState: 'new',
        iceGatheringState: 'new',
        signalingState: 'stable'
      },
      metrics: null,
      config: {
        servers: [{ urls: 'stun:stun.l.google.com:19302' }],
        videoConstraints: {
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: 60 }
        },
        audioConstraints: {
          echoCancellation: true,
          noiseSuppression: true
        },
        dataChannels: {
          enabled: true,
          ordered: true
        }
      },
      isConnected: false,
      isReconnecting: false,
      connectionQuality: 'fair',
      lastError: null,
      reconnectAttempts: 0,
      maxReconnectAttempts: 5,

      // Actions
      setStatus: (statusUpdates) => set((prev) => ({
        status: { ...prev.status, ...statusUpdates }
      })),

      setMetrics: (metrics) => set({ metrics }),

      setConfig: (configUpdates) => set((prev) => ({
        config: { ...prev.config, ...configUpdates }
      })),

      setConnected: (connected) => set({ isConnected: connected }),

      setReconnecting: (reconnecting) => set({ isReconnecting: reconnecting }),

      setConnectionQuality: (quality) => set({ connectionQuality: quality }),

      setLastError: (error) => set({ lastError: error }),

      incrementReconnectAttempts: () => set((prev) => ({
        reconnectAttempts: prev.reconnectAttempts + 1
      })),

      resetReconnectAttempts: () => set({ reconnectAttempts: 0 }),

      // Async actions
      connect: async (configOverrides) => {
        const { isConnected, isReconnecting } = get();
        if (isConnected || isReconnecting) {
          return;
        }

        try {
          set({
            lastError: null,
            isConnected: false
          });

          if (configOverrides) {
            get().setConfig(configOverrides);
          }

          // WebRTC connection logic would go here
          set({
            isConnected: true,
            reconnectAttempts: 0
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Connection failed';
          set({
            lastError: errorMessage,
            isConnected: false
          });
          throw error;
        }
      },

      disconnect: async () => {
        try {
          // WebRTC disconnection logic would go here
          set({
            isConnected: false,
            metrics: null,
            reconnectAttempts: 0
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Disconnection failed';
          set({ lastError: errorMessage });
          throw error;
        }
      },

      reconnect: async () => {
        const { reconnectAttempts, maxReconnectAttempts } = get();

        if (reconnectAttempts >= maxReconnectAttempts) {
          set({
            lastError: 'Maximum reconnection attempts reached',
            isReconnecting: false
          });
          return;
        }

        set({ isReconnecting: true });
        get().incrementReconnectAttempts();

        try {
          await get().disconnect();
          await new Promise(resolve => setTimeout(resolve, 2000 * reconnectAttempts)); // Exponential backoff
          await get().connect();
          set({ isReconnecting: false, reconnectAttempts: 0 });
        } catch (error) {
          set({ isReconnecting: false });
          throw error;
        }
      },

      updateConfig: async (configUpdates) => {
        const { isConnected } = get();
        get().setConfig(configUpdates);

        if (isConnected) {
          // Would renegotiate connection with new config
          try {
            await get().reconnect();
          } catch (error) {
            // Handle reconnection failure
          }
        }
      },

      getConnectionStats: async () => {
        // Would return actual RTCStatsReport from WebRTC connection
        return {} as RTCStatsReport;
      }
    }),
    { name: 'webrtc-store' }
  )
);

/**
 * Settings Store - manages user preferences and configuration
 */
export const useSettingsStore = create<SettingsState>()(
  devtools(
    persist(
      (set, get) => ({
        // Initial state
        settings: {
          ui: {
            theme: 'system',
            language: 'en',
            compactMode: false,
            showGrid: true,
            showElementBounds: true,
            screenshotQuality: 'medium'
          },
          capture: {
            autoCapture: false,
            captureInterval: 30,
            maxHistorySize: 100,
            captureOnInteraction: true,
            includeHiddenElements: false,
            timeoutMs: 10000
          },
          debugging: {
            enableLogs: true,
            logLevel: 'info',
            showPerformanceMetrics: false,
            enableConsoleDebug: false
          },
          performance: {
            maxConcurrentFlows: 3,
            stepTimeoutMs: 30000,
            flowRetryCount: 3,
            enableCaching: true,
            cacheSize: 1000
          },
          notifications: {
            enableSounds: true,
            enableDesktop: true,
            flowCompletion: true,
            errors: true,
            connectionStatus: false
          }
        },
        isLoading: false,
        error: null,
        lastSaved: null,

        // Actions
        updateSettings: (updates) => set((prev) => ({
          settings: {
            ...prev.settings,
            ...updates
          }
        })),

        resetSettings: () => set({
          settings: {
            ui: {
              theme: 'system',
              language: 'en',
              compactMode: false,
              showGrid: true,
              showElementBounds: true,
              screenshotQuality: 'medium'
            },
            capture: {
              autoCapture: false,
              captureInterval: 30,
              maxHistorySize: 100,
              captureOnInteraction: true,
              includeHiddenElements: false,
              timeoutMs: 10000
            },
            debugging: {
              enableLogs: true,
              logLevel: 'info',
              showPerformanceMetrics: false,
              enableConsoleDebug: false
            },
            performance: {
              maxConcurrentFlows: 3,
              stepTimeoutMs: 30000,
              flowRetryCount: 3,
              enableCaching: true,
              cacheSize: 1000
            },
            notifications: {
              enableSounds: true,
              enableDesktop: true,
              flowCompletion: true,
              errors: true,
              connectionStatus: false
            }
          }
        }),

        setLoading: (loading) => set({ isLoading: loading }),

        setError: (error) => set({ error }),

        setLastSaved: (timestamp) => set({ lastSaved: timestamp }),

        // Async actions
        saveSettings: async () => {
          set({ isLoading: true, error: null });

          try {
            // Settings are automatically persisted via zustand persist middleware
            set({ lastSaved: new Date().toISOString() });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to save settings';
            set({ error: errorMessage });
            throw error;
          } finally {
            set({ isLoading: false });
          }
        },

        loadSettings: async () => {
          set({ isLoading: true, error: null });

          try {
            // Settings are automatically loaded via zustand persist middleware
            set({ lastSaved: new Date().toISOString() });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to load settings';
            set({ error: errorMessage });
            throw error;
          } finally {
            set({ isLoading: false });
          }
        },

        exportSettings: async () => {
          try {
            return JSON.stringify(get().settings, null, 2);
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to export settings';
            set({ error: errorMessage });
            throw error;
          }
        },

        importSettings: async (settingsData) => {
          set({ isLoading: true, error: null });

          try {
            const settings = JSON.parse(settingsData) as UserSettings;
            set({ settings });
            set({ lastSaved: new Date().toISOString() });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to import settings';
            set({ error: errorMessage });
            throw error;
          } finally {
            set({ isLoading: false });
          }
        },

        resetToDefaults: async () => {
          set({ isLoading: true, error: null });

          try {
            get().resetSettings();
            set({ lastSaved: new Date().toISOString() });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to reset settings';
            set({ error: errorMessage });
            throw error;
          } finally {
            set({ isLoading: false });
          }
        }
      }),
      {
        name: 'app-settings',
        version: 1
      }
    ),
    { name: 'settings-store' }
  )
);

// ===== Selector Hooks =====

/**
 * Get current selected flow
 */
export function useSelectedFlow(): FlowDefinition | null {
  const flows = useFlowStore((state) => state.flows);
  const selectedId = useFlowStore((state) => state.selectedFlowId);

  if (!selectedId) return null;
  return flows.find((flow) => flow.id === selectedId) || null;
}

/**
 * Get current selected execution
 */
export function useSelectedExecution(): FlowExecution | null {
  const executions = useFlowStore((state) => state.executions);
  const selectedId = useFlowStore((state) => state.selectedExecutionId);

  if (!selectedId) return null;
  return executions.find((execution) => execution.id === selectedId) || null;
}

/**
 * Get filtered flows based on search criteria
 */
export function useFilteredFlows(searchQuery: string, category?: string): FlowDefinition[] {
  const flows = useFlowStore((state) => state.flows);

  return flows.filter((flow) => {
    const matchesSearch = !searchQuery ||
      flow.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      flow.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      flow.metadata.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesCategory = !category || flow.metadata.category === category;

    return matchesSearch && matchesCategory;
  });
}

/**
 * Get flow executions by status
 */
export function useExecutionsByStatus(status: FlowExecution['status']): FlowExecution[] {
  const executions = useFlowStore((state) => state.executions);
  return executions.filter((execution) => execution.status === status);
}

/**
 * Get recent captured states
 */
export function useRecentStates(limit: number = 10): UIState[] {
  const states = useDiscoveryStore((state) => state.capturedStates);
  return states
    .slice()
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);
}

/**
 * Get connection quality indicator
 */
export function useConnectionQuality(): {
  quality: WebRTCState['connectionQuality'];
  isGood: boolean;
  status: string;
} {
  const quality = useWebRTCStore((state) => state.connectionQuality);
  const isConnected = useWebRTCStore((state) => state.isConnected);
  const isReconnecting = useWebRTCStore((state) => state.isReconnecting);

  const isGood = quality === 'good' || quality === 'excellent';

  let status = 'Disconnected';
  if (isReconnecting) status = 'Reconnecting...';
  else if (isConnected) {
    status = quality.charAt(0).toUpperCase() + quality.slice(1);
  }

  return { quality, isGood, status };
}

// ===== Export everything =====