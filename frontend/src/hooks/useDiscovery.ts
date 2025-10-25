/**
 * Discovery Hook
 *
 * React hook for UI discovery API integration.
 * Handles state capture, graph management, and real-time updates.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
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

interface SnapshotRequest {
  forceScreenshot?: boolean;
  tags?: string[];
}

interface SnapshotResponse {
  state: StateRecord;
  merged: boolean;
  mergedInto?: string;
}

interface CreateTransitionRequest {
  fromStateId?: string;
  action: UserAction;
  toStateId?: string;
  evidence?: {
    beforeDigest?: string;
    afterDigest?: string;
    notes?: string;
  };
}

interface MergeStatesRequest {
  sourceId: string;
  targetId: string;
}

interface MergeStatesResponse {
  success: boolean;
  mergedCount: number;
  updatedTransitions: string[];
  removedTransitions: string[];
}

interface CurrentStateResponse {
  state?: StateRecord;
  confidence: number;
  candidates: Array<{
    state: StateRecord;
    similarity: number;
  }>;
}

interface DiscoveryState {
  graph: UIGraph | null;
  currentState: StateRecord | null;
  isCapturing: boolean;
  isLoading: boolean;
  error: string | null;
  lastUpdated: Date | null;
}

interface DiscoveryActions {
  captureState: (options?: SnapshotRequest) => Promise<SnapshotResponse>;
  getCurrentState: () => Promise<CurrentStateResponse>;
  createTransition: (request: CreateTransitionRequest) => Promise<TransitionRecord>;
  mergeStates: (request: MergeStatesRequest) => Promise<MergeStatesResponse>;
  refreshGraph: () => Promise<void>;
  clearError: () => void;
}

interface UseDiscoveryReturn extends DiscoveryState, DiscoveryActions {}

const API_BASE = '/api';

export const useDiscovery = (refreshInterval?: number): UseDiscoveryReturn => {
  const [state, setState] = useState<DiscoveryState>({
    graph: null,
    currentState: null,
    isCapturing: false,
    isLoading: false,
    error: null,
    lastUpdated: null
  });

  const abortControllerRef = useRef<AbortController | null>(null);
  const intervalRef = useRef<number | null>(null);

  /**
   * Handle API errors consistently
   */
  const handleApiError = useCallback((error: unknown, message: string) => {
    let errorMessage = message;

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return; // Request was aborted, don't set error
      }
      errorMessage = `${message}: ${error.message}`;
    }

    setState(prev => ({
      ...prev,
      error: errorMessage,
      isLoading: false,
      isCapturing: false
    }));
  }, []);

  /**
   * Make API request with error handling
   */
  const apiRequest = useCallback(async <T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> => {
    const url = `${API_BASE}${endpoint}`;

    // Cancel previous request if still pending
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    abortControllerRef.current = new AbortController();

    try {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        },
        signal: abortControllerRef.current.signal,
        ...options
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      return await response.json();
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw error;
      }
      throw error;
    }
  }, []);

  /**
   * Capture current UI state
   */
  const captureState = useCallback(async (options?: SnapshotRequest): Promise<SnapshotResponse> => {
    setState(prev => ({ ...prev, isCapturing: true, error: null }));

    try {
      const response = await apiRequest<SnapshotResponse>('/graph/snapshot', {
        method: 'POST',
        body: JSON.stringify(options || {})
      });

      setState(prev => ({
        ...prev,
        isCapturing: false,
        lastUpdated: new Date()
      }));

      // Refresh graph to get updated state
      await refreshGraph();

      return response;
    } catch (error) {
      handleApiError(error, 'Failed to capture state');
      throw error;
    }
  }, [apiRequest, handleApiError]);

  /**
   * Get current detected state
   */
  const getCurrentState = useCallback(async (): Promise<CurrentStateResponse> => {
    try {
      const response = await apiRequest<CurrentStateResponse>('/state/current');

      setState(prev => ({
        ...prev,
        currentState: response.state || null
      }));

      return response;
    } catch (error) {
      handleApiError(error, 'Failed to get current state');
      throw error;
    }
  }, [apiRequest, handleApiError]);

  /**
   * Create transition between states
   */
  const createTransition = useCallback(async (request: CreateTransitionRequest): Promise<TransitionRecord> => {
    try {
      const response = await apiRequest<TransitionRecord>('/graph/transition', {
        method: 'POST',
        body: JSON.stringify(request)
      });

      // Refresh graph to include new transition
      await refreshGraph();

      return response;
    } catch (error) {
      handleApiError(error, 'Failed to create transition');
      throw error;
    }
  }, [apiRequest, handleApiError]);

  /**
   * Merge two states
   */
  const mergeStates = useCallback(async (request: MergeStatesRequest): Promise<MergeStatesResponse> => {
    try {
      const response = await apiRequest<MergeStatesResponse>('/graph/merge', {
        method: 'POST',
        body: JSON.stringify(request)
      });

      // Refresh graph after merge
      await refreshGraph();

      return response;
    } catch (error) {
      handleApiError(error, 'Failed to merge states');
      throw error;
    }
  }, [apiRequest, handleApiError]);

  /**
   * Refresh graph data
   */
  const refreshGraph = useCallback(async (): Promise<void> => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const graph = await apiRequest<UIGraph>('/graph');

      setState(prev => ({
        ...prev,
        graph,
        isLoading: false,
        lastUpdated: new Date()
      }));
    } catch (error) {
      handleApiError(error, 'Failed to refresh graph');
      throw error;
    }
  }, [apiRequest, handleApiError]);

  /**
   * Clear error state
   */
  const clearError = useCallback((): void => {
    setState(prev => ({ ...prev, error: null }));
  }, []);

  /**
   * Initialize data and set up refresh interval
   */
  useEffect(() => {
    // Load initial data
    refreshGraph();

    // Set up automatic refresh if interval is specified
    if (refreshInterval && refreshInterval > 0) {
      intervalRef.current = setInterval(() => {
        refreshGraph();
      }, refreshInterval);
    }

    // Cleanup
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [refreshGraph, refreshInterval]);

  /**
   * Periodically update current state
   */
  useEffect(() => {
    if (!state.graph) return;

    const updateCurrentState = async () => {
      try {
        await getCurrentState();
      } catch (error) {
        // Don't set error for current state updates, just log
        console.warn('Failed to update current state:', error);
      }
    };

    // Update current state every 5 seconds
    const interval = setInterval(updateCurrentState, 5000);

    return () => clearInterval(interval);
  }, [state.graph, getCurrentState]);

  return {
    ...state,
    captureState,
    getCurrentState,
    createTransition,
    mergeStates,
    refreshGraph,
    clearError
  };
};

/**
 * Hook for managing capture queue and batch operations
 */
export const useCaptureQueue = () => {
  const [queue, setQueue] = useState<SnapshotRequest[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);

  const addToQueue = useCallback((request: SnapshotRequest) => {
    setQueue(prev => [...prev, request]);
  }, []);

  const processQueue = useCallback(async (): Promise<SnapshotResponse[]> => {
    if (queue.length === 0 || isProcessing) return [];

    setIsProcessing(true);
    const results: SnapshotResponse[] = [];

    try {
      for (const request of queue) {
        // This would use the captureState function from useDiscovery
        // For now, we'll simulate API calls
        try {
          const response = await fetch(`${API_BASE}/graph/snapshot`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(request)
          });

          if (response.ok) {
            const result = await response.json();
            results.push(result);
          }
        } catch (error) {
          console.error('Failed to process queue item:', error);
        }
      }

      setQueue([]);
      return results;
    } finally {
      setIsProcessing(false);
    }
  }, [queue, isProcessing]);

  const clearQueue = useCallback(() => {
    setQueue([]);
  }, []);

  return {
    queue,
    isProcessing,
    addToQueue,
    processQueue,
    clearQueue,
    queueSize: queue.length
  };
};

/**
 * Hook for state comparison and analysis
 */
export const useStateComparison = () => {
  const [comparison, setComparison] = useState<{
    state1: StateRecord | null;
    state2: StateRecord | null;
    similarity: number;
  }>({
    state1: null,
    state2: null,
    similarity: 0
  });

  const compareStates = useCallback((state1: StateRecord, state2: StateRecord) => {
    // Simple similarity calculation - in a real implementation,
    // this would use the same algorithm as the backend
    let similarity = 0;
    let commonElements = 0;

    // Compare selectors
    const selectors1 = new Set(state1.selectors.map(s => s.rid || s.text || s.cls));
    const selectors2 = new Set(state2.selectors.map(s => s.rid || s.text || s.cls));

    for (const selector of selectors1) {
      if (selectors2.has(selector)) {
        commonElements++;
      }
    }

    similarity = commonElements / Math.max(selectors1.size, selectors2.size, 1);

    setComparison({
      state1,
      state2,
      similarity: Math.round(similarity * 100) / 100
    });
  }, []);

  const clearComparison = useCallback(() => {
    setComparison({
      state1: null,
      state2: null,
      similarity: 0
    });
  }, []);

  return {
    ...comparison,
    compareStates,
    clearComparison
  };
};

export default useDiscovery;