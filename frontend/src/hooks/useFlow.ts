/**
 * Flow Management Hook
 *
 * React hook for flow management operations including
 * CRUD operations, execution, and real-time updates.
 */

import { useState, useEffect, useCallback } from 'react';

// Types matching the backend flow types
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

interface UserAction {
  type: 'tap' | 'type' | 'swipe' | 'back' | 'intent' | 'long_press';
  target?: any;
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

interface FlowValidationError {
  type: 'syntax' | 'semantic' | 'logic' | 'reference';
  severity: 'error' | 'warning';
  message: string;
  stepId?: string;
  location?: {
    line?: number;
    column?: number;
    property?: string;
  };
  code: string;
  details?: Record<string, any>;
}

interface FlowValidationResult {
  isValid: boolean;
  errors: FlowValidationError[];
  warnings: FlowValidationError[];
  summary: {
    totalSteps: number;
    validSteps: number;
    invalidSteps: number;
    unreachableStates: number;
    circularDependencies: number;
  };
}

export interface UseFlowReturn {
  // State
  flows: FlowDefinition[] | null;
  executions: FlowExecution[] | null;
  flowLoading: boolean;
  flowError: string | null;

  // Flow CRUD operations
  createFlow: (flow: Partial<FlowDefinition>) => Promise<FlowDefinition>;
  updateFlow: (flowId: string, updates: Partial<FlowDefinition>) => Promise<FlowDefinition>;
  deleteFlow: (flowId: string) => Promise<void>;
  getFlow: (flowId: string) => Promise<FlowDefinition | null>;

  // Flow execution
  executeFlow: (flowId: string, config?: any) => Promise<string>;
  getFlowExecutionStatus: (executionId: string) => Promise<FlowExecution | null>;
  getFlowExecutionResult: (executionId: string) => Promise<any>;
  cancelFlowExecution: (executionId: string) => Promise<void>;

  // Flow validation
  validateFlow: (flow: FlowDefinition) => Promise<FlowValidationResult>;

  // Utility functions
  refreshFlows: () => Promise<void>;
  refreshExecutions: () => Promise<void>;
  clearFlowError: () => void;
}

export const useFlow = (refreshInterval: number = 15000): UseFlowReturn => {
  const [flows, setFlows] = useState<FlowDefinition[] | null>(null);
  const [executions, setExecutions] = useState<FlowExecution[] | null>(null);
  const [flowLoading, setFlowLoading] = useState<boolean>(false);
  const [flowError, setFlowError] = useState<string | null>(null);

  // API base URL
  const API_BASE = '/api/flows';

  // Error handling
  const handleError = (error: any, message: string) => {
    console.error(message, error);
    setFlowError(error?.message || message);
    setFlowLoading(false);
  };

  // Clear error
  const clearFlowError = useCallback(() => {
    setFlowError(null);
  }, []);

  // Generic API request helper
  const apiRequest = async <T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> => {
    const url = `${API_BASE}${endpoint}`;
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  };

  // Load flows
  const loadFlows = useCallback(async () => {
    try {
      const response = await apiRequest<{ flows: FlowDefinition[]; pagination: any }>('?limit=100');
      setFlows(response.flows);
    } catch (error) {
      handleError(error, 'Failed to load flows');
    }
  }, []);

  // Load executions
  const loadExecutions = useCallback(async () => {
    try {
      // For now, we'll track executions in memory since there's no dedicated executions endpoint
      // In a real implementation, this would call /api/flows/executions
      setExecutions([]);
    } catch (error) {
      handleError(error, 'Failed to load executions');
    }
  }, []);

  // Create flow
  const createFlow = useCallback(async (flow: Partial<FlowDefinition>): Promise<FlowDefinition> => {
    setFlowLoading(true);
    try {
      const newFlow = await apiRequest<FlowDefinition>('', {
        method: 'POST',
        body: JSON.stringify({ flow }),
      });

      setFlows(prev => prev ? [newFlow, ...prev] : [newFlow]);
      setFlowLoading(false);
      return newFlow;
    } catch (error) {
      handleError(error, 'Failed to create flow');
      throw error;
    }
  }, []);

  // Update flow
  const updateFlow = useCallback(async (
    flowId: string,
    updates: Partial<FlowDefinition>
  ): Promise<FlowDefinition> => {
    setFlowLoading(true);
    try {
      const updatedFlow = await apiRequest<FlowDefinition>(`/${flowId}`, {
        method: 'PUT',
        body: JSON.stringify(updates),
      });

      setFlows(prev =>
        prev?.map(flow => (flow.id === flowId ? updatedFlow : flow)) || null
      );
      setFlowLoading(false);
      return updatedFlow;
    } catch (error) {
      handleError(error, 'Failed to update flow');
      throw error;
    }
  }, []);

  // Delete flow
  const deleteFlow = useCallback(async (flowId: string): Promise<void> => {
    setFlowLoading(true);
    try {
      await apiRequest(`/${flowId}`, {
        method: 'DELETE',
      });

      setFlows(prev => prev?.filter(flow => flow.id !== flowId) || null);
      setFlowLoading(false);
    } catch (error) {
      handleError(error, 'Failed to delete flow');
      throw error;
    }
  }, []);

  // Get flow
  const getFlow = useCallback(async (flowId: string): Promise<FlowDefinition | null> => {
    try {
      const flow = await apiRequest<FlowDefinition>(`/${flowId}`);
      return flow;
    } catch (error) {
      if ((error as any).message?.includes('404')) {
        return null;
      }
      handleError(error, 'Failed to get flow');
      throw error;
    }
  }, []);

  // Execute flow
  const executeFlow = useCallback(async (
    flowId: string,
    config: any = {}
  ): Promise<string> => {
    setFlowLoading(true);
    try {
      const response = await apiRequest<{ executionId: string; status: string }>(
        `/${flowId}/execute`,
        {
          method: 'POST',
          body: JSON.stringify({ config }),
        }
      );

      // Refresh executions after starting execution
      setTimeout(() => loadExecutions(), 500);
      setFlowLoading(false);
      return response.executionId;
    } catch (error) {
      handleError(error, 'Failed to execute flow');
      throw error;
    }
  }, [loadExecutions]);

  // Get flow execution status
  const getFlowExecutionStatus = useCallback(async (
    executionId: string
  ): Promise<FlowExecution | null> => {
    try {
      // This would need to be implemented on the backend
      // For now, return a mock response
      return null;
    } catch (error) {
      handleError(error, 'Failed to get execution status');
      throw error;
    }
  }, []);

  // Get flow execution result
  const getFlowExecutionResult = useCallback(async (executionId: string): Promise<any> => {
    try {
      // This would need to be implemented on the backend
      // For now, return a mock response
      return null;
    } catch (error) {
      handleError(error, 'Failed to get execution result');
      throw error;
    }
  }, []);

  // Cancel flow execution
  const cancelFlowExecution = useCallback(async (executionId: string): Promise<void> => {
    try {
      // This would need to be implemented on the backend
      await apiRequest(`/executions/${executionId}/cancel`, {
        method: 'POST',
      });

      // Refresh executions after cancellation
      loadExecutions();
    } catch (error) {
      handleError(error, 'Failed to cancel execution');
      throw error;
    }
  }, [loadExecutions]);

  // Validate flow
  const validateFlow = useCallback(async (flow: FlowDefinition): Promise<FlowValidationResult> => {
    try {
      const validation = await apiRequest<FlowValidationResult>('/validate', {
        method: 'POST',
        body: JSON.stringify({ flow }),
      });
      return validation;
    } catch (error) {
      handleError(error, 'Failed to validate flow');
      throw error;
    }
  }, []);

  // Refresh flows
  const refreshFlows = useCallback(async () => {
    await loadFlows();
  }, [loadFlows]);

  // Refresh executions
  const refreshExecutions = useCallback(async () => {
    await loadExecutions();
  }, [loadExecutions]);

  // Initial load and auto-refresh
  useEffect(() => {
    loadFlows();
    loadExecutions();

    if (refreshInterval > 0) {
      const interval = setInterval(() => {
        loadFlows();
        loadExecutions();
      }, refreshInterval);

      return () => clearInterval(interval);
    }
  }, [loadFlows, loadExecutions, refreshInterval]);

  return {
    // State
    flows,
    executions,
    flowLoading,
    flowError,

    // Flow CRUD operations
    createFlow,
    updateFlow,
    deleteFlow,
    getFlow,

    // Flow execution
    executeFlow,
    getFlowExecutionStatus,
    getFlowExecutionResult,
    cancelFlowExecution,

    // Flow validation
    validateFlow,

    // Utility functions
    refreshFlows,
    refreshExecutions,
    clearFlowError,
  };
};