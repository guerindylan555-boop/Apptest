/**
 * API Client Service
 *
 * Provides HTTP client for backend API communication with
 * proper error handling, retries, and response transformation.
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';

// API Configuration
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:3000/api';
const API_TIMEOUT = process.env.REACT_APP_API_TIMEOUT || 30000;

// Response type definitions
export interface ApiResponse<T = any> {
  data?: T;
  error?: string;
  message?: string;
  timestamp?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface ApiError {
  message: string;
  code?: string;
  details?: any;
  timestamp: string;
}

// Request/Response types for the API
export interface CaptureScreenRequest {
  name: string;
  hints?: string[];
  startStateTag?: 'clean' | 'logged_out_home' | 'logged_in_no_rental' | 'logged_in_with_rental' | 'other';
  operatorId?: string;
}

export interface CaptureActionRequest {
  fromNodeId: string;
  action: {
    kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    delayMs?: number;
  };
  notes?: string;
}

export interface StateDetectionRequest {
  xmlDump?: string;
  screenshotPath?: string;
  thresholds?: {
    matched: number;
    ambiguous: number;
  };
}

export interface FlowExecutionRequest {
  flowId: string;
  variables?: Record<string, any>;
  startStateId?: string;
  dryRun?: boolean;
}

// API Client Class
export class ApiClient {
  private client: AxiosInstance;
  private retryConfig = {
    retries: 3,
    retryDelay: 1000,
    retryCondition: (error: AxiosError) => {
      // Retry on network errors or 5xx server errors
      return !error.response || (error.response.status >= 500 && error.response.status < 600);
    }
  };

  constructor(baseURL: string = API_BASE_URL, timeout: number = API_TIMEOUT) {
    this.client = axios.create({
      baseURL,
      timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    this.setupInterceptors();
  }

  /**
   * Setup request and response interceptors
   */
  private setupInterceptors(): void {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add request timestamp
        config.metadata = { startTime: Date.now() };

        // Add auth token if available
        const token = localStorage.getItem('authToken');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Log request in development
        if (process.env.NODE_ENV === 'development') {
          console.log(`🚀 API Request: ${config.method?.toUpperCase()} ${config.url}`);
        }

        return config;
      },
      (error) => {
        console.error('Request interceptor error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => {
        // Calculate request duration
        const duration = Date.now() - (response.config.metadata?.startTime || Date.now());

        // Log response in development
        if (process.env.NODE_ENV === 'development') {
          console.log(`✅ API Response: ${response.config.method?.toUpperCase()} ${response.config.url} (${duration}ms)`);
        }

        return response;
      },
      async (error) => {
        const originalRequest = error.config;

        // Calculate request duration
        const duration = Date.now() - (originalRequest?.metadata?.startTime || Date.now());

        // Log error in development
        if (process.env.NODE_ENV === 'development') {
          console.error(`❌ API Error: ${originalRequest?.method?.toUpperCase()} ${originalRequest?.url} (${duration}ms)`, error);
        }

        // Handle 401 Unauthorized (token refresh logic could go here)
        if (error.response?.status === 401 && !originalRequest._retry) {
          // TODO: Implement token refresh logic
          console.warn('Authentication failed - token refresh needed');
        }

        // Retry logic
        if (this.shouldRetry(error) && !originalRequest._retryCount) {
          originalRequest._retryCount = 0;
        }

        if (this.shouldRetry(error) && originalRequest._retryCount < this.retryConfig.retries) {
          originalRequest._retryCount += 1;
          const delay = this.retryConfig.retryDelay * Math.pow(2, originalRequest._retryCount - 1);

          console.log(`🔄 Retrying request (${originalRequest._retryCount}/${this.retryConfig.retries}) after ${delay}ms`);

          await new Promise(resolve => setTimeout(resolve, delay));
          return this.client(originalRequest);
        }

        return Promise.reject(this.formatError(error));
      }
    );
  }

  /**
   * Check if request should be retried
   */
  private shouldRetry(error: AxiosError): boolean {
    return this.retryConfig.retryCondition(error);
  }

  /**
   * Format error for consistent error handling
   */
  private formatError(error: AxiosError): ApiError {
    if (error.response) {
      // Server responded with error status
      return {
        message: error.response.data?.message || error.response.statusText || 'Request failed',
        code: error.response.data?.code || `HTTP_${error.response.status}`,
        details: error.response.data,
        timestamp: new Date().toISOString()
      };
    } else if (error.request) {
      // Request was made but no response received
      return {
        message: 'Network error - no response received',
        code: 'NETWORK_ERROR',
        details: { originalError: error.message },
        timestamp: new Date().toISOString()
      };
    } else {
      // Something else happened
      return {
        message: error.message || 'Unknown error occurred',
        code: 'UNKNOWN_ERROR',
        details: { originalError: error.message },
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Generic request method with type safety
   */
  private async request<T>(
    config: AxiosRequestConfig
  ): Promise<ApiResponse<T>> {
    try {
      const response: AxiosResponse<T> = await this.client.request(config);
      return {
        data: response.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw error; // Error is already formatted by interceptor
    }
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<ApiResponse<{
    status: string;
    timestamp: string;
    version: string;
    uptime: number;
    memory: { used: number; total: number };
  }>> {
    return this.request({
      method: 'GET',
      url: '/health'
    });
  }

  /**
   * Get API version
   */
  async getVersion(): Promise<ApiResponse<{
    version: string;
    buildTime: string;
    gitCommit: string;
    environment: string;
  }>> {
    return this.request({
      method: 'GET',
      url: '/version'
    });
  }

  /**
   * Capture screen
   */
  async captureScreen(request: CaptureScreenRequest): Promise<ApiResponse<{
    nodeId: string;
    screenshotPath: string;
    xmlPath: string;
    checksum: string;
  }>> {
    return this.request({
      method: 'POST',
      url: '/captures/screen',
      data: request
    });
  }

  /**
   * Capture action
   */
  async captureAction(request: CaptureActionRequest): Promise<ApiResponse<{
    edgeId: string;
    destinationNodeId?: string;
    executionResult: {
      success: boolean;
      duration: number;
      screenshotPath?: string;
    };
  }>> {
    return this.request({
      method: 'POST',
      url: '/captures/action',
      data: request
    });
  }

  /**
   * Get node by ID
   */
  async getNode(nodeId: string): Promise<ApiResponse<any>> {
    return this.request({
      method: 'GET',
      url: `/nodes/${nodeId}`
    });
  }

  /**
   * Update node
   */
  async updateNode(nodeId: string, updates: any): Promise<ApiResponse<any>> {
    return this.request({
      method: 'PUT',
      url: `/nodes/${nodeId}`,
      data: updates
    });
  }

  /**
   * Delete node
   */
  async deleteNode(nodeId: string): Promise<ApiResponse<void>> {
    return this.request({
      method: 'DELETE',
      url: `/nodes/${nodeId}`
    });
  }

  /**
   * Get all nodes with optional filtering
   */
  async getNodes(params?: {
    status?: string;
    startStateTag?: string;
    search?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<PaginatedResponse<any>>> {
    return this.request({
      method: 'GET',
      url: '/nodes',
      params
    });
  }

  /**
   * Detect state from XML dump
   */
  async detectState(request: StateDetectionRequest): Promise<ApiResponse<{
    candidates: Array<{
      nodeId: string;
      nodeName: string;
      score: number;
      reasons: string[];
    }>;
    selectedNodeId?: string;
    status: 'matched' | 'ambiguous' | 'unknown';
    confidence: number;
  }>> {
    return this.request({
      method: 'POST',
      url: '/detect',
      data: request
    });
  }

  /**
   * Get detection history
   */
  async getDetectionHistory(params?: {
    limit?: number;
    offset?: number;
    status?: string;
    startDate?: string;
    endDate?: string;
  }): Promise<ApiResponse<PaginatedResponse<any>>> {
    return this.request({
      method: 'GET',
      url: '/detect/history',
      params
    });
  }

  /**
   * Get all flows
   */
  async getFlows(params?: {
    status?: string;
    search?: string;
    page?: number;
    limit?: number;
  }): Promise<ApiResponse<PaginatedResponse<any>>> {
    return this.request({
      method: 'GET',
      url: '/flows',
      params
    });
  }

  /**
   * Get flow by ID
   */
  async getFlow(flowId: string): Promise<ApiResponse<any>> {
    return this.request({
      method: 'GET',
      url: `/flows/${flowId}`
    });
  }

  /**
   * Create flow
   */
  async createFlow(flowData: any): Promise<ApiResponse<any>> {
    return this.request({
      method: 'POST',
      url: '/flows',
      data: flowData
    });
  }

  /**
   * Update flow
   */
  async updateFlow(flowId: string, updates: any): Promise<ApiResponse<any>> {
    return this.request({
      method: 'PUT',
      url: `/flows/${flowId}`,
      data: updates
    });
  }

  /**
   * Delete flow
   */
  async deleteFlow(flowId: string): Promise<ApiResponse<void>> {
    return this.request({
      method: 'DELETE',
      url: `/flows/${flowId}`
    });
  }

  /**
   * Execute flow
   */
  async executeFlow(request: FlowExecutionRequest): Promise<ApiResponse<{
    executionId: string;
    status: 'started' | 'running' | 'completed' | 'failed';
    steps: Array<{
      stepId: string;
      status: string;
      duration?: number;
      error?: string;
    }>;
  }>> {
    return this.request({
      method: 'POST',
      url: '/flows/run',
      data: request
    });
  }

  /**
   * Get flow execution status
   */
  async getFlowExecution(executionId: string): Promise<ApiResponse<{
    executionId: string;
    status: string;
    currentStep: number;
    totalSteps: number;
    progress: number;
    logs: Array<{
      timestamp: string;
      level: string;
      message: string;
    }>;
    startTime: string;
    endTime?: string;
    duration?: number;
  }>> {
    return this.request({
      method: 'GET',
      url: `/flows/executions/${executionId}`
    });
  }

  /**
   * Cancel flow execution
   */
  async cancelFlowExecution(executionId: string): Promise<ApiResponse<void>> {
    return this.request({
      method: 'POST',
      url: `/flows/executions/${executionId}/cancel`
    });
  }

  /**
   * Get telemetry data
   */
  async getTelemetry(params?: {
    type?: 'detections' | 'executions' | 'performance';
    startDate?: string;
    endDate?: string;
    granularity?: 'hour' | 'day' | 'week';
  }): Promise<ApiResponse<any>> {
    return this.request({
      method: 'GET',
      url: '/telemetry',
      params
    });
  }

  /**
   * Upload file (e.g., screenshot, XML dump)
   */
  async uploadFile(file: File, type: 'screenshot' | 'xml'): Promise<ApiResponse<{
    filename: string;
    path: string;
    size: number;
    checksum: string;
  }>> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('type', type);

    return this.request({
      method: 'POST',
      url: '/upload',
      data: formData,
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
  }

  /**
   * Download file
   */
  async downloadFile(path: string): Promise<Blob> {
    const response = await this.client.get(`/download/${encodeURIComponent(path)}`, {
      responseType: 'blob'
    });
    return response.data;
  }

  /**
   * Get static data for development/testing
   */
  async getStaticScreens(): Promise<ApiResponse<any>> {
    return this.request({
      method: 'GET',
      url: '/static/screens'
    });
  }

  async getStaticFlows(): Promise<ApiResponse<any>> {
    return this.request({
      method: 'GET',
      url: '/static/flows'
    });
  }
}

// Create singleton instance
export const apiClient = new ApiClient();

// Export individual methods for convenience
export const {
  healthCheck,
  getVersion,
  captureScreen,
  captureAction,
  getNode,
  updateNode,
  deleteNode,
  getNodes,
  detectState,
  getDetectionHistory,
  getFlows,
  getFlow,
  createFlow,
  updateFlow,
  deleteFlow,
  executeFlow,
  getFlowExecution,
  cancelFlowExecution,
  getTelemetry,
  uploadFile,
  downloadFile,
  getStaticScreens,
  getStaticFlows
} = apiClient;

// Export types for use in components
export type { ApiError, ApiResponse, PaginatedResponse };

export default apiClient;