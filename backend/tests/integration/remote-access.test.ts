/**
 * Remote API Accessibility Integration Tests
 *
 * Comprehensive test suite for verifying remote API accessibility through Dockploy domain.
 * Tests CORS configuration, health checks, API endpoints, and WebRTC streaming access.
 *
 * These tests ensure the AutoApp system works correctly when deployed remotely
 * through Dockploy with custom domains and proxy configurations.
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { createServer } from '../../src/api/server';
import { Server } from 'http';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * Test configuration interface
 */
interface TestConfig {
  baseUrl: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
  dockployDomain?: string;
  traefikProxy?: string;
  customHeaders?: Record<string, string>;
}

/**
 * CORS test result interface
 */
interface CorsTestResult {
  method: string;
  origin: string;
  headers: Record<string, string>;
  statusCode: number;
  corsHeaders: Record<string, string>;
  passed: boolean;
  details?: string;
}

/**
 * Health check result interface
 */
interface HealthCheckResult {
  endpoint: string;
  responseTime: number;
  status: 'ok' | 'degraded' | 'error';
  statusCode: number;
  body?: any;
  headers?: Record<string, string>;
  passed: boolean;
  details?: string;
}

/**
 * API endpoint test result interface
 */
interface ApiEndpointResult {
  endpoint: string;
  method: string;
  statusCode: number;
  responseTime: number;
  body?: any;
  validation: {
    hasCorrectStructure: boolean;
    hasRequiredFields: boolean;
    hasCorrectDataTypes: boolean;
  };
  passed: boolean;
  details?: string;
}

/**
 * WebRTC configuration test result interface
 */
interface WebRTCResult {
  endpoint: string;
  config: {
    publicUrl?: string;
    iceServers?: any;
    grpcEndpoint?: string;
  };
  accessibility: {
    reachable: boolean;
    responseTime: number;
    statusCode: number;
  };
  passed: boolean;
  details?: string;
}

/**
 * Complete test suite results
 */
interface TestSuiteResults {
  testConfig: TestConfig;
  timestamp: string;
  environment: {
    nodeVersion: string;
    platform: string;
    dockerContainer: boolean;
    envVars: Record<string, string>;
  };
  cors: CorsTestResult[];
  health: HealthCheckResult[];
  api: ApiEndpointResult[];
  webrtc: WebRTCResult[];
  summary: {
    totalTests: number;
    passedTests: number;
    failedTests: number;
    successRate: number;
    overallStatus: 'passed' | 'failed' | 'partial';
  };
}

// ============================================================================
// HTTP CLIENT UTILITIES
// ============================================================================

/**
 * HTTP client with retry capabilities for testing
 */
class TestHttpClient {
  private client: AxiosInstance;
  private retryAttempts: number;
  private retryDelay: number;

  constructor(config: TestConfig) {
    this.retryAttempts = config.retryAttempts;
    this.retryDelay = config.retryDelay;

    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout,
      headers: {
        'User-Agent': 'AutoApp-Remote-Access-Test/1.0.0',
        ...config.customHeaders
      },
      validateStatus: () => true // Don't throw on any status code
    });
  }

  /**
   * Make HTTP request with retry logic
   */
  async requestWithRetry(config: AxiosRequestConfig): Promise<AxiosResponse> {
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
      try {
        const response = await this.client.request(config);
        return response;
      } catch (error) {
        lastError = error as Error;

        if (attempt < this.retryAttempts) {
          await this.delay(this.retryDelay * attempt);
        }
      }
    }

    throw lastError;
  }

  /**
   * Make OPTIONS request for CORS testing
   */
  async options(url: string, origin?: string, headers?: Record<string, string>): Promise<AxiosResponse> {
    return this.requestWithRetry({
      method: 'OPTIONS',
      url,
      headers: {
        ...(origin && { Origin: origin }),
        'Access-Control-Request-Method': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Request-Headers': 'Content-Type, Authorization',
        ...headers
      }
    });
  }

  /**
   * Make GET request
   */
  async get(url: string, headers?: Record<string, string>): Promise<AxiosResponse> {
    return this.requestWithRetry({
      method: 'GET',
      url,
      headers
    });
  }

  /**
   * Make POST request
   */
  async post(url: string, data?: any, headers?: Record<string, string>): Promise<AxiosResponse> {
    return this.requestWithRetry({
      method: 'POST',
      url,
      data,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    });
  }

  /**
   * Simple delay utility
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// CORS TESTING UTILITIES
// ============================================================================

/**
 * CORS configuration validator
 */
class CorsTester {
  private httpClient: TestHttpClient;

  constructor(httpClient: TestHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Test CORS preflight request
   */
  async testCorsPreflight(origin: string, endpoint: string): Promise<CorsTestResult> {
    const startTime = Date.now();

    try {
      const response = await this.httpClient.options(endpoint, origin);

      const corsHeaders: Record<string, string> = {};
      const corsHeaderNames = [
        'access-control-allow-origin',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-max-age',
        'access-control-allow-credentials'
      ];

      corsHeaderNames.forEach(headerName => {
        const value = response.headers[headerName];
        if (value) {
          corsHeaders[headerName] = value;
        }
      });

      const responseTime = Date.now() - startTime;

      // Validate CORS configuration
      const passed = this.validateCorsHeaders(corsHeaders, origin, response.status);

      return {
        method: 'OPTIONS',
        origin,
        headers: corsHeaders,
        statusCode: response.status,
        corsHeaders,
        passed,
        details: passed ?
          `CORS preflight successful in ${responseTime}ms` :
          `CORS validation failed: ${this.getCorsValidationErrors(corsHeaders, origin)}`
      };
    } catch (error) {
      return {
        method: 'OPTIONS',
        origin,
        headers: {},
        statusCode: 0,
        corsHeaders: {},
        passed: false,
        details: `CORS preflight request failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Test multiple origins for CORS configuration
   */
  async testMultipleOrigins(endpoint: string, origins: string[]): Promise<CorsTestResult[]> {
    const results: CorsTestResult[] = [];

    for (const origin of origins) {
      const result = await this.testCorsPreflight(origin, endpoint);
      results.push(result);
    }

    return results;
  }

  /**
   * Validate CORS headers
   */
  private validateCorsHeaders(headers: Record<string, string>, origin: string, statusCode: number): boolean {
    // Check for proper preflight response
    if (statusCode !== 200 && statusCode !== 204) {
      return false;
    }

    // Check for required headers
    if (!headers['access-control-allow-origin']) {
      return false;
    }

    // Check if origin is properly reflected or wildcard is used
    const allowedOrigin = headers['access-control-allow-origin'];
    if (allowedOrigin !== '*' && allowedOrigin !== origin) {
      return false;
    }

    // Check for allowed methods
    if (!headers['access-control-allow-methods']) {
      return false;
    }

    const allowedMethods = headers['access-control-allow-methods'].toLowerCase();
    const requiredMethods = ['get', 'post', 'options'];

    return requiredMethods.some(method => allowedMethods.includes(method));
  }

  /**
   * Get detailed CORS validation errors
   */
  private getCorsValidationErrors(headers: Record<string, string>, origin: string): string {
    const errors: string[] = [];

    if (!headers['access-control-allow-origin']) {
      errors.push('Missing Access-Control-Allow-Origin header');
    }

    if (!headers['access-control-allow-methods']) {
      errors.push('Missing Access-Control-Allow-Methods header');
    }

    const allowedOrigin = headers['access-control-allow-origin'];
    if (allowedOrigin && allowedOrigin !== '*' && allowedOrigin !== origin) {
      errors.push(`Origin ${origin} not in allowed origins`);
    }

    return errors.join(', ');
  }
}

// ============================================================================
// HEALTH CHECK TESTING UTILITIES
// ============================================================================

/**
 * Health check endpoint tester
 */
class HealthCheckTester {
  private httpClient: TestHttpClient;

  constructor(httpClient: TestHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Test health check endpoint
   */
  async testHealthEndpoint(endpoint: string): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      const response = await this.httpClient.get(endpoint);
      const responseTime = Date.now() - startTime;

      // Validate response structure
      const validation = this.validateHealthResponse(response.data, response.status);

      return {
        endpoint,
        responseTime,
        status: this.getHealthStatus(response.data),
        statusCode: response.status,
        body: response.data,
        headers: response.headers,
        passed: validation.isValid,
        details: validation.isValid ?
          `Health check passed in ${responseTime}ms` :
          `Health check validation failed: ${validation.errors.join(', ')}`
      };
    } catch (error) {
      return {
        endpoint,
        responseTime: Date.now() - startTime,
        status: 'error',
        statusCode: 0,
        passed: false,
        details: `Health check request failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Test all health check endpoints
   */
  async testAllHealthEndpoints(): Promise<HealthCheckResult[]> {
    const endpoints = [
      '/api/health',
      '/api/healthz',
      '/api/health/ready',
      '/api/health/live',
      '/api/health/detailed'
    ];

    const results: HealthCheckResult[] = [];

    for (const endpoint of endpoints) {
      const result = await this.testHealthEndpoint(endpoint);
      results.push(result);
    }

    return results;
  }

  /**
   * Validate health response structure
   */
  private validateHealthResponse(body: any, statusCode: number): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check status code
    if (statusCode !== 200 && statusCode !== 503) {
      errors.push(`Unexpected status code: ${statusCode}`);
    }

    // Check required fields
    if (!body || typeof body !== 'object') {
      errors.push('Response body is not an object');
      return { isValid: false, errors };
    }

    if (!body.status || !['ok', 'degraded', 'error'].includes(body.status)) {
      errors.push('Missing or invalid status field');
    }

    if (!body.timestamp) {
      errors.push('Missing timestamp field');
    }

    if (typeof body.uptime !== 'number') {
      errors.push('Missing or invalid uptime field');
    }

    // Check services if present
    if (body.services && typeof body.services === 'object') {
      const requiredServices = ['adb', 'webrtc', 'graph', 'storage'];

      for (const service of requiredServices) {
        if (!body.services[service]) {
          errors.push(`Missing service status: ${service}`);
        } else if (!body.services[service].status) {
          errors.push(`Missing status for service: ${service}`);
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Extract health status from response
   */
  private getHealthStatus(body: any): 'ok' | 'degraded' | 'error' {
    if (!body || !body.status) {
      return 'error';
    }

    return ['ok', 'degraded', 'error'].includes(body.status) ?
      body.status : 'error';
  }
}

// ============================================================================
// API ENDPOINT TESTING UTILITIES
// ============================================================================

/**
 * API endpoint tester
 */
class ApiEndpointTester {
  private httpClient: TestHttpClient;

  constructor(httpClient: TestHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Test API endpoint
   */
  async testApiEndpoint(method: string, endpoint: string, expectedSchema?: any): Promise<ApiEndpointResult> {
    const startTime = Date.now();

    try {
      let response: AxiosResponse;

      switch (method.toUpperCase()) {
        case 'GET':
          response = await this.httpClient.get(endpoint);
          break;
        case 'POST':
          response = await this.httpClient.post(endpoint, {});
          break;
        default:
          throw new Error(`Unsupported HTTP method: ${method}`);
      }

      const responseTime = Date.now() - startTime;

      // Validate response structure
      const validation = this.validateApiResponse(response.data, expectedSchema);

      return {
        endpoint,
        method,
        statusCode: response.status,
        responseTime,
        body: response.data,
        validation,
        passed: validation.hasCorrectStructure && validation.hasRequiredFields && validation.hasCorrectDataTypes,
        details: this.getApiTestDetails(response.status, responseTime, validation)
      };
    } catch (error) {
      return {
        endpoint,
        method,
        statusCode: 0,
        responseTime: Date.now() - startTime,
        validation: {
          hasCorrectStructure: false,
          hasRequiredFields: false,
          hasCorrectDataTypes: false
        },
        passed: false,
        details: `API request failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Test all graph management API endpoints
   */
  async testGraphManagementApis(): Promise<ApiEndpointResult[]> {
    const endpoints = [
      { method: 'GET', endpoint: '/api/graph' },
      { method: 'GET', endpoint: '/api/state/current' },
      { method: 'GET', endpoint: '/api/sessions' },
      { method: 'GET', endpoint: '/api/device/validate' },
      { method: 'GET', endpoint: '/api/device/info' }
    ];

    const results: ApiEndpointResult[] = [];

    for (const { method, endpoint } of endpoints) {
      const result = await this.testApiEndpoint(method, endpoint);
      results.push(result);
    }

    return results;
  }

  /**
   * Test all flow management API endpoints
   */
  async testFlowManagementApis(): Promise<ApiEndpointResult[]> {
    const endpoints = [
      { method: 'GET', endpoint: '/api/flows' },
      { method: 'GET', endpoint: '/api/flows/templates' },
      { method: 'GET', endpoint: '/api/flows/library' },
      { method: 'POST', endpoint: '/api/flows/validate', expectedSchema: { flow: { name: 'test', steps: [] } } }
    ];

    const results: ApiEndpointResult[] = [];

    for (const { method, endpoint, expectedSchema } of endpoints) {
      const result = await this.testApiEndpoint(method, endpoint, expectedSchema);
      results.push(result);
    }

    return results;
  }

  /**
   * Validate API response structure
   */
  private validateApiResponse(body: any, expectedSchema?: any): {
    hasCorrectStructure: boolean;
    hasRequiredFields: boolean;
    hasCorrectDataTypes: boolean;
  } {
    const result = {
      hasCorrectStructure: true,
      hasRequiredFields: true,
      hasCorrectDataTypes: true
    };

    // Check if response is an object
    if (!body || typeof body !== 'object') {
      return {
        hasCorrectStructure: false,
        hasRequiredFields: false,
        hasCorrectDataTypes: false
      };
    }

    // Check for error response
    if (body.error) {
      result.hasCorrectStructure = typeof body.error === 'object' || typeof body.error === 'string';
      return result;
    }

    // Basic structure validation based on endpoint type
    if (Array.isArray(body)) {
      // Array response validation
      result.hasCorrectStructure = true;
    } else if (body.states && body.transitions) {
      // Graph response validation
      result.hasCorrectStructure = Array.isArray(body.states) && Array.isArray(body.transitions);
      result.hasRequiredFields = body.states !== undefined && body.transitions !== undefined;
    } else if (body.flows && body.pagination) {
      // Flow list response validation
      result.hasCorrectStructure = Array.isArray(body.flows) && typeof body.pagination === 'object';
      result.hasRequiredFields = body.flows !== undefined && body.pagination !== undefined;
    }

    return result;
  }

  /**
   * Get API test details
   */
  private getApiTestDetails(statusCode: number, responseTime: number, validation: any): string {
    const parts: string[] = [];

    parts.push(`Status: ${statusCode}`);
    parts.push(`Time: ${responseTime}ms`);

    if (!validation.hasCorrectStructure) {
      parts.push('Invalid structure');
    }

    if (!validation.hasRequiredFields) {
      parts.push('Missing required fields');
    }

    if (!validation.hasCorrectDataTypes) {
      parts.push('Invalid data types');
    }

    return parts.join(', ');
  }
}

// ============================================================================
// WEBRTC TESTING UTILITIES
// ============================================================================

/**
 * WebRTC configuration tester
 */
class WebRTCTester {
  private httpClient: TestHttpClient;

  constructor(httpClient: TestHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Test WebRTC endpoint configuration
   */
  async testWebRTCConfig(): Promise<WebRTCResult> {
    const startTime = Date.now();

    try {
      const response = await this.httpClient.get('/api/stream/url');
      const responseTime = Date.now() - startTime;

      const config = this.extractWebRTCConfig(response.data);
      const accessibility = await this.testWebRTCAccessibility(config);

      const passed = config.publicUrl && accessibility.reachable;

      return {
        endpoint: '/api/stream/url',
        config,
        accessibility,
        passed,
        details: passed ?
          `WebRTC configuration valid and accessible in ${responseTime}ms` :
          `WebRTC configuration invalid or not accessible`
      };
    } catch (error) {
      return {
        endpoint: '/api/stream/url',
        config: {},
        accessibility: {
          reachable: false,
          responseTime: Date.now() - startTime,
          statusCode: 0
        },
        passed: false,
        details: `WebRTC configuration test failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Extract WebRTC configuration from response
   */
  private extractWebRTCConfig(data: any): {
    publicUrl?: string;
    iceServers?: any;
    grpcEndpoint?: string;
  } {
    const config: any = {};

    if (data && typeof data === 'object') {
      if (data.url) {
        config.publicUrl = data.url;
      } else if (data.publicUrl) {
        config.publicUrl = data.publicUrl;
      }

      if (data.iceServers) {
        config.iceServers = data.iceServers;
      }

      if (data.grpcEndpoint) {
        config.grpcEndpoint = data.grpcEndpoint;
      }
    }

    return config;
  }

  /**
   * Test WebRTC endpoint accessibility
   */
  private async testWebRTCAccessibility(config: any): Promise<{
    reachable: boolean;
    responseTime: number;
    statusCode: number;
  }> {
    if (!config.publicUrl) {
      return {
        reachable: false,
        responseTime: 0,
        statusCode: 0
      };
    }

    const startTime = Date.now();

    try {
      const response = await axios.head(config.publicUrl, {
        timeout: 5000,
        validateStatus: () => true
      });

      return {
        reachable: response.status < 500,
        responseTime: Date.now() - startTime,
        statusCode: response.status
      };
    } catch (error) {
      return {
        reachable: false,
        responseTime: Date.now() - startTime,
        statusCode: 0
      };
    }
  }
}

// ============================================================================
// DOMAIN SIMULATION UTILITIES
// ============================================================================

/**
 * Domain simulation utilities for testing different access scenarios
 */
class DomainSimulator {
  private httpClient: TestHttpClient;

  constructor(httpClient: TestHttpClient) {
    this.httpClient = httpClient;
  }

  /**
   * Test accessibility with different host headers
   */
  async testWithDifferentHosts(baseEndpoint: string, hosts: string[]): Promise<any[]> {
    const results: any[] = [];

    for (const host of hosts) {
      try {
        const response = await this.httpClient.get(baseEndpoint, {
          'Host': host,
          'X-Forwarded-Host': host,
          'X-Forwarded-Proto': 'https',
          'X-Forwarded-For': '192.168.1.100'
        });

        results.push({
          host,
          statusCode: response.status,
          responseTime: response.headers['x-response-time'] || 'unknown',
          passed: response.status === 200
        });
      } catch (error) {
        results.push({
          host,
          statusCode: 0,
          responseTime: 'unknown',
          passed: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    return results;
  }

  /**
   * Test accessibility through different user agents
   */
  async testWithDifferentUserAgents(baseEndpoint: string, userAgents: string[]): Promise<any[]> {
    const results: any[] = [];

    for (const userAgent of userAgents) {
      try {
        const response = await this.httpClient.get(baseEndpoint, {
          'User-Agent': userAgent
        });

        results.push({
          userAgent: userAgent.substring(0, 50) + '...',
          statusCode: response.status,
          passed: response.status === 200
        });
      } catch (error) {
        results.push({
          userAgent: userAgent.substring(0, 50) + '...',
          statusCode: 0,
          passed: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    return results;
  }
}

// ============================================================================
// MAIN TEST SUITE
// ============================================================================

/**
 * Main remote accessibility test suite
 */
class RemoteAccessibilityTestSuite {
  private testConfig: TestConfig;
  private httpClient: TestHttpClient;
  private corsTester: CorsTester;
  private healthCheckTester: HealthCheckTester;
  private apiEndpointTester: ApiEndpointTester;
  private webrtcTester: WebRTCTester;
  private domainSimulator: DomainSimulator;

  constructor(config: TestConfig) {
    this.testConfig = config;
    this.httpClient = new TestHttpClient(config);
    this.corsTester = new CorsTester(this.httpClient);
    this.healthCheckTester = new HealthCheckTester(this.httpClient);
    this.apiEndpointTester = new ApiEndpointTester(this.httpClient);
    this.webrtcTester = new WebRTCTester(this.httpClient);
    this.domainSimulator = new DomainSimulator(this.httpClient);
  }

  /**
   * Run complete test suite
   */
  async runCompleteTestSuite(): Promise<TestSuiteResults> {
    console.log('Starting Remote API Accessibility Test Suite...');
    console.log(`Target URL: ${this.testConfig.baseUrl}`);

    const timestamp = new Date().toISOString();

    // Test CORS configuration
    console.log('Testing CORS configuration...');
    const corsOrigins = this.getTestOrigins();
    const corsResults = await this.testCorsConfiguration(corsOrigins);

    // Test health check endpoints
    console.log('Testing health check endpoints...');
    const healthResults = await this.healthCheckTester.testAllHealthEndpoints();

    // Test graph management APIs
    console.log('Testing graph management APIs...');
    const graphApiResults = await this.apiEndpointTester.testGraphManagementApis();

    // Test flow management APIs
    console.log('Testing flow management APIs...');
    const flowApiResults = await this.apiEndpointTester.testFlowManagementApis();

    // Test WebRTC configuration
    console.log('Testing WebRTC configuration...');
    const webrtcResults = [await this.webrtcTester.testWebRTCConfig()];

    // Test domain accessibility
    console.log('Testing domain accessibility...');
    await this.testDomainAccessibility();

    // Combine all API results
    const apiResults = [...graphApiResults, ...flowApiResults];

    // Calculate summary
    const summary = this.calculateTestSummary(corsResults, healthResults, apiResults, webrtcResults);

    const results: TestSuiteResults = {
      testConfig: this.testConfig,
      timestamp,
      environment: this.getEnvironmentInfo(),
      cors: corsResults,
      health: healthResults,
      api: apiResults,
      webrtc: webrtcResults,
      summary
    };

    console.log(`Test suite completed. Overall status: ${summary.overallStatus}`);
    console.log(`Success rate: ${summary.successRate}% (${summary.passedTests}/${summary.totalTests})`);

    return results;
  }

  /**
   * Test CORS configuration
   */
  private async testCorsConfiguration(origins: string[]): Promise<CorsTestResult[]> {
    const results: CorsTestResult[] = [];

    for (const origin of origins) {
      const result = await this.corsTester.testCorsPreflight(origin, '/api/health');
      results.push(result);
    }

    return results;
  }

  /**
   * Test domain accessibility
   */
  private async testDomainAccessibility(): Promise<void> {
    const testHosts = [
      'localhost',
      '127.0.0.1',
      'autoapp.dockploy.io',
      'autoapp.example.com'
    ];

    const testUserAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
      'axios/0.21.1',
      'curl/7.68.0'
    ];

    await this.domainSimulator.testWithDifferentHosts('/api/health', testHosts);
    await this.domainSimulator.testWithDifferentUserAgents('/api/health', testUserAgents);
  }

  /**
   * Get test origins for CORS testing
   */
  private getTestOrigins(): string[] {
    const origins = [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'https://autoapp.dockploy.io',
      'https://autoapp.example.com',
      'https://maydrive.fr'
    ];

    if (this.testConfig.dockployDomain) {
      origins.push(`https://${this.testConfig.dockployDomain}`);
    }

    return origins;
  }

  /**
   * Get environment information
   */
  private getEnvironmentInfo(): any {
    return {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      dockerContainer: this.isRunningInDocker(),
      envVars: {
        NODE_ENV: process.env.NODE_ENV || 'development',
        PORT: process.env.PORT || '3001',
        HOST: process.env.HOST || '0.0.0.0',
        CORS_ALLOWED_ORIGINS: process.env.CORS_ALLOWED_ORIGINS || 'default',
        EXTERNAL_EMULATOR: process.env.EXTERNAL_EMULATOR || 'false'
      }
    };
  }

  /**
   * Check if running in Docker container
   */
  private isRunningInDocker(): boolean {
    try {
      if (existsSync('/.dockerenv')) {
        return true;
      }

      if (existsSync('/proc/1/cgroup')) {
        const cgroup = readFileSync('/proc/1/cgroup', 'utf8');
        return cgroup.includes('docker') || cgroup.includes('containerd');
      }

      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Calculate test suite summary
   */
  private calculateTestSummary(
    cors: CorsTestResult[],
    health: HealthCheckResult[],
    api: ApiEndpointResult[],
    webrtc: WebRTCResult[]
  ): TestSuiteResults['summary'] {
    const allResults = [...cors, ...health, ...api, ...webrtc];
    const totalTests = allResults.length;
    const passedTests = allResults.filter(result => result.passed).length;
    const failedTests = totalTests - passedTests;
    const successRate = Math.round((passedTests / totalTests) * 100);

    let overallStatus: 'passed' | 'failed' | 'partial';
    if (successRate >= 90) {
      overallStatus = 'passed';
    } else if (successRate >= 70) {
      overallStatus = 'partial';
    } else {
      overallStatus = 'failed';
    }

    return {
      totalTests,
      passedTests,
      failedTests,
      successRate,
      overallStatus
    };
  }
}

// ============================================================================
// TEST CONFIGURATION AND EXECUTION
// ============================================================================

/**
 * Get test configuration based on environment
 */
function getTestConfig(): TestConfig {
  const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3001';
  const dockployDomain = process.env.DOCKPLOY_DOMAIN;
  const traefikProxy = process.env.TRAEFIK_PROXY;

  return {
    baseUrl,
    timeout: parseInt(process.env.TEST_TIMEOUT || '10000'),
    retryAttempts: parseInt(process.env.TEST_RETRY_ATTEMPTS || '3'),
    retryDelay: parseInt(process.env.TEST_RETRY_DELAY || '1000'),
    dockployDomain,
    traefikProxy,
    customHeaders: {
      'X-Test-Environment': process.env.NODE_ENV || 'test',
      'X-Test-Suite': 'remote-accessibility',
      'X-Test-Timestamp': new Date().toISOString()
    }
  };
}

/**
 * Save test results to file
 */
async function saveTestResults(results: TestSuiteResults): Promise<void> {
  try {
    const fs = require('fs').promises;
    const path = require('path');

    const resultsDir = path.join(process.cwd(), 'test-results');
    await fs.mkdir(resultsDir, { recursive: true });

    const filename = `remote-access-results-${Date.now()}.json`;
    const filepath = path.join(resultsDir, filename);

    await fs.writeFile(filepath, JSON.stringify(results, null, 2));

    console.log(`Test results saved to: ${filepath}`);
  } catch (error) {
    console.error('Failed to save test results:', error);
  }
}

// ============================================================================
// TEST EXECUTION
// ============================================================================

/**
 * Main test execution function
 */
async function runRemoteAccessibilityTests(): Promise<TestSuiteResults> {
  console.log('='.repeat(80));
  console.log('REMOTE API ACCESSIBILITY INTEGRATION TESTS');
  console.log('='.repeat(80));

  const config = getTestConfig();
  const testSuite = new RemoteAccessibilityTestSuite(config);

  try {
    const results = await testSuite.runCompleteTestSuite();
    await saveTestResults(results);

    console.log('='.repeat(80));
    console.log('TEST RESULTS SUMMARY');
    console.log('='.repeat(80));
    console.log(`Overall Status: ${results.summary.overallStatus.toUpperCase()}`);
    console.log(`Total Tests: ${results.summary.totalTests}`);
    console.log(`Passed: ${results.summary.passedTests}`);
    console.log(`Failed: ${results.summary.failedTests}`);
    console.log(`Success Rate: ${results.summary.successRate}%`);

    // Log failed tests
    const allTests = [
      ...results.cors.map(t => ({ ...t, type: 'CORS' })),
      ...results.health.map(t => ({ ...t, type: 'Health' })),
      ...results.api.map(t => ({ ...t, type: 'API' })),
      ...results.webrtc.map(t => ({ ...t, type: 'WebRTC' }))
    ];

    const failedTests = allTests.filter(t => !t.passed);
    if (failedTests.length > 0) {
      console.log('\nFAILED TESTS:');
      failedTests.forEach(test => {
        console.log(`  [${test.type}] ${test.details || 'Unknown failure'}`);
      });
    }

    return results;
  } catch (error) {
    console.error('Test suite execution failed:', error);
    throw error;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  // Main test suite
  RemoteAccessibilityTestSuite,
  runRemoteAccessibilityTests,

  // Test utilities
  TestHttpClient,
  CorsTester,
  HealthCheckTester,
  ApiEndpointTester,
  WebRTCTester,
  DomainSimulator,

  // Types
  TestConfig,
  CorsTestResult,
  HealthCheckResult,
  ApiEndpointResult,
  WebRTCResult,
  TestSuiteResults,

  // Utilities
  getTestConfig,
  saveTestResults
};

// ============================================================================
// SELF-EXECUTION
// ============================================================================

// Run tests if this file is executed directly
if (require.main === module) {
  runRemoteAccessibilityTests()
    .then((results) => {
      process.exit(results.summary.overallStatus === 'failed' ? 1 : 0);
    })
    .catch((error) => {
      console.error('Test execution failed:', error);
      process.exit(1);
    });
}