/**
 * Discovery System Configuration
 *
 * Centralized configuration for UI discovery, graph management,
 * and state capture settings.
 */

import { GraphConfig, ADBConfig } from '../types/graph';

/**
 * Default discovery system configuration
 */
export const DEFAULT_GRAPH_CONFIG: GraphConfig = {
  graphPath: process.env.GRAPH_PATH || '/app/data/graph.json',
  sessionsDir: process.env.SESSIONS_DIR || '/app/data/sessions',
  screenshotsDir: process.env.SCREENSHOTS_DIR || '/app/data/screenshots',
  mergeThreshold: parseFloat(process.env.MERGE_THRESHOLD || '0.9'),
  maxStates: parseInt(process.env.MAX_STATES || '500'),
  maxTransitions: parseInt(process.env.MAX_TRANSITIONS || '2000'),
  retentionDays: parseInt(process.env.RETENTION_DAYS || '30'),
  debug: process.env.DEBUG === 'true' || process.env.LOG_LEVEL === 'debug'
};

/**
 * Default ADB configuration
 */
export const DEFAULT_ADB_CONFIG: ADBConfig = {
  host: process.env.ADB_HOST || 'host.docker.internal',
  port: parseInt(process.env.ADB_PORT || '5555'),
  serial: process.env.ANDROID_SERIAL || 'emulator-5554',
  timeout: parseInt(process.env.SNAPSHOT_TIMEOUT_MS || '5000'),
  maxRetries: parseInt(process.env.ADB_MAX_RETRIES || '3'),
  poolSize: parseInt(process.env.ADB_POOL_SIZE || '5')
};

/**
 * Capture performance targets
 */
export const CAPTURE_TARGETS = {
  /** Target total capture time in milliseconds */
  CAPTURE_TIME: parseInt(process.env.TARGET_CAPTURE_TIME || '1000'),

  /** Target UI hierarchy extraction time in milliseconds */
  UI_EXTRACTION_TIME: parseInt(process.env.TARGET_UI_EXTRACTION_TIME || '400'),

  /** Target screenshot capture time in milliseconds */
  SCREENSHOT_TIME: parseInt(process.env.TARGET_SCREENSHOT_TIME || '600'),

  /** Target state validation time in milliseconds */
  VALIDATION_TIME: parseInt(process.env.TARGET_VALIDATION_TIME || '2000'),

  /** Target API response time in milliseconds (95th percentile) */
  API_RESPONSE_TIME: parseInt(process.env.TARGET_API_RESPONSE_TIME || '500')
};

/**
 * File size and memory limits
 */
export const LIMITS = {
  /** Maximum graph file size in bytes */
  MAX_GRAPH_SIZE: parseInt(process.env.MAX_GRAPH_SIZE || '10485760'), // 10MB

  /** Maximum screenshot file size in bytes */
  MAX_SCREENSHOT_SIZE: parseInt(process.env.MAX_SCREENSHOT_SIZE || '2097152'), // 2MB

  /** Maximum session log file size in bytes */
  MAX_SESSION_LOG_SIZE: parseInt(process.env.MAX_SESSION_LOG_SIZE || '5242880'), // 5MB

  /** Maximum memory usage for graph operations in bytes */
  MAX_GRAPH_MEMORY: parseInt(process.env.MAX_GRAPH_MEMORY || '104857600'), // 100MB

  /** Maximum XML hierarchy size in bytes */
  MAX_XML_SIZE: parseInt(process.env.MAX_XML_SIZE || '1048576') // 1MB
};

/**
 * Selector prioritization rules
 */
export const SELECTOR_PRIORITIES = {
  /** Resource ID gets highest priority */
  RESOURCE_ID: 1,

  /** Content description gets high priority */
  CONTENT_DESC: 2,

  /** Text content gets medium priority */
  TEXT: 3,

  /** Class name gets low priority */
  CLASS: 4,

  /** Bounds get lowest priority */
  BOUNDS: 5
};

/**
 * Interactive element detection rules
 */
export const INTERACTIVE_PATTERNS = {
  /** Classes that are considered interactive */
  INTERACTIVE_CLASSES: [
    'Button', 'EditText', 'TextView', 'ImageView', 'ImageButton',
    'CheckBox', 'RadioButton', 'Switch', 'Spinner', 'SeekBar',
    'RecyclerView', 'ListView', 'GridView', 'WebView'
  ],

  /** Clickable attributes that indicate interactivity */
  CLICKABLE_ATTRIBUTES: ['clickable', 'focusable', 'long-clickable'],

  /** Text patterns that suggest buttons or actions */
  ACTION_TEXT_PATTERNS: [
    /^(ok|cancel|yes|no|save|delete|edit|add|remove|submit|login|logout)$/i,
    /^(continue|next|previous|back|skip|finish|done)$/i,
    /^(start|stop|play|pause|reset|clear)$/i
  ]
};

/**
 * Session logging configuration
 */
export const SESSION_CONFIG = {
  /** Session log file format */
  LOG_FORMAT: 'jsonl',

  /** Log rotation settings */
  MAX_LOG_ENTRIES: parseInt(process.env.MAX_LOG_ENTRIES || '10000'),
  MAX_LOG_SIZE: LIMITS.MAX_SESSION_LOG_SIZE,

  /** Log levels to record */
  LOG_LEVELS: ['debug', 'info', 'warn', 'error'],

  /** Session timeout in milliseconds */
  SESSION_TIMEOUT: parseInt(process.env.SESSION_TIMEOUT || '1800000'), // 30 minutes

  /** Event types to log */
  EVENT_TYPES: [
    'state_capture',
    'action_execute',
    'transition_create',
    'error',
    'info'
  ]
};

/**
 * Performance monitoring settings
 */
export const PERFORMANCE_CONFIG = {
  /** Enable performance metrics collection */
  ENABLE_METRICS: process.env.ENABLE_PERFORMANCE_METRICS !== 'false',

  /** Metrics collection interval in milliseconds */
  METRICS_INTERVAL: parseInt(process.env.METRICS_INTERVAL || '60000'), // 1 minute

  /** Performance alert thresholds */
  ALERT_THRESHOLDS: {
    CAPURE_TIME: CAPTURE_TARGETS.CAPTURE_TIME * 1.5,
    API_RESPONSE_TIME: CAPTURE_TARGETS.API_RESPONSE_TIME * 2,
    MEMORY_USAGE: LIMITS.MAX_GRAPH_MEMORY * 0.8
  },

  /** Enable performance logging */
  ENABLE_PERFORMANCE_LOGS: process.env.ENABLE_PERFORMANCE_LOGS !== 'false'
};

/**
 * Feature flags
 */
export const FEATURE_FLAGS = {
  /** Enable discovery system */
  ENABLE_DISCOVERY: process.env.ENABLE_DISCOVERY === 'true',

  /** Enable discovery panel in frontend */
  DISCOVERY_PANEL: process.env.DISCOVERY_PANEL === 'true',

  /** Disable legacy GPS panel */
  GPS_PANEL: process.env.GPS_PANEL !== 'true',

  /** Enable experimental features */
  ENABLE_EXPERIMENTAL: process.env.ENABLE_EXPERIMENTAL === 'true',

  /** Enable advanced state deduplication */
  ADVANCED_DEDUPLICATION: process.env.ADVANCED_DEDUPLICATION === 'true',

  /** Enable state similarity analysis */
  SIMILARITY_ANALYSIS: process.env.SIMILARITY_ANALYSIS !== 'false'
};

/**
 * Validation configuration
 */
export const VALIDATION_CONFIG = {
  /** Enable strict validation of input data */
  STRICT_VALIDATION: process.env.STRICT_VALIDATION !== 'false',

  /** Maximum selector length */
  MAX_SELECTOR_LENGTH: parseInt(process.env.MAX_SELECTOR_LENGTH || '1000'),

  /** Maximum text content length */
  MAX_TEXT_LENGTH: parseInt(process.env.MAX_TEXT_LENGTH || '500'),

  /** Maximum number of selectors per state */
  MAX_SELECTORS_PER_STATE: parseInt(process.env.MAX_SELECTORS_PER_STATE || '100'),

  /** Maximum visible text entries per state */
  MAX_VISIBLE_TEXT_PER_STATE: parseInt(process.env.MAX_VISIBLE_TEXT_PER_STATE || '50')
};

/**
 * Get configuration with validation
 */
export function getGraphConfig(): GraphConfig {
  const config = { ...DEFAULT_GRAPH_CONFIG };

  // Validate configuration
  if (config.mergeThreshold < 0 || config.mergeThreshold > 1) {
    throw new Error(`Invalid merge threshold: ${config.mergeThreshold}. Must be between 0 and 1.`);
  }

  if (config.maxStates <= 0) {
    throw new Error(`Invalid max states: ${config.maxStates}. Must be greater than 0.`);
  }

  if (config.maxTransitions <= 0) {
    throw new Error(`Invalid max transitions: ${config.maxTransitions}. Must be greater than 0.`);
  }

  return config;
}

/**
 * Get ADB configuration with validation
 */
export function getADBConfig(): ADBConfig {
  const config = { ...DEFAULT_ADB_CONFIG };

  // Validate configuration
  if (config.port <= 0 || config.port > 65535) {
    throw new Error(`Invalid ADB port: ${config.port}. Must be between 1 and 65535.`);
  }

  if (config.timeout <= 0) {
    throw new Error(`Invalid ADB timeout: ${config.timeout}. Must be greater than 0.`);
  }

  if (config.maxRetries < 0) {
    throw new Error(`Invalid max retries: ${config.maxRetries}. Must be non-negative.`);
  }

  if (config.poolSize <= 0) {
    throw new Error(`Invalid pool size: ${config.poolSize}. Must be greater than 0.`);
  }

  return config;
}

/**
 * Check if discovery system is enabled
 */
export function isDiscoveryEnabled(): boolean {
  return FEATURE_FLAGS.ENABLE_DISCOVERY;
}

/**
 * Flow configuration
 */
export const FLOW_CONFIG = {
  /** Directory for flow definitions */
  flowsDir: process.env.FLOWS_DIR || '/app/data/flows',

  /** Directory for flow execution logs */
  flowLogsDir: process.env.FLOW_LOGS_DIR || '/app/data/flow_logs',

  /** Maximum flow complexity score */
  maxFlowComplexity: parseInt(process.env.MAX_FLOW_COMPLEXITY || '100'),

  /** Default flow execution timeout in milliseconds */
  defaultFlowTimeout: parseInt(process.env.DEFAULT_FLOW_TIMEOUT || '60000'), // 1 minute

  /** Maximum flow execution timeout in milliseconds */
  maxFlowTimeout: parseInt(process.env.MAX_FLOW_TIMEOUT || '300000'), // 5 minutes

  /** Maximum number of parallel flow executions */
  maxParallelExecutions: parseInt(process.env.MAX_PARALLEL_EXECUTIONS || '5'),

  /** Flow execution retry attempts */
  flowRetryAttempts: parseInt(process.env.FLOW_RETRY_ATTEMPTS || '3'),

  /** Flow result retention in days */
  flowRetentionDays: parseInt(process.env.FLOW_RETENTION_DAYS || '30'),

  /** Enable flow execution caching */
  enableFlowCaching: process.env.ENABLE_FLOW_CACHING !== 'false',

  /** Flow validation strictness */
  flowValidationStrict: process.env.FLOW_VALIDATION_STRICT !== 'false',

  /** Maximum flow steps */
  maxFlowSteps: parseInt(process.env.MAX_FLOW_STEPS || '50')
};

/**
 * Flow performance targets
 */
export const FLOW_TARGETS = {
  /** Target flow validation time in milliseconds */
  VALIDATION_TIME: parseInt(process.env.TARGET_FLOW_VALIDATION_TIME || '2000'),

  /** Target step execution time in milliseconds */
  STEP_EXECUTION_TIME: parseInt(process.env.TARGET_STEP_EXECUTION_TIME || '5000'),

  /** Target flow compilation time in milliseconds */
  COMPILATION_TIME: parseInt(process.env.TARGET_FLOW_COMPILATION_TIME || '1000'),

  /** Target flow loading time in milliseconds */
  LOADING_TIME: parseInt(process.env.TARGET_FLOW_LOADING_TIME || '500')
};

/**
 * Get current configuration summary for health checks
 */
export function getConfigSummary(): Record<string, any> {
  return {
    graph: getGraphConfig(),
    adb: getADBConfig(),
    targets: CAPTURE_TARGETS,
    limits: LIMITS,
    features: FEATURE_FLAGS,
    performance: PERFORMANCE_CONFIG,
    flow: FLOW_CONFIG,
    flowTargets: FLOW_TARGETS
  };
}