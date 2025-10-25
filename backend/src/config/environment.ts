/**
 * Environment Configuration Validation
 *
 * Comprehensive validation for all environment variables used by the AutoApp
 * UI Map & Intelligent Flow Engine system. This module ensures all required
 * environment variables are present, properly typed, and within valid ranges.
 *
 * @author AutoApp Team
 * @version 1.0.0
 */

import * as path from 'path';
import { existsSync } from 'fs';

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

/**
 * WebRTC Configuration Interface
 */
export interface WebRTCConfig {
  /** Public URL for WebRTC connections */
  publicUrl: string;
  /** ICE servers for STUN/TURN */
  iceServers: string[];
  /** gRPC endpoint for emulator communication */
  grpcEndpoint: string;
  /** Connection timeout in milliseconds */
  timeout: number;
  /** ICE connection timeout */
  iceTimeout: number;
  /** Maximum reconnection attempts */
  reconnectionAttempts: number;
  /** Video resolution */
  resolution: string;
  /** Frame rate */
  frameRate: number;
  /** Bitrate in kbps */
  bitrate: number;
}

/**
 * ADB Configuration Interface
 */
export interface ADBConfig {
  /** ADB host address */
  host: string;
  /** ADB port number */
  port: number;
  /** Android device serial number */
  deviceSerial: string;
  /** Connection timeout in milliseconds */
  timeout: number;
  /** UIAutomator2 timeout */
  uiAutomatorTimeout: number;
  /** UI capture timeout */
  uiCaptureTimeout: number;
  /** Temporary UI XML file path */
  xmlTempPath: string;
  /** State deduplication threshold (0-1) */
  stateDedupThreshold: number;
  /** Merge threshold (0-1) */
  mergeThreshold: number;
}

/**
 * Storage Configuration Interface
 */
export interface StorageConfig {
  /** Root directory for graphs */
  graphRoot: string;
  /** Root directory for flows */
  flowRoot: string;
  /** Sessions directory */
  sessionsDir: string;
  /** Screenshots directory */
  screenshotsDir: string;
  /** Specific graph file path */
  graphPath: string;
  /** Maximum graph states */
  graphStateLimit: number;
  /** Maximum graph transitions */
  graphTransitionLimit: number;
}

/**
 * Flow Execution Configuration Interface
 */
export interface FlowConfig {
  /** Maximum replay retry attempts */
  replayRetryLimit: number;
  /** Replay step timeout in milliseconds */
  replayStepTimeout: number;
  /** Flow execution timeout in milliseconds */
  executionTimeout: number;
  /** Flow validation timeout in milliseconds */
  validationTimeout: number;
  /** State detection timeout */
  stateDetectionTimeout: number;
  /** State recovery timeout */
  stateRecoveryTimeout: number;
  /** Maximum recovery attempts */
  recoveryMaxAttempts: number;
}

/**
 * MaynDrive Configuration Interface
 */
export interface MaynDriveConfig {
  /** MaynDrive package name */
  packageName: string;
  /** Main activity name */
  mainActivity: string;
  /** Login activity name */
  loginActivity: string;
  /** Login flow file path */
  loginFlow: string;
  /** Unlock flow file path */
  unlockFlow: string;
  /** Lock flow file path */
  lockFlow: string;
}

/**
 * Performance Configuration Interface
 */
export interface PerformanceConfig {
  /** Snapshot timeout in milliseconds */
  snapshotTimeout: number;
  /** Snapshot batch size */
  snapshotBatchSize: number;
  /** Concurrent capture limit */
  captureConcurrentLimit: number;
  /** Graph validation timeout */
  graphValidationTimeout: number;
  /** Graph pathfinding timeout */
  graphPathfindingTimeout: number;
  /** State comparison cache size */
  stateComparisonCacheSize: number;
  /** Maximum session memory in MB */
  maxSessionMemoryMB: number;
  /** Maximum graph load time */
  maxGraphLoadTime: number;
  /** Concurrent flow limit */
  concurrentFlowLimit: number;
}

/**
 * Logging Configuration Interface
 */
export interface LoggingConfig {
  /** Global log level */
  level: string;
  /** Log format (json|text) */
  format: string;
  /** Log output destination */
  output: string;
  /** Log file path */
  filePath: string;
  /** Flow engine log level */
  flowEngineLevel: string;
  /** Graph log level */
  graphLevel: string;
  /** Replay log level */
  replayLevel: string;
  /** WebRTC log level */
  webrtcLevel: string;
  /** Session log retention in days */
  sessionRetentionDays: number;
  /** Debug screenshot capture */
  debugScreenshotCapture: boolean;
  /** Detailed state logging */
  detailedStateLogging: boolean;
}

/**
 * API Configuration Interface
 */
export interface APIConfig {
  /** Flow API port */
  port: number;
  /** API prefix */
  prefix: string;
  /** API timeout in milliseconds */
  timeout: number;
  /** Enable authentication */
  authEnabled: boolean;
  /** CORS origin */
  corsOrigin: string;
  /** Rate limit */
  rateLimit: number;
}

/**
 * Security Configuration Interface
 */
export interface SecurityConfig {
  /** ADB key path */
  adbKeyPath?: string;
  /** Allow external ADB connections */
  allowExternalADB: boolean;
  /** Require device authentication */
  requireDeviceAuth: boolean;
  /** Session timeout in seconds */
  sessionTimeout: number;
}

/**
 * Development Configuration Interface
 */
export interface DevelopmentConfig {
  /** Development mode */
  devMode: boolean;
  /** Debug graph exports */
  debugGraphExports: boolean;
  /** Enable LLM flow assistance */
  enableLLMFlowAssistance: boolean;
  /** Test mode */
  testMode: boolean;
  /** Mock ADB responses */
  mockADBResponses: boolean;
  /** Enable flow validation */
  enableFlowValidation: boolean;
}

/**
 * Complete Environment Configuration Interface
 */
export interface EnvironmentConfig {
  webrtc: WebRTCConfig;
  adb: ADBConfig;
  storage: StorageConfig;
  flow: FlowConfig;
  maynDrive: MaynDriveConfig;
  performance: PerformanceConfig;
  logging: LoggingConfig;
  api: APIConfig;
  security: SecurityConfig;
  development: DevelopmentConfig;
  /** Current environment (development|production|test) */
  environment: string;
  /** Project root directory */
  projectRoot: string;
}

// =============================================================================
// VALIDATION UTILITIES
// =============================================================================

/**
 * Configuration validation error
 */
export class ConfigValidationError extends Error {
  constructor(
    message: string,
    public readonly variable?: string,
    public readonly suggestion?: string
  ) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

/**
 * Validate URL format
 */
function validateUrl(value: string, variableName: string): string {
  try {
    new URL(value);
    return value;
  } catch {
    throw new ConfigValidationError(
      `Invalid URL format for ${variableName}: ${value}`,
      variableName,
      'Please provide a valid URL including protocol (http:// or https://)'
    );
  }
}

/**
 * Validate port number
 */
function validatePort(value: string, variableName: string): number {
  const port = parseInt(value, 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    throw new ConfigValidationError(
      `Invalid port number for ${variableName}: ${value}`,
      variableName,
      'Please provide a valid port number between 1 and 65535'
    );
  }
  return port;
}

/**
 * Validate timeout value (milliseconds)
 */
function validateTimeout(value: string, variableName: string, min = 100, max = 3600000): number {
  const timeout = parseInt(value, 10);
  if (isNaN(timeout) || timeout < min || timeout > max) {
    throw new ConfigValidationError(
      `Invalid timeout for ${variableName}: ${value}ms`,
      variableName,
      `Please provide a timeout between ${min}ms and ${max}ms`
    );
  }
  return timeout;
}

/**
 * Validate boolean value
 */
function validateBoolean(value: string | undefined, variableName: string, defaultValue = false): boolean {
  if (value === undefined) return defaultValue;
  const normalized = value.toLowerCase().trim();
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
  if (['false', '0', 'no', 'off'].includes(normalized)) return false;

  throw new ConfigValidationError(
    `Invalid boolean value for ${variableName}: ${value}`,
    variableName,
    'Please use true, false, 1, 0, yes, no, on, or off'
  );
}

/**
 * Validate threshold value (0-1)
 */
function validateThreshold(value: string, variableName: string): number {
  const threshold = parseFloat(value);
  if (isNaN(threshold) || threshold < 0 || threshold > 1) {
    throw new ConfigValidationError(
      `Invalid threshold for ${variableName}: ${value}`,
      variableName,
      'Please provide a number between 0 and 1'
    );
  }
  return threshold;
}

/**
 * Validate file path exists or can be created
 */
function validatePath(value: string, variableName: string, mustExist = false): string {
  if (!value || value.trim() === '') {
    throw new ConfigValidationError(
      `Empty path for ${variableName}`,
      variableName,
      'Please provide a valid file system path'
    );
  }

  const normalizedPath = path.resolve(value);

  if (mustExist && !existsSync(normalizedPath)) {
    throw new ConfigValidationError(
      `Path does not exist for ${variableName}: ${normalizedPath}`,
      variableName,
      `Please ensure the path exists or create it: ${normalizedPath}`
    );
  }

  return normalizedPath;
}

/**
 * Validate log level
 */
function validateLogLevel(value: string, variableName: string): string {
  const validLevels = ['error', 'warn', 'info', 'debug', 'trace'];
  const normalized = value.toLowerCase().trim();

  if (!validLevels.includes(normalized)) {
    throw new ConfigValidationError(
      `Invalid log level for ${variableName}: ${value}`,
      variableName,
      `Please use one of: ${validLevels.join(', ')}`
    );
  }

  return normalized;
}

/**
 * Validate log format
 */
function validateLogFormat(value: string, variableName: string): string {
  const validFormats = ['json', 'text'];
  const normalized = value.toLowerCase().trim();

  if (!validFormats.includes(normalized)) {
    throw new ConfigValidationError(
      `Invalid log format for ${variableName}: ${value}`,
      variableName,
      `Please use one of: ${validFormats.join(', ')}`
    );
  }

  return normalized;
}

/**
 * Parse ICE servers from comma-separated string
 */
function parseIceServers(value: string | undefined): string[] {
  if (!value || value.trim() === '') {
    return [];
  }

  return value
    .split(',')
    .map(server => server.trim())
    .filter(server => server.length > 0);
}

/**
 * Validate ICE server URLs
 */
function validateIceServers(value: string | undefined, variableName: string): string[] {
  const servers = parseIceServers(value);

  for (const server of servers) {
    if (!server.startsWith('stun:') && !server.startsWith('turn:')) {
      throw new ConfigValidationError(
        `Invalid ICE server format: ${server}`,
        variableName,
        'ICE servers must start with stun: or turn: (e.g., stun:stun.l.google.com:19302)'
      );
    }
  }

  return servers;
}

// =============================================================================
// CONFIGURATION LOADERS
// =============================================================================

/**
 * Load WebRTC configuration
 */
function loadWebRTCConfig(): WebRTCConfig {
  return {
    publicUrl: validateUrl(
      process.env.EMULATOR_WEBRTC_PUBLIC_URL || 'http://127.0.0.1:9000',
      'EMULATOR_WEBRTC_PUBLIC_URL'
    ),
    iceServers: validateIceServers(
      process.env.EMULATOR_WEBRTC_ICE_SERVERS,
      'EMULATOR_WEBRTC_ICE_SERVERS'
    ),
    grpcEndpoint: validateUrl(
      process.env.EMULATOR_GRPC_ENDPOINT || 'http://envoy:8080',
      'EMULATOR_GRPC_ENDPOINT'
    ),
    timeout: validateTimeout(
      process.env.WEBRTC_TIMEOUT || '30000',
      'WEBRTC_TIMEOUT'
    ),
    iceTimeout: validateTimeout(
      process.env.WEBRTC_ICE_TIMEOUT || '10000',
      'WEBRTC_ICE_TIMEOUT'
    ),
    reconnectionAttempts: parseInt(process.env.WEBRTC_RECONNECTION_ATTEMPTS || '3', 10),
    resolution: process.env.WEBRTC_RESOLUTION || '720p',
    frameRate: parseInt(process.env.WEBRTC_FRAME_RATE || '15', 10),
    bitrate: parseInt(process.env.WEBRTC_BITRATE || '2000', 10)
  };
}

/**
 * Load ADB configuration
 */
function loadADBConfig(): ADBConfig {
  return {
    host: process.env.ADB_HOST || 'host.docker.internal',
    port: validatePort(
      process.env.ADB_PORT || '5555',
      'ADB_PORT'
    ),
    deviceSerial: process.env.ANDROID_SERIAL || 'emulator-5554',
    timeout: validateTimeout(
      process.env.ADB_TIMEOUT || '30000',
      'ADB_TIMEOUT'
    ),
    uiAutomatorTimeout: validateTimeout(
      process.env.UIAUTOMATOR2_TIMEOUT || '15000',
      'UIAUTOMATOR2_TIMEOUT'
    ),
    uiCaptureTimeout: validateTimeout(
      process.env.UI_CAPTURE_TIMEOUT || '10000',
      'UI_CAPTURE_TIMEOUT'
    ),
    xmlTempPath: validatePath(
      process.env.UIXML_TMP || '/tmp/view.xml',
      'UIXML_TMP'
    ),
    stateDedupThreshold: validateThreshold(
      process.env.STATE_DEDUP_THRESHOLD || '0.9',
      'STATE_DEDUP_THRESHOLD'
    ),
    mergeThreshold: validateThreshold(
      process.env.MERGE_THRESHOLD || '0.9',
      'MERGE_THRESHOLD'
    )
  };
}

/**
 * Load Storage configuration
 */
function loadStorageConfig(): StorageConfig {
  const projectRoot = path.resolve(__dirname, '..', '..', '..');

  return {
    graphRoot: validatePath(
      process.env.GRAPH_ROOT || path.join(projectRoot, 'data', 'graphs'),
      'GRAPH_ROOT'
    ),
    flowRoot: validatePath(
      process.env.FLOW_ROOT || path.join(projectRoot, 'data', 'flows'),
      'FLOW_ROOT'
    ),
    sessionsDir: validatePath(
      process.env.SESSIONS_DIR || path.join(projectRoot, 'data', 'sessions'),
      'SESSIONS_DIR'
    ),
    screenshotsDir: validatePath(
      process.env.SCREENSHOTS_DIR || path.join(projectRoot, 'data', 'screenshots'),
      'SCREENSHOTS_DIR'
    ),
    graphPath: validatePath(
      process.env.GRAPH_PATH || path.join(projectRoot, 'data', 'graph.json'),
      'GRAPH_PATH'
    ),
    graphStateLimit: parseInt(process.env.GRAPH_STATE_LIMIT || '500', 10),
    graphTransitionLimit: parseInt(process.env.GRAPH_TRANSITION_LIMIT || '2000', 10)
  };
}

/**
 * Load Flow execution configuration
 */
function loadFlowConfig(): FlowConfig {
  return {
    replayRetryLimit: parseInt(process.env.REPLAY_RETRY_LIMIT || '3', 10),
    replayStepTimeout: validateTimeout(
      process.env.REPLAY_STEP_TIMEOUT || '30000',
      'REPLAY_STEP_TIMEOUT'
    ),
    executionTimeout: validateTimeout(
      process.env.FLOW_EXECUTION_TIMEOUT || '300000',
      'FLOW_EXECUTION_TIMEOUT'
    ),
    validationTimeout: validateTimeout(
      process.env.FLOW_VALIDATION_TIMEOUT || '5000',
      'FLOW_VALIDATION_TIMEOUT'
    ),
    stateDetectionTimeout: validateTimeout(
      process.env.STATE_DETECTION_TIMEOUT || '5000',
      'STATE_DETECTION_TIMEOUT'
    ),
    stateRecoveryTimeout: validateTimeout(
      process.env.STATE_RECOVERY_TIMEOUT || '15000',
      'STATE_RECOVERY_TIMEOUT'
    ),
    recoveryMaxAttempts: parseInt(process.env.RECOVERY_MAX_ATTEMPTS || '2', 10)
  };
}

/**
 * Load MaynDrive configuration
 */
function loadMaynDriveConfig(): MaynDriveConfig {
  return {
    packageName: process.env.MAYNDRIVE_PACKAGE || 'com.mayn.mayndrive',
    mainActivity: process.env.MAYNDRIVE_MAIN_ACTIVITY || 'com.mayn.mayndrive.MainActivity',
    loginActivity: process.env.MAYNDRIVE_LOGIN_ACTIVITY || 'com.mayn.mayndrive.LoginActivity',
    loginFlow: process.env.MAYNDRIVE_LOGIN_FLOW || 'flows/login.json',
    unlockFlow: process.env.MAYNDRIVE_UNLOCK_FLOW || 'flows/unlock.json',
    lockFlow: process.env.MAYNDRIVE_LOCK_FLOW || 'flows/lock.json'
  };
}

/**
 * Load Performance configuration
 */
function loadPerformanceConfig(): PerformanceConfig {
  return {
    snapshotTimeout: validateTimeout(
      process.env.SNAPSHOT_TIMEOUT_MS || '5000',
      'SNAPSHOT_TIMEOUT_MS'
    ),
    snapshotBatchSize: parseInt(process.env.SNAPSHOT_BATCH_SIZE || '10', 10),
    captureConcurrentLimit: parseInt(process.env.CAPTURE_CONCURRENT_LIMIT || '3', 10),
    graphValidationTimeout: validateTimeout(
      process.env.GRAPH_VALIDATION_TIMEOUT || '2000',
      'GRAPH_VALIDATION_TIMEOUT'
    ),
    graphPathfindingTimeout: validateTimeout(
      process.env.GRAPH_PATHFINDING_TIMEOUT || '1000',
      'GRAPH_PATHFINDING_TIMEOUT'
    ),
    stateComparisonCacheSize: parseInt(process.env.STATE_COMPARISON_CACHE_SIZE || '1000', 10),
    maxSessionMemoryMB: parseInt(process.env.MAX_SESSION_MEMORY_MB || '512', 10),
    maxGraphLoadTime: validateTimeout(
      process.env.MAX_GRAPH_LOAD_TIME || '5000',
      'MAX_GRAPH_LOAD_TIME'
    ),
    concurrentFlowLimit: parseInt(process.env.CONCURRENT_FLOW_LIMIT || '5', 10)
  };
}

/**
 * Load Logging configuration
 */
function loadLoggingConfig(): LoggingConfig {
  return {
    level: validateLogLevel(
      process.env.LOG_LEVEL || 'info',
      'LOG_LEVEL'
    ),
    format: validateLogFormat(
      process.env.LOG_FORMAT || 'json',
      'LOG_FORMAT'
    ),
    output: process.env.LOG_OUTPUT || 'console',
    filePath: validatePath(
      process.env.LOG_FILE_PATH || '/app/logs/autoapp.log',
      'LOG_FILE_PATH'
    ),
    flowEngineLevel: validateLogLevel(
      process.env.FLOW_ENGINE_LOG_LEVEL || 'info',
      'FLOW_ENGINE_LOG_LEVEL'
    ),
    graphLevel: validateLogLevel(
      process.env.GRAPH_LOG_LEVEL || 'warn',
      'GRAPH_LOG_LEVEL'
    ),
    replayLevel: validateLogLevel(
      process.env.REPLAY_LOG_LEVEL || 'info',
      'REPLAY_LOG_LEVEL'
    ),
    webrtcLevel: validateLogLevel(
      process.env.WEBRTC_LOG_LEVEL || 'error',
      'WEBRTC_LOG_LEVEL'
    ),
    sessionRetentionDays: parseInt(process.env.SESSION_LOG_RETENTION_DAYS || '7', 10),
    debugScreenshotCapture: validateBoolean(
      process.env.DEBUG_SCREENSHOT_CAPTURE,
      'DEBUG_SCREENSHOT_CAPTURE'
    ),
    detailedStateLogging: validateBoolean(
      process.env.DETAILED_STATE_LOGGING,
      'DETAILED_STATE_LOGGING'
    )
  };
}

/**
 * Load API configuration
 */
function loadAPIConfig(): APIConfig {
  return {
    port: validatePort(
      process.env.FLOW_API_PORT || '8080',
      'FLOW_API_PORT'
    ),
    prefix: process.env.FLOW_API_PREFIX || '/api/v1',
    timeout: validateTimeout(
      process.env.FLOW_API_TIMEOUT || '30000',
      'FLOW_API_TIMEOUT'
    ),
    authEnabled: validateBoolean(
      process.env.API_AUTH_ENABLED,
      'API_AUTH_ENABLED'
    ),
    corsOrigin: process.env.API_CORS_ORIGIN || '*',
    rateLimit: parseInt(process.env.API_RATE_LIMIT || '100', 10)
  };
}

/**
 * Load Security configuration
 */
function loadSecurityConfig(): SecurityConfig {
  return {
    adbKeyPath: process.env.ADBKEY || undefined,
    allowExternalADB: validateBoolean(
      process.env.ALLOW_EXTERNAL_ADB,
      'ALLOW_EXTERNAL_ADB'
    ),
    requireDeviceAuth: validateBoolean(
      process.env.REQUIRE_DEVICE_AUTH,
      'REQUIRE_DEVICE_AUTH'
    ),
    sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '3600', 10)
  };
}

/**
 * Load Development configuration
 */
function loadDevelopmentConfig(): DevelopmentConfig {
  return {
    devMode: validateBoolean(
      process.env.DEV_MODE,
      'DEV_MODE'
    ),
    debugGraphExports: validateBoolean(
      process.env.DEBUG_GRAPH_EXPORTS,
      'DEBUG_GRAPH_EXPORTS'
    ),
    enableLLMFlowAssistance: validateBoolean(
      process.env.ENABLE_LLM_FLOW_ASSISTANCE,
      'ENABLE_LLM_FLOW_ASSISTANCE',
      true
    ),
    testMode: validateBoolean(
      process.env.TEST_MODE,
      'TEST_MODE'
    ),
    mockADBResponses: validateBoolean(
      process.env.MOBT_ADB_RESPONSES, // Note: typo in original env var name
      'MOBT_ADB_RESPONSES'
    ),
    enableFlowValidation: validateBoolean(
      process.env.ENABLE_FLOW_VALIDATION,
      'ENABLE_FLOW_VALIDATION',
      true
    )
  };
}

// =============================================================================
// MAIN CONFIGURATION LOADER
// =============================================================================

/**
 * Load and validate complete environment configuration
 */
export function loadEnvironmentConfig(): EnvironmentConfig {
  const projectRoot = path.resolve(__dirname, '..', '..', '..');

  try {
    const config: EnvironmentConfig = {
      webrtc: loadWebRTCConfig(),
      adb: loadADBConfig(),
      storage: loadStorageConfig(),
      flow: loadFlowConfig(),
      maynDrive: loadMaynDriveConfig(),
      performance: loadPerformanceConfig(),
      logging: loadLoggingConfig(),
      api: loadAPIConfig(),
      security: loadSecurityConfig(),
      development: loadDevelopmentConfig(),
      environment: process.env.NODE_ENV || 'development',
      projectRoot
    };

    return config;
  } catch (error) {
    if (error instanceof ConfigValidationError) {
      console.error(`\n🚫 Configuration Error:\n  Variable: ${error.variable}\n  Issue: ${error.message}\n  Suggestion: ${error.suggestion}\n`);
      process.exit(1);
    }

    console.error('Unexpected error loading configuration:', error);
    process.exit(1);
  }
}

/**
 * Validate configuration for specific environment
 */
export function validateEnvironmentConfig(config: EnvironmentConfig, environment?: string): void {
  const targetEnv = environment || config.environment;

  // Environment-specific validation rules
  switch (targetEnv) {
    case 'production':
      // Production-specific validations
      if (config.logging.level === 'debug' || config.logging.level === 'trace') {
        console.warn('⚠️  Warning: Debug logging enabled in production environment');
      }

      if (config.security.allowExternalADB) {
        console.warn('⚠️  Warning: External ADB connections allowed in production environment');
      }

      if (config.api.corsOrigin === '*') {
        console.warn('⚠️  Warning: CORS origin set to wildcard in production environment');
      }
      break;

    case 'development':
      // Development-specific validations
      if (!config.development.devMode) {
        console.info('ℹ️  Info: Development mode disabled, you may want to set DEV_MODE=true');
      }
      break;

    case 'test':
      // Test-specific validations
      if (!config.development.testMode) {
        console.info('ℹ️  Info: Test mode detected, consider setting TEST_MODE=true');
      }
      break;
  }
}

/**
 * Get environment-specific configuration
 */
export function getEnvironmentConfig(environment?: string): EnvironmentConfig {
  const config = loadEnvironmentConfig();
  validateEnvironmentConfig(config, environment);
  return config;
}

/**
 * Export default configuration instance
 */
export const environmentConfig: EnvironmentConfig = getEnvironmentConfig();

// =============================================================================
// CONFIGURATION UTILITIES
// =============================================================================

/**
 * Check if a feature is enabled
 */
export function isFeatureEnabled(feature: string): boolean {
  const featureEnv = process.env[`ENABLE_${feature.toUpperCase()}`];
  return validateBoolean(featureEnv, `ENABLE_${feature.toUpperCase()}`, false);
}

/**
 * Get configuration summary for logging
 */
export function getConfigSummary(config: EnvironmentConfig): Record<string, any> {
  return {
    environment: config.environment,
    projectRoot: config.projectRoot,
    webrtc: {
      publicUrl: config.webrtc.publicUrl,
      grpcEndpoint: config.webrtc.grpcEndpoint,
      timeout: config.webrtc.timeout
    },
    adb: {
      host: config.adb.host,
      port: config.adb.port,
      deviceSerial: config.adb.deviceSerial
    },
    storage: {
      graphRoot: config.storage.graphRoot,
      flowRoot: config.storage.flowRoot,
      sessionsDir: config.storage.sessionsDir
    },
    logging: {
      level: config.logging.level,
      format: config.logging.format,
      output: config.logging.output
    },
    api: {
      port: config.api.port,
      prefix: config.api.prefix,
      authEnabled: config.api.authEnabled
    },
    development: {
      devMode: config.development.devMode,
      testMode: config.development.testMode,
      enableLLMFlowAssistance: config.development.enableLLMFlowAssistance
    }
  };
}

/**
 * Export configuration for use in other modules
 */
export default environmentConfig;