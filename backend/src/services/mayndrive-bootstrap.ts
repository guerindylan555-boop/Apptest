/**
 * MaynDrive Bootstrap Service (T037.1)
 *
 * Specialized service for MaynDrive app initialization, package validation,
 * app state verification, and health monitoring. Provides comprehensive
 * bootstrap functionality with recovery procedures and fallback strategies.
 */

import { EventEmitter } from 'events';
import { ADBBridgeService, getADBBridgeService } from './adb-bridge';
import { logger } from './logger';
import { validateMaynDrivePackage } from '../utils/app-validation';

// ============================================================================
// Configuration Types
// ============================================================================

export interface MaynDriveBootstrapConfig {
  /** MaynDrive package name */
  packageName: string;

  /** MaynDrive main activity */
  mainActivity: string;

  /** App launch timeout (ms) */
  launchTimeout: number;

  /** Bootstrap health check interval (ms) */
  healthCheckInterval: number;

  /** Maximum bootstrap retry attempts */
  maxBootstrapRetries: number;

  /** Bootstrap retry backoff multiplier */
  retryBackoffMultiplier: number;

  /** Enable detailed debug logging */
  debugBootstrap: boolean;

  /** Enable automatic recovery procedures */
  enableAutoRecovery: boolean;

  /** Cache validation results timeout (ms) */
  cacheValidationTimeout: number;

  /** Force clean start on bootstrap failure */
  forceCleanStart: boolean;
}

export interface BootstrapState {
  /** Current bootstrap phase */
  phase: 'initializing' | 'validating' | 'installing' | 'launching' | 'verifying' | 'ready' | 'failed';

  /** Bootstrap progress percentage (0-100) */
  progress: number;

  /** Current phase description */
  description: string;

  /** Last successful phase */
  lastSuccessfulPhase?: string;

  /** Error information if failed */
  error?: BootstrapError;

  /** Bootstrap start timestamp */
  startedAt: string;

  /** Estimated completion time */
  estimatedCompletion?: string;

  /** Retry count */
  retryCount: number;
}

export interface BootstrapError {
  /** Error code */
  code: string;

  /** Error message */
  message: string;

  /** Phase where error occurred */
  phase: string;

  /** Error details */
  details?: Record<string, any>;

  /** Suggested recovery action */
  recoveryAction?: string;

  /** Timestamp */
  timestamp: string;
}

export interface AppHealthStatus {
  /** Is app running */
  isRunning: boolean;

  /** Current activity */
  currentActivity?: string;

  /** App response time (ms) */
  responseTime?: number;

  /** Memory usage (MB) */
  memoryUsage?: number;

  /** CPU usage percentage */
  cpuUsage?: number;

  /** Network connectivity status */
  networkStatus: 'connected' | 'disconnected' | 'unknown';

  /** Last health check timestamp */
  lastHealthCheck: string;

  /** Overall health score (0-100) */
  healthScore: number;

  /** Active issues */
  issues: HealthIssue[];
}

export interface HealthIssue {
  /** Issue severity */
  severity: 'low' | 'medium' | 'high' | 'critical';

  /** Issue type */
  type: string;

  /** Issue description */
  description: string;

  /** Issue detection timestamp */
  detectedAt: string;

  /** Recommended action */
  recommendedAction?: string;
}

export interface BootstrapMetrics {
  /** Total bootstrap attempts */
  totalAttempts: number;

  /** Successful bootstraps */
  successfulBootstraps: number;

  /** Average bootstrap time (ms) */
  averageBootstrapTime: number;

  /** Average recovery time (ms) */
  averageRecoveryTime: number;

  /** Most common failure reasons */
  commonFailures: Array<{
    reason: string;
    count: number;
    percentage: number;
  }>;

  /** Last bootstrap timestamp */
  lastBootstrapTime?: string;

  /** Uptime percentage */
  uptimePercentage: number;
}

// ============================================================================
// Error Types
// ============================================================================

export class MaynDriveBootstrapError extends Error {
  constructor(
    message: string,
    public code: string,
    public phase?: string,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'MaynDriveBootstrapError';
  }
}

export class PackageValidationError extends MaynDriveBootstrapError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'PACKAGE_VALIDATION_ERROR', 'validating', details);
  }
}

export class AppLaunchError extends MaynDriveBootstrapError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'APP_LAUNCH_ERROR', 'launching', details);
  }
}

export class HealthCheckError extends MaynDriveBootstrapError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'HEALTH_CHECK_ERROR', 'verifying', details);
  }
}

// ============================================================================
// Main MaynDrive Bootstrap Service
// ============================================================================

export class MaynDriveBootstrapService extends EventEmitter {
  private config: MaynDriveBootstrapConfig;
  private adbBridge: ADBBridgeService;
  private healthCheckTimer?: NodeJS.Timeout;
  private bootstrapState: BootstrapState;
  private metrics: BootstrapMetrics;
  private isInitialized = false;

  constructor(config?: Partial<MaynDriveBootstrapConfig>) {
    super();

    this.config = this.createConfig(config);
    this.adbBridge = getADBBridgeService();
    this.bootstrapState = this.createInitialState();
    this.metrics = this.createInitialMetrics();

    logger.info('MaynDrive Bootstrap Service initialized', {
      packageName: this.config.packageName,
      mainActivity: this.config.mainActivity,
      launchTimeout: this.config.launchTimeout
    });
  }

  private createConfig(override?: Partial<MaynDriveBootstrapConfig>): MaynDriveBootstrapConfig {
    const baseConfig: MaynDriveBootstrapConfig = {
      packageName: 'com.mayndrive.app',
      mainActivity: 'com.mayndrive.app.MainActivity',
      launchTimeout: 10000,
      healthCheckInterval: parseInt(process.env.MAYNDRIVE_HEALTH_CHECK_INTERVAL || '30000'),
      maxBootstrapRetries: parseInt(process.env.MAYNDRIVE_MAX_BOOTSTRAP_RETRIES || '3'),
      retryBackoffMultiplier: parseFloat(process.env.MAYNDRIVE_RETRY_BACKOFF_MULTIPLIER || '2.0'),
      debugBootstrap: process.env.MAYNDRIVE_DEBUG_BOOTSTRAP === 'true',
      enableAutoRecovery: process.env.MAYNDRIVE_ENABLE_AUTO_RECOVERY !== 'false',
      cacheValidationTimeout: parseInt(process.env.MAYNDRIVE_CACHE_VALIDATION_TIMEOUT || '300000'),
      forceCleanStart: process.env.MAYNDRIVE_FORCE_CLEAN_START === 'true'
    };

    return { ...baseConfig, ...override };
  }

  private createInitialState(): BootstrapState {
    return {
      phase: 'initializing',
      progress: 0,
      description: 'Initializing MaynDrive bootstrap service',
      startedAt: new Date().toISOString(),
      retryCount: 0
    };
  }

  private createInitialMetrics(): BootstrapMetrics {
    return {
      totalAttempts: 0,
      successfulBootstraps: 0,
      averageBootstrapTime: 0,
      averageRecoveryTime: 0,
      commonFailures: [],
      uptimePercentage: 0
    };
  }

  // ============================================================================
  // Bootstrap Lifecycle
  // ============================================================================

  /**
   * Initialize MaynDrive bootstrap service
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('MaynDrive Bootstrap Service already initialized');
      return;
    }

    logger.info('Initializing MaynDrive Bootstrap Service', {
      packageName: this.config.packageName
    });

    try {
      this.updateBootstrapState('initializing', 0, 'Starting bootstrap initialization');
      this.metrics.totalAttempts++;

      // Ensure ADB bridge is ready
      if (!this.adbBridge) {
        throw new MaynDriveBootstrapError('ADB Bridge service not available');
      }

      // Start health monitoring
      this.startHealthMonitoring();

      this.isInitialized = true;

      this.updateBootstrapState('ready', 100, 'Bootstrap service initialized successfully');

      logger.info('MaynDrive Bootstrap Service initialized successfully', {
        packageName: this.config.packageName,
        duration: Date.now() - new Date(this.bootstrapState.startedAt).getTime()
      });

      this.emit('initialized');

    } catch (error) {
      const bootstrapError = this.createBootstrapError(error as Error, 'initializing');
      this.updateBootstrapState('failed', this.bootstrapState.progress, bootstrapError.message, bootstrapError);

      logger.error('MaynDrive Bootstrap Service initialization failed', {
        error: bootstrapError.message,
        phase: bootstrapError.phase,
        details: bootstrapError.details
      });

      this.emit('error', bootstrapError);
      throw bootstrapError;
    }
  }

  /**
   * Bootstrap MaynDrive app with comprehensive validation and setup
   */
  async bootstrapApp(): Promise<void> {
    if (!this.isInitialized) {
      throw new MaynDriveBootstrapError('Bootstrap service not initialized');
    }

    const bootstrapStartTime = Date.now();
    let retryCount = 0;
    let lastError: MaynDriveBootstrapError | null = null;

    logger.info('Starting MaynDrive app bootstrap', {
      packageName: this.config.packageName,
      maxRetries: this.config.maxBootstrapRetries
    });

    while (retryCount <= this.config.maxBootstrapRetries) {
      try {
        await this.performBootstrap();

        // Bootstrap successful
        this.metrics.successfulBootstraps++;
        const bootstrapDuration = Date.now() - bootstrapStartTime;
        this.updateAverageBootstrapTime(bootstrapDuration);

        logger.info('MaynDrive app bootstrap completed successfully', {
          packageName: this.config.packageName,
          duration: bootstrapDuration,
          retryCount
        });

        this.emit('bootstrap:success', {
          packageName: this.config.packageName,
          duration: bootstrapDuration,
          retryCount
        });

        return;

      } catch (error) {
        lastError = error as MaynDriveBootstrapError;
        retryCount++;

        logger.warn('MaynDrive app bootstrap attempt failed', {
          attempt: retryCount,
          maxRetries: this.config.maxBootstrapRetries + 1,
          error: lastError.message,
          phase: lastError.phase
        });

        this.recordFailure(lastError);

        if (retryCount <= this.config.maxBootstrapRetries) {
          if (this.config.enableAutoRecovery) {
            await this.performRecovery(lastError);
          }

          const delay = Math.min(
            1000 * Math.pow(this.config.retryBackoffMultiplier, retryCount - 1),
            30000
          );

          logger.debug('Waiting before retry', { delay, retryCount });
          await this.sleep(delay);
        }
      }
    }

    // All retries exhausted
    const finalError = new MaynDriveBootstrapError(
      `MaynDrive app bootstrap failed after ${retryCount} attempts`,
      'BOOTSTRAP_EXHAUSTED',
      'failed',
      {
        totalAttempts: retryCount,
        lastError: lastError?.message,
        packageName: this.config.packageName
      }
    );

    logger.error('MaynDrive app bootstrap failed - all retries exhausted', {
      totalAttempts: retryCount,
      packageName: this.config.packageName,
      lastError: lastError?.message
    });

    this.emit('bootstrap:failed', finalError);
    throw finalError;
  }

  /**
   * Perform the actual bootstrap sequence
   */
  private async performBootstrap(): Promise<void> {
    // Phase 1: Package Validation
    this.updateBootstrapState('validating', 10, 'Validating MaynDrive package');
    await this.validatePackage();

    // Phase 2: App Installation (if needed)
    this.updateBootstrapState('installing', 30, 'Ensuring MaynDrive is installed');
    await this.ensureAppInstalled();

    // Phase 3: App Launch
    this.updateBootstrapState('launching', 60, 'Launching MaynDrive app');
    await this.launchApp();

    // Phase 4: Verification
    this.updateBootstrapState('verifying', 90, 'Verifying app state and health');
    await this.verifyAppHealth();

    // Phase 5: Ready
    this.updateBootstrapState('ready', 100, 'MaynDrive app is ready');
  }

  /**
   * Validate MaynDrive package
   */
  private async validatePackage(): Promise<void> {
    try {
      const validation = await validateMaynDrivePackage(this.adbBridge);

      if (!validation.isValid) {
        throw new PackageValidationError(
          'MaynDrive package validation failed',
          {
            packageName: this.config.packageName,
            issues: validation.issues,
            warnings: validation.warnings
          }
        );
      }

      if (validation.warnings.length > 0) {
        logger.warn('MaynDrive package validation warnings', {
          warnings: validation.warnings
        });
      }

      logger.debug('MaynDrive package validation successful', {
        packageName: this.config.packageName,
        version: validation.version
      });

    } catch (error) {
      if (error instanceof PackageValidationError) {
        throw error;
      }
      throw new PackageValidationError(
        `Package validation failed: ${(error as Error).message}`,
        { originalError: (error as Error).message }
      );
    }
  }

  /**
   * Ensure MaynDrive app is installed
   */
  private async ensureAppInstalled(): Promise<void> {
    try {
      const deviceInfo = await this.adbBridge.getDeviceInfo();

      // Check if app is installed
      const packageCheck = await this.adbBridge.executeCommand([
        'shell', 'pm', 'list', 'packages', this.config.packageName
      ], this.config.launchTimeout);

      if (packageCheck.exitCode !== 0 || !packageCheck.stdout.includes(this.config.packageName)) {
        logger.warn('MaynDrive app not found, attempting installation', {
          packageName: this.config.packageName
        });

        // In a real implementation, you would install the app here
        // For now, we'll throw an error indicating the app needs to be installed
        throw new MaynDriveBootstrapError(
          'MaynDrive app is not installed. Please install the app first.',
          'APP_NOT_INSTALLED',
          'installing',
          { packageName: this.config.packageName }
        );
      }

      logger.debug('MaynDrive app installation verified', {
        packageName: this.config.packageName
      });

    } catch (error) {
      if (error instanceof MaynDriveBootstrapError) {
        throw error;
      }
      throw new MaynDriveBootstrapError(
        `App installation check failed: ${(error as Error).message}`,
        'INSTALLATION_CHECK_ERROR',
        'installing',
        { packageName: this.config.packageName }
      );
    }
  }

  /**
   * Launch MaynDrive app
   */
  private async launchApp(): Promise<void> {
    try {
      const launchStartTime = Date.now();

      // Force stop the app first if clean start is enabled
      if (this.config.forceCleanStart) {
        await this.adbBridge.executeCommand([
          'shell', 'am', 'force-stop', this.config.packageName
        ], this.config.launchTimeout);

        await this.sleep(1000); // Brief pause
      }

      // Launch the app
      const launchResult = await this.adbBridge.executeCommand([
        'shell', 'am', 'start',
        '-n', `${this.config.packageName}/${this.config.mainActivity}`,
        '-a', 'android.intent.action.MAIN',
        '-c', 'android.intent.category.LAUNCHER'
      ], this.config.launchTimeout);

      if (launchResult.exitCode !== 0) {
        throw new AppLaunchError(
          'Failed to launch MaynDrive app',
          {
            packageName: this.config.packageName,
            mainActivity: this.config.mainActivity,
            exitCode: launchResult.exitCode,
            stderr: launchResult.stderr
          }
        );
      }

      // Wait for app to fully launch
      await this.waitForAppLaunch();

      const launchDuration = Date.now() - launchStartTime;

      logger.info('MaynDrive app launched successfully', {
        packageName: this.config.packageName,
        mainActivity: this.config.mainActivity,
        duration: launchDuration
      });

    } catch (error) {
      if (error instanceof AppLaunchError) {
        throw error;
      }
      throw new AppLaunchError(
        `App launch failed: ${(error as Error).message}`,
        {
          packageName: this.config.packageName,
          mainActivity: this.config.mainActivity,
          originalError: (error as Error).message
        }
      );
    }
  }

  /**
   * Wait for app to fully launch
   */
  private async waitForAppLaunch(): Promise<void> {
    const maxWaitTime = this.config.launchTimeout;
    const checkInterval = 1000;
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      try {
        const currentActivity = await this.adbBridge.executeCommand([
          'shell', 'dumpsys', 'window', 'windows'
        ], this.config.launchTimeout);

        if (currentActivity.stdout.includes(this.config.mainActivity)) {
          logger.debug('MaynDrive app launch detected', {
            packageName: this.config.packageName,
            mainActivity: this.config.mainActivity,
            waitTime: Date.now() - startTime
          });
          return;
        }

        await this.sleep(checkInterval);

      } catch (error) {
        logger.debug('Error checking app launch status', {
          error: (error as Error).message
        });
        await this.sleep(checkInterval);
      }
    }

    throw new AppLaunchError(
      `MaynDrive app did not launch within ${maxWaitTime}ms`,
      {
        packageName: this.config.packageName,
        mainActivity: this.config.mainActivity,
        timeout: maxWaitTime
      }
    );
  }

  /**
   * Verify app health after launch
   */
  private async verifyAppHealth(): Promise<void> {
    try {
      const healthStatus = await this.checkAppHealth();

      if (healthStatus.healthScore < 50) {
        throw new HealthCheckError(
          'MaynDrive app health check failed',
          {
            healthScore: healthStatus.healthScore,
            issues: healthStatus.issues
          }
        );
      }

      if (healthStatus.issues.some(issue => issue.severity === 'critical')) {
        throw new HealthCheckError(
          'Critical issues detected during health check',
          {
            criticalIssues: healthStatus.issues.filter(i => i.severity === 'critical')
          }
        );
      }

      logger.info('MaynDrive app health verification passed', {
        healthScore: healthStatus.healthScore,
        responseTime: healthStatus.responseTime,
        issueCount: healthStatus.issues.length
      });

    } catch (error) {
      if (error instanceof HealthCheckError) {
        throw error;
      }
      throw new HealthCheckError(
        `Health verification failed: ${(error as Error).message}`,
        { originalError: (error as Error).message }
      );
    }
  }

  // ============================================================================
  // Health Monitoring
  // ============================================================================

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    this.healthCheckTimer = setInterval(
      () => this.performHealthCheck(),
      this.config.healthCheckInterval
    );

    logger.debug('MaynDrive health monitoring started', {
      interval: this.config.healthCheckInterval
    });
  }

  /**
   * Stop health monitoring
   */
  private stopHealthMonitoring(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = undefined;
      logger.debug('MaynDrive health monitoring stopped');
    }
  }

  /**
   * Perform routine health check
   */
  private async performHealthCheck(): Promise<void> {
    try {
      const healthStatus = await this.checkAppHealth();

      this.emit('health:check', healthStatus);

      // Auto-recovery for critical issues
      if (healthStatus.issues.some(issue => issue.severity === 'critical') && this.config.enableAutoRecovery) {
        logger.warn('Critical health issues detected, initiating auto-recovery', {
          issues: healthStatus.issues.filter(i => i.severity === 'critical')
        });

        await this.performAutoRecovery(healthStatus);
      }

    } catch (error) {
      logger.error('Health check failed', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Check comprehensive app health
   */
  async checkAppHealth(): Promise<AppHealthStatus> {
    const startTime = Date.now();

    try {
      // Check if app is running
      const currentActivityResult = await this.adbBridge.executeCommand([
        'shell', 'dumpsys', 'activity', 'activities'
      ], this.config.launchTimeout);

      const isRunning = currentActivityResult.stdout.includes(this.config.packageName);
      const currentActivity = this.extractCurrentActivity(currentActivityResult.stdout);

      // Get memory usage
      const memoryResult = await this.adbBridge.executeCommand([
        'shell', 'dumpsys', 'meminfo', this.config.packageName
      ], this.config.launchTimeout);

      const memoryUsage = this.parseMemoryUsage(memoryResult.stdout);

      // Get CPU usage (simplified)
      const cpuResult = await this.adbBridge.executeCommand([
        'shell', 'top', '-n', '1'
      ], this.config.launchTimeout);

      const cpuUsage = this.parseCpuUsage(cpuResult.stdout, this.config.packageName);

      // Check network connectivity
      const networkResult = await this.adbBridge.executeCommand([
        'shell', 'ping', '-c', '1', '8.8.8.8'
      ], this.config.launchTimeout);

      const networkStatus = networkResult.exitCode === 0 ? 'connected' : 'disconnected';

      // Calculate health score
      const healthScore = this.calculateHealthScore({
        isRunning,
        memoryUsage,
        cpuUsage,
        networkStatus
      });

      // Identify issues
      const issues = this.identifyHealthIssues({
        isRunning,
        memoryUsage,
        cpuUsage,
        networkStatus,
        healthScore
      });

      const healthStatus: AppHealthStatus = {
        isRunning,
        currentActivity,
        responseTime: Date.now() - startTime,
        memoryUsage,
        cpuUsage,
        networkStatus,
        lastHealthCheck: new Date().toISOString(),
        healthScore,
        issues
      };

      logger.debug('MaynDrive health check completed', {
        isRunning,
        healthScore,
        responseTime: healthStatus.responseTime,
        issueCount: issues.length
      });

      return healthStatus;

    } catch (error) {
      logger.error('App health check failed', {
        error: (error as Error).message
      });

      return {
        isRunning: false,
        networkStatus: 'unknown',
        lastHealthCheck: new Date().toISOString(),
        healthScore: 0,
        issues: [{
          severity: 'critical',
          type: 'health_check_error',
          description: `Health check failed: ${(error as Error).message}`,
          detectedAt: new Date().toISOString(),
          recommendedAction: 'Restart app and check system status'
        }]
      };
    }
  }

  // ============================================================================
  // Recovery Procedures
  // ============================================================================

  /**
   * Perform recovery based on error type
   */
  private async performRecovery(error: MaynDriveBootstrapError): Promise<void> {
    const recoveryStartTime = Date.now();

    logger.info('Starting MaynDrive recovery procedure', {
      errorCode: error.code,
      phase: error.phase,
      recoveryAction: error.recoveryAction
    });

    try {
      switch (error.code) {
        case 'PACKAGE_VALIDATION_ERROR':
          await this.recoverFromValidationError(error);
          break;

        case 'APP_LAUNCH_ERROR':
          await this.recoverFromLaunchError(error);
          break;

        case 'HEALTH_CHECK_ERROR':
          await this.recoverFromHealthError(error);
          break;

        default:
          await this.performGenericRecovery(error);
      }

      const recoveryDuration = Date.now() - recoveryStartTime;
      this.updateAverageRecoveryTime(recoveryDuration);

      logger.info('MaynDrive recovery completed successfully', {
        errorCode: error.code,
        recoveryDuration
      });

      this.emit('recovery:success', {
        errorCode: error.code,
        recoveryDuration
      });

    } catch (recoveryError) {
      logger.error('MaynDrive recovery failed', {
        originalError: error.message,
        recoveryError: (recoveryError as Error).message
      });

      this.emit('recovery:failed', {
        originalError: error,
        recoveryError
      });
    }
  }

  /**
   * Auto-recovery for critical health issues
   */
  private async performAutoRecovery(healthStatus: AppHealthStatus): Promise<void> {
    logger.info('Starting auto-recovery for critical health issues');

    try {
      // Force stop and restart app
      await this.adbBridge.executeCommand([
        'shell', 'am', 'force-stop', this.config.packageName
      ], this.config.launchTimeout);

      await this.sleep(2000);

      await this.launchApp();
      await this.verifyAppHealth();

      logger.info('Auto-recovery completed successfully');

    } catch (error) {
      logger.error('Auto-recovery failed', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Recover from package validation errors
   */
  private async recoverFromValidationError(error: MaynDriveBootstrapError): Promise<void> {
    logger.debug('Recovering from package validation error');

    // Clear package cache and retry validation
    await this.adbBridge.executeCommand([
      'shell', 'pm', 'clear', this.config.packageName
    ], this.config.launchTimeout);
  }

  /**
   * Recover from app launch errors
   */
  private async recoverFromLaunchError(error: MaynDriveBootstrapError): Promise<void> {
    logger.debug('Recovering from app launch error');

    // Force stop app and clear cache
    await this.adbBridge.executeCommand([
      'shell', 'am', 'force-stop', this.config.packageName
    ], this.config.launchTimeout);

    await this.adbBridge.executeCommand([
      'shell', 'pm', 'clear', this.config.packageName
    ], this.config.launchTimeout);
  }

  /**
   * Recover from health check errors
   */
  private async recoverFromHealthError(error: MaynDriveBootstrapError): Promise<void> {
    logger.debug('Recovering from health check error');

    // Restart app
    await this.adbBridge.executeCommand([
      'shell', 'am', 'force-stop', this.config.packageName
    ], this.config.launchTimeout);
  }

  /**
   * Perform generic recovery
   */
  private async performGenericRecovery(error: MaynDriveBootstrapError): Promise<void> {
    logger.debug('Performing generic recovery');

    // Full app reset
    await this.adbBridge.executeCommand([
      'shell', 'am', 'force-stop', this.config.packageName
    ], this.config.launchTimeout);

    await this.sleep(3000);
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  private updateBootstrapState(
    phase: BootstrapState['phase'],
    progress: number,
    description: string,
    error?: BootstrapError
  ): void {
    this.bootstrapState = {
      ...this.bootstrapState,
      phase,
      progress,
      description,
      lastSuccessfulPhase: error ? this.bootstrapState.lastSuccessfulPhase : phase,
      error,
      retryCount: error ? this.bootstrapState.retryCount + 1 : this.bootstrapState.retryCount
    };

    this.emit('state:change', this.bootstrapState);
  }

  private createBootstrapError(error: Error, phase: string): BootstrapError {
    return {
      code: error.name.replace(/Error$/, '').toUpperCase() || 'UNKNOWN_ERROR',
      message: error.message,
      phase,
      timestamp: new Date().toISOString(),
      details: {
        originalError: error.message,
        stack: error.stack
      }
    };
  }

  private recordFailure(error: MaynDriveBootstrapError): void {
    // Record failure for metrics
    const existingFailure = this.metrics.commonFailures.find(f => f.reason === error.message);
    if (existingFailure) {
      existingFailure.count++;
    } else {
      this.metrics.commonFailures.push({
        reason: error.message,
        count: 1,
        percentage: 0
      });
    }

    // Update percentages
    const totalFailures = this.metrics.commonFailures.reduce((sum, f) => sum + f.count, 0);
    this.metrics.commonFailures.forEach(f => {
      f.percentage = (f.count / totalFailures) * 100;
    });
  }

  private updateAverageBootstrapTime(duration: number): void {
    const totalTime = this.metrics.averageBootstrapTime * (this.metrics.successfulBootstraps - 1) + duration;
    this.metrics.averageBootstrapTime = Math.round(totalTime / this.metrics.successfulBootstraps);
  }

  private updateAverageRecoveryTime(duration: number): void {
    const recoveryCount = this.metrics.totalAttempts - this.metrics.successfulBootstraps;
    if (recoveryCount > 0) {
      const totalTime = this.metrics.averageRecoveryTime * (recoveryCount - 1) + duration;
      this.metrics.averageRecoveryTime = Math.round(totalTime / recoveryCount);
    }
  }

  private extractCurrentActivity(dumpsysOutput: string): string | undefined {
    const activityMatch = dumpsysOutput.match(/mResumedActivity:.*ActivityRecord{.*[^ ]+ ([^\/]+)\/([^ ]+)}/);
    return activityMatch ? `${activityMatch[1]}/${activityMatch[2]}` : undefined;
  }

  private parseMemoryUsage(meminfoOutput: string): number {
    const totalMatch = meminfoOutput.match(/TOTAL:\s+(\d+)/);
    return totalMatch ? Math.round(parseInt(totalMatch[1]) / 1024) : 0; // Convert KB to MB
  }

  private parseCpuUsage(topOutput: string, packageName: string): number {
    const lines = topOutput.split('\n');
    for (const line of lines) {
      if (line.includes(packageName)) {
        const cpuMatch = line.match(/\s+(\d+\.?\d*)%cpu/);
        return cpuMatch ? parseFloat(cpuMatch[1]) : 0;
      }
    }
    return 0;
  }

  private calculateHealthScore(metrics: {
    isRunning: boolean;
    memoryUsage: number;
    cpuUsage: number;
    networkStatus: string;
  }): number {
    let score = 0;

    // App running (40 points)
    if (metrics.isRunning) {
      score += 40;
    }

    // Memory usage (20 points)
    if (metrics.memoryUsage < 100) {
      score += 20;
    } else if (metrics.memoryUsage < 200) {
      score += 15;
    } else if (metrics.memoryUsage < 500) {
      score += 10;
    }

    // CPU usage (20 points)
    if (metrics.cpuUsage < 20) {
      score += 20;
    } else if (metrics.cpuUsage < 50) {
      score += 15;
    } else if (metrics.cpuUsage < 80) {
      score += 10;
    }

    // Network connectivity (20 points)
    if (metrics.networkStatus === 'connected') {
      score += 20;
    }

    return Math.min(score, 100);
  }

  private identifyHealthIssues(metrics: {
    isRunning: boolean;
    memoryUsage: number;
    cpuUsage: number;
    networkStatus: string;
    healthScore: number;
  }): HealthIssue[] {
    const issues: HealthIssue[] = [];

    if (!metrics.isRunning) {
      issues.push({
        severity: 'critical',
        type: 'app_not_running',
        description: 'MaynDrive app is not running',
        detectedAt: new Date().toISOString(),
        recommendedAction: 'Launch the app'
      });
    }

    if (metrics.memoryUsage > 500) {
      issues.push({
        severity: 'high',
        type: 'high_memory_usage',
        description: `High memory usage: ${metrics.memoryUsage}MB`,
        detectedAt: new Date().toISOString(),
        recommendedAction: 'Restart app to free memory'
      });
    }

    if (metrics.cpuUsage > 80) {
      issues.push({
        severity: 'medium',
        type: 'high_cpu_usage',
        description: `High CPU usage: ${metrics.cpuUsage}%`,
        detectedAt: new Date().toISOString(),
        recommendedAction: 'Check for heavy operations'
      });
    }

    if (metrics.networkStatus === 'disconnected') {
      issues.push({
        severity: 'medium',
        type: 'network_disconnected',
        description: 'Network connectivity issues detected',
        detectedAt: new Date().toISOString(),
        recommendedAction: 'Check network connection'
      });
    }

    if (metrics.healthScore < 30) {
      issues.push({
        severity: 'critical',
        type: 'poor_health',
        description: `Overall health score is critical: ${metrics.healthScore}`,
        detectedAt: new Date().toISOString(),
        recommendedAction: 'Perform full app reset'
      });
    }

    return issues;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ============================================================================
  // Public API Methods
  // ============================================================================

  /**
   * Get current bootstrap state
   */
  getBootstrapState(): BootstrapState {
    return { ...this.bootstrapState };
  }

  /**
   * Get bootstrap metrics
   */
  getBootstrapMetrics(): BootstrapMetrics {
    return { ...this.metrics };
  }

  /**
   * Get current app health status
   */
  async getHealthStatus(): Promise<AppHealthStatus> {
    return this.checkAppHealth();
  }

  /**
   * Force re-bootstrap the app
   */
  async rebootstrap(): Promise<void> {
    logger.info('Force re-bootstrap requested');
    await this.bootstrapApp();
  }

  /**
   * Close bootstrap service and cleanup resources
   */
  async close(): Promise<void> {
    logger.info('Closing MaynDrive Bootstrap Service', {
      packageName: this.config.packageName,
      uptime: Date.now() - new Date(this.bootstrapState.startedAt).getTime()
    });

    this.stopHealthMonitoring();
    this.removeAllListeners();
    this.isInitialized = false;

    logger.info('MaynDrive Bootstrap Service closed');
  }
}

// ============================================================================
// Service Factory
// ============================================================================

let maynDriveBootstrapInstance: MaynDriveBootstrapService | null = null;

/**
 * Get singleton MaynDrive Bootstrap service instance
 */
export function getMaynDriveBootstrapService(config?: Partial<MaynDriveBootstrapConfig>): MaynDriveBootstrapService {
  if (!maynDriveBootstrapInstance) {
    maynDriveBootstrapInstance = new MaynDriveBootstrapService(config);
  }
  return maynDriveBootstrapInstance;
}

/**
 * Initialize MaynDrive Bootstrap service
 */
export async function initializeMaynDriveBootstrap(config?: Partial<MaynDriveBootstrapConfig>): Promise<MaynDriveBootstrapService> {
  const service = getMaynDriveBootstrapService(config);
  await service.initialize();
  return service;
}

/**
 * Close MaynDrive Bootstrap service
 */
export async function closeMaynDriveBootstrap(): Promise<void> {
  if (maynDriveBootstrapInstance) {
    await maynDriveBootstrapInstance.close();
    maynDriveBootstrapInstance = null;
  }
}