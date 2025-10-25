/**
 * App Reset Service (T037.2)
 *
 * Clean-state reset functionality for MaynDrive with comprehensive data clearing,
 * cache management, force restart capabilities, and state validation. Provides
 * backup and restore capabilities with automated recovery procedures.
 */

import { EventEmitter } from 'events';
import { ADBBridgeService, getADBBridgeService } from './adb-bridge';
import { logger } from './logger';
import { validateMaynDrivePackage } from '../utils/app-validation';

// ============================================================================
// Configuration Types
// ============================================================================

export interface AppResetConfig {
  /** MaynDrive package name */
  packageName: string;

  /** MaynDrive main activity */
  mainActivity: string;

  /** App launch timeout after reset (ms) */
  launchTimeout: number;

  /** Reset operation timeout (ms) */
  resetTimeout: number;

  /** Enable backup before reset */
  enableBackup: boolean;

  /** Backup storage directory */
  backupDirectory: string;

  /** Maximum backup retention time (ms) */
  backupRetentionTime: number;

  /** Force stop before reset */
  forceStopBeforeReset: boolean;

  /** Clear app data during reset */
  clearAppData: boolean;

  /** Clear cache during reset */
  clearCache: boolean;

  /** Clear shared preferences */
  clearSharedPreferences: boolean;

  /** Clear external storage */
  clearExternalStorage: boolean;

  /** Enable post-reset validation */
  enablePostResetValidation: boolean;

  /** Auto-launch after reset */
  autoLaunchAfterReset: boolean;

  /** Reset retry attempts */
  maxResetRetries: number;

  /** Reset retry backoff multiplier */
  retryBackoffMultiplier: number;
}

export interface ResetState {
  /** Current reset phase */
  phase: 'idle' | 'backing_up' | 'stopping' | 'clearing_data' | 'clearing_cache' | 'clearing_storage' | 'restarting' | 'validating' | 'launching' | 'completed' | 'failed';

  /** Reset progress percentage (0-100) */
  progress: number;

  /** Current phase description */
  description: string;

  /** Reset start timestamp */
  startedAt: string;

  /** Estimated completion time */
  estimatedCompletion?: string;

  /** Reset type */
  resetType: ResetType;

  /** Current retry attempt */
  retryCount: number;

  /** Error information if failed */
  error?: ResetError;

  /** Backup information */
  backup?: BackupInfo;
}

export type ResetType = 'soft' | 'hard' | 'full' | 'custom';

export interface ResetError {
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

export interface BackupInfo {
  /** Backup ID */
  id: string;

  /** Backup timestamp */
  timestamp: string;

  /** Backup type */
  type: 'full' | 'data' | 'cache' | 'preferences';

  /** Backup size in bytes */
  sizeBytes: number;

  /** Backup file path */
  filePath: string;

  /** Backup metadata */
  metadata: {
    appVersion: string;
    dataDirs: string[];
    cacheDirs: string[];
    prefFiles: string[];
    externalFiles: string[];
  };

  /** Backup status */
  status: 'in_progress' | 'completed' | 'failed';

  /** Completion timestamp */
  completedAt?: string;
}

export interface ResetOptions {
  /** Reset type */
  type: ResetType;

  /** Create backup before reset */
  backup?: boolean;

  /** Custom directories to clear (for custom reset) */
  customDirectories?: string[];

  /** Preserve specific data */
  preserveData?: {
    /** Preserve user accounts */
    accounts?: boolean;

    /** Preserve user settings */
    settings?: boolean;

    /** Preserve specific files/directories */
    files?: string[];
  };

  /** Skip post-reset validation */
  skipValidation?: boolean;

  /** Auto-launch after reset */
  autoLaunch?: boolean;
}

export interface ResetMetrics {
  /** Total reset operations */
  totalResets: number;

  /** Successful resets */
  successfulResets: number;

  /** Failed resets */
  failedResets: number;

  /** Average reset time (ms) */
  averageResetTime: number;

  /** Total backup size (bytes) */
  totalBackupSize: number;

  /** Backups created */
  backupsCreated: number;

  /** Restores performed */
  restoresPerformed: number;

  /** Most common reset types */
  commonResetTypes: Array<{
    type: ResetType;
    count: number;
    percentage: number;
  }>;

  /** Last reset timestamp */
  lastResetTime?: string;

  /** Success rate percentage */
  successRate: number;
}

// ============================================================================
// Error Types
// ============================================================================

export class AppResetError extends Error {
  constructor(
    message: string,
    public code: string,
    public phase?: string,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'AppResetError';
  }
}

export class BackupError extends AppResetError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'BACKUP_ERROR', 'backing_up', details);
  }
}

export class ClearDataError extends AppResetError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'CLEAR_DATA_ERROR', 'clearing_data', details);
  }
}

export class RestoreError extends AppResetError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, 'RESTORE_ERROR', 'restoring', details);
  }
}

// ============================================================================
// Main App Reset Service
// ============================================================================

export class AppResetService extends EventEmitter {
  private config: AppResetConfig;
  private adbBridge: ADBBridgeService;
  private resetState: ResetState;
  private metrics: ResetMetrics;
  private isInitialized = false;

  constructor(config?: Partial<AppResetConfig>) {
    super();

    this.config = this.createConfig(config);
    this.adbBridge = getADBBridgeService();
    this.resetState = this.createInitialState();
    this.metrics = this.createInitialMetrics();

    logger.info('App Reset Service initialized', {
      packageName: this.config.packageName,
      enableBackup: this.config.enableBackup,
      clearAppData: this.config.clearAppData
    });
  }

  private createConfig(override?: Partial<AppResetConfig>): AppResetConfig {
    const baseConfig: AppResetConfig = {
      packageName: 'com.mayndrive.app',
      mainActivity: 'com.mayndrive.app.MainActivity',
      launchTimeout: 10000,
      resetTimeout: 60000,
      enableBackup: process.env.APP_RESET_ENABLE_BACKUP !== 'false',
      backupDirectory: process.env.APP_RESET_BACKUP_DIR || '/tmp/mayndrive-backups',
      backupRetentionTime: parseInt(process.env.APP_RESET_BACKUP_RETENTION || '604800000'), // 7 days
      forceStopBeforeReset: process.env.APP_RESET_FORCE_STOP !== 'false',
      clearAppData: process.env.APP_RESET_CLEAR_DATA !== 'false',
      clearCache: process.env.APP_RESET_CLEAR_CACHE !== 'false',
      clearSharedPreferences: process.env.APP_RESET_CLEAR_PREFS !== 'false',
      clearExternalStorage: process.env.APP_RESET_CLEAR_EXTERNAL === 'true',
      enablePostResetValidation: process.env.APP_RESET_ENABLE_VALIDATION !== 'false',
      autoLaunchAfterReset: process.env.APP_RESET_AUTO_LAUNCH !== 'false',
      maxResetRetries: parseInt(process.env.APP_RESET_MAX_RETRIES || '3'),
      retryBackoffMultiplier: parseFloat(process.env.APP_RESET_RETRY_BACKOFF || '1.5')
    };

    return { ...baseConfig, ...override };
  }

  private createInitialState(): ResetState {
    return {
      phase: 'idle',
      progress: 0,
      description: 'App reset service idle',
      startedAt: new Date().toISOString(),
      resetType: 'soft',
      retryCount: 0
    };
  }

  private createInitialMetrics(): ResetMetrics {
    return {
      totalResets: 0,
      successfulResets: 0,
      failedResets: 0,
      averageResetTime: 0,
      totalBackupSize: 0,
      backupsCreated: 0,
      restoresPerformed: 0,
      commonResetTypes: [],
      successRate: 0
    };
  }

  // ============================================================================
  // Service Lifecycle
  // ============================================================================

  /**
   * Initialize app reset service
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('App Reset Service already initialized');
      return;
    }

    logger.info('Initializing App Reset Service', {
      packageName: this.config.packageName
    });

    try {
      // Ensure backup directory exists
      if (this.config.enableBackup) {
        await this.ensureBackupDirectory();
      }

      // Clean old backups
      await this.cleanOldBackups();

      this.isInitialized = true;

      logger.info('App Reset Service initialized successfully', {
        packageName: this.config.packageName,
        backupDirectory: this.config.backupDirectory
      });

      this.emit('initialized');

    } catch (error) {
      logger.error('App Reset Service initialization failed', {
        error: (error as Error).message
      });
      throw new AppResetError(
        `Failed to initialize app reset service: ${(error as Error).message}`,
        'INITIALIZATION_ERROR'
      );
    }
  }

  // ============================================================================
  // Reset Operations
  // ============================================================================

  /**
   * Perform app reset with specified options
   */
  async resetApp(options: ResetOptions): Promise<void> {
    if (!this.isInitialized) {
      throw new AppResetError('Reset service not initialized');
    }

    const resetStartTime = Date.now();
    let retryCount = 0;
    let lastError: AppResetError | null = null;

    logger.info('Starting MaynDrive app reset', {
      packageName: this.config.packageName,
      resetType: options.type,
      backup: options.backup ?? this.config.enableBackup
    });

    // Initialize reset state
    this.resetState = {
      ...this.createInitialState(),
      phase: 'backing_up',
      progress: 0,
      description: 'Starting app reset',
      startedAt: new Date().toISOString(),
      resetType: options.type,
      retryCount: 0
    };

    this.metrics.totalResets++;
    this.recordResetType(options.type);

    while (retryCount <= this.config.maxResetRetries) {
      try {
        await this.performReset(options);

        // Reset successful
        this.metrics.successfulResets++;
        const resetDuration = Date.now() - resetStartTime;
        this.updateAverageResetTime(resetDuration);

        logger.info('MaynDrive app reset completed successfully', {
          packageName: this.config.packageName,
          resetType: options.type,
          duration: resetDuration,
          retryCount
        });

        this.emit('reset:success', {
          packageName: this.config.packageName,
          resetType: options.type,
          duration: resetDuration,
          retryCount
        });

        return;

      } catch (error) {
        lastError = error as AppResetError;
        retryCount++;

        logger.warn('MaynDrive app reset attempt failed', {
          attempt: retryCount,
          maxRetries: this.config.maxResetRetries + 1,
          error: lastError.message,
          phase: lastError.phase
        });

        this.metrics.failedResets++;

        if (retryCount <= this.config.maxResetRetries) {
          const delay = Math.min(
            1000 * Math.pow(this.config.retryBackoffMultiplier, retryCount - 1),
            10000
          );

          logger.debug('Waiting before retry', { delay, retryCount });
          await this.sleep(delay);
        }
      }
    }

    // All retries exhausted
    const finalError = new AppResetError(
      `App reset failed after ${retryCount} attempts`,
      'RESET_EXHAUSTED',
      'failed',
      {
        totalAttempts: retryCount,
        lastError: lastError?.message,
        resetType: options.type,
        packageName: this.config.packageName
      }
    );

    logger.error('MaynDrive app reset failed - all retries exhausted', {
      totalAttempts: retryCount,
      packageName: this.config.packageName,
      lastError: lastError?.message
    });

    this.updateResetState('failed', this.resetState.progress, finalError.message, finalError);
    this.emit('reset:failed', finalError);
    throw finalError;
  }

  /**
   * Perform the actual reset sequence
   */
  private async performReset(options: ResetOptions): Promise<void> {
    // Phase 1: Backup (if enabled)
    if (options.backup ?? this.config.enableBackup) {
      this.updateResetState('backing_up', 5, 'Creating backup before reset');
      const backup = await this.createBackup(options.type);
      this.resetState.backup = backup;
    }

    // Phase 2: Force Stop App
    if (this.config.forceStopBeforeReset) {
      this.updateResetState('stopping', 15, 'Stopping MaynDrive app');
      await this.stopApp();
    }

    // Phase 3: Clear Data (based on reset type)
    this.updateResetState('clearing_data', 30, 'Clearing app data');
    await this.clearAppData(options);

    // Phase 4: Clear Cache
    if (this.config.clearCache) {
      this.updateResetState('clearing_cache', 50, 'Clearing app cache');
      await this.clearAppCache();
    }

    // Phase 5: Clear External Storage
    if (this.config.clearExternalStorage && options.type === 'full') {
      this.updateResetState('clearing_storage', 70, 'Clearing external storage');
      await this.clearExternalStorage();
    }

    // Phase 6: Restart App
    this.updateResetState('restarting', 80, 'Restarting app services');
    await this.restartAppServices();

    // Phase 7: Post-reset Validation
    if (this.config.enablePostResetValidation && !options.skipValidation) {
      this.updateResetState('validating', 90, 'Validating app state after reset');
      await this.validateResetState();
    }

    // Phase 8: Auto Launch
    if (options.autoLaunch ?? this.config.autoLaunchAfterReset) {
      this.updateResetState('launching', 95, 'Launching app after reset');
      await this.launchApp();
    }

    // Phase 9: Completed
    this.updateResetState('completed', 100, 'App reset completed successfully');
  }

  /**
   * Create backup before reset
   */
  private async createBackup(resetType: ResetType): Promise<BackupInfo> {
    const backupId = `backup_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const backupPath = `${this.config.backupDirectory}/${backupId}`;

    const backup: BackupInfo = {
      id: backupId,
      timestamp: new Date().toISOString(),
      type: resetType === 'full' ? 'full' : 'data',
      sizeBytes: 0,
      filePath: backupPath,
      metadata: {
        appVersion: '',
        dataDirs: [],
        cacheDirs: [],
        prefFiles: [],
        externalFiles: []
      },
      status: 'in_progress'
    };

    try {
      logger.info('Creating app backup', {
        backupId,
        type: backup.type,
        path: backupPath
      });

      // Get app version
      const versionResult = await this.adbBridge.executeCommand([
        'shell', 'dumpsys', 'package', this.config.packageName
      ], this.config.launchTimeout);

      const versionMatch = versionResult.stdout.match(/versionName=([^\s]+)/);
      backup.metadata.appVersion = versionMatch?.[1] || 'unknown';

      // Create backup directory on device
      await this.adbBridge.executeCommand([
        'shell', 'mkdir', '-p', `/sdcard/Android/data/${this.config.packageName}/backup`
      ], this.config.launchTimeout);

      // Backup app data directories
      const dataDirs = [
        `/data/data/${this.config.packageName}`,
        `/sdcard/Android/data/${this.config.packageName}`,
        `/sdcard/Android/obb/${this.config.packageName}`
      ];

      for (const dir of dataDirs) {
        try {
          const checkResult = await this.adbBridge.executeCommand([
            'shell', 'test', '-d', dir, '&&', 'echo', 'exists'
          ], this.config.launchTimeout);

          if (checkResult.stdout.includes('exists')) {
            backup.metadata.dataDirs.push(dir);

            // Copy data to backup location
            await this.adbBridge.executeCommand([
              'shell', 'cp', '-r', dir, `/sdcard/Android/data/${this.config.packageName}/backup/`
            ], this.config.resetTimeout);
          }
        } catch (error) {
          logger.warn('Failed to backup directory', {
            directory: dir,
            error: (error as Error).message
          });
        }
      }

      // Pull backup to host
      await this.adbBridge.executeCommand([
        'pull', `/sdcard/Android/data/${this.config.packageName}/backup`, backupPath
      ], this.config.resetTimeout);

      // Get backup size
      const sizeResult = await this.adbBridge.executeCommand([
        'shell', 'du', '-sb', `/sdcard/Android/data/${this.config.packageName}/backup`
      ], this.config.launchTimeout);

      const sizeMatch = sizeResult.stdout.match(/^(\d+)/);
      backup.sizeBytes = sizeMatch ? parseInt(sizeMatch[1]) : 0;

      // Cleanup device backup
      await this.adbBridge.executeCommand([
        'shell', 'rm', '-rf', `/sdcard/Android/data/${this.config.packageName}/backup`
      ], this.config.launchTimeout);

      backup.status = 'completed';
      backup.completedAt = new Date().toISOString();

      this.metrics.totalBackupSize += backup.sizeBytes;
      this.metrics.backupsCreated++;

      logger.info('App backup created successfully', {
        backupId,
        sizeBytes: backup.sizeBytes,
        duration: Date.now() - new Date(backup.timestamp).getTime()
      });

      this.emit('backup:created', backup);

      return backup;

    } catch (error) {
      backup.status = 'failed';
      throw new BackupError(
        `Failed to create backup: ${(error as Error).message}`,
        {
          backupId,
          originalError: (error as Error).message
        }
      );
    }
  }

  /**
   * Stop the app
   */
  private async stopApp(): Promise<void> {
    try {
      await this.adbBridge.executeCommand([
        'shell', 'am', 'force-stop', this.config.packageName
      ], this.config.launchTimeout);

      logger.debug('App stopped successfully', {
        packageName: this.config.packageName
      });

    } catch (error) {
      throw new AppResetError(
        `Failed to stop app: ${(error as Error).message}`,
        'STOP_APP_ERROR',
        'stopping',
        { packageName: this.config.packageName }
      );
    }
  }

  /**
   * Clear app data based on reset type
   */
  private async clearAppData(options: ResetOptions): Promise<void> {
    try {
      switch (options.type) {
        case 'soft':
          await this.performSoftReset(options);
          break;

        case 'hard':
          await this.performHardReset(options);
          break;

        case 'full':
          await this.performFullReset(options);
          break;

        case 'custom':
          await this.performCustomReset(options);
          break;

        default:
          throw new AppResetError(`Unknown reset type: ${options.type}`);
      }

      logger.debug('App data cleared successfully', {
        resetType: options.type,
        packageName: this.config.packageName
      });

    } catch (error) {
      throw new ClearDataError(
        `Failed to clear app data: ${(error as Error).message}`,
        {
          resetType: options.type,
          originalError: (error as Error).message
        }
      );
    }
  }

  /**
   * Perform soft reset (clear cache only)
   */
  private async performSoftReset(options: ResetOptions): Promise<void> {
    // Clear app cache
    await this.adbBridge.executeCommand([
      'shell', 'pm', 'clear', '--cache-only', this.config.packageName
    ], this.config.resetTimeout);
  }

  /**
   * Perform hard reset (clear app data)
   */
  private async performHardReset(options: ResetOptions): Promise<void> {
    // Clear app data
    await this.adbBridge.executeCommand([
      'shell', 'pm', 'clear', this.config.packageName
    ], this.config.resetTimeout);
  }

  /**
   * Perform full reset (clear everything)
   */
  private async performFullReset(options: ResetOptions): Promise<void> {
    // Force stop first
    await this.adbBridge.executeCommand([
      'shell', 'am', 'force-stop', this.config.packageName
    ], this.config.launchTimeout);

    // Clear all app data
    await this.adbBridge.executeCommand([
      'shell', 'pm', 'clear', this.config.packageName
    ], this.config.resetTimeout);

    // Clear external storage
    await this.adbBridge.executeCommand([
      'shell', 'rm', '-rf', `/sdcard/Android/data/${this.config.packageName}`
    ], this.config.resetTimeout);

    // Clear OBB files
    await this.adbBridge.executeCommand([
      'shell', 'rm', '-rf', `/sdcard/Android/obb/${this.config.packageName}`
    ], this.config.resetTimeout);
  }

  /**
   * Perform custom reset (clear specific directories)
   */
  private async performCustomReset(options: ResetOptions): Promise<void> {
    if (!options.customDirectories || options.customDirectories.length === 0) {
      throw new AppResetError('Custom reset requires customDirectories to be specified');
    }

    for (const dir of options.customDirectories) {
      try {
        await this.adbBridge.executeCommand([
          'shell', 'rm', '-rf', dir
        ], this.config.resetTimeout);
      } catch (error) {
        logger.warn('Failed to clear custom directory', {
          directory: dir,
          error: (error as Error).message
        });
      }
    }
  }

  /**
   * Clear app cache
   */
  private async clearAppCache(): Promise<void> {
    try {
      await this.adbBridge.executeCommand([
        'shell', 'rm', '-rf', `/data/data/${this.config.packageName}/cache`
      ], this.config.resetTimeout);

      await this.adbBridge.executeCommand([
        'shell', 'rm', '-rf', `/sdcard/Android/data/${this.config.packageName}/cache`
      ], this.config.resetTimeout);

      logger.debug('App cache cleared successfully');

    } catch (error) {
      logger.warn('Failed to clear app cache', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Clear external storage
   */
  private async clearExternalStorage(): Promise<void> {
    try {
      const externalPaths = [
        `/sdcard/Android/data/${this.config.packageName}`,
        `/sdcard/Android/obb/${this.config.packageName}`,
        `/sdcard/Android/media/${this.config.packageName}`
      ];

      for (const path of externalPaths) {
        try {
          await this.adbBridge.executeCommand([
            'shell', 'rm', '-rf', path
          ], this.config.resetTimeout);
        } catch (error) {
          logger.warn('Failed to clear external path', {
            path,
            error: (error as Error).message
          });
        }
      }

      logger.debug('External storage cleared successfully');

    } catch (error) {
      logger.warn('Failed to clear external storage', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Restart app services
   */
  private async restartAppServices(): Promise<void> {
    try {
      // Kill any lingering processes
      await this.adbBridge.executeCommand([
        'shell', 'pkill', '-f', this.config.packageName
      ], this.config.launchTimeout);

      // Small delay to ensure processes are fully stopped
      await this.sleep(2000);

      logger.debug('App services restarted successfully');

    } catch (error) {
      logger.warn('Failed to restart app services', {
        error: (error as Error).message
      });
    }
  }

  /**
   * Validate app state after reset
   */
  private async validateResetState(): Promise<void> {
    try {
      // Verify package is still installed
      const packageCheck = await this.adbBridge.executeCommand([
        'shell', 'pm', 'list', 'packages', this.config.packageName
      ], this.config.launchTimeout);

      if (packageCheck.exitCode !== 0 || !packageCheck.stdout.includes(this.config.packageName)) {
        throw new AppResetError('Package not found after reset');
      }

      // Validate package integrity
      const validation = await validateMaynDrivePackage(this.adbBridge);

      if (!validation.isValid) {
        throw new AppResetError(
          'Package validation failed after reset',
          'VALIDATION_ERROR',
          'validating',
          { issues: validation.issues }
        );
      }

      logger.debug('Post-reset validation successful');

    } catch (error) {
      if (error instanceof AppResetError) {
        throw error;
      }
      throw new AppResetError(
        `Post-reset validation failed: ${(error as Error).message}`,
        'VALIDATION_ERROR',
        'validating',
        { originalError: (error as Error).message }
      );
    }
  }

  /**
   * Launch app after reset
   */
  private async launchApp(): Promise<void> {
    try {
      const launchResult = await this.adbBridge.executeCommand([
        'shell', 'am', 'start',
        '-n', `${this.config.packageName}/${this.config.mainActivity}`,
        '-a', 'android.intent.action.MAIN',
        '-c', 'android.intent.category.LAUNCHER'
      ], this.config.launchTimeout);

      if (launchResult.exitCode !== 0) {
        throw new AppResetError(
          'Failed to launch app after reset',
          'LAUNCH_ERROR',
          'launching',
          { exitCode: launchResult.exitCode, stderr: launchResult.stderr }
        );
      }

      // Wait for app to launch
      await this.waitForAppLaunch();

      logger.debug('App launched successfully after reset');

    } catch (error) {
      if (error instanceof AppResetError) {
        throw error;
      }
      throw new AppResetError(
        `Failed to launch app after reset: ${(error as Error).message}`,
        'LAUNCH_ERROR',
        'launching',
        { originalError: (error as Error).message }
      );
    }
  }

  /**
   * Wait for app to launch
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
          return;
        }

        await this.sleep(checkInterval);

      } catch (error) {
        await this.sleep(checkInterval);
      }
    }

    throw new AppResetError(
      `App did not launch within ${maxWaitTime}ms`,
      'LAUNCH_TIMEOUT_ERROR',
      'launching'
    );
  }

  // ============================================================================
  // Restore Operations
  // ============================================================================

  /**
   * Restore app from backup
   */
  async restoreFromBackup(backupId: string): Promise<void> {
    try {
      logger.info('Starting app restore from backup', { backupId });

      // Find backup file
      const backupPath = `${this.config.backupDirectory}/${backupId}`;

      // Push backup to device
      await this.adbBridge.executeCommand([
        'push', backupPath, `/sdcard/Android/data/${this.config.packageName}/restore`
      ], this.config.resetTimeout);

      // Stop app first
      await this.stopApp();

      // Restore data
      await this.adbBridge.executeCommand([
        'shell', 'cp', '-r', `/sdcard/Android/data/${this.config.packageName}/restore/*`, `/data/data/${this.config.packageName}/`
      ], this.config.resetTimeout);

      // Set proper permissions
      await this.adbBridge.executeCommand([
        'shell', 'chown', '-R', `shell:shell`, `/data/data/${this.config.packageName}/`
      ], this.config.resetTimeout);

      // Cleanup
      await this.adbBridge.executeCommand([
        'shell', 'rm', '-rf', `/sdcard/Android/data/${this.config.packageName}/restore`
      ], this.config.resetTimeout);

      // Launch app
      await this.launchApp();

      this.metrics.restoresPerformed++;

      logger.info('App restore completed successfully', { backupId });

      this.emit('restore:success', { backupId });

    } catch (error) {
      const restoreError = new RestoreError(
        `Failed to restore from backup: ${(error as Error).message}`,
        { backupId, originalError: (error as Error).message }
      );

      logger.error('App restore failed', {
        backupId,
        error: restoreError.message
      });

      this.emit('restore:failed', { backupId, error: restoreError });
      throw restoreError;
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  private updateResetState(
    phase: ResetState['phase'],
    progress: number,
    description: string,
    error?: ResetError
  ): void {
    this.resetState = {
      ...this.resetState,
      phase,
      progress,
      description,
      error,
      retryCount: error ? this.resetState.retryCount + 1 : this.resetState.retryCount
    };

    this.emit('state:change', this.resetState);
  }

  private recordResetType(type: ResetType): void {
    const existingType = this.metrics.commonResetTypes.find(t => t.type === type);
    if (existingType) {
      existingType.count++;
    } else {
      this.metrics.commonResetTypes.push({
        type,
        count: 1,
        percentage: 0
      });
    }

    // Update percentages
    const totalResets = this.metrics.commonResetTypes.reduce((sum, t) => sum + t.count, 0);
    this.metrics.commonResetTypes.forEach(t => {
      t.percentage = (t.count / totalResets) * 100;
    });
  }

  private updateAverageResetTime(duration: number): void {
    const totalTime = this.metrics.averageResetTime * (this.metrics.successfulResets - 1) + duration;
    this.metrics.averageResetTime = Math.round(totalTime / this.metrics.successfulResets);
    this.metrics.lastResetTime = new Date().toISOString();

    // Update success rate
    this.metrics.successRate = (this.metrics.successfulResets / this.metrics.totalResets) * 100;
  }

  private async ensureBackupDirectory(): Promise<void> {
    try {
      const fs = require('fs').promises;
      await fs.mkdir(this.config.backupDirectory, { recursive: true });
    } catch (error) {
      throw new BackupError(
        `Failed to create backup directory: ${(error as Error).message}`,
        { directory: this.config.backupDirectory }
      );
    }
  }

  private async cleanOldBackups(): Promise<void> {
    try {
      const fs = require('fs').promises;
      const files = await fs.readdir(this.config.backupDirectory);
      const now = Date.now();

      for (const file of files) {
        const filePath = `${this.config.backupDirectory}/${file}`;
        const stats = await fs.stat(filePath);

        if (now - stats.mtime.getTime() > this.config.backupRetentionTime) {
          await fs.rm(filePath, { recursive: true });
          logger.debug('Removed old backup', { file });
        }
      }
    } catch (error) {
      logger.warn('Failed to clean old backups', {
        error: (error as Error).message
      });
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ============================================================================
  // Public API Methods
  // ============================================================================

  /**
   * Get current reset state
   */
  getResetState(): ResetState {
    return { ...this.resetState };
  }

  /**
   * Get reset metrics
   */
  getResetMetrics(): ResetMetrics {
    return { ...this.metrics };
  }

  /**
   * List available backups
   */
  async listBackups(): Promise<BackupInfo[]> {
    try {
      const fs = require('fs').promises;
      const files = await fs.readdir(this.config.backupDirectory);

      const backups: BackupInfo[] = [];
      for (const file of files) {
        try {
          const filePath = `${this.config.backupDirectory}/${file}`;
          const stats = await fs.stat(filePath);

          // Simple backup info (in real implementation, you'd read metadata files)
          backups.push({
            id: file,
            timestamp: stats.mtime.toISOString(),
            type: 'full',
            sizeBytes: stats.size,
            filePath,
            metadata: {
              appVersion: 'unknown',
              dataDirs: [],
              cacheDirs: [],
              prefFiles: [],
              externalFiles: []
            },
            status: 'completed',
            completedAt: stats.mtime.toISOString()
          });
        } catch (error) {
          logger.warn('Failed to read backup info', { file });
        }
      }

      return backups.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    } catch (error) {
      logger.error('Failed to list backups', {
        error: (error as Error).message
      });
      return [];
    }
  }

  /**
   * Delete backup
   */
  async deleteBackup(backupId: string): Promise<void> {
    try {
      const fs = require('fs').promises;
      const backupPath = `${this.config.backupDirectory}/${backupId}`;
      await fs.rm(backupPath, { recursive: true });

      logger.info('Backup deleted successfully', { backupId });
      this.emit('backup:deleted', { backupId });

    } catch (error) {
      throw new BackupError(
        `Failed to delete backup: ${(error as Error).message}`,
        { backupId }
      );
    }
  }

  /**
   * Close reset service and cleanup resources
   */
  async close(): Promise<void> {
    logger.info('Closing App Reset Service', {
      packageName: this.config.packageName
    });

    this.removeAllListeners();
    this.isInitialized = false;

    logger.info('App Reset Service closed');
  }
}

// ============================================================================
// Service Factory
// ============================================================================

let appResetInstance: AppResetService | null = null;

/**
 * Get singleton App Reset service instance
 */
export function getAppResetService(config?: Partial<AppResetConfig>): AppResetService {
  if (!appResetInstance) {
    appResetInstance = new AppResetService(config);
  }
  return appResetInstance;
}

/**
 * Initialize App Reset service
 */
export async function initializeAppReset(config?: Partial<AppResetConfig>): Promise<AppResetService> {
  const service = getAppResetService(config);
  await service.initialize();
  return service;
}

/**
 * Close App Reset service
 */
export async function closeAppReset(): Promise<void> {
  if (appResetInstance) {
    await appResetInstance.close();
    appResetInstance = null;
  }
}