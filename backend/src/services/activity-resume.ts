/**
 * Activity Resume Service (T037.3)
 *
 * Activity-specific resume procedures for MaynDrive with comprehensive handlers
 * for MainActivity, LoginScreen, MapScreen, and other activities. Provides
 * state recovery, navigation management, context-aware activity handling,
 * and transition preservation.
 */

import { EventEmitter } from 'events';
import { ADBBridgeService, getADBBridgeService } from './adb-bridge';
import { logger } from './logger';

// ============================================================================
// Configuration Types
// ============================================================================

export interface ActivityResumeConfig {
  /** MaynDrive package name */
  packageName: string;

  /** Supported activities with their handlers */
  activities: Record<string, ActivityConfig>;

  /** Default resume timeout (ms) */
  defaultResumeTimeout: number;

  /** Activity transition timeout (ms) */
  transitionTimeout: number;

  /** State capture timeout (ms) */
  stateCaptureTimeout: number;

  /** Maximum resume retry attempts */
  maxResumeRetries: number;

  /** Resume retry backoff multiplier */
  retryBackoffMultiplier: number;

  /** Enable activity state preservation */
  enableStatePreservation: boolean;

  /** State storage directory */
  stateStorageDirectory: string;

  /** Enable context-aware resume */
  enableContextAwareResume: boolean;

  /** Enable automatic navigation recovery */
  enableAutoNavigationRecovery: boolean;

  /** Debug activity transitions */
  debugTransitions: boolean;
}

export interface ActivityConfig {
  /** Activity name */
  name: string;

  /** Activity type */
  type: 'main' | 'login' | 'map' | 'settings' | 'splash' | 'custom';

  /** Expected launch timeout (ms) */
  launchTimeout: number;

  /** Resume strategies in priority order */
  resumeStrategies: ResumeStrategy[];

  /** Required UI elements for verification */
  requiredElements: string[];

  /** Navigation patterns for this activity */
  navigationPatterns: NavigationPattern[];

  /** State preservation rules */
  statePreservation: StatePreservationRule[];

  /** Context requirements */
  contextRequirements: ContextRequirement[];

  /** Activity-specific resume handlers */
  customHandlers?: Record<string, ResumeHandler>;
}

export type ResumeStrategy = 'launch' | 'resume' | 'restart' | 'restore_state' | 'force_launch' | 'custom';

export interface NavigationPattern {
  /** Pattern name */
  name: string;

  /** Source activity */
  from: string;

  /** Target activity */
  to: string;

  /** Navigation action */
  action: 'click' | 'swipe' | 'back' | 'intent' | 'custom';

  /** Navigation parameters */
  params: Record<string, any>;

  /** Expected transition time (ms) */
  transitionTime: number;

  /** Verification requirements */
  verification?: string[];
}

export interface StatePreservationRule {
  /** State element name */
  element: string;

  /** Preservation method */
  method: 'ui_state' | 'shared_prefs' | 'database' | 'file' | 'custom';

  /** Priority (higher = more important) */
  priority: number;

  /** Expiration time (ms) */
  expiration: number;

  /** Custom extraction logic */
  extractor?: string;
}

export interface ContextRequirement {
  /** Requirement name */
  name: string;

  /** Requirement type */
  type: 'network' | 'location' | 'authentication' | 'permissions' | 'custom';

  /** Required value/state */
  required: any;

  /** Validation method */
  validator?: string;

  /** Auto-fulfill capability */
  autoFulfill?: boolean;
}

export interface ResumeHandler {
  /** Handler name */
  name: string;

  /** Handler function */
  execute: (context: ResumeContext) => Promise<ResumeResult>;

  /** Handler priority */
  priority: number;

  /** Handler conditions */
  conditions?: ResumeCondition[];
}

export interface ResumeCondition {
  /** Condition type */
  type: 'activity' | 'state' | 'context' | 'time' | 'custom';

  /** Condition value */
  value: any;

  /** Comparison operator */
  operator: 'equals' | 'contains' | 'greater_than' | 'less_than' | 'exists' | 'custom';

  /** Custom validator */
  validator?: string;
}

export interface ResumeContext {
  /** Target activity */
  activity: string;

  /** Current activity */
  currentActivity?: string;

  /** Previous activity */
  previousActivity?: string;

  /** Resume strategy */
  strategy: ResumeStrategy;

  /** Resume attempt count */
  attempt: number;

  /** Resume start time */
  startTime: number;

  /** App state information */
  appState: AppState;

  /** Context data */
  context: Record<string, any>;

  /** Preserved state */
  preservedState?: PreservedState;
}

export interface ResumeResult {
  /** Success status */
  success: boolean;

  /** Result message */
  message: string;

  /** Final activity */
  finalActivity?: string;

  /** Resume duration (ms) */
  duration: number;

  /** Strategy used */
  strategyUsed: ResumeStrategy;

  /** State restored */
  stateRestored: boolean;

  /** Navigation performed */
  navigationPerformed: boolean;

  /** Result metadata */
  metadata: Record<string, any>;

  /** Warnings encountered */
  warnings: string[];

  /** Error if failed */
  error?: ResumeError;
}

export interface AppState {
  /** App is running */
  isRunning: boolean;

  /** Current activity */
  currentActivity?: string;

  /** Current activity state */
  activityState: 'foreground' | 'background' | 'stopped' | 'destroyed';

  /** App process ID */
  pid?: number;

  /** Memory usage (MB) */
  memoryUsage?: number;

  /** Network connectivity */
  networkConnected: boolean;

  /** Device orientation */
  orientation: 'portrait' | 'landscape';

  /** Last activity change timestamp */
  lastActivityChange?: string;
}

export interface PreservedState {
  /** State ID */
  id: string;

  /** Activity name */
  activity: string;

  /** State timestamp */
  timestamp: string;

  /** State data */
  data: Record<string, any>;

  /** UI elements state */
  uiElements: Record<string, any>;

  /** Navigation state */
  navigationState: NavigationState;

  /** Context state */
  contextState: Record<string, any>;

  /** Expiration time */
  expiresAt: string;
}

export interface NavigationState {
  /** Current navigation stack */
  stack: string[];

  /** Current index in stack */
  currentIndex: number;

  /** Navigation history */
  history: NavigationEvent[];

  /** Deep link information */
  deepLink?: string;
}

export interface NavigationEvent {
  /** Event timestamp */
  timestamp: string;

  /** From activity */
  from: string;

  /** To activity */
  to: string;

  /** Navigation action */
  action: string;

  /** Transition duration */
  duration: number;
}

export interface ActivityTransition {
  /** Transition ID */
  id: string;

  /** Source activity */
  from: string;

  /** Target activity */
  to: string;

  /** Transition type */
  type: 'forward' | 'backward' | 'lateral' | 'custom';

  /** Transition start time */
  startTime: string;

  /** Transition completion time */
  completedTime?: string;

  /** Transition status */
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'timeout';

  /** Transition data */
  data: Record<string, any>;
}

export interface ResumeError {
  /** Error code */
  code: string;

  /** Error message */
  message: string;

  /** Activity where error occurred */
  activity: string;

  /** Strategy that failed */
  strategy: ResumeStrategy;

  /** Error details */
  details?: Record<string, any>;

  /** Suggested recovery action */
  recoveryAction?: string;

  /** Timestamp */
  timestamp: string;
}

export interface ActivityResumeMetrics {
  /** Total resume operations */
  totalResumes: number;

  /** Successful resumes */
  successfulResumes: number;

  /** Failed resumes */
  failedResumes: number;

  /** Average resume time (ms) */
  averageResumeTime: number;

  /** Most resumed activities */
  commonActivities: Array<{
    activity: string;
    count: number;
    percentage: number;
  }>;

  /** Most successful strategies */
  successfulStrategies: Array<{
    strategy: ResumeStrategy;
    count: number;
    successRate: number;
  }>;

  /** State preservation usage */
  statePreservationUsage: {
    totalPreservations: number;
    successfulRestorations: number;
    averageRestorationTime: number;
  };

  /** Navigation recovery usage */
  navigationRecoveryUsage: {
    totalRecoveries: number;
    successfulRecoveries: number;
    averageRecoveryTime: number;
  };
}

// ============================================================================
// Error Types
// ============================================================================

export class ActivityResumeError extends Error {
  constructor(
    message: string,
    public code: string,
    public activity?: string,
    public strategy?: ResumeStrategy,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'ActivityResumeError';
  }
}

export class ActivityNotFoundError extends ActivityResumeError {
  constructor(activity: string, details?: Record<string, any>) {
    super(`Activity not found: ${activity}`, 'ACTIVITY_NOT_FOUND', activity, 'launch', details);
  }
}

export class ResumeTimeoutError extends ActivityResumeError {
  constructor(activity: string, strategy: ResumeStrategy, timeout: number, details?: Record<string, any>) {
    super(`Resume timeout for ${activity} using ${strategy} after ${timeout}ms`, 'RESUME_TIMEOUT', activity, strategy, { timeout, ...details });
  }
}

export class StatePreservationError extends ActivityResumeError {
  constructor(activity: string, details?: Record<string, any>) {
    super(`State preservation failed for ${activity}`, 'STATE_PRESERVATION_ERROR', activity, 'restore_state', details);
  }
}

// ============================================================================
// Main Activity Resume Service
// ============================================================================

export class ActivityResumeService extends EventEmitter {
  private config: ActivityResumeConfig;
  private adbBridge: ADBBridgeService;
  private metrics: ActivityResumeMetrics;
  private activeTransitions: Map<string, ActivityTransition> = new Map();
  private preservedStates: Map<string, PreservedState> = new Map();
  private isInitialized = false;

  constructor(config?: Partial<ActivityResumeConfig>) {
    super();

    this.config = this.createConfig(config);
    this.adbBridge = getADBBridgeService();
    this.metrics = this.createInitialMetrics();

    logger.info('Activity Resume Service initialized', {
      packageName: this.config.packageName,
      activitiesCount: Object.keys(this.config.activities).length,
      enableStatePreservation: this.config.enableStatePreservation
    });
  }

  private createConfig(override?: Partial<ActivityResumeConfig>): ActivityResumeConfig {
    const defaultActivities: Record<string, ActivityConfig> = {
      'com.mayndrive.app.MainActivity': {
        name: 'MainActivity',
        type: 'main',
        launchTimeout: 10000,
        resumeStrategies: ['resume', 'launch', 'restart', 'force_launch'],
        requiredElements: ['map_view', 'navigation_bar', 'user_profile'],
        navigationPatterns: [
          {
            name: 'main_to_login',
            from: 'com.mayndrive.app.MainActivity',
            to: 'com.mayndrive.app.LoginScreen',
            action: 'click',
            params: { element: 'login_button' },
            transitionTime: 2000
          },
          {
            name: 'main_to_map',
            from: 'com.mayndrive.app.MainActivity',
            to: 'com.mayndrive.app.MapScreen',
            action: 'click',
            params: { element: 'map_button' },
            transitionTime: 1500
          }
        ],
        statePreservation: [
          {
            element: 'user_session',
            method: 'shared_prefs',
            priority: 100,
            expiration: 3600000 // 1 hour
          },
          {
            element: 'map_state',
            method: 'ui_state',
            priority: 80,
            expiration: 1800000 // 30 minutes
          }
        ],
        contextRequirements: [
          {
            name: 'network',
            type: 'network',
            required: true,
            autoFulfill: false
          },
          {
            name: 'location',
            type: 'location',
            required: true,
            autoFulfill: true
          }
        ]
      },
      'com.mayndrive.app.LoginScreen': {
        name: 'LoginScreen',
        type: 'login',
        launchTimeout: 8000,
        resumeStrategies: ['resume', 'launch', 'force_launch'],
        requiredElements: ['username_field', 'password_field', 'login_button'],
        navigationPatterns: [
          {
            name: 'login_to_main',
            from: 'com.mayndrive.app.LoginScreen',
            to: 'com.mayndrive.app.MainActivity',
            action: 'click',
            params: { element: 'login_button' },
            transitionTime: 3000,
            verification: ['main_activity_loaded']
          }
        ],
        statePreservation: [
          {
            element: 'login_credentials',
            method: 'ui_state',
            priority: 60,
            expiration: 300000 // 5 minutes
          }
        ],
        contextRequirements: [
          {
            name: 'authentication',
            type: 'authentication',
            required: true,
            autoFulfill: false
          }
        ]
      },
      'com.mayndrive.app.MapScreen': {
        name: 'MapScreen',
        type: 'map',
        launchTimeout: 12000,
        resumeStrategies: ['resume', 'restore_state', 'launch', 'restart'],
        requiredElements: ['map_container', 'location_marker', 'zoom_controls'],
        navigationPatterns: [
          {
            name: 'map_to_main',
            from: 'com.mayndrive.app.MapScreen',
            to: 'com.mayndrive.app.MainActivity',
            action: 'back',
            params: {},
            transitionTime: 1000
          },
          {
            name: 'map_to_settings',
            from: 'com.mayndrive.app.MapScreen',
            to: 'com.mayndrive.app.SettingsScreen',
            action: 'click',
            params: { element: 'settings_button' },
            transitionTime: 1500
          }
        ],
        statePreservation: [
          {
            element: 'map_position',
            method: 'ui_state',
            priority: 90,
            expiration: 3600000 // 1 hour
          },
          {
            element: 'zoom_level',
            method: 'shared_prefs',
            priority: 70,
            expiration: 1800000 // 30 minutes
          }
        ],
        contextRequirements: [
          {
            name: 'location',
            type: 'location',
            required: true,
            autoFulfill: true
          },
          {
            name: 'network',
            type: 'network',
            required: true,
            autoFulfill: false
          }
        ]
      }
    };

    const baseConfig: ActivityResumeConfig = {
      packageName: 'com.mayndrive.app',
      activities: defaultActivities,
      defaultResumeTimeout: 15000,
      transitionTimeout: 5000,
      stateCaptureTimeout: 3000,
      maxResumeRetries: parseInt(process.env.ACTIVITY_RESUME_MAX_RETRIES || '3'),
      retryBackoffMultiplier: parseFloat(process.env.ACTIVITY_RESUME_RETRY_BACKOFF || '1.5'),
      enableStatePreservation: process.env.ACTIVITY_RESUME_ENABLE_PRESERVATION !== 'false',
      stateStorageDirectory: process.env.ACTIVITY_RESUME_STATE_DIR || '/tmp/mayndrive-states',
      enableContextAwareResume: process.env.ACTIVITY_RESUME_ENABLE_CONTEXT_AWARE !== 'false',
      enableAutoNavigationRecovery: process.env.ACTIVITY_RESUME_ENABLE_AUTO_NAVIGATION !== 'false',
      debugTransitions: process.env.ACTIVITY_RESUME_DEBUG_TRANSITIONS === 'true'
    };

    return { ...baseConfig, ...override, activities: { ...baseConfig.activities, ...override?.activities } };
  }

  private createInitialMetrics(): ActivityResumeMetrics {
    return {
      totalResumes: 0,
      successfulResumes: 0,
      failedResumes: 0,
      averageResumeTime: 0,
      commonActivities: [],
      successfulStrategies: [],
      statePreservationUsage: {
        totalPreservations: 0,
        successfulRestorations: 0,
        averageRestorationTime: 0
      },
      navigationRecoveryUsage: {
        totalRecoveries: 0,
        successfulRecoveries: 0,
        averageRecoveryTime: 0
      }
    };
  }

  // ============================================================================
  // Service Lifecycle
  // ============================================================================

  /**
   * Initialize activity resume service
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('Activity Resume Service already initialized');
      return;
    }

    logger.info('Initializing Activity Resume Service', {
      packageName: this.config.packageName
    });

    try {
      // Ensure state storage directory exists
      if (this.config.enableStatePreservation) {
        await this.ensureStateStorageDirectory();
      }

      // Load preserved states
      await this.loadPreservedStates();

      this.isInitialized = true;

      logger.info('Activity Resume Service initialized successfully', {
        packageName: this.config.packageName,
        activitiesCount: Object.keys(this.config.activities).length,
        preservedStatesCount: this.preservedStates.size
      });

      this.emit('initialized');

    } catch (error) {
      logger.error('Activity Resume Service initialization failed', {
        error: (error as Error).message
      });
      throw new ActivityResumeError(
        `Failed to initialize activity resume service: ${(error as Error).message}`,
        'INITIALIZATION_ERROR'
      );
    }
  }

  // ============================================================================
  // Activity Resume Operations
  // ============================================================================

  /**
   * Resume to a specific activity
   */
  async resumeToActivity(
    targetActivity: string,
    options?: {
      strategy?: ResumeStrategy;
      preserveCurrentState?: boolean;
      context?: Record<string, any>;
      force?: boolean;
    }
  ): Promise<ResumeResult> {
    if (!this.isInitialized) {
      throw new ActivityResumeError('Resume service not initialized');
    }

    const resumeStartTime = Date.now();
    let retryCount = 0;
    let lastError: ActivityResumeError | null = null;

    logger.info('Starting activity resume', {
      targetActivity,
      strategy: options?.strategy,
      preserveState: options?.preserveCurrentState
    });

    // Verify target activity is supported
    if (!this.config.activities[targetActivity]) {
      throw new ActivityNotFoundError(targetActivity);
    }

    // Get current app state
    const appState = await this.getAppState();
    const activityConfig = this.config.activities[targetActivity];

    // Create resume context
    const context: ResumeContext = {
      activity: targetActivity,
      currentActivity: appState.currentActivity,
      previousActivity: undefined, // Would need to track this
      strategy: options?.strategy || activityConfig.resumeStrategies[0],
      attempt: 0,
      startTime: resumeStartTime,
      appState,
      context: options?.context || {}
    };

    // Preserve current state if requested
    if (options?.preserveCurrentState && appState.currentActivity) {
      try {
        context.preservedState = await this.preserveActivityState(appState.currentActivity);
      } catch (error) {
        logger.warn('Failed to preserve current state', {
          activity: appState.currentActivity,
          error: (error as Error).message
        });
      }
    }

    this.metrics.totalResumes++;
    this.recordActivityResume(targetActivity);

    // Try each strategy until one succeeds
    const strategies = options?.strategy
      ? [options.strategy]
      : activityConfig.resumeStrategies;

    for (const strategy of strategies) {
      retryCount = 0;
      context.strategy = strategy;

      while (retryCount <= this.config.maxResumeRetries) {
        try {
          context.attempt = retryCount + 1;

          const result = await this.executeResumeStrategy(context, strategy);

          // Resume successful
          this.metrics.successfulResumes++;
          const resumeDuration = Date.now() - resumeStartTime;
          this.updateAverageResumeTime(resumeDuration);
          this.recordStrategySuccess(strategy);

          logger.info('Activity resume completed successfully', {
            targetActivity,
            strategy,
            duration: resumeDuration,
            finalActivity: result.finalActivity,
            attempt: context.attempt
          });

          this.emit('resume:success', {
            targetActivity,
            strategy,
            result,
            duration: resumeDuration
          });

          return result;

        } catch (error) {
          lastError = error as ActivityResumeError;
          retryCount++;

          logger.warn('Activity resume attempt failed', {
            targetActivity,
            strategy,
            attempt: context.attempt,
            maxRetries: this.config.maxResumeRetries + 1,
            error: lastError.message
          });

          if (retryCount <= this.config.maxResumeRetries) {
            const delay = Math.min(
              1000 * Math.pow(this.config.retryBackoffMultiplier, retryCount - 1),
              8000
            );

            logger.debug('Waiting before retry', { delay, retryCount });
            await this.sleep(delay);
          }
        }
      }
    }

    // All strategies and retries exhausted
    this.metrics.failedResumes++;

    const finalError = new ActivityResumeError(
      `Activity resume failed for ${targetActivity} after trying all strategies`,
      'RESUME_EXHAUSTED',
      targetActivity,
      strategies[strategies.length - 1],
      {
        totalAttempts: retryCount,
        strategies: strategies,
        lastError: lastError?.message
      }
    );

    logger.error('Activity resume failed - all strategies exhausted', {
      targetActivity,
      strategies,
      totalAttempts: retryCount,
      lastError: lastError?.message
    });

    this.emit('resume:failed', {
      targetActivity,
      error: finalError
    });
    throw finalError;
  }

  /**
   * Execute a specific resume strategy
   */
  private async executeResumeStrategy(context: ResumeContext, strategy: ResumeStrategy): Promise<ResumeResult> {
    const activityConfig = this.config.activities[context.activity];
    const startTime = Date.now();

    logger.debug('Executing resume strategy', {
      activity: context.activity,
      strategy,
      attempt: context.attempt
    });

    try {
      let result: ResumeResult;

      switch (strategy) {
        case 'resume':
          result = await this.executeResumeStrategy(context);
          break;

        case 'launch':
          result = await this.executeLaunchStrategy(context);
          break;

        case 'restart':
          result = await this.executeRestartStrategy(context);
          break;

        case 'restore_state':
          result = await this.executeRestoreStateStrategy(context);
          break;

        case 'force_launch':
          result = await this.executeForceLaunchStrategy(context);
          break;

        case 'custom':
          result = await this.executeCustomStrategy(context);
          break;

        default:
          throw new ActivityResumeError(
            `Unknown resume strategy: ${strategy}`,
            'UNKNOWN_STRATEGY',
            context.activity,
            strategy
          );
      }

      // Verify activity is properly resumed
      if (result.success) {
        await this.verifyActivityResumed(context.activity, activityConfig);
        result.finalActivity = await this.getCurrentActivity();
      }

      result.duration = Date.now() - startTime;
      result.strategyUsed = strategy;

      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      const resumeError: ResumeError = {
        code: (error as ActivityResumeError).code || 'STRATEGY_ERROR',
        message: (error as Error).message,
        activity: context.activity,
        strategy,
        details: (error as ActivityResumeError).details,
        timestamp: new Date().toISOString()
      };

      return {
        success: false,
        message: resumeError.message,
        duration,
        strategyUsed: strategy,
        stateRestored: false,
        navigationPerformed: false,
        metadata: { error: resumeError },
        warnings: [],
        error: resumeError
      };
    }
  }

  /**
   * Execute standard resume strategy
   */
  private async executeResumeStrategy(context: ResumeContext): Promise<ResumeResult> {
    const activityConfig = this.config.activities[context.activity];

    // Check if app is running and activity can be resumed
    if (context.appState.isRunning && context.appState.activityState !== 'destroyed') {
      try {
        // Bring app to foreground if in background
        if (context.appState.activityState === 'background') {
          await this.adbBridge.executeCommand([
            'shell', 'am', 'start',
            '-n', `${this.config.packageName}/${context.activity}`
          ], activityConfig.launchTimeout);
        }

        // Wait for activity to be in foreground
        await this.waitForActivity(context.activity, activityConfig.launchTimeout);

        return {
          success: true,
          message: `Successfully resumed ${context.activity}`,
          strategyUsed: 'resume',
          stateRestored: false,
          navigationPerformed: false,
          metadata: {},
          warnings: []
        };

      } catch (error) {
        throw new ActivityResumeError(
          `Failed to resume activity: ${(error as Error).message}`,
          'RESUME_FAILED',
          context.activity,
          'resume'
        );
      }
    }

    // App not running, fallback to launch
    throw new ActivityResumeError(
      'App not running, cannot resume',
      'APP_NOT_RUNNING',
      context.activity,
      'resume'
    );
  }

  /**
   * Execute launch strategy
   */
  private async executeLaunchStrategy(context: ResumeContext): Promise<ResumeResult> {
    const activityConfig = this.config.activities[context.activity];

    try {
      // Launch the specific activity
      await this.adbBridge.executeCommand([
        'shell', 'am', 'start',
        '-n', `${this.config.packageName}/${context.activity}`,
        '-a', 'android.intent.action.MAIN'
      ], activityConfig.launchTimeout);

      // Wait for activity to launch
      await this.waitForActivity(context.activity, activityConfig.launchTimeout);

      return {
        success: true,
        message: `Successfully launched ${context.activity}`,
        strategyUsed: 'launch',
        stateRestored: false,
        navigationPerformed: false,
        metadata: {},
        warnings: []
      };

    } catch (error) {
      throw new ActivityResumeError(
        `Failed to launch activity: ${(error as Error).message}`,
        'LAUNCH_FAILED',
        context.activity,
        'launch'
      );
    }
  }

  /**
   * Execute restart strategy
   */
  private async executeRestartStrategy(context: ResumeContext): Promise<ResumeResult> {
    const activityConfig = this.config.activities[context.activity];

    try {
      // Force stop the app
      await this.adbBridge.executeCommand([
        'shell', 'am', 'force-stop', this.config.packageName
      ], this.config.launchTimeout);

      // Wait a moment
      await this.sleep(2000);

      // Launch the activity
      await this.adbBridge.executeCommand([
        'shell', 'am', 'start',
        '-n', `${this.config.packageName}/${context.activity}`,
        '-a', 'android.intent.action.MAIN'
      ], activityConfig.launchTimeout);

      // Wait for activity to launch
      await this.waitForActivity(context.activity, activityConfig.launchTimeout);

      return {
        success: true,
        message: `Successfully restarted and launched ${context.activity}`,
        strategyUsed: 'restart',
        stateRestored: false,
        navigationPerformed: false,
        metadata: {},
        warnings: ['App was restarted during resume']
      };

    } catch (error) {
      throw new ActivityResumeError(
        `Failed to restart activity: ${(error as Error).message}`,
        'RESTART_FAILED',
        context.activity,
        'restart'
      );
    }
  }

  /**
   * Execute restore state strategy
   */
  private async executeRestoreStateStrategy(context: ResumeContext): Promise<ResumeResult> {
    if (!this.config.enableStatePreservation) {
      throw new ActivityResumeError(
        'State preservation is disabled',
        'STATE_PRESERVATION_DISABLED',
        context.activity,
        'restore_state'
      );
    }

    try {
      // Find preserved state for this activity
      const preservedState = this.findPreservedState(context.activity);

      if (!preservedState) {
        throw new ActivityResumeError(
          'No preserved state found for activity',
          'NO_PRESERVED_STATE',
          context.activity,
          'restore_state'
        );
      }

      // Check if state is still valid
      if (new Date(preservedState.expiresAt) < new Date()) {
        throw new ActivityResumeError(
          'Preserved state has expired',
          'STATE_EXPIRED',
          context.activity,
          'restore_state'
        );
      }

      // Launch activity first
      const launchResult = await this.executeLaunchStrategy(context);
      if (!launchResult.success) {
        return launchResult;
      }

      // Restore state
      const restoreStartTime = Date.now();
      await this.restoreActivityState(context.activity, preservedState);
      const restoreDuration = Date.now() - restoreStartTime;

      this.metrics.statePreservationUsage.successfulRestorations++;
      this.updateAverageRestorationTime(restoreDuration);

      return {
        success: true,
        message: `Successfully restored state for ${context.activity}`,
        strategyUsed: 'restore_state',
        stateRestored: true,
        navigationPerformed: false,
        metadata: {
          stateId: preservedState.id,
          restoreDuration,
          stateAge: Date.now() - new Date(preservedState.timestamp).getTime()
        },
        warnings: []
      };

    } catch (error) {
      this.metrics.statePreservationUsage.totalPreservations++;
      throw new ActivityResumeError(
        `Failed to restore state: ${(error as Error).message}`,
        'STATE_RESTORE_FAILED',
        context.activity,
        'restore_state'
      );
    }
  }

  /**
   * Execute force launch strategy
   */
  private async executeForceLaunchStrategy(context: ResumeContext): Promise<ResumeResult> {
    const activityConfig = this.config.activities[context.activity];

    try {
      // Force stop the app
      await this.adbBridge.executeCommand([
        'shell', 'am', 'force-stop', this.config.packageName
      ], this.config.launchTimeout);

      // Clear app data to force clean state
      await this.adbBridge.executeCommand([
        'shell', 'pm', 'clear', this.config.packageName
      ], this.config.launchTimeout);

      // Wait a moment
      await this.sleep(3000);

      // Launch the activity with flags
      await this.adbBridge.executeCommand([
        'shell', 'am', 'start',
        '-n', `${this.config.packageName}/${context.activity}`,
        '-a', 'android.intent.action.MAIN',
        '-f', '0x10000000', // FLAG_ACTIVITY_NEW_TASK
        '--ez', 'force_clean', 'true'
      ], activityConfig.launchTimeout);

      // Wait for activity to launch
      await this.waitForActivity(context.activity, activityConfig.launchTimeout);

      return {
        success: true,
        message: `Successfully force launched ${context.activity}`,
        strategyUsed: 'force_launch',
        stateRestored: false,
        navigationPerformed: false,
        metadata: { cleanStart: true },
        warnings: ['App data was cleared during force launch']
      };

    } catch (error) {
      throw new ActivityResumeError(
        `Failed to force launch activity: ${(error as Error).message}`,
        'FORCE_LAUNCH_FAILED',
        context.activity,
        'force_launch'
      );
    }
  }

  /**
   * Execute custom strategy
   */
  private async executeCustomStrategy(context: ResumeContext): Promise<ResumeResult> {
    const activityConfig = this.config.activities[context.activity];

    if (!activityConfig.customHandlers || Object.keys(activityConfig.customHandlers).length === 0) {
      throw new ActivityResumeError(
        'No custom handlers available for this activity',
        'NO_CUSTOM_HANDLERS',
        context.activity,
        'custom'
      );
    }

    // Find the highest priority custom handler that matches conditions
    const handlers = Object.values(activityConfig.customHandlers)
      .sort((a, b) => b.priority - a.priority);

    for (const handler of handlers) {
      try {
        // Check if handler conditions are met
        if (handler.conditions && !this.checkHandlerConditions(handler.conditions, context)) {
          continue;
        }

        // Execute custom handler
        const result = await handler.execute(context);

        if (result.success) {
          return result;
        }

      } catch (error) {
        logger.warn('Custom handler failed', {
          handler: handler.name,
          error: (error as Error).message
        });
      }
    }

    throw new ActivityResumeError(
      'All custom handlers failed',
      'CUSTOM_HANDLERS_FAILED',
      context.activity,
      'custom'
    );
  }

  // ============================================================================
  // State Preservation
  // ============================================================================

  /**
   * Preserve activity state
   */
  async preserveActivityState(activity: string): Promise<PreservedState> {
    if (!this.config.enableStatePreservation) {
      throw new StatePreservationError(activity, { reason: 'State preservation disabled' });
    }

    const activityConfig = this.config.activities[activity];
    if (!activityConfig) {
      throw new ActivityNotFoundError(activity);
    }

    try {
      const stateId = `state_${activity}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Capture UI hierarchy
      const uiHierarchy = await this.adbBridge.getUIHierarchy();

      // Capture screenshot
      const screenshot = await this.adbBridge.captureScreenshot({ includeData: true });

      // Extract relevant state based on preservation rules
      const stateData = await this.extractActivityState(activity, activityConfig);

      const preservedState: PreservedState = {
        id: stateId,
        activity,
        timestamp: new Date().toISOString(),
        data: stateData,
        uiElements: this.parseUIElements(uiHierarchy),
        navigationState: await this.captureNavigationState(),
        contextState: await this.captureContextState(activity),
        expiresAt: new Date(Date.now() + 3600000).toISOString() // 1 hour
      };

      // Store in memory
      this.preservedStates.set(stateId, preservedState);

      // Save to disk
      await this.savePreservedState(preservedState);

      this.metrics.statePreservationUsage.totalPreservations++;

      logger.debug('Activity state preserved', {
        activity,
        stateId,
        dataSize: JSON.stringify(stateData).length
      });

      this.emit('state:preserved', { activity, stateId });

      return preservedState;

    } catch (error) {
      throw new StatePreservationError(activity, {
        originalError: (error as Error).message
      });
    }
  }

  /**
   * Restore activity state
   */
  private async restoreActivityState(activity: string, preservedState: PreservedState): Promise<void> {
    try {
      logger.debug('Restoring activity state', {
        activity,
        stateId: preservedState.id
      });

      // Restore UI elements
      await this.restoreUIElements(activity, preservedState.uiElements);

      // Restore data state
      await this.restoreDataState(activity, preservedState.data);

      // Restore navigation state if applicable
      await this.restoreNavigationState(preservedState.navigationState);

      logger.debug('Activity state restored successfully', {
        activity,
        stateId: preservedState.id
      });

    } catch (error) {
      throw new StatePreservationError(activity, {
        originalError: (error as Error).message,
        stateId: preservedState.id
      });
    }
  }

  /**
   * Find preserved state for activity
   */
  private findPreservedState(activity: string): PreservedState | undefined {
    // Find the most recent valid preserved state for the activity
    const validStates = Array.from(this.preservedStates.values())
      .filter(state =>
        state.activity === activity &&
        new Date(state.expiresAt) > new Date()
      )
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    return validStates[0];
  }

  // ============================================================================
  // Navigation Management
  // ============================================================================

  /**
   * Navigate to activity with transition tracking
   */
  async navigateToActivity(
    fromActivity: string,
    toActivity: string,
    action?: string,
    params?: Record<string, any>
  ): Promise<ActivityTransition> {
    const transitionId = `transition_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const transition: ActivityTransition = {
      id: transitionId,
      from: fromActivity,
      to: toActivity,
      type: this.determineTransitionType(fromActivity, toActivity),
      startTime: new Date().toISOString(),
      status: 'pending',
      data: params || {}
    };

    this.activeTransitions.set(transitionId, transition);

    try {
      logger.debug('Starting navigation transition', {
        transitionId,
        from: fromActivity,
        to: toActivity,
        action
      });

      transition.status = 'in_progress';

      // Find navigation pattern
      const fromConfig = this.config.activities[fromActivity];
      const navigationPattern = fromConfig?.navigationPatterns.find(
        pattern => pattern.to === toActivity && (!action || pattern.action === action)
      );

      if (!navigationPattern) {
        throw new ActivityResumeError(
          `No navigation pattern found from ${fromActivity} to ${toActivity}`,
          'NO_NAVIGATION_PATTERN',
          fromActivity
        );
      }

      // Execute navigation action
      await this.executeNavigationAction(navigationPattern);

      // Wait for transition
      await this.waitForActivityTransition(toActivity, navigationPattern.transitionTime);

      transition.completedTime = new Date().toISOString();
      transition.status = 'completed';

      logger.debug('Navigation transition completed', {
        transitionId,
        duration: new Date(transition.completedTime).getTime() - new Date(transition.startTime).getTime()
      });

      this.emit('navigation:completed', transition);

      return transition;

    } catch (error) {
      transition.status = 'failed';
      transition.data.error = (error as Error).message;

      logger.error('Navigation transition failed', {
        transitionId,
        error: (error as Error).message
      });

      this.emit('navigation:failed', { transition, error: (error as Error).message });
      throw error;
    } finally {
      this.activeTransitions.delete(transitionId);
    }
  }

  /**
   * Execute navigation action
   */
  private async executeNavigationAction(pattern: NavigationPattern): Promise<void> {
    switch (pattern.action) {
      case 'click':
        await this.adbBridge.performTap(
          pattern.params.x || 0,
          pattern.params.y || 0
        );
        break;

      case 'swipe':
        await this.adbBridge.performSwipe(
          pattern.params.startX || 0,
          pattern.params.startY || 0,
          pattern.params.endX || 0,
          pattern.params.endY || 0,
          pattern.params.duration || 300
        );
        break;

      case 'back':
        await this.adbBridge.performBack();
        break;

      case 'intent':
        await this.adbBridge.executeCommand([
          'shell', 'am', 'start',
          '-n', `${this.config.packageName}/${pattern.to}`,
          '-a', pattern.params.action || 'android.intent.action.MAIN'
        ], this.config.transitionTimeout);
        break;

      default:
        throw new ActivityResumeError(
          `Unknown navigation action: ${pattern.action}`,
          'UNKNOWN_NAVIGATION_ACTION'
        );
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  private async getAppState(): Promise<AppState> {
    try {
      const currentActivityResult = await this.adbBridge.executeCommand([
        'shell', 'dumpsys', 'activity', 'activities'
      ], this.config.launchTimeout);

      const isRunning = currentActivityResult.stdout.includes(this.config.packageName);
      const currentActivity = this.extractCurrentActivity(currentActivityResult.stdout);
      const activityState = this.determineActivityState(currentActivityResult.stdout);

      // Get process info
      let pid: number | undefined;
      if (isRunning) {
        const pidResult = await this.adbBridge.executeCommand([
          'shell', 'pidof', this.config.packageName
        ], this.config.launchTimeout);

        if (pidResult.exitCode === 0 && pidResult.stdout.trim()) {
          pid = parseInt(pidResult.stdout.trim());
        }
      }

      // Get memory usage
      let memoryUsage: number | undefined;
      if (pid) {
        const memoryResult = await this.adbBridge.executeCommand([
          'shell', 'cat', `/proc/${pid}/status`
        ], this.config.launchTimeout);

        const vmSizeMatch = memoryResult.stdout.match(/VmRSS:\s+(\d+)\s+kB/);
        if (vmSizeMatch) {
          memoryUsage = Math.round(parseInt(vmSizeMatch[1]) / 1024); // Convert to MB
        }
      }

      // Check network connectivity
      const networkResult = await this.adbBridge.executeCommand([
        'shell', 'ping', '-c', '1', '-W', '1', '8.8.8.8'
      ], this.config.launchTimeout);

      const networkConnected = networkResult.exitCode === 0;

      // Get device orientation
      const orientationResult = await this.adbBridge.executeCommand([
        'shell', 'dumpsys', 'input'
      ], this.config.launchTimeout);

      const orientationMatch = orientationResult.stdout.match(/SurfaceOrientation: (\d)/);
      const orientation = orientationMatch?.[1] === '1' ? 'landscape' : 'portrait';

      return {
        isRunning,
        currentActivity,
        activityState,
        pid,
        memoryUsage,
        networkConnected,
        orientation,
        lastActivityChange: new Date().toISOString()
      };

    } catch (error) {
      logger.error('Failed to get app state', {
        error: (error as Error).message
      });

      return {
        isRunning: false,
        activityState: 'destroyed',
        networkConnected: false,
        orientation: 'portrait'
      };
    }
  }

  private async getCurrentActivity(): Promise<string | undefined> {
    try {
      const result = await this.adbBridge.executeCommand([
        'shell', 'dumpsys', 'window', 'windows'
      ], this.config.launchTimeout);

      return this.extractCurrentActivity(result.stdout);

    } catch (error) {
      logger.warn('Failed to get current activity', {
        error: (error as Error).message
      });
      return undefined;
    }
  }

  private extractCurrentActivity(dumpsysOutput: string): string | undefined {
    const activityMatch = dumpsysOutput.match(/mResumedActivity:.*ActivityRecord{.*[^ ]+ ([^\/]+)\/([^ ]+)}/);
    return activityMatch ? `${activityMatch[1]}/${activityMatch[2]}` : undefined;
  }

  private determineActivityState(dumpsysOutput: string): AppState['activityState'] {
    if (dumpsysOutput.includes('mResumedActivity')) {
      return 'foreground';
    } else if (dumpsysOutput.includes('mPausedActivity')) {
      return 'background';
    } else if (dumpsysOutput.includes('mStoppedActivities')) {
      return 'stopped';
    } else {
      return 'destroyed';
    }
  }

  private async waitForActivity(activity: string, timeout: number): Promise<void> {
    const startTime = Date.now();
    const checkInterval = 500;

    while (Date.now() - startTime < timeout) {
      const currentActivity = await this.getCurrentActivity();
      if (currentActivity && currentActivity.includes(activity)) {
        return;
      }
      await this.sleep(checkInterval);
    }

    throw new ResumeTimeoutError(activity, 'launch', timeout);
  }

  private async waitForActivityTransition(activity: string, timeout: number): Promise<void> {
    const startTime = Date.now();
    const checkInterval = 500;

    while (Date.now() - startTime < timeout) {
      const currentActivity = await this.getCurrentActivity();
      if (currentActivity && currentActivity.includes(activity)) {
        return;
      }
      await this.sleep(checkInterval);
    }

    throw new ActivityResumeError(
      `Activity transition timeout waiting for ${activity}`,
      'TRANSITION_TIMEOUT',
      activity,
      'launch',
      { timeout }
    );
  }

  private async verifyActivityResumed(activity: string, config: ActivityConfig): Promise<void> {
    // Check that required elements are present
    for (const element of config.requiredElements) {
      // In a real implementation, you would check UI hierarchy for required elements
      logger.debug('Verifying required element', { activity, element });
    }

    // Verify context requirements
    for (const requirement of config.contextRequirements) {
      if (!await this.verifyContextRequirement(requirement)) {
        throw new ActivityResumeError(
          `Context requirement not met: ${requirement.name}`,
          'CONTEXT_REQUIREMENT_FAILED',
          activity
        );
      }
    }
  }

  private async verifyContextRequirement(requirement: ContextRequirement): Promise<boolean> {
    switch (requirement.type) {
      case 'network':
        const networkResult = await this.adbBridge.executeCommand([
          'shell', 'ping', '-c', '1', '8.8.8.8'
        ], this.config.launchTimeout);
        return networkResult.exitCode === 0;

      case 'location':
        // In a real implementation, check location services
        return true;

      case 'authentication':
        // In a real implementation, check authentication state
        return true;

      default:
        return true;
    }
  }

  private determineTransitionType(from: string, to: string): ActivityTransition['type'] {
    const fromConfig = this.config.activities[from];
    const toConfig = this.config.activities[to];

    if (!fromConfig || !toConfig) {
      return 'custom';
    }

    // Simple transition type logic
    if (fromConfig.type === 'login' && toConfig.type === 'main') {
      return 'forward';
    } else if (fromConfig.type === 'main' && toConfig.type === 'login') {
      return 'backward';
    } else {
      return 'lateral';
    }
  }

  private checkHandlerConditions(conditions: ResumeCondition[], context: ResumeContext): boolean {
    return conditions.every(condition => {
      switch (condition.type) {
        case 'activity':
          return condition.value === context.activity;

        case 'state':
          return condition.value === context.appState.activityState;

        default:
          return true;
      }
    });
  }

  private async extractActivityState(activity: string, config: ActivityConfig): Promise<Record<string, any>> {
    const state: Record<string, any> = {};

    // Extract state based on preservation rules
    for (const rule of config.statePreservation) {
      try {
        switch (rule.method) {
          case 'ui_state':
            // Extract UI state
            state[rule.element] = await this.extractUIState(rule.element);
            break;

          case 'shared_prefs':
            // Extract shared preferences
            state[rule.element] = await this.extractSharedPreferences(rule.element);
            break;

          default:
            logger.warn('Unknown preservation method', { method: rule.method });
        }
      } catch (error) {
        logger.warn('Failed to extract state element', {
          element: rule.element,
          error: (error as Error).message
        });
      }
    }

    return state;
  }

  private async extractUIState(element: string): Promise<any> {
    // In a real implementation, extract specific UI element state
    return { element, value: 'extracted_value' };
  }

  private async extractSharedPreferences(key: string): Promise<any> {
    // In a real implementation, extract shared preferences
    return { key, value: 'extracted_preference' };
  }

  private parseUIElements(uiHierarchy: string): Record<string, any> {
    // In a real implementation, parse UI hierarchy for element states
    return { parsed: true, elementCount: (uiHierarchy.match(/<[^>]+>/g) || []).length };
  }

  private async captureNavigationState(): Promise<NavigationState> {
    // In a real implementation, capture current navigation state
    return {
      stack: ['MainActivity'],
      currentIndex: 0,
      history: [],
      deepLink: undefined
    };
  }

  private async captureContextState(activity: string): Promise<Record<string, any>> {
    // In a real implementation, capture context-specific state
    return { activity, timestamp: new Date().toISOString() };
  }

  private async restoreUIElements(activity: string, uiElements: Record<string, any>): Promise<void> {
    // In a real implementation, restore UI elements to their previous state
    logger.debug('Restoring UI elements', { activity, elementCount: Object.keys(uiElements).length });
  }

  private async restoreDataState(activity: string, data: Record<string, any>): Promise<void> {
    // In a real implementation, restore data state
    logger.debug('Restoring data state', { activity, dataKeys: Object.keys(data) });
  }

  private async restoreNavigationState(navigationState: NavigationState): Promise<void> {
    // In a real implementation, restore navigation state
    logger.debug('Restoring navigation state', {
      stackSize: navigationState.stack.length,
      currentIndex: navigationState.currentIndex
    });
  }

  private async ensureStateStorageDirectory(): Promise<void> {
    try {
      const fs = require('fs').promises;
      await fs.mkdir(this.config.stateStorageDirectory, { recursive: true });
    } catch (error) {
      throw new ActivityResumeError(
        `Failed to create state storage directory: ${(error as Error).message}`,
        'STORAGE_DIRECTORY_ERROR'
      );
    }
  }

  private async loadPreservedStates(): Promise<void> {
    try {
      const fs = require('fs').promises;
      const files = await fs.readdir(this.config.stateStorageDirectory);

      for (const file of files) {
        if (file.endsWith('.json')) {
          try {
            const filePath = `${this.config.stateStorageDirectory}/${file}`;
            const content = await fs.readFile(filePath, 'utf8');
            const state: PreservedState = JSON.parse(content);

            // Check if state is still valid
            if (new Date(state.expiresAt) > new Date()) {
              this.preservedStates.set(state.id, state);
            } else {
              // Remove expired state
              await fs.unlink(filePath);
            }
          } catch (error) {
            logger.warn('Failed to load preserved state', { file });
          }
        }
      }

      logger.debug('Loaded preserved states', { count: this.preservedStates.size });

    } catch (error) {
      logger.warn('Failed to load preserved states', {
        error: (error as Error).message
      });
    }
  }

  private async savePreservedState(state: PreservedState): Promise<void> {
    try {
      const fs = require('fs').promises;
      const filePath = `${this.config.stateStorageDirectory}/${state.id}.json`;
      await fs.writeFile(filePath, JSON.stringify(state, null, 2));
    } catch (error) {
      logger.warn('Failed to save preserved state', {
        stateId: state.id,
        error: (error as Error).message
      });
    }
  }

  private recordActivityResume(activity: string): void {
    const existingActivity = this.metrics.commonActivities.find(a => a.activity === activity);
    if (existingActivity) {
      existingActivity.count++;
    } else {
      this.metrics.commonActivities.push({
        activity,
        count: 1,
        percentage: 0
      });
    }

    // Update percentages
    const totalResumes = this.metrics.commonActivities.reduce((sum, a) => sum + a.count, 0);
    this.metrics.commonActivities.forEach(a => {
      a.percentage = (a.count / totalResumes) * 100;
    });
  }

  private recordStrategySuccess(strategy: ResumeStrategy): void {
    const existingStrategy = this.metrics.successfulStrategies.find(s => s.strategy === strategy);
    if (existingStrategy) {
      existingStrategy.count++;
      existingStrategy.successRate = (existingStrategy.count / this.metrics.totalResumes) * 100;
    } else {
      this.metrics.successfulStrategies.push({
        strategy,
        count: 1,
        successRate: (1 / this.metrics.totalResumes) * 100
      });
    }
  }

  private updateAverageResumeTime(duration: number): void {
    const totalTime = this.metrics.averageResumeTime * (this.metrics.successfulResumes - 1) + duration;
    this.metrics.averageResumeTime = Math.round(totalTime / this.metrics.successfulResumes);
  }

  private updateAverageRestorationTime(duration: number): void {
    const totalTime = this.metrics.statePreservationUsage.averageRestorationTime *
      (this.metrics.statePreservationUsage.successfulRestorations - 1) + duration;
    this.metrics.statePreservationUsage.averageRestorationTime =
      Math.round(totalTime / this.metrics.statePreservationUsage.successfulRestorations);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ============================================================================
  // Public API Methods
  // ============================================================================

  /**
   * Get resume metrics
   */
  getResumeMetrics(): ActivityResumeMetrics {
    return { ...this.metrics };
  }

  /**
   * Get current activity
   */
  async getCurrentActivitySafe(): Promise<string | undefined> {
    return this.getCurrentActivity();
  }

  /**
   * Get app state
   */
  async getAppStateSafe(): Promise<AppState> {
    return this.getAppState();
  }

  /**
   * List preserved states
   */
  listPreservedStates(): PreservedState[] {
    return Array.from(this.preservedStates.values())
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  /**
   * Clear preserved states
   */
  async clearPreservedStates(activity?: string): Promise<void> {
    const statesToRemove = activity
      ? Array.from(this.preservedStates.values()).filter(s => s.activity === activity)
      : Array.from(this.preservedStates.values());

    for (const state of statesToRemove) {
      this.preservedStates.delete(state.id);

      try {
        const fs = require('fs').promises;
        const filePath = `${this.config.stateStorageDirectory}/${state.id}.json`;
        await fs.unlink(filePath);
      } catch (error) {
        logger.warn('Failed to delete preserved state file', {
          stateId: state.id,
          error: (error as Error).message
        });
      }
    }

    logger.info('Cleared preserved states', {
      activity,
      count: statesToRemove.length
    });
  }

  /**
   * Close activity resume service and cleanup resources
   */
  async close(): Promise<void> {
    logger.info('Closing Activity Resume Service', {
      packageName: this.config.packageName,
      totalResumes: this.metrics.totalResumes,
      successRate: this.metrics.successfulResumes / this.metrics.totalResumes * 100
    });

    // Clear active transitions
    this.activeTransitions.clear();

    // Save preserved states
    for (const state of this.preservedStates.values()) {
      await this.savePreservedState(state);
    }

    this.removeAllListeners();
    this.isInitialized = false;

    logger.info('Activity Resume Service closed');
  }
}

// ============================================================================
// Service Factory
// ============================================================================

let activityResumeInstance: ActivityResumeService | null = null;

/**
 * Get singleton Activity Resume service instance
 */
export function getActivityResumeService(config?: Partial<ActivityResumeConfig>): ActivityResumeService {
  if (!activityResumeInstance) {
    activityResumeInstance = new ActivityResumeService(config);
  }
  return activityResumeInstance;
}

/**
 * Initialize Activity Resume service
 */
export async function initializeActivityResume(config?: Partial<ActivityResumeConfig>): Promise<ActivityResumeService> {
  const service = getActivityResumeService(config);
  await service.initialize();
  return service;
}

/**
 * Close Activity Resume service
 */
export async function closeActivityResume(): Promise<void> {
  if (activityResumeInstance) {
    await activityResumeInstance.close();
    activityResumeInstance = null;
  }
}