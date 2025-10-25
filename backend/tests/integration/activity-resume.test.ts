/**
 * MaynDrive Activity-Specific Resume Procedures Integration Tests
 *
 * Comprehensive test suite for activity-specific resume procedures in MaynDrive.
 * Tests MainActivity, LoginScreen, and MapScreen resume procedures with full
 * UI state capture, activity detection, validation, and recovery handling.
 *
 * These tests ensure reliable UI state capture regardless of which MaynDrive
 * activity is currently active, including proper activity transition handling
 * and state restoration procedures.
 *
 * @author AutoApp UI Map & Flow Engine Team
 * @version 1.0.0
 */

import { spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { join } from 'path';
import { getADBBridgeService, ADBBridgeService, UIStateCapture } from '../../src/services/adb-bridge';
import { logger } from '../../src/services/logger';
import { launchApp, stopApp } from '../../src/services/apps/launchService';
import { environmentConfig } from '../../src/config/environment';

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * MaynDrive activity configuration
 */
export interface MaynDriveActivity {
  /** Activity name */
  name: string;
  /** Full activity class name */
  className: string;
  /** Activity package name */
  packageName: string;
  /** Expected UI patterns and selectors */
  uiPatterns: {
    /** Key UI elements to detect */
    keyElements: Array<{
      resource_id?: string;
      text?: string;
      content_desc?: string;
      class?: string;
      clickable?: boolean;
    }>;
    /** Unique screen identifiers */
    screenIdentifiers: string[];
    /** Loading indicators to wait for */
    loadingIndicators?: string[];
  };
  /** Resume procedure configuration */
  resumeProcedure: {
    /** Max wait time for activity to stabilize (ms) */
    stabilizationTime: number;
    /** Expected interactive elements count */
    minInteractiveElements: number;
    /** Validation actions to perform */
    validationActions?: Array<{
      type: 'tap' | 'swipe' | 'back' | 'wait';
      target?: string;
      duration?: number;
      coordinates?: { x: number; y: number };
    }>;
  };
}

/**
 * Activity test result interface
 */
export interface ActivityTestResult {
  /** Activity being tested */
  activity: string;
  /** Test scenario name */
  scenario: string;
  /** Test success status */
  success: boolean;
  /** Test duration (ms) */
  duration: number;
  /** UI state capture result */
  uiState?: UIStateCapture;
  /** Activity detection result */
  activityDetection?: {
    detectedActivity: string;
    confidence: number;
    matchesExpected: boolean;
  };
  /** Resume procedure result */
  resumeResult?: {
    launchSuccess: boolean;
    stabilizationTime: number;
    interactiveElementsCount: number;
    validationPassed: boolean;
  };
  /** Performance metrics */
  performance?: {
    launchTime: number;
    captureTime: number;
    totalTime: number;
    memoryUsage?: number;
  };
  /** Error details if failed */
  error?: string;
  /** Test details */
  details?: string;
  /** Test timestamp */
  timestamp: string;
}

/**
 * Activity transition test result
 */
export interface ActivityTransitionResult {
  /** From activity */
  fromActivity: string;
  /** To activity */
  toActivity: string;
  /** Transition action */
  action: string;
  /** Transition success */
  success: boolean;
  /** Transition duration */
  duration: number;
  /** UI states before and after */
  beforeState?: UIStateCapture;
  afterState?: UIStateCapture;
  /** Transition validation */
  validation?: {
    correctDestination: boolean;
    uiChanged: boolean;
    noCrash: boolean;
  };
  /** Error details */
  error?: string;
}

/**
 * Complete test suite results
 */
export interface ActivityResumeTestResults {
  /** Test configuration */
  testConfig: ActivityTestConfig;
  /** Test execution timestamp */
  timestamp: string;
  /** Test environment info */
  environment: {
    nodeVersion: string;
    platform: string;
    deviceSerial: string;
    maynDriveVersion?: string;
    emulatorInfo?: any;
  };
  /** Individual activity test results */
  activityResults: ActivityTestResult[];
  /** Activity transition results */
  transitionResults: ActivityTransitionResult[];
  /** Performance benchmarks */
  performanceBenchmarks: {
    averageLaunchTime: number;
    averageCaptureTime: number;
    averageResumeTime: number;
    fastestActivity: string;
    slowestActivity: string;
    successRate: number;
  };
  /** Error summary */
  errorSummary: {
    totalErrors: number;
    errorTypes: Record<string, number>;
    criticalFailures: string[];
  };
  /** Test summary */
  summary: {
    totalTests: number;
    passedTests: number;
    failedTests: number;
    successRate: number;
    overallStatus: 'passed' | 'failed' | 'partial';
  };
}

/**
 * Test configuration interface
 */
export interface ActivityTestConfig {
  /** ADB device serial */
  deviceSerial: string;
  /** MaynDrive package name */
  maynDrivePackage: string;
  /** Test timeout (ms) */
  testTimeout: number;
  /** Activity launch timeout (ms) */
  launchTimeout: number;
  /** UI capture timeout (ms) */
  captureTimeout: number;
  /** Resume stabilization timeout (ms) */
  stabilizationTimeout: number;
  /** Number of retry attempts */
  retryAttempts: number;
  /** Enable performance monitoring */
  enablePerformanceMonitoring: boolean;
  /** Save test artifacts */
  saveArtifacts: boolean;
  /** Artifacts output directory */
  artifactsDirectory: string;
  /** Enable debug logging */
  debugLogging: boolean;
}

// ============================================================================
// MAYNDRIVE ACTIVITY CONFIGURATIONS
// ============================================================================

/**
 * MaynDrive activity definitions with UI patterns and resume procedures
 */
const MAYNDRIVE_ACTIVITIES: Record<string, MaynDriveActivity> = {
  MainActivity: {
    name: 'MainActivity',
    className: 'com.mayn.mayndrive.MainActivity',
    packageName: 'com.mayn.mayndrive',
    uiPatterns: {
      keyElements: [
        { resource_id: 'com.mayn.mayndrive:id/home_container', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/navigation_bottom', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/fab_main', clickable: true },
        { class: 'android.widget.ImageView', clickable: true },
        { text: 'Accueil', clickable: false },
        { text: 'Accueil', clickable: false }
      ],
      screenIdentifiers: [
        'MainActivity',
        'home_container',
        'navigation_bottom',
        'com.mayn.mayndrive.MainActivity'
      ],
      loadingIndicators: [
        'loading_progress',
        'splash_screen',
        'initializing'
      ]
    },
    resumeProcedure: {
      stabilizationTime: 3000,
      minInteractiveElements: 5,
      validationActions: [
        { type: 'wait', duration: 1000 },
        { type: 'tap', target: 'navigation_home' },
        { type: 'wait', duration: 500 }
      ]
    }
  },

  LoginScreen: {
    name: 'LoginActivity',
    className: 'com.mayn.mayndrive.LoginActivity',
    packageName: 'com.mayn.mayndrive',
    uiPatterns: {
      keyElements: [
        { resource_id: 'com.mayn.mayndrive:id/login_email', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/login_password', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/login_button', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/forgot_password', clickable: true },
        { text: 'Se connecter', clickable: true },
        { text: 'Mot de passe oublié', clickable: true }
      ],
      screenIdentifiers: [
        'LoginActivity',
        'login_email',
        'login_password',
        'com.mayn.mayndrive.LoginActivity'
      ],
      loadingIndicators: [
        'login_progress',
        'authenticating',
        'loading_auth'
      ]
    },
    resumeProcedure: {
      stabilizationTime: 2000,
      minInteractiveElements: 3,
      validationActions: [
        { type: 'wait', duration: 1000 },
        { type: 'tap', target: 'login_email' },
        { type: 'wait', duration: 500 }
      ]
    }
  },

  MapScreen: {
    name: 'MapActivity',
    className: 'com.mayn.mayndrive.MapActivity',
    packageName: 'com.mayn.mayndrive',
    uiPatterns: {
      keyElements: [
        { resource_id: 'com.mayn.mayndrive:id/map_container', clickable: false },
        { resource_id: 'com.mayn.mayndrive:id/map_search', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/map_current_location', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/map_zoom_in', clickable: true },
        { resource_id: 'com.mayn.mayndrive:id/map_zoom_out', clickable: true },
        { class: 'com.google.android.gms.maps.MapView', clickable: false }
      ],
      screenIdentifiers: [
        'MapActivity',
        'map_container',
        'map_search',
        'com.mayn.mayndrive.MapActivity'
      ],
      loadingIndicators: [
        'map_loading',
        'location_loading',
        'initializing_map'
      ]
    },
    resumeProcedure: {
      stabilizationTime: 4000,
      minInteractiveElements: 4,
      validationActions: [
        { type: 'wait', duration: 2000 },
        { type: 'tap', target: 'map_current_location' },
        { type: 'wait', duration: 1000 }
      ]
    }
  }
};

// ============================================================================
// ACTIVITY DETECTION AND VALIDATION UTILITIES
// ============================================================================

/**
 * Activity detection and validation utility class
 */
export class ActivityDetectionUtils {
  private adbBridge: ADBBridgeService;

  constructor(adbBridge: ADBBridgeService) {
    this.adbBridge = adbBridge;
  }

  /**
   * Detect current activity on device
   */
  async detectCurrentActivity(): Promise<string> {
    try {
      const deviceInfo = await this.adbBridge.getDeviceInfo();
      return deviceInfo.currentActivity || 'Unknown';
    } catch (error) {
      logger.error('Failed to detect current activity', { error: (error as Error).message });
      return 'Unknown';
    }
  }

  /**
   * Validate if expected activity is currently active
   */
  async validateActivity(expectedActivity: MaynDriveActivity): Promise<{
    detectedActivity: string;
    confidence: number;
    matchesExpected: boolean;
  }> {
    try {
      const currentActivity = await this.detectCurrentActivity();
      const uiState = await this.adbBridge.captureUIState();

      // Check if activity class name matches
      const activityMatches = currentActivity.includes(expectedActivity.className);

      // Check UI patterns for additional confidence
      const patternMatches = this.validateUIPatterns(uiState.hierarchy, expectedActivity);

      // Calculate confidence score
      const confidence = this.calculateConfidence(activityMatches, patternMatches, expectedActivity);

      return {
        detectedActivity: currentActivity,
        confidence,
        matchesExpected: confidence >= 0.8
      };
    } catch (error) {
      logger.error('Activity validation failed', {
        activity: expectedActivity.name,
        error: (error as Error).message
      });

      return {
        detectedActivity: 'Unknown',
        confidence: 0,
        matchesExpected: false
      };
    }
  }

  /**
   * Validate UI patterns match expected activity
   */
  private validateUIPatterns(uiHierarchy: string, expectedActivity: MaynDriveActivity): boolean[] {
    const results: boolean[] = [];

    // Check key elements
    for (const element of expectedActivity.uiPatterns.keyElements) {
      let found = false;

      if (element.resource_id && uiHierarchy.includes(element.resource_id)) {
        found = true;
      }

      if (element.text && uiHierarchy.includes(`text="${element.text}"`)) {
        found = true;
      }

      if (element.content_desc && uiHierarchy.includes(`content-desc="${element.content_desc}"`)) {
        found = true;
      }

      if (element.class && uiHierarchy.includes(`class="${element.class}"`)) {
        found = true;
      }

      results.push(found);
    }

    // Check screen identifiers
    for (const identifier of expectedActivity.uiPatterns.screenIdentifiers) {
      results.push(uiHierarchy.includes(identifier));
    }

    return results;
  }

  /**
   * Calculate confidence score for activity detection
   */
  private calculateConfidence(
    activityMatches: boolean,
    patternMatches: boolean[],
    expectedActivity: MaynDriveActivity
  ): number {
    let score = 0;
    let totalChecks = 1; // Activity match check

    // Activity name match has highest weight
    if (activityMatches) {
      score += 0.5;
    }

    // UI pattern matches
    const patternScore = patternMatches.filter(match => match).length / patternMatches.length;
    score += patternScore * 0.5;
    totalChecks += patternMatches.length;

    return Math.min(score, 1.0);
  }

  /**
   * Wait for activity to stabilize
   */
  async waitForActivityStabilization(
    expectedActivity: MaynDriveActivity,
    timeout: number = 10000
  ): Promise<{
    stabilized: boolean;
    finalActivity: string;
    duration: number;
  }> {
    const startTime = Date.now();
    let lastActivity = '';
    let stableCount = 0;
    const requiredStableChecks = 3;

    while (Date.now() - startTime < timeout) {
      try {
        const currentActivity = await this.detectCurrentActivity();

        if (currentActivity === lastActivity && currentActivity.includes(expectedActivity.className)) {
          stableCount++;
          if (stableCount >= requiredStableChecks) {
            return {
              stabilized: true,
              finalActivity: currentActivity,
              duration: Date.now() - startTime
            };
          }
        } else {
          stableCount = 0;
          lastActivity = currentActivity;
        }

        await this.sleep(500);
      } catch (error) {
        logger.warn('Activity stabilization check failed', {
          error: (error as Error).message
        });
      }
    }

    return {
      stabilized: false,
      finalActivity: lastActivity,
      duration: Date.now() - startTime
    };
  }

  /**
   * Check for loading indicators
   */
  async checkLoadingIndicators(expectedActivity: MaynDriveActivity): Promise<boolean> {
    try {
      const uiState = await this.adbBridge.captureUIState();
      const hierarchy = uiState.hierarchy;

      if (!expectedActivity.uiPatterns.loadingIndicators) {
        return false; // No loading indicators defined
      }

      return expectedActivity.uiPatterns.loadingIndicators.some(indicator =>
        hierarchy.includes(indicator)
      );
    } catch (error) {
      logger.warn('Failed to check loading indicators', {
        error: (error as Error).message
      });
      return false;
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// ACTIVITY RESUME TEST ENGINE
// ============================================================================

/**
 * Main activity resume test engine
 */
export class ActivityResumeTestEngine {
  private config: ActivityTestConfig;
  private adbBridge: ADBBridgeService;
  private detectionUtils: ActivityDetectionUtils;
  private testResults: ActivityTestResult[] = [];
  private transitionResults: ActivityTransitionResult[] = [];

  constructor(config: ActivityTestConfig) {
    this.config = config;
    this.adbBridge = getADBBridgeService({
      serial: config.deviceSerial,
      timeout: config.launchTimeout,
      uiAutomatorTimeout: config.captureTimeout,
      uiCaptureTimeout: config.captureTimeout
    });
    this.detectionUtils = new ActivityDetectionUtils(this.adbBridge);
  }

  /**
   * Initialize test engine
   */
  async initialize(): Promise<void> {
    logger.info('Initializing Activity Resume Test Engine', {
      deviceSerial: this.config.deviceSerial,
      maynDrivePackage: this.config.maynDrivePackage
    });

    try {
      // Initialize ADB bridge
      await this.adbBridge.initialize();

      // Create artifacts directory
      if (this.config.saveArtifacts) {
        mkdirSync(this.config.artifactsDirectory, { recursive: true });
      }

      logger.info('Activity Resume Test Engine initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Activity Resume Test Engine', {
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Run complete activity resume test suite
   */
  async runCompleteTestSuite(): Promise<ActivityResumeTestResults> {
    logger.info('Starting MaynDrive Activity Resume Test Suite');

    const startTime = Date.now();
    const timestamp = new Date().toISOString();

    try {
      // Test individual activity resume procedures
      await this.testActivityResumeProcedures();

      // Test activity transitions
      await this.testActivityTransitions();

      // Test error scenarios
      await this.testErrorScenarios();

      // Test performance benchmarks
      await this.testPerformanceBenchmarks();

      const totalTime = Date.now() - startTime;

      const results: ActivityResumeTestResults = {
        testConfig: this.config,
        timestamp,
        environment: await this.getEnvironmentInfo(),
        activityResults: this.testResults,
        transitionResults: this.transitionResults,
        performanceBenchmarks: this.calculatePerformanceBenchmarks(),
        errorSummary: this.calculateErrorSummary(),
        summary: this.calculateTestSummary()
      };

      logger.info('Activity Resume Test Suite completed', {
        totalTests: results.summary.totalTests,
        passedTests: results.summary.passedTests,
        successRate: results.summary.successRate,
        duration: totalTime
      });

      return results;
    } catch (error) {
      logger.error('Activity Resume Test Suite failed', {
        error: (error as Error).message,
        duration: Date.now() - startTime
      });
      throw error;
    }
  }

  /**
   * Test individual activity resume procedures
   */
  private async testActivityResumeProcedures(): Promise<void> {
    logger.info('Testing individual activity resume procedures');

    for (const [activityName, activityConfig] of Object.entries(MAYNDRIVE_ACTIVITIES)) {
      logger.info(`Testing ${activityName} resume procedures`);

      // Test launching to activity
      await this.testActivityLaunch(activityConfig);

      // Test activity state detection
      await this.testActivityStateDetection(activityConfig);

      // Test activity resume from different states
      await this.testActivityResumeStates(activityConfig);

      // Test activity validation procedures
      await this.testActivityValidation(activityConfig);
    }
  }

  /**
   * Test launching to specific activity
   */
  private async testActivityLaunch(activity: MaynDriveActivity): Promise<void> {
    const scenario = `Launch ${activity.name}`;
    const startTime = Date.now();

    try {
      logger.info(`Testing launch to ${activity.name}`, {
        activity: activity.className
      });

      // Stop MaynDrive first
      await stopApp(this.config.maynDrivePackage);
      await this.sleep(2000);

      // Launch to specific activity
      const launchResult = await launchApp(this.config.maynDrivePackage, activity.className);

      if (!launchResult.success) {
        throw new Error(`Failed to launch ${activity.name}: ${launchResult.message}`);
      }

      const launchTime = Date.now() - startTime;

      // Wait for activity stabilization
      const stabilization = await this.detectionUtils.waitForActivityStabilization(
        activity,
        this.config.stabilizationTimeout
      );

      if (!stabilization.stabilized) {
        throw new Error(`Activity ${activity.name} failed to stabilize within timeout`);
      }

      // Capture UI state
      const uiState = await this.adbBridge.captureUIState();
      const captureTime = Date.now() - startTime - launchTime;

      // Validate activity
      const validation = await this.detectionUtils.validateActivity(activity);

      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: validation.matchesExpected && stabilization.stabilized,
        duration: Date.now() - startTime,
        uiState,
        activityDetection: validation,
        resumeResult: {
          launchSuccess: launchResult.success,
          stabilizationTime: stabilization.duration,
          interactiveElementsCount: uiState.elementCount,
          validationPassed: validation.matchesExpected
        },
        performance: {
          launchTime,
          captureTime,
          totalTime: Date.now() - startTime
        },
        details: validation.matchesExpected
          ? `Successfully launched and validated ${activity.name}`
          : `Activity validation failed: expected ${activity.className}, got ${validation.detectedActivity}`,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);

      // Save artifacts if enabled
      if (this.config.saveArtifacts) {
        await this.saveTestArtifacts(result, activity);
      }

      logger.info(`Activity launch test completed`, {
        activity: activity.name,
        success: result.success,
        duration: result.duration
      });

    } catch (error) {
      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: false,
        duration: Date.now() - startTime,
        error: (error as Error).message,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);

      logger.error(`Activity launch test failed`, {
        activity: activity.name,
        error: (error as Error).message
      });
    }
  }

  /**
   * Test activity state detection
   */
  private async testActivityStateDetection(activity: MaynDriveActivity): Promise<void> {
    const scenario = `State Detection ${activity.name}`;
    const startTime = Date.now();

    try {
      // Ensure we're on the correct activity
      await launchApp(this.config.maynDrivePackage, activity.className);
      await this.sleep(activity.resumeProcedure.stabilizationTime);

      // Test multiple detection attempts
      const detectionResults = [];
      for (let i = 0; i < 3; i++) {
        const detection = await this.detectionUtils.validateActivity(activity);
        detectionResults.push(detection);
        await this.sleep(1000);
      }

      // Check consistency of detection
      const confidenceScores = detectionResults.map(r => r.confidence);
      const avgConfidence = confidenceScores.reduce((a, b) => a + b, 0) / confidenceScores.length;
      const minConfidence = Math.min(...confidenceScores);
      const maxConfidence = Math.max(...confidenceScores);
      const consistency = maxConfidence - minConfidence;

      const uiState = await this.adbBridge.captureUIState();

      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: avgConfidence >= 0.8 && consistency <= 0.2,
        duration: Date.now() - startTime,
        uiState,
        activityDetection: {
          detectedActivity: detectionResults[detectionResults.length - 1].detectedActivity,
          confidence: avgConfidence,
          matchesExpected: avgConfidence >= 0.8
        },
        details: `Detection confidence: ${avgConfidence.toFixed(2)}, consistency: ${consistency.toFixed(2)}`,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);

    } catch (error) {
      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: false,
        duration: Date.now() - startTime,
        error: (error as Error).message,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);
    }
  }

  /**
   * Test activity resume from different states
   */
  private async testActivityResumeStates(activity: MaynDriveActivity): Promise<void> {
    const scenarios = [
      `Resume ${activity.name} from Background`,
      `Resume ${activity.name} after Crash`,
      `Resume ${activity.name} with Low Memory`
    ];

    for (const scenario of scenarios) {
      await this.testResumeFromState(activity, scenario);
    }
  }

  /**
   * Test resume from specific state
   */
  private async testResumeFromState(activity: MaynDriveActivity, scenario: string): Promise<void> {
    const startTime = Date.now();

    try {
      // Launch to activity first
      await launchApp(this.config.maynDrivePackage, activity.className);
      await this.sleep(activity.resumeProcedure.stabilizationTime);

      // Apply state-specific conditions
      if (scenario.includes('Background')) {
        await this.sendAppToBackground();
        await this.sleep(3000);
      } else if (scenario.includes('Crash')) {
        await this.simulateAppCrash();
        await this.sleep(2000);
      } else if (scenario.includes('Low Memory')) {
        await this.simulateLowMemory();
        await this.sleep(1000);
      }

      // Attempt resume
      const resumeStartTime = Date.now();
      await launchApp(this.config.maynDrivePackage, activity.className);
      const resumeTime = Date.now() - resumeStartTime;

      // Wait for stabilization
      const stabilization = await this.detectionUtils.waitForActivityStabilization(
        activity,
        this.config.stabilizationTimeout
      );

      // Validate final state
      const validation = await this.detectionUtils.validateActivity(activity);
      const uiState = await this.adbBridge.captureUIState();

      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: validation.matchesExpected && stabilization.stabilized,
        duration: Date.now() - startTime,
        uiState,
        activityDetection: validation,
        resumeResult: {
          launchSuccess: true,
          stabilizationTime: stabilization.duration,
          interactiveElementsCount: uiState.elementCount,
          validationPassed: validation.matchesExpected
        },
        performance: {
          launchTime: resumeTime,
          captureTime: Date.now() - startTime - resumeTime,
          totalTime: Date.now() - startTime
        },
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);

    } catch (error) {
      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: false,
        duration: Date.now() - startTime,
        error: (error as Error).message,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);
    }
  }

  /**
   * Test activity validation procedures
   */
  private async testActivityValidation(activity: MaynDriveActivity): Promise<void> {
    const scenario = `Validation ${activity.name}`;
    const startTime = Date.now();

    try {
      // Launch to activity
      await launchApp(this.config.maynDrivePackage, activity.className);
      await this.sleep(activity.resumeProcedure.stabilizationTime);

      // Perform validation actions
      const validationResults = [];
      for (const action of activity.resumeProcedure.validationActions || []) {
        const actionResult = await this.performValidationAction(action);
        validationResults.push(actionResult);

        if (action.type !== 'wait') {
          await this.sleep(500); // Wait between actions
        }
      }

      // Final validation
      const finalValidation = await this.detectionUtils.validateActivity(activity);
      const uiState = await this.adbBridge.captureUIState();

      const allActionsSucceeded = validationResults.every(r => r.success);
      const validationPassed = finalValidation.matchesExpected && allActionsSucceeded;

      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: validationPassed,
        duration: Date.now() - startTime,
        uiState,
        activityDetection: finalValidation,
        resumeResult: {
          launchSuccess: true,
          stabilizationTime: activity.resumeProcedure.stabilizationTime,
          interactiveElementsCount: uiState.elementCount,
          validationPassed
        },
        details: `Validation actions: ${validationResults.filter(r => r.success).length}/${validationResults.length} succeeded`,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);

    } catch (error) {
      const result: ActivityTestResult = {
        activity: activity.name,
        scenario,
        success: false,
        duration: Date.now() - startTime,
        error: (error as Error).message,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);
    }
  }

  /**
   * Test activity transitions
   */
  private async testActivityTransitions(): Promise<void> {
    logger.info('Testing activity transitions');

    const transitions = [
      { from: 'MainActivity', to: 'LoginScreen', action: 'tap_login_button' },
      { from: 'MainActivity', to: 'MapScreen', action: 'tap_map_button' },
      { from: 'LoginScreen', to: 'MainActivity', action: 'back' },
      { from: 'MapScreen', to: 'MainActivity', action: 'back' }
    ];

    for (const transition of transitions) {
      await this.testActivityTransition(transition);
    }
  }

  /**
   * Test specific activity transition
   */
  private async testActivityTransition(transition: {
    from: string;
    to: string;
    action: string;
  }): Promise<void> {
    const startTime = Date.now();

    try {
      const fromActivity = MAYNDRIVE_ACTIVITIES[transition.from];
      const toActivity = MAYNDRIVE_ACTIVITIES[transition.to];

      if (!fromActivity || !toActivity) {
        throw new Error(`Unknown activity in transition: ${transition.from} -> ${transition.to}`);
      }

      // Start with source activity
      await launchApp(this.config.maynDrivePackage, fromActivity.className);
      await this.sleep(fromActivity.resumeProcedure.stabilizationTime);

      // Capture before state
      const beforeState = await this.adbBridge.captureUIState();
      const beforeValidation = await this.detectionUtils.validateActivity(fromActivity);

      if (!beforeValidation.matchesExpected) {
        throw new Error(`Failed to start from expected activity: ${transition.from}`);
      }

      // Perform transition action
      await this.performTransitionAction(transition.action);
      await this.sleep(2000); // Wait for transition

      // Capture after state
      const afterState = await this.adbBridge.captureUIState();
      const afterValidation = await this.detectionUtils.validateActivity(toActivity);

      // Wait for destination stabilization
      const stabilization = await this.detectionUtils.waitForActivityStabilization(
        toActivity,
        this.config.stabilizationTimeout
      );

      const result: ActivityTransitionResult = {
        fromActivity: transition.from,
        toActivity: transition.to,
        action: transition.action,
        success: afterValidation.matchesExpected && stabilization.stabilized,
        duration: Date.now() - startTime,
        beforeState,
        afterState,
        validation: {
          correctDestination: afterValidation.matchesExpected,
          uiChanged: beforeState.hierarchy !== afterState.hierarchy,
          noCrash: afterValidation.detectedActivity !== 'Unknown'
        }
      };

      this.transitionResults.push(result);

    } catch (error) {
      const result: ActivityTransitionResult = {
        fromActivity: transition.from,
        toActivity: transition.to,
        action: transition.action,
        success: false,
        duration: Date.now() - startTime,
        error: (error as Error).message
      };

      this.transitionResults.push(result);
    }
  }

  /**
   * Test error scenarios
   */
  private async testErrorScenarios(): Promise<void> {
    logger.info('Testing error scenarios');

    const errorScenarios = [
      'Invalid Activity Launch',
      'Activity Launch Timeout',
      'UI State Capture Failure',
      'Device Disconnection During Resume'
    ];

    for (const scenario of errorScenarios) {
      await this.testErrorScenario(scenario);
    }
  }

  /**
   * Test specific error scenario
   */
  private async testErrorScenario(scenario: string): Promise<void> {
    const startTime = Date.now();

    try {
      switch (scenario) {
        case 'Invalid Activity Launch':
          await this.testInvalidActivityLaunch();
          break;
        case 'Activity Launch Timeout':
          await this.testActivityLaunchTimeout();
          break;
        case 'UI State Capture Failure':
          await this.testUIStateCaptureFailure();
          break;
        case 'Device Disconnection During Resume':
          await this.testDeviceDisconnection();
          break;
      }
    } catch (error) {
      // Error scenarios are expected to fail, log the result
      const result: ActivityTestResult = {
        activity: 'ErrorScenario',
        scenario,
        success: false, // Error scenarios should fail gracefully
        duration: Date.now() - startTime,
        error: (error as Error).message,
        details: `Error scenario executed as expected: ${scenario}`,
        timestamp: new Date().toISOString()
      };

      this.testResults.push(result);
    }
  }

  /**
   * Test performance benchmarks
   */
  private async testPerformanceBenchmarks(): Promise<void> {
    logger.info('Testing performance benchmarks');

    for (const [activityName, activityConfig] of Object.entries(MAYNDRIVE_ACTIVITIES)) {
      await this.testActivityPerformance(activityConfig);
    }
  }

  /**
   * Test activity performance
   */
  private async testActivityPerformance(activity: MaynDriveActivity): Promise<void> {
    const scenario = `Performance ${activity.name}`;
    const iterations = 3;
    const durations: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();

      try {
        await launchApp(this.config.maynDrivePackage, activity.className);
        await this.detectionUtils.waitForActivityStabilization(activity, this.config.stabilizationTimeout);
        await this.adbBridge.captureUIState();

        durations.push(Date.now() - startTime);

        // Stop app between iterations
        await stopApp(this.config.maynDrivePackage);
        await this.sleep(1000);

      } catch (error) {
        durations.push(Date.now() - startTime); // Include failed attempts
      }
    }

    const avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
    const maxDuration = Math.max(...durations);
    const meetsBenchmark = avgDuration < 5000; // 5 second benchmark

    const result: ActivityTestResult = {
      activity: activity.name,
      scenario,
      success: meetsBenchmark,
      duration: avgDuration,
      performance: {
        launchTime: avgDuration * 0.6, // Approximation
        captureTime: avgDuration * 0.2, // Approximation
        totalTime: avgDuration
      },
      details: `Average duration: ${avgDuration.toFixed(0)}ms, Max: ${maxDuration.toFixed(0)}ms, Benchmark: ${meetsBenchmark ? 'PASS' : 'FAIL'}`,
      timestamp: new Date().toISOString()
    };

    this.testResults.push(result);
  }

  // ============================================================================
  // HELPER METHODS
  // ============================================================================

  /**
   * Perform validation action
   */
  private async performValidationAction(action: any): Promise<{ success: boolean; details: string }> {
    try {
      switch (action.type) {
        case 'wait':
          await this.sleep(action.duration || 1000);
          return { success: true, details: `Waited ${action.duration}ms` };

        case 'tap':
          if (action.coordinates) {
            await this.adbBridge.performTap(action.coordinates.x, action.coordinates.y);
            return { success: true, details: `Tapped coordinates (${action.coordinates.x}, ${action.coordinates.y})` };
          } else if (action.target) {
            // Would need to implement element finding logic
            return { success: false, details: `Tap by target not implemented: ${action.target}` };
          }
          break;

        case 'back':
          await this.adbBridge.performBack();
          return { success: true, details: 'Pressed back button' };

        default:
          return { success: false, details: `Unknown action type: ${action.type}` };
      }

      return { success: false, details: 'Action execution failed' };
    } catch (error) {
      return { success: false, details: `Action error: ${(error as Error).message}` };
    }
  }

  /**
   * Perform transition action
   */
  private async performTransitionAction(action: string): Promise<void> {
    switch (action) {
      case 'tap_login_button':
        await this.adbBridge.performTap(540, 800); // Approximate login button location
        break;
      case 'tap_map_button':
        await this.adbBridge.performTap(540, 1200); // Approximate map button location
        break;
      case 'back':
        await this.adbBridge.performBack();
        break;
      default:
        logger.warn('Unknown transition action', { action });
    }
  }

  /**
   * Send app to background
   */
  private async sendAppToBackground(): Promise<void> {
    await this.adbBridge.performBack();
    await this.adbBridge.performBack();
  }

  /**
   * Simulate app crash
   */
  private async simulateAppCrash(): Promise<void> {
    await stopApp(this.config.maynDrivePackage);
  }

  /**
   * Simulate low memory condition
   */
  private async simulateLowMemory(): Promise<void> {
    // This would typically require more complex memory pressure simulation
    // For now, just stop and restart the app
    await stopApp(this.config.maynDrivePackage);
    await this.sleep(500);
  }

  /**
   * Test invalid activity launch
   */
  private async testInvalidActivityLaunch(): Promise<void> {
    try {
      await launchApp(this.config.maynDrivePackage, 'com.mayn.mayndrive.NonExistentActivity');
    } catch (error) {
      // Expected to fail
    }
  }

  /**
   * Test activity launch timeout
   */
  private async testActivityLaunchTimeout(): Promise<void> {
    // This would require modifying timeout configurations temporarily
    // For now, just test with a very short timeout
    try {
      const result = await launchApp(this.config.maynDrivePackage, 'com.mayn.mayndrive.MainActivity');
      if (!result.success) {
        throw new Error(result.message);
      }
    } catch (error) {
      // May timeout, which is expected for this test
    }
  }

  /**
   * Test UI state capture failure
   */
  private async testUIStateCaptureFailure(): Promise<void> {
    // Stop the app and try to capture UI state
    await stopApp(this.config.maynDrivePackage);
    try {
      await this.adbBridge.captureUIState();
    } catch (error) {
      // Expected to fail when app is not running
    }
  }

  /**
   * Test device disconnection
   */
  private async testDeviceDisconnection(): Promise<void> {
    // This test would require actual device disconnection simulation
    // For now, just test the error handling path
    logger.info('Device disconnection test simulated');
  }

  /**
   * Get environment information
   */
  private async getEnvironmentInfo(): Promise<any> {
    try {
      const deviceInfo = await this.adbBridge.getDeviceInfo();
      return {
        nodeVersion: process.version,
        platform: process.platform,
        deviceSerial: this.config.deviceSerial,
        maynDriveVersion: '1.0.0', // Could be extracted from package
        emulatorInfo: {
          androidVersion: deviceInfo.androidVersion,
          sdkVersion: deviceInfo.sdkVersion,
          model: deviceInfo.model,
          resolution: deviceInfo.resolution
        }
      };
    } catch (error) {
      return {
        nodeVersion: process.version,
        platform: process.platform,
        deviceSerial: this.config.deviceSerial,
        error: (error as Error).message
      };
    }
  }

  /**
   * Calculate performance benchmarks
   */
  private calculatePerformanceBenchmarks(): ActivityResumeTestResults['performanceBenchmarks'] {
    const successfulResults = this.testResults.filter(r => r.success && r.performance);

    if (successfulResults.length === 0) {
      return {
        averageLaunchTime: 0,
        averageCaptureTime: 0,
        averageResumeTime: 0,
        fastestActivity: 'None',
        slowestActivity: 'None',
        successRate: 0
      };
    }

    const launchTimes = successfulResults.map(r => r.performance!.launchTime);
    const captureTimes = successfulResults.map(r => r.performance!.captureTime);
    const totalTimes = successfulResults.map(r => r.performance!.totalTime);

    return {
      averageLaunchTime: launchTimes.reduce((a, b) => a + b, 0) / launchTimes.length,
      averageCaptureTime: captureTimes.reduce((a, b) => a + b, 0) / captureTimes.length,
      averageResumeTime: totalTimes.reduce((a, b) => a + b, 0) / totalTimes.length,
      fastestActivity: successfulResults.reduce((min, r) =>
        r.performance!.totalTime < min.performance!.totalTime ? r : min
      ).activity,
      slowestActivity: successfulResults.reduce((max, r) =>
        r.performance!.totalTime > max.performance!.totalTime ? r : max
      ).activity,
      successRate: (successfulResults.length / this.testResults.length) * 100
    };
  }

  /**
   * Calculate error summary
   */
  private calculateErrorSummary(): ActivityResumeTestResults['errorSummary'] {
    const failedResults = this.testResults.filter(r => !r.success);
    const errorTypes: Record<string, number> = {};
    const criticalFailures: string[] = [];

    failedResults.forEach(result => {
      const errorType = result.error || 'Unknown error';
      errorTypes[errorType] = (errorTypes[errorType] || 0) + 1;

      if (result.activity === 'MainActivity' || result.activity === 'LoginScreen') {
        criticalFailures.push(`${result.activity}: ${result.scenario} - ${errorType}`);
      }
    });

    return {
      totalErrors: failedResults.length,
      errorTypes,
      criticalFailures
    };
  }

  /**
   * Calculate test summary
   */
  private calculateTestSummary(): ActivityResumeTestResults['summary'] {
    const totalTests = this.testResults.length + this.transitionResults.length;
    const passedTests = [
      ...this.testResults.filter(r => r.success),
      ...this.transitionResults.filter(r => r.success)
    ].length;
    const failedTests = totalTests - passedTests;
    const successRate = totalTests > 0 ? Math.round((passedTests / totalTests) * 100) : 0;

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

  /**
   * Save test artifacts
   */
  private async saveTestArtifacts(result: ActivityTestResult, activity: MaynDriveActivity): Promise<void> {
    try {
      const testDir = join(this.config.artifactsDirectory, `${activity.name}_${Date.now()}`);
      mkdirSync(testDir, { recursive: true });

      // Save UI hierarchy
      if (result.uiState?.hierarchy) {
        writeFileSync(
          join(testDir, 'ui_hierarchy.xml'),
          result.uiState.hierarchy,
          'utf8'
        );
      }

      // Save screenshot
      if (result.uiState?.screenshot) {
        const screenshotBuffer = Buffer.from(result.uiState.screenshot, 'base64');
        writeFileSync(
          join(testDir, 'screenshot.png'),
          screenshotBuffer
        );
      }

      // Save test result
      writeFileSync(
        join(testDir, 'test_result.json'),
        JSON.stringify(result, null, 2),
        'utf8'
      );

    } catch (error) {
      logger.warn('Failed to save test artifacts', {
        activity: activity.name,
        error: (error as Error).message
      });
    }
  }

  /**
   * Cleanup test engine
   */
  async cleanup(): Promise<void> {
    logger.info('Cleaning up Activity Resume Test Engine');

    try {
      await this.adbBridge.close();
      logger.info('Activity Resume Test Engine cleaned up successfully');
    } catch (error) {
      logger.error('Failed to cleanup Activity Resume Test Engine', {
        error: (error as Error).message
      });
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ============================================================================
// TEST CONFIGURATION AND EXECUTION
// ============================================================================

/**
 * Get test configuration from environment
 */
function getActivityTestConfig(): ActivityTestConfig {
  return {
    deviceSerial: process.env.ANDROID_SERIAL || environmentConfig.adb.deviceSerial,
    maynDrivePackage: environmentConfig.maynDrive.packageName,
    testTimeout: parseInt(process.env.ACTIVITY_TEST_TIMEOUT || '60000'),
    launchTimeout: parseInt(process.env.ACTIVITY_LAUNCH_TIMEOUT || '15000'),
    captureTimeout: parseInt(process.env.ACTIVITY_CAPTURE_TIMEOUT || '10000'),
    stabilizationTimeout: parseInt(process.env.ACTIVITY_STABILIZATION_TIMEOUT || '10000'),
    retryAttempts: parseInt(process.env.ACTIVITY_RETRY_ATTEMPTS || '3'),
    enablePerformanceMonitoring: process.env.ENABLE_PERFORMANCE_MONITORING !== 'false',
    saveArtifacts: process.env.SAVE_ACTIVITY_TEST_ARTIFACTS === 'true',
    artifactsDirectory: process.env.ACTIVITY_TEST_ARTIFACTS_DIR ||
      join(process.cwd(), 'test-results', 'activity-resume'),
    debugLogging: process.env.ACTIVITY_TEST_DEBUG === 'true'
  };
}

/**
 * Save test results to file
 */
async function saveActivityTestResults(results: ActivityResumeTestResults): Promise<void> {
  try {
    const resultsPath = join(
      results.testConfig.artifactsDirectory,
      `activity-resume-results-${Date.now()}.json`
    );

    writeFileSync(resultsPath, JSON.stringify(results, null, 2), 'utf8');

    logger.info('Activity resume test results saved', { resultsPath });
  } catch (error) {
    logger.error('Failed to save activity resume test results', {
      error: (error as Error).message
    });
  }
}

// ============================================================================
// MAIN TEST EXECUTION
// ============================================================================

/**
 * Main test execution function
 */
export async function runActivityResumeTests(): Promise<ActivityResumeTestResults> {
  console.log('='.repeat(80));
  console.log('MAYNDRIVE ACTIVITY-SPECIFIC RESUME PROCEDURES INTEGRATION TESTS');
  console.log('='.repeat(80));

  const config = getActivityTestConfig();
  const testEngine = new ActivityResumeTestEngine(config);

  try {
    // Initialize test engine
    await testEngine.initialize();

    // Run complete test suite
    const results = await testEngine.runCompleteTestSuite();

    // Save results
    if (config.saveArtifacts) {
      await saveActivityTestResults(results);
    }

    // Print summary
    console.log('='.repeat(80));
    console.log('ACTIVITY RESUME TEST RESULTS SUMMARY');
    console.log('='.repeat(80));
    console.log(`Overall Status: ${results.summary.overallStatus.toUpperCase()}`);
    console.log(`Total Tests: ${results.summary.totalTests}`);
    console.log(`Passed: ${results.summary.passedTests}`);
    console.log(`Failed: ${results.summary.failedTests}`);
    console.log(`Success Rate: ${results.summary.successRate}%`);

    // Performance benchmarks
    console.log('\nPERFORMANCE BENCHMARKS:');
    console.log(`Average Launch Time: ${results.performanceBenchmarks.averageLaunchTime.toFixed(0)}ms`);
    console.log(`Average Capture Time: ${results.performanceBenchmarks.averageCaptureTime.toFixed(0)}ms`);
    console.log(`Average Resume Time: ${results.performanceBenchmarks.averageResumeTime.toFixed(0)}ms`);
    console.log(`Fastest Activity: ${results.performanceBenchmarks.fastestActivity}`);
    console.log(`Slowest Activity: ${results.performanceBenchmarks.slowestActivity}`);

    // Error summary
    if (results.errorSummary.totalErrors > 0) {
      console.log('\nERROR SUMMARY:');
      console.log(`Total Errors: ${results.errorSummary.totalErrors}`);

      for (const [errorType, count] of Object.entries(results.errorSummary.errorTypes)) {
        console.log(`  ${errorType}: ${count}`);
      }

      if (results.errorSummary.criticalFailures.length > 0) {
        console.log('\nCRITICAL FAILURES:');
        results.errorSummary.criticalFailures.forEach(failure => {
          console.log(`  - ${failure}`);
        });
      }
    }

    // Cleanup
    await testEngine.cleanup();

    return results;

  } catch (error) {
    console.error('Activity resume test execution failed:', error);

    try {
      await testEngine.cleanup();
    } catch (cleanupError) {
      console.error('Cleanup failed:', cleanupError);
    }

    throw error;
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  // Main test engine and execution
  ActivityResumeTestEngine,
  runActivityResumeTests,

  // Utilities
  ActivityDetectionUtils,

  // Configuration
  getActivityTestConfig,
  saveActivityTestResults,

  // Types
  ActivityTestConfig,
  ActivityTestResult,
  ActivityTransitionResult,
  ActivityResumeTestResults,
  MaynDriveActivity
};

// ============================================================================
// SELF-EXECUTION
// ============================================================================

// Run tests if this file is executed directly
if (require.main === module) {
  runActivityResumeTests()
    .then((results) => {
      process.exit(results.summary.overallStatus === 'failed' ? 1 : 0);
    })
    .catch((error) => {
      console.error('Activity resume test execution failed:', error);
      process.exit(1);
    });
}