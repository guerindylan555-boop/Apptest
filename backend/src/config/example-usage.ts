/**
 * Example Usage of Environment Configuration
 *
 * This file demonstrates how to use the environment configuration
 * system in a typical backend service.
 */

import {
  environmentConfig,
  getEnvironmentConfig,
  isFeatureEnabled,
  getConfigSummary,
  ConfigValidationError
} from './environment';

/**
 * Example service class that uses environment configuration
 */
export class ExampleWebRTCService {
  private config = environmentConfig.webrtc;

  constructor() {
    console.log('WebRTC Service initialized with configuration:');
    console.log(`  Public URL: ${this.config.publicUrl}`);
    console.log(`  gRPC Endpoint: ${this.config.grpcEndpoint}`);
    console.log(`  Timeout: ${this.config.timeout}ms`);
    console.log(`  ICE Servers: ${this.config.iceServers.join(', ')}`);
  }

  public connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`WebRTC connection timeout after ${this.config.timeout}ms`));
      }, this.config.timeout);

      // Simulate WebRTC connection logic
      console.log(`Connecting to WebRTC at ${this.config.publicUrl}...`);
      console.log(`Using gRPC endpoint: ${this.config.grpcEndpoint}`);

      // Mock successful connection
      setTimeout(() => {
        clearTimeout(timeout);
        console.log('WebRTC connection established successfully');
        resolve();
      }, 1000);
    });
  }

  public getConnectionInfo() {
    return {
      publicUrl: this.config.publicUrl,
      grpcEndpoint: this.config.grpcEndpoint,
      iceServers: this.config.iceServers,
      timeout: this.config.timeout,
      resolution: this.config.resolution,
      frameRate: this.config.frameRate,
      bitrate: this.config.bitrate
    };
  }
}

/**
 * Example ADB service using environment configuration
 */
export class ExampleADBService {
  private config = environmentConfig.adb;

  constructor() {
    console.log('ADB Service initialized with configuration:');
    console.log(`  Host: ${this.config.host}`);
    console.log(`  Port: ${this.config.port}`);
    console.log(`  Device Serial: ${this.config.deviceSerial}`);
    console.log(`  Timeout: ${this.config.timeout}ms`);
  }

  public async connect(): Promise<void> {
    console.log(`Connecting to ADB at ${this.config.host}:${this.config.port}...`);
    console.log(`Target device: ${this.config.deviceSerial}`);

    // Simulate ADB connection with timeout
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`ADB connection timeout after ${this.config.timeout}ms`));
      }, this.config.timeout);

      // Mock successful connection
      setTimeout(() => {
        clearTimeout(timeout);
        console.log('ADB connection established successfully');
        resolve();
      }, 500);
    });
  }

  public async captureUI(): Promise<string> {
    console.log('Capturing UI with UIAutomator2...');
    console.log(`UIAutomator2 timeout: ${this.config.uiAutomatorTimeout}ms`);
    console.log(`UI capture timeout: ${this.config.uiCaptureTimeout}ms`);

    // Simulate UI capture
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`UI capture timeout after ${this.config.uiCaptureTimeout}ms`));
      }, this.config.uiCaptureTimeout);

      setTimeout(() => {
        clearTimeout(timeout);
        const mockXml = '<?xml version="1.0" encoding="UTF-8"?><hierarchy>...</hierarchy>';
        resolve(mockXml);
      }, 1000);
    });
  }
}

/**
 * Example flow engine service using environment configuration
 */
export class ExampleFlowEngine {
  private config = environmentConfig.flow;
  private storageConfig = environmentConfig.storage;

  constructor() {
    console.log('Flow Engine initialized with configuration:');
    console.log(`  Replay Retry Limit: ${this.config.replayRetryLimit}`);
    console.log(`  Execution Timeout: ${this.config.executionTimeout}ms`);
    console.log(`  Graph Root: ${this.storageConfig.graphRoot}`);
    console.log(`  Flow Root: ${this.storageConfig.flowRoot}`);
  }

  public async executeFlow(flowPath: string): Promise<void> {
    console.log(`Executing flow: ${flowPath}`);
    console.log(`Retry limit: ${this.config.replayRetryLimit}`);
    console.log(`Step timeout: ${this.config.replayStepTimeout}ms`);

    // Simulate flow execution
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Flow execution timeout after ${this.config.executionTimeout}ms`));
      }, this.config.executionTimeout);

      setTimeout(() => {
        clearTimeout(timeout);
        console.log('Flow executed successfully');
        resolve();
      }, 2000);
    });
  }

  public getFlowPaths(): { graphPath: string; flowRoot: string } {
    return {
      graphPath: this.storageConfig.graphPath,
      flowRoot: this.storageConfig.flowRoot
    };
  }
}

/**
 * Example service that demonstrates feature flag usage
 */
export class ExampleDiscoveryService {
  private enabled = isFeatureEnabled('discovery');
  private panelEnabled = isFeatureEnabled('discovery_panel');

  constructor() {
    console.log('Discovery Service initialized:');
    console.log(`  Discovery Feature: ${this.enabled ? 'ENABLED' : 'DISABLED'}`);
    console.log(`  Discovery Panel: ${this.panelEnabled ? 'ENABLED' : 'DISABLED'}`);

    if (!this.enabled) {
      console.log('Discovery features are disabled. Set ENABLE_DISCOVERY=true to enable.');
    }
  }

  public async startDiscovery(): Promise<void> {
    if (!this.enabled) {
      throw new Error('Discovery feature is not enabled');
    }

    console.log('Starting discovery process...');
    // Simulate discovery work
    await new Promise(resolve => setTimeout(resolve, 1000));
    console.log('Discovery process completed');
  }

  public showPanel(): boolean {
    return this.panelEnabled;
  }
}

/**
 * Example application startup with configuration
 */
export async function initializeApplication(): Promise<void> {
  try {
    console.log('🚀 Initializing AutoApp Backend Application\n');

    // Load and validate configuration
    console.log('📋 Loading environment configuration...');
    const config = getEnvironmentConfig();

    // Display configuration summary
    console.log('📊 Configuration Summary:');
    const summary = getConfigSummary(config);
    console.log(JSON.stringify(summary, null, 2));
    console.log('');

    // Initialize services based on configuration
    console.log('🔧 Initializing services...');

    const webrtcService = new ExampleWebRTCService();
    const adbService = new ExampleADBService();
    const flowEngine = new ExampleFlowEngine();
    const discoveryService = new ExampleDiscoveryService();

    console.log('✅ Services initialized successfully\n');

    // Start services
    console.log('🏃 Starting services...');

    await webrtcService.connect();
    await adbService.connect();

    if (discoveryService.showPanel()) {
      console.log('🎯 Discovery panel is enabled');
    }

    // Example flow execution
    await flowEngine.executeFlow('example-flow.json');

    console.log('\n🎉 Application initialized successfully!');
    console.log(`Environment: ${config.environment}`);
    console.log(`Project Root: ${config.projectRoot}`);

  } catch (error) {
    console.error('❌ Failed to initialize application:');

    if (error instanceof ConfigValidationError) {
      console.error(`Configuration Error: ${error.message}`);
      console.error(`Variable: ${error.variable}`);
      console.error(`Suggestion: ${error.suggestion}`);
    } else {
      console.error(error);
    }

    process.exit(1);
  }
}

/**
 * Example of how to handle configuration changes
 */
export class ConfigurationManager {
  private currentConfig = environmentConfig;

  constructor() {
    console.log('Configuration Manager initialized');
    this.printCurrentConfig();
  }

  public printCurrentConfig(): void {
    const summary = getConfigSummary(this.currentConfig);
    console.log('Current Configuration:');
    console.log(JSON.stringify(summary, null, 2));
  }

  public reloadConfiguration(): void {
    try {
      console.log('Reloading configuration...');
      this.currentConfig = getEnvironmentConfig();
      console.log('Configuration reloaded successfully');
      this.printCurrentConfig();
    } catch (error) {
      console.error('Failed to reload configuration:', error);
    }
  }

  public getWebRTCConfig() {
    return this.currentConfig.webrtc;
  }

  public getADBConfig() {
    return this.currentConfig.adb;
  }

  public getStorageConfig() {
    return this.currentConfig.storage;
  }

  public isDevelopmentMode(): boolean {
    return this.currentConfig.development.devMode;
  }

  public isTestMode(): boolean {
    return this.currentConfig.development.testMode;
  }
}

// Example usage - this would typically be in your main application file
if (require.main === module) {
  initializeApplication().catch(console.error);
}