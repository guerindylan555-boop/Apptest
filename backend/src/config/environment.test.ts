/**
 * Environment Configuration Tests
 *
 * This file contains basic tests for the environment configuration system.
 * Run with: npm test -- environment.test.ts
 */

import {
  loadEnvironmentConfig,
  validateEnvironmentConfig,
  getEnvironmentConfig,
  isFeatureEnabled,
  getConfigSummary,
  ConfigValidationError
} from './environment';

describe('Environment Configuration', () => {
  describe('loadEnvironmentConfig', () => {
    it('should load configuration without throwing errors', () => {
      expect(() => {
        const config = loadEnvironmentConfig();
        expect(config).toBeDefined();
        expect(config.webrtc).toBeDefined();
        expect(config.adb).toBeDefined();
        expect(config.storage).toBeDefined();
      }).not.toThrow();
    });

    it('should have valid default values', () => {
      const config = loadEnvironmentConfig();

      // Check WebRTC defaults
      expect(config.webrtc.publicUrl).toMatch(/^https?:\/\/.+/);
      expect(config.webrtc.timeout).toBeGreaterThan(0);
      expect(Array.isArray(config.webrtc.iceServers)).toBe(true);

      // Check ADB defaults
      expect(config.adb.host).toBeDefined();
      expect(config.adb.port).toBeGreaterThan(0);
      expect(config.adb.port).toBeLessThan(65536);
      expect(config.adb.timeout).toBeGreaterThan(0);

      // Check storage paths
      expect(config.storage.graphRoot).toBeDefined();
      expect(config.storage.flowRoot).toBeDefined();
      expect(config.storage.sessionsDir).toBeDefined();
      expect(config.storage.screenshotsDir).toBeDefined();

      // Check logging
      expect(['error', 'warn', 'info', 'debug', 'trace']).toContain(config.logging.level);
      expect(['json', 'text']).toContain(config.logging.format);
    });
  });

  describe('validateEnvironmentConfig', () => {
    it('should validate configuration without warnings for test environment', () => {
      const config = loadEnvironmentConfig();
      expect(() => {
        validateEnvironmentConfig(config, 'test');
      }).not.toThrow();
    });

    it('should accept development environment', () => {
      const config = loadEnvironmentConfig();
      expect(() => {
        validateEnvironmentConfig(config, 'development');
      }).not.toThrow();
    });

    it('should accept production environment', () => {
      const config = loadEnvironmentConfig();
      expect(() => {
        validateEnvironmentConfig(config, 'production');
      }).not.toThrow();
    });
  });

  describe('getEnvironmentConfig', () => {
    it('should return validated configuration', () => {
      const config = getEnvironmentConfig();
      expect(config).toBeDefined();
      expect(config.environment).toBeDefined();
      expect(config.projectRoot).toBeDefined();
    });
  });

  describe('isFeatureEnabled', () => {
    it('should return boolean for feature flags', () => {
      // Test with potentially set environment variable
      const result = isFeatureEnabled('discovery');
      expect(typeof result).toBe('boolean');
    });

    it('should return false for unknown features', () => {
      const result = isFeatureEnabled('unknown_feature_xyz');
      expect(result).toBe(false);
    });
  });

  describe('getConfigSummary', () => {
    it('should return configuration summary', () => {
      const config = loadEnvironmentConfig();
      const summary = getConfigSummary(config);

      expect(summary).toBeDefined();
      expect(summary.environment).toBeDefined();
      expect(summary.webrtc).toBeDefined();
      expect(summary.adb).toBeDefined();
      expect(summary.storage).toBeDefined();
      expect(summary.logging).toBeDefined();
      expect(summary.api).toBeDefined();
      expect(summary.development).toBeDefined();

      // Should not include sensitive information
      expect(summary.security).toBeUndefined();
    });
  });

  describe('Configuration Error Handling', () => {
    it('should handle ConfigValidationError properly', () => {
      const error = new ConfigValidationError(
        'Test error message',
        'TEST_VARIABLE',
        'Test suggestion'
      );

      expect(error.message).toBe('Test error message');
      expect(error.variable).toBe('TEST_VARIABLE');
      expect(error.suggestion).toBe('Test suggestion');
      expect(error.name).toBe('ConfigValidationError');
    });
  });

  describe('Configuration Types', () => {
    it('should have proper TypeScript types', () => {
      const config = loadEnvironmentConfig();

      // Test that configuration has expected structure
      expect(typeof config.webrtc.publicUrl).toBe('string');
      expect(typeof config.webrtc.timeout).toBe('number');
      expect(Array.isArray(config.webrtc.iceServers)).toBe(true);

      expect(typeof config.adb.host).toBe('string');
      expect(typeof config.adb.port).toBe('number');
      expect(typeof config.adb.timeout).toBe('number');

      expect(typeof config.storage.graphRoot).toBe('string');
      expect(typeof config.storage.graphStateLimit).toBe('number');

      expect(typeof config.logging.level).toBe('string');
      expect(typeof config.logging.debugScreenshotCapture).toBe('boolean');

      expect(typeof config.api.port).toBe('number');
      expect(typeof config.api.authEnabled).toBe('boolean');

      expect(typeof config.development.devMode).toBe('boolean');
      expect(typeof config.development.enableLLMFlowAssistance).toBe('boolean');
    });
  });
});

/**
 * Integration test to verify configuration works with real environment
 */
describe('Configuration Integration', () => {
  it('should work with existing stream configuration', () => {
    // Import existing stream config to ensure compatibility
    const { streamConfig } = require('./stream');

    const envConfig = loadEnvironmentConfig();

    // Verify that values match (or are compatible)
    expect(streamConfig.grpcEndpoint).toBe(envConfig.webrtc.grpcEndpoint);
    expect(streamConfig.publicUrl).toBe(envConfig.webrtc.publicUrl);
    expect(Array.isArray(streamConfig.iceServers)).toBe(true);
  });

  it('should work with existing app paths', () => {
    const { appPaths } = require('./appPaths');

    // Verify app paths are still available
    expect(appPaths.root).toBeDefined();
    expect(appPaths.libraryDir).toBeDefined();
    expect(appPaths.logsDir).toBeDefined();
  });

  it('should work with existing feature flags', () => {
    const { featureFlags, isFridaEnabled } = require('./featureFlags');

    // Verify feature flags still work
    expect(featureFlags).toBeDefined();
    expect(typeof isFridaEnabled()).toBe('boolean');
  });
});