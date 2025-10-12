/**
 * Feature Flags Configuration
 *
 * Controls availability of optional features, particularly those requiring
 * governance approval (e.g., Frida instrumentation tools).
 *
 * Environment Variables:
 * - ENABLE_FRIDA: Set to "true" to enable Frida instrumentation features (default: false)
 */

export interface FeatureFlags {
  /** Enable Frida server controls and script injection */
  enableFrida: boolean;
}

/**
 * Load feature flags from environment variables
 */
function loadFeatureFlags(): FeatureFlags {
  return {
    enableFrida: process.env.ENABLE_FRIDA === 'true'
  };
}

/**
 * Current feature flag configuration
 */
export const featureFlags: FeatureFlags = loadFeatureFlags();

/**
 * Check if Frida features are enabled
 */
export function isFridaEnabled(): boolean {
  return featureFlags.enableFrida;
}
