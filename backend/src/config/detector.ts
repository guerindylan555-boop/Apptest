/**
 * Detector Configuration Schema
 *
 * This file contains configuration options for the state detection system,
 * including thresholds, weights, and scoring parameters as defined in research.md
 */

export interface DetectorConfig {
  // Scoring thresholds (0-100 scale)
  thresholds: {
    matched: number;      // ≥70 considered matched
    ambiguous: number;    // 50-69 considered ambiguous (prompt operator)
    unknown: number;      // <50 considered UNKNOWN
  };

  // Weight factors for different scoring components
  weights: {
    signature: number;    // Weight for signature hash matching
    selectors: {
      'resource-id': number;  // Weight 3 (most reliable)
      'content-desc': number; // Weight 2
      'text': number;         // Weight 1
      'accessibility': number; // Weight 1
      'xpath': number;        // Weight 1
      'coords': number;       // Weight 1 (least reliable)
    };
    structural: number;  // Weight for Jaccard structural similarity
  };

  // Detector behavior settings
  settings: {
    maxCandidates: number;    // Maximum top-K candidates to return
    enableStructuralScoring: boolean;  // Whether to use Jaccard similarity
    minConfidenceThreshold: number;    // Minimum selector confidence to consider
    signatureHashAlgorithm: 'sha256';  // Algorithm for signature hashing
  };

  // Performance tuning
  performance: {
    maxXmlSize: number;      // Maximum XML dump size to process (bytes)
    timeoutMs: number;       // Maximum time for detection (ms)
    enableCaching: boolean;  // Cache detection results
    cacheExpiryMs: number;   // Cache expiry time
  };
}

// Default configuration based on research.md decisions
export const defaultDetectorConfig: DetectorConfig = {
  thresholds: {
    matched: 70,      // ≥70 matched
    ambiguous: 50,    // 50-69 ambiguous (prompt operator)
    unknown: 50       // <50 UNKNOWN
  },

  weights: {
    signature: 40,     // High weight for exact signature match
    selectors: {
      'resource-id': 3,    // Most stable selector type
      'content-desc': 2,   // Second most stable
      'text': 1,           // Less stable due to localization
      'accessibility': 1,  // Similar stability to text
      'xpath': 1,          // Brittle, low weight
      'coords': 1          // Least reliable, fallback only
    },
    structural: 20   // Moderate weight for structural similarity
  },

  settings: {
    maxCandidates: 5,           // Return top 5 candidates
    enableStructuralScoring: true,  // Use Jaccard similarity
    minConfidenceThreshold: 0.4,    // Ignore selectors with <0.4 confidence
    signatureHashAlgorithm: 'sha256' // SHA-256 for signature hashing
  },

  performance: {
    maxXmlSize: 10 * 1024 * 1024,  // 10MB max XML size
    timeoutMs: 2000,               // 2 second timeout (per SC-002)
    enableCaching: true,           // Cache results for performance
    cacheExpiryMs: 300 * 1000      // 5 minute cache expiry
  }
};

// Environment-specific configuration overrides
export function getDetectorConfig(): DetectorConfig {
  const config = { ...defaultDetectorConfig };

  // Allow environment variable overrides
  if (process.env.DETECTOR_THRESHOLD_MATCHED) {
    config.thresholds.matched = parseInt(process.env.DETECTOR_THRESHOLD_MATCHED, 10);
  }

  if (process.env.DETECTOR_THRESHOLD_AMBIGUOUS) {
    config.thresholds.ambiguous = parseInt(process.env.DETECTOR_THRESHOLD_AMBIGUOUS, 10);
  }

  if (process.env.DETECTOR_TIMEOUT_MS) {
    config.performance.timeoutMs = parseInt(process.env.DETECTOR_TIMEOUT_MS, 10);
  }

  if (process.env.DETECTOR_MAX_CANDIDATES) {
    config.settings.maxCandidates = parseInt(process.env.DETECTOR_MAX_CANDIDATES, 10);
  }

  return config;
}

// Validation function for configuration
export function validateDetectorConfig(config: DetectorConfig): string[] {
  const errors: string[] = [];

  // Validate thresholds
  if (config.thresholds.matched < 0 || config.thresholds.matched > 100) {
    errors.push('thresholds.matched must be between 0 and 100');
  }

  if (config.thresholds.ambiguous < 0 || config.thresholds.ambiguous > 100) {
    errors.push('thresholds.ambiguous must be between 0 and 100');
  }

  if (config.thresholds.ambiguous >= config.thresholds.matched) {
    errors.push('thresholds.ambiguous must be less than thresholds.matched');
  }

  // Validate weights sum roughly equals 100
  const totalWeight = config.weights.signature +
    Object.values(config.weights.selectors).reduce((sum, weight) => sum + weight, 0) +
    config.weights.structural;

  if (totalWeight < 50 || totalWeight > 150) {
    errors.push(`Total weight (${totalWeight}) should be around 100 for balanced scoring`);
  }

  // Validate performance settings
  if (config.performance.timeoutMs < 100) {
    errors.push('performance.timeoutMs must be at least 100ms');
  }

  if (config.settings.maxCandidates < 1) {
    errors.push('settings.maxCandidates must be at least 1');
  }

  return errors;
}