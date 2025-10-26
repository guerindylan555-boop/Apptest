/**
 * Graph Types for MaynDrive State-Aware UI Mapping
 *
 * This file contains additional types that complement the UI graph types,
 * specifically for StartStateProfile and other missing entities from the data model.
 */

export type StartStateTag = 'clean' | 'logged_out_home' | 'logged_in_no_rental' | 'logged_in_with_rental' | 'other';

export interface StartStateProfile {
  id: string; // slug (e.g., 'clean', 'logged-in-no-rental')
  description: string; // Human-readable summary
  nodeIds: string[]; // Set of ScreenNodes that compose this profile
  preferredEntryEdgeIds: string[]; // Recommended edges to reach this state
  unlockPolicy: 'any_available' | 'existing_rental_only' | 'n/a';
  detectorHints: {
    [key: string]: any; // Additional selector/text cues
  };
}

// Extended ScreenNode interface with missing fields
export interface ExtendedScreenNode {
  id: string;
  name: string;
  signature: {
    activity: string;
    resourceIds: string[];
    requiredTexts: string[];
    layoutFingerprint: string;
    hash: string;
    version: number;
  };
  selectors: Array<{
    id: string;
    type: 'resource-id' | 'content-desc' | 'text' | 'accessibility' | 'xpath' | 'coords';
    value: string;
    confidence: number;
    lastValidatedAt: string;
  }>;
  hints: string[];
  samples: {
    screenshotPath: string;
    xmlPath: string;
    metadataPath?: string;
    checksum: string;
  };
  metadata: {
    activity?: string;
    class?: string;
    package?: string;
    emulatorBuild?: string;
    captureTimestamp: string;
    operatorId: string;
  };
  startStateTag?: StartStateTag; // Missing from uiGraph.ts
  outgoingEdgeIds: string[];
  incomingEdgeIds: string[];
  status: 'active' | 'deprecated' | 'duplicate';
}

// Extended ActionEdge with missing fields
export interface ExtendedActionEdge {
  id: string;
  fromNodeId: string;
  toNodeId: string | null;
  action: {
    kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    delayMs?: number;
  };
  guard: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  notes: string;
  createdAt: string;
  createdBy: string;
  confidence: number;
  startStateConstraint?: string; // Missing from uiGraph.ts
}

// Export common types for reusability
export type {
  ScreenNode,
  ScreenSignature,
  SelectorCandidate,
  ArtifactBundle,
  ActionEdge,
  FlowDefinition,
  FlowVariable,
  FlowStep,
  RecoveryRule,
  StateDetectionResult
} from './uiGraph';