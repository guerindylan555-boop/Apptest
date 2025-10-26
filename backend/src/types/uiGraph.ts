/**
 * UI Graph Types for MaynDrive State-Aware UI Mapping
 *
 * This file contains TypeScript interfaces that mirror the data model
 * defined in specs/001-mayndrive-ui-map/data-model.md
 */

export interface ScreenNode {
  id: string; // hex, 16 bytes - deterministic hash
  name: string; // Human-readable label, 3-80 chars
  signature: ScreenSignature;
  selectors: SelectorCandidate[]; // Ranked by reliability
  hints: string[]; // Optional callouts, max 5 entries
  samples: ArtifactBundle;
  metadata: {
    activity?: string;
    class?: string;
    package?: string;
    emulatorBuild?: string;
    captureTimestamp: string; // ISO datetime
    operatorId: string;
  };
  outgoingEdgeIds: string[];
  incomingEdgeIds: string[];
  startStateTag?: 'clean' | 'logged_out_home' | 'logged_in_no_rental' | 'logged_in_with_rental' | 'other';
  status: 'active' | 'deprecated' | 'duplicate';
}

export interface ScreenSignature {
  activity: string; // Fully qualified Android activity/fragment class
  resourceIds: string[]; // Sorted ascending for hashing
  requiredTexts: string[]; // Language-normalized strings
  layoutFingerprint: string; // Digest of XML depth walk
  hash: string; // SHA-256 truncated to 16 bytes
  version: number; // Increment when signature definition changes
}

export interface SelectorCandidate {
  id: string; // Unique within node
  type: 'resource-id' | 'content-desc' | 'text' | 'accessibility' | 'xpath' | 'coords';
  value: string; // Selector payload, coords as "x,y"
  confidence: number; // 0-1, <0.4 flagged as risky
  lastValidatedAt: string; // ISO datetime
}

export interface ArtifactBundle {
  screenshotPath: string; // Relative under var/captures/<nodeId>/
  xmlPath: string; // UIAutomator dump path
  metadataPath?: string; // Optional JSON with device context
  checksum: string; // SHA-1 or SHA-256 for integrity
}

export interface ActionEdge {
  id: string; // UUID or semantic nodeId-action
  fromNodeId: string;
  toNodeId: string | null; // null until target captured
  action: {
    kind: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    delayMs?: number;
    intent?: {
      action: string;
      package?: string;
      component?: string;
    };
  };
  guard: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  notes: string; // Operator hints for LLM editing
  createdAt: string; // ISO datetime
  createdBy: string; // Operator id / automation agent
  confidence: number; // Historical success rate, <0.6 flagged
  startStateConstraint?: string; // Optional StartStateProfile.id indicating this edge only applies in a given start-state family
}

export interface FlowDefinition {
  name: string; // kebab-case
  description: string; // 1-2 sentence summary
  version: string; // semver
  variables: FlowVariable[];
  precondition: {
    nodeId?: string;
    query?: {
      activity?: string;
      requiredTexts?: string[];
    };
  };
  steps: FlowStep[];
  postcondition: {
    nodeId?: string;
    query?: {
      activity?: string;
      requiredTexts?: string[];
    };
  };
  recovery: RecoveryRule[];
  metadata: {
    owner?: string;
    lastUpdatedAt: string;
    validationStatus: 'draft' | 'validated' | 'deprecated';
    notes?: string;
  };
}

export interface FlowVariable {
  name: string;
  description: string;
  type: 'string' | 'number' | 'boolean';
  required: boolean;
  prompt: string; // Displayed to operator when missing
}

export interface FlowStep {
  kind: 'edgeRef' | 'inline';
  edgeId?: string; // Required when kind=edgeRef
  inlineAction?: {
    action: 'tap' | 'type' | 'wait' | 'back' | 'intent';
    selectorId?: string;
    text?: string;
    keycode?: number;
    waitMs?: number;
  }; // Required when kind=inline
  guard?: {
    mustMatchSignatureHash?: string;
    requiredTexts?: string[];
  };
  retryPolicy?: {
    maxAttempts: number;
    delayMs: number;
  };
  expectNodeId?: string; // Optional explicit node expectation
}

export interface RecoveryRule {
  trigger: 'unexpected_node' | 'system_dialog' | 'timeout';
  allowedActions: ('back' | 'dismiss' | 'reopen' | 'relogin' | 'wait' | 'retry')[];
}

export interface StateDetectionResult {
  timestamp: string; // ISO datetime
  dumpSource: string; // Path to evaluated XML
  topCandidates: Array<{
    nodeId: string;
    score: number; // 0-100
  }>;
  selectedNodeId?: string; // Highest-scoring if >= threshold
  status: 'matched' | 'ambiguous' | 'unknown';
  operatorAction?: 'accept' | 'map_new' | 'merge' | 'retry';
}

export interface UIGraph {
  metadata: {
    version: string;
    lastUpdated: string;
    checksum: string;
    totalNodes: number;
    totalEdges: number;
  };
  nodes: ScreenNode[];
  edges: ActionEdge[];
}

export interface GraphIndex {
  metadata: {
    version: string;
    lastUpdated: string;
    checksum: string;
    totalNodes: number;
    totalEdges: number;
  };
  nodes: string[]; // Node IDs for quick lookup
  edges: string[]; // Edge IDs for quick lookup
  graphs: Array<{
    version: string;
    timestamp: string;
    path: string;
    checksum: string;
    description: string;
  }>;
}