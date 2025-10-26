/**
 * Zod-based validation schemas for UI Graph types
 *
 * Provides runtime validation and serialization helpers for all
 * UI graph entities defined in the data model.
 */

import { z } from 'zod';

// Common utility schemas
const hexHashSchema = z.string().regex(/^[a-f0-9]{16}$/, '16-character hex hash required');
const isoDateTimeSchema = z.string().datetime({ offset: true });
const kebabCaseSchema = z.string().regex(/^[a-z0-9-]+$/, 'kebab-case required');
const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/, 'semantic version required');

// SelectorCandidate schema
export const selectorCandidateSchema = z.object({
  id: z.string().min(1, 'Selector ID required'),
  type: z.enum(['resource-id', 'content-desc', 'text', 'accessibility', 'xpath', 'coords']),
  value: z.string().min(1, 'Selector value required'),
  confidence: z.number().min(0).max(1),
  lastValidatedAt: isoDateTimeSchema,
});

// ScreenSignature schema
export const screenSignatureSchema = z.object({
  activity: z.string().min(1, 'Activity name required'),
  resourceIds: z.array(z.string()).default([]),
  requiredTexts: z.array(z.string()).default([]),
  layoutFingerprint: z.string().min(1, 'Layout fingerprint required'),
  hash: hexHashSchema,
  version: z.number().int().min(0),
});

// ArtifactBundle schema
export const artifactBundleSchema = z.object({
  screenshotPath: z.string().min(1, 'Screenshot path required'),
  xmlPath: z.string().min(1, 'XML path required'),
  metadataPath: z.string().optional(),
  checksum: z.string().min(1, 'Checksum required'),
});

// ScreenNode schema
export const screenNodeSchema = z.object({
  id: hexHashSchema,
  name: z.string().min(3).max(80, 'Name must be 3-80 characters'),
  signature: screenSignatureSchema,
  selectors: z.array(selectorCandidateSchema).min(1, 'At least one selector required'),
  hints: z.array(z.string()).max(5, 'Maximum 5 hints allowed').default([]),
  samples: artifactBundleSchema,
  metadata: z.object({
    activity: z.string().optional(),
    class: z.string().optional(),
    package: z.string().optional(),
    emulatorBuild: z.string().optional(),
    captureTimestamp: isoDateTimeSchema,
    operatorId: z.string().min(1, 'Operator ID required'),
  }),
  outgoingEdgeIds: z.array(z.string()).default([]),
  incomingEdgeIds: z.array(z.string()).default([]),
  status: z.enum(['active', 'deprecated', 'duplicate']),
});

// Action schema (used in ActionEdge and FlowStep)
export const actionSchema = z.object({
  kind: z.enum(['tap', 'type', 'wait', 'back', 'intent']),
  selectorId: z.string().optional(),
  text: z.string().optional(),
  keycode: z.number().int().min(0).max(255).optional(),
  delayMs: z.number().int().min(0).optional(),
  intent: z.object({
    action: z.string(),
    package: z.string().optional(),
    component: z.string().optional(),
  }).optional(),
});

// Guard schema
export const guardSchema = z.object({
  mustMatchSignatureHash: hexHashSchema.optional(),
  requiredTexts: z.array(z.string()).optional(),
});

// ActionEdge schema
export const actionEdgeSchema = z.object({
  id: z.string().min(1, 'Edge ID required'),
  fromNodeId: hexHashSchema,
  toNodeId: hexHashSchema.nullable(), // This should infer as string | null
  action: actionSchema,
  guard: guardSchema.default({}),
  notes: z.string().default(''),
  createdAt: isoDateTimeSchema,
  createdBy: z.string().min(1, 'Creator ID required'),
  confidence: z.number().min(0).max(1),
});

// FlowVariable schema
export const flowVariableSchema = z.object({
  name: z.string().min(1, 'Variable name required'),
  description: z.string().min(1, 'Variable description required'),
  type: z.enum(['string', 'number', 'boolean']),
  required: z.boolean(),
  prompt: z.string().min(1, 'Variable prompt required'),
});

// Precondition/Postcondition schema
export const conditionSchema = z.object({
  nodeId: hexHashSchema.optional(),
  query: z.object({
    activity: z.string().optional(),
    requiredTexts: z.array(z.string()).optional(),
  }).optional(),
}).refine(
  (data) => data.nodeId || data.query,
  { message: 'Either nodeId or query must be specified' }
);

// RetryPolicy schema
export const retryPolicySchema = z.object({
  maxAttempts: z.number().int().min(1).max(10),
  delayMs: z.number().int().min(0).max(30000),
});

// FlowStep schema
export const flowStepSchema = z.object({
  kind: z.enum(['edgeRef', 'inline']),
  edgeId: z.string().optional(),
  inlineAction: actionSchema.optional(),
  guard: guardSchema.optional(),
  retryPolicy: retryPolicySchema.optional(),
  expectNodeId: hexHashSchema.optional(),
}).refine(
  (data) => (data.kind === 'edgeRef' && data.edgeId) ||
           (data.kind === 'inline' && data.inlineAction),
  { message: 'Step must have valid edgeId or inlineAction based on kind' }
);

// RecoveryRule schema
export const recoveryRuleSchema = z.object({
  trigger: z.enum(['unexpected_node', 'system_dialog', 'timeout']),
  allowedActions: z.array(z.enum(['back', 'dismiss', 'reopen', 'relogin', 'wait'])).min(1),
});

// FlowDefinition schema
export const flowDefinitionSchema = z.object({
  name: kebabCaseSchema,
  description: z.string().min(1, 'Description required').max(200),
  version: semverSchema,
  variables: z.array(flowVariableSchema).default([]),
  precondition: conditionSchema,
  steps: z.array(flowStepSchema).min(1, 'At least one step required'),
  postcondition: conditionSchema,
  recovery: z.array(recoveryRuleSchema).min(1, 'At least one recovery rule required'),
  metadata: z.object({
    owner: z.string().optional(),
    lastUpdatedAt: isoDateTimeSchema,
    validationStatus: z.enum(['draft', 'validated', 'deprecated']),
    notes: z.string().optional(),
  }),
});

// StateDetectionResult schema
export const stateDetectionResultSchema = z.object({
  timestamp: isoDateTimeSchema,
  dumpSource: z.string().min(1, 'Dump source required'),
  topCandidates: z.array(z.object({
    nodeId: hexHashSchema,
    score: z.number().min(0).max(100),
  })),
  selectedNodeId: hexHashSchema.optional(),
  status: z.enum(['matched', 'ambiguous', 'unknown']),
  operatorAction: z.enum(['accept', 'map_new', 'merge', 'retry']).optional(),
});

// UIGraph schema
export const uiGraphSchema = z.object({
  metadata: z.object({
    version: z.string(),
    lastUpdated: isoDateTimeSchema,
    checksum: z.string(),
    totalNodes: z.number().int().min(0),
    totalEdges: z.number().int().min(0),
  }),
  nodes: z.array(screenNodeSchema),
  edges: z.array(actionEdgeSchema),
});

// GraphIndex schema
export const graphIndexSchema = z.object({
  metadata: z.object({
    version: z.string(),
    lastUpdated: isoDateTimeSchema,
    checksum: z.string(),
    totalNodes: z.number().int().min(0),
    totalEdges: z.number().int().min(0),
  }),
  nodes: z.array(hexHashSchema),
  edges: z.array(z.string()),
  graphs: z.array(z.object({
    version: z.string(),
    timestamp: isoDateTimeSchema,
    path: z.string(),
    checksum: z.string(),
    description: z.string(),
  })),
});

// Validation helper functions
export const validateScreenNode = (data: unknown) => {
  return screenNodeSchema.safeParse(data);
};

export const validateActionEdge = (data: unknown) => {
  return actionEdgeSchema.safeParse(data);
};

export const validateFlowDefinition = (data: unknown) => {
  return flowDefinitionSchema.safeParse(data);
};

export const validateStateDetectionResult = (data: unknown) => {
  return stateDetectionResultSchema.safeParse(data);
};

export const validateUIGraph = (data: unknown) => {
  return uiGraphSchema.safeParse(data);
};

export const validateGraphIndex = (data: unknown) => {
  return graphIndexSchema.safeParse(data);
};

// Serialization helpers with validation
export const serializeScreenNode = (node: unknown): string => {
  const result = screenNodeSchema.parse(node);
  return JSON.stringify(result, null, 2);
};

export const serializeActionEdge = (edge: unknown): string => {
  const result = actionEdgeSchema.parse(edge);
  return JSON.stringify(result, null, 2);
};

export const serializeFlowDefinition = (flow: unknown): string => {
  const result = flowDefinitionSchema.parse(flow);
  return JSON.stringify(result, null, 2);
};

export const serializeUIGraph = (graph: unknown): string => {
  const result = uiGraphSchema.parse(graph);
  return JSON.stringify(result, null, 2);
};

export const serializeGraphIndex = (index: unknown): string => {
  const result = graphIndexSchema.parse(index);
  return JSON.stringify(result, null, 2);
};

// Parse helpers with validation
export const parseScreenNode = (json: string) => {
  try {
    const data = JSON.parse(json);
    return screenNodeSchema.parse(data);
  } catch (error) {
    throw new Error(`Invalid ScreenNode JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

export const parseActionEdge = (json: string) => {
  try {
    const data = JSON.parse(json);
    return actionEdgeSchema.parse(data);
  } catch (error) {
    throw new Error(`Invalid ActionEdge JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

export const parseFlowDefinition = (json: string) => {
  try {
    const data = JSON.parse(json);
    return flowDefinitionSchema.parse(data);
  } catch (error) {
    throw new Error(`Invalid FlowDefinition JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

export const parseUIGraph = (json: string) => {
  try {
    const data = JSON.parse(json);
    return uiGraphSchema.parse(data);
  } catch (error) {
    throw new Error(`Invalid UIGraph JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

// Type exports for convenience
export type ScreenNodeInput = z.infer<typeof screenNodeSchema>;
export type ActionEdgeInput = z.infer<typeof actionEdgeSchema>;
export type FlowDefinitionInput = z.infer<typeof flowDefinitionSchema>;
export type StateDetectionResultInput = z.infer<typeof stateDetectionResultSchema>;
export type UIGraphInput = z.infer<typeof uiGraphSchema>;
export type GraphIndexInput = z.infer<typeof graphIndexSchema>;