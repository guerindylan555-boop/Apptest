"use strict";
/**
 * Zod-based validation schemas for UI Graph types
 *
 * Provides runtime validation and serialization helpers for all
 * UI graph entities defined in the data model.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseUIGraph = exports.parseFlowDefinition = exports.parseActionEdge = exports.parseScreenNode = exports.serializeGraphIndex = exports.serializeUIGraph = exports.serializeFlowDefinition = exports.serializeActionEdge = exports.serializeScreenNode = exports.validateGraphIndex = exports.validateUIGraph = exports.validateStateDetectionResult = exports.validateFlowDefinition = exports.validateActionEdge = exports.validateScreenNode = exports.graphIndexSchema = exports.uiGraphSchema = exports.stateDetectionResultSchema = exports.flowDefinitionSchema = exports.recoveryRuleSchema = exports.flowStepSchema = exports.retryPolicySchema = exports.conditionSchema = exports.flowVariableSchema = exports.actionEdgeSchema = exports.guardSchema = exports.actionSchema = exports.screenNodeSchema = exports.artifactBundleSchema = exports.screenSignatureSchema = exports.selectorCandidateSchema = void 0;
const zod_1 = require("zod");
// Common utility schemas
const hexHashSchema = zod_1.z.string().regex(/^[a-f0-9]{16}$/, '16-character hex hash required');
const isoDateTimeSchema = zod_1.z.string().datetime({ offset: true });
const kebabCaseSchema = zod_1.z.string().regex(/^[a-z0-9-]+$/, 'kebab-case required');
const semverSchema = zod_1.z.string().regex(/^\d+\.\d+\.\d+$/, 'semantic version required');
// SelectorCandidate schema
exports.selectorCandidateSchema = zod_1.z.object({
    id: zod_1.z.string().min(1, 'Selector ID required'),
    type: zod_1.z.enum(['resource-id', 'content-desc', 'text', 'accessibility', 'xpath', 'coords']),
    value: zod_1.z.string().min(1, 'Selector value required'),
    confidence: zod_1.z.number().min(0).max(1),
    lastValidatedAt: isoDateTimeSchema,
});
// ScreenSignature schema
exports.screenSignatureSchema = zod_1.z.object({
    activity: zod_1.z.string().min(1, 'Activity name required'),
    resourceIds: zod_1.z.array(zod_1.z.string()).default([]),
    requiredTexts: zod_1.z.array(zod_1.z.string()).default([]),
    layoutFingerprint: zod_1.z.string().min(1, 'Layout fingerprint required'),
    hash: hexHashSchema,
    version: zod_1.z.number().int().min(0),
});
// ArtifactBundle schema
exports.artifactBundleSchema = zod_1.z.object({
    screenshotPath: zod_1.z.string().min(1, 'Screenshot path required'),
    xmlPath: zod_1.z.string().min(1, 'XML path required'),
    metadataPath: zod_1.z.string().optional(),
    checksum: zod_1.z.string().min(1, 'Checksum required'),
});
// ScreenNode schema
exports.screenNodeSchema = zod_1.z.object({
    id: hexHashSchema,
    name: zod_1.z.string().min(3).max(80, 'Name must be 3-80 characters'),
    signature: exports.screenSignatureSchema,
    selectors: zod_1.z.array(exports.selectorCandidateSchema).min(1, 'At least one selector required'),
    hints: zod_1.z.array(zod_1.z.string()).max(5, 'Maximum 5 hints allowed').default([]),
    samples: exports.artifactBundleSchema,
    metadata: zod_1.z.object({
        activity: zod_1.z.string().optional(),
        class: zod_1.z.string().optional(),
        package: zod_1.z.string().optional(),
        emulatorBuild: zod_1.z.string().optional(),
        captureTimestamp: isoDateTimeSchema,
        operatorId: zod_1.z.string().min(1, 'Operator ID required'),
    }),
    outgoingEdgeIds: zod_1.z.array(zod_1.z.string()).default([]),
    incomingEdgeIds: zod_1.z.array(zod_1.z.string()).default([]),
    status: zod_1.z.enum(['active', 'deprecated', 'duplicate']),
});
// Action schema (used in ActionEdge and FlowStep)
exports.actionSchema = zod_1.z.object({
    kind: zod_1.z.enum(['tap', 'type', 'wait', 'back', 'intent']),
    selectorId: zod_1.z.string().optional(),
    text: zod_1.z.string().optional(),
    keycode: zod_1.z.number().int().min(0).max(255).optional(),
    delayMs: zod_1.z.number().int().min(0).optional(),
});
// Guard schema
exports.guardSchema = zod_1.z.object({
    mustMatchSignatureHash: hexHashSchema.optional(),
    requiredTexts: zod_1.z.array(zod_1.z.string()).optional(),
});
// ActionEdge schema
exports.actionEdgeSchema = zod_1.z.object({
    id: zod_1.z.string().min(1, 'Edge ID required'),
    fromNodeId: hexHashSchema,
    toNodeId: hexHashSchema.nullable(),
    action: exports.actionSchema,
    guard: exports.guardSchema.default({}),
    notes: zod_1.z.string().default(''),
    createdAt: isoDateTimeSchema,
    createdBy: zod_1.z.string().min(1, 'Creator ID required'),
    confidence: zod_1.z.number().min(0).max(1),
});
// FlowVariable schema
exports.flowVariableSchema = zod_1.z.object({
    name: zod_1.z.string().min(1, 'Variable name required'),
    description: zod_1.z.string().min(1, 'Variable description required'),
    type: zod_1.z.enum(['string', 'number', 'boolean']),
    required: zod_1.z.boolean(),
    prompt: zod_1.z.string().min(1, 'Variable prompt required'),
});
// Precondition/Postcondition schema
exports.conditionSchema = zod_1.z.object({
    nodeId: hexHashSchema.optional(),
    query: zod_1.z.object({
        activity: zod_1.z.string().optional(),
        requiredTexts: zod_1.z.array(zod_1.z.string()).optional(),
    }).optional(),
}).refine((data) => data.nodeId || data.query, { message: 'Either nodeId or query must be specified' });
// RetryPolicy schema
exports.retryPolicySchema = zod_1.z.object({
    maxAttempts: zod_1.z.number().int().min(1).max(10),
    delayMs: zod_1.z.number().int().min(0).max(30000),
});
// FlowStep schema
exports.flowStepSchema = zod_1.z.object({
    kind: zod_1.z.enum(['edgeRef', 'inline']),
    edgeId: zod_1.z.string().optional(),
    inlineAction: exports.actionSchema.optional(),
    guard: exports.guardSchema.optional(),
    retryPolicy: exports.retryPolicySchema.optional(),
    expectNodeId: hexHashSchema.optional(),
}).refine((data) => (data.kind === 'edgeRef' && data.edgeId) ||
    (data.kind === 'inline' && data.inlineAction), { message: 'Step must have valid edgeId or inlineAction based on kind' });
// RecoveryRule schema
exports.recoveryRuleSchema = zod_1.z.object({
    trigger: zod_1.z.enum(['unexpected_node', 'system_dialog', 'timeout']),
    allowedActions: zod_1.z.array(zod_1.z.enum(['back', 'dismiss', 'reopen', 'relogin', 'wait'])).min(1),
});
// FlowDefinition schema
exports.flowDefinitionSchema = zod_1.z.object({
    name: kebabCaseSchema,
    description: zod_1.z.string().min(1, 'Description required').max(200),
    version: semverSchema,
    variables: zod_1.z.array(exports.flowVariableSchema).default([]),
    precondition: exports.conditionSchema,
    steps: zod_1.z.array(exports.flowStepSchema).min(1, 'At least one step required'),
    postcondition: exports.conditionSchema,
    recovery: zod_1.z.array(exports.recoveryRuleSchema).min(1, 'At least one recovery rule required'),
    metadata: zod_1.z.object({
        owner: zod_1.z.string().optional(),
        lastUpdatedAt: isoDateTimeSchema,
        validationStatus: zod_1.z.enum(['draft', 'validated', 'deprecated']),
        notes: zod_1.z.string().optional(),
    }),
});
// StateDetectionResult schema
exports.stateDetectionResultSchema = zod_1.z.object({
    timestamp: isoDateTimeSchema,
    dumpSource: zod_1.z.string().min(1, 'Dump source required'),
    topCandidates: zod_1.z.array(zod_1.z.object({
        nodeId: hexHashSchema,
        score: zod_1.z.number().min(0).max(100),
    })),
    selectedNodeId: hexHashSchema.optional(),
    status: zod_1.z.enum(['matched', 'ambiguous', 'unknown']),
    operatorAction: zod_1.z.enum(['accept', 'map_new', 'merge', 'retry']).optional(),
});
// UIGraph schema
exports.uiGraphSchema = zod_1.z.object({
    metadata: zod_1.z.object({
        version: zod_1.z.string(),
        lastUpdated: isoDateTimeSchema,
        checksum: zod_1.z.string(),
        totalNodes: zod_1.z.number().int().min(0),
        totalEdges: zod_1.z.number().int().min(0),
    }),
    nodes: zod_1.z.array(exports.screenNodeSchema),
    edges: zod_1.z.array(exports.actionEdgeSchema),
});
// GraphIndex schema
exports.graphIndexSchema = zod_1.z.object({
    metadata: zod_1.z.object({
        version: zod_1.z.string(),
        lastUpdated: isoDateTimeSchema,
        checksum: zod_1.z.string(),
        totalNodes: zod_1.z.number().int().min(0),
        totalEdges: zod_1.z.number().int().min(0),
    }),
    nodes: zod_1.z.array(hexHashSchema),
    edges: zod_1.z.array(zod_1.z.string()),
    graphs: zod_1.z.array(zod_1.z.object({
        version: zod_1.z.string(),
        timestamp: isoDateTimeSchema,
        path: zod_1.z.string(),
        checksum: zod_1.z.string(),
        description: zod_1.z.string(),
    })),
});
// Validation helper functions
const validateScreenNode = (data) => {
    return exports.screenNodeSchema.safeParse(data);
};
exports.validateScreenNode = validateScreenNode;
const validateActionEdge = (data) => {
    return exports.actionEdgeSchema.safeParse(data);
};
exports.validateActionEdge = validateActionEdge;
const validateFlowDefinition = (data) => {
    return exports.flowDefinitionSchema.safeParse(data);
};
exports.validateFlowDefinition = validateFlowDefinition;
const validateStateDetectionResult = (data) => {
    return exports.stateDetectionResultSchema.safeParse(data);
};
exports.validateStateDetectionResult = validateStateDetectionResult;
const validateUIGraph = (data) => {
    return exports.uiGraphSchema.safeParse(data);
};
exports.validateUIGraph = validateUIGraph;
const validateGraphIndex = (data) => {
    return exports.graphIndexSchema.safeParse(data);
};
exports.validateGraphIndex = validateGraphIndex;
// Serialization helpers with validation
const serializeScreenNode = (node) => {
    const result = exports.screenNodeSchema.parse(node);
    return JSON.stringify(result, null, 2);
};
exports.serializeScreenNode = serializeScreenNode;
const serializeActionEdge = (edge) => {
    const result = exports.actionEdgeSchema.parse(edge);
    return JSON.stringify(result, null, 2);
};
exports.serializeActionEdge = serializeActionEdge;
const serializeFlowDefinition = (flow) => {
    const result = exports.flowDefinitionSchema.parse(flow);
    return JSON.stringify(result, null, 2);
};
exports.serializeFlowDefinition = serializeFlowDefinition;
const serializeUIGraph = (graph) => {
    const result = exports.uiGraphSchema.parse(graph);
    return JSON.stringify(result, null, 2);
};
exports.serializeUIGraph = serializeUIGraph;
const serializeGraphIndex = (index) => {
    const result = exports.graphIndexSchema.parse(index);
    return JSON.stringify(result, null, 2);
};
exports.serializeGraphIndex = serializeGraphIndex;
// Parse helpers with validation
const parseScreenNode = (json) => {
    try {
        const data = JSON.parse(json);
        return exports.screenNodeSchema.parse(data);
    }
    catch (error) {
        throw new Error(`Invalid ScreenNode JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
};
exports.parseScreenNode = parseScreenNode;
const parseActionEdge = (json) => {
    try {
        const data = JSON.parse(json);
        return exports.actionEdgeSchema.parse(data);
    }
    catch (error) {
        throw new Error(`Invalid ActionEdge JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
};
exports.parseActionEdge = parseActionEdge;
const parseFlowDefinition = (json) => {
    try {
        const data = JSON.parse(json);
        return exports.flowDefinitionSchema.parse(data);
    }
    catch (error) {
        throw new Error(`Invalid FlowDefinition JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
};
exports.parseFlowDefinition = parseFlowDefinition;
const parseUIGraph = (json) => {
    try {
        const data = JSON.parse(json);
        return exports.uiGraphSchema.parse(data);
    }
    catch (error) {
        throw new Error(`Invalid UIGraph JSON: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
};
exports.parseUIGraph = parseUIGraph;
