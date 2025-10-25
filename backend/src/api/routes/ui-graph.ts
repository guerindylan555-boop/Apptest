/**
 * UI Graph API Routes
 *
 * Express routes for UI graph operations including:
 * - Node creation and retrieval
 * - Action edge creation
 * - Graph download and management
 *
 * Follows OpenAPI contract: contracts/ui-map.openapi.yaml
 */

import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { nodeCaptureService } from '../../services/ui-graph/nodeCaptureService';
import { graphStore } from '../../services/ui-graph/graphStore';
import { validateScreenNodeInput, validateActionEdgeInput } from '../../utils/validation/uiGraphSchema';
import type { ScreenNode, ActionEdge } from '../../types/uiGraph';

const router = Router();

// Request validation schemas
const createNodeSchema = z.object({
  name: z.string().min(3).max(80),
  hints: z.array(z.string()).max(5).optional(),
  metadata: z.object({
    activity: z.string().optional(),
    package: z.string().optional(),
    emulatorBuild: z.string().optional(),
  }).optional(),
});

const createEdgeSchema = z.object({
  toNodeId: z.string().nullable(),
  action: z.object({
    kind: z.enum(['tap', 'type', 'wait', 'back', 'intent']),
    selectorId: z.string().optional(),
    text: z.string().optional(),
    keycode: z.number().int().min(0).max(255).optional(),
    delayMs: z.number().int().min(0).optional(),
  }),
  guard: z.object({
    mustMatchSignatureHash: z.string().optional(),
    requiredTexts: z.array(z.string()).optional(),
  }).optional(),
  notes: z.string().optional(),
});

// Middleware for extracting operator ID
const extractOperatorId = (req: Request): string => {
  return req.headers['x-operator-id'] as string ||
         req.body?.operatorId ||
         req.query?.operatorId as string ||
         'unknown-operator';
};

// POST /ui-graph/nodes - Capture a screen node
router.post('/nodes', async (req: Request, res: Response) => {
  try {
    const operatorId = extractOperatorId(req);
    const input = createNodeSchema.parse(req.body);

    console.log(`Creating node for operator: ${operatorId}`);

    // Capture node using the capture service
    const node = await nodeCaptureService.captureNode({
      name: input.name,
      hints: input.hints,
      operatorId,
      metadata: input.metadata,
    });

    // Store node in graph store
    await graphStore.addNode(node, `Node captured: ${node.name}`);

    res.status(201).json({
      success: true,
      data: node,
    });
  } catch (error) {
    console.error('Failed to create node:', error);
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// GET /ui-graph/nodes/:nodeId - Fetch a screen node
router.get('/nodes/:nodeId', async (req: Request, res: Response) => {
  try {
    const { nodeId } = req.params;

    const node = await graphStore.getNode(nodeId);
    if (!node) {
      return res.status(404).json({
        success: false,
        error: `Node ${nodeId} not found`,
      });
    }

    res.json({
      success: true,
      data: node,
    });
  } catch (error) {
    console.error('Failed to get node:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// PUT /ui-graph/nodes/:nodeId - Update node metadata
router.put('/nodes/:nodeId', async (req: Request, res: Response) => {
  try {
    const { nodeId } = req.params;
    const updateSchema = z.object({
      name: z.string().min(3).max(80).optional(),
      hints: z.array(z.string()).max(5).optional(),
      status: z.enum(['active', 'deprecated', 'duplicate']).optional(),
    });

    const update = updateSchema.parse(req.body);

    // Get existing node
    const existingNode = await graphStore.getNode(nodeId);
    if (!existingNode) {
      return res.status(404).json({
        success: false,
        error: `Node ${nodeId} not found`,
      });
    }

    // Update mutable fields
    const updatedNode: ScreenNode = {
      ...existingNode,
      name: update.name ?? existingNode.name,
      hints: update.hints ?? existingNode.hints,
      status: update.status ?? existingNode.status,
    };

    // Store updated node
    await graphStore.addNode(updatedNode, `Updated node: ${updatedNode.name}`);

    res.json({
      success: true,
      data: updatedNode,
    });
  } catch (error) {
    console.error('Failed to update node:', error);
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// POST /ui-graph/nodes/:nodeId/actions - Add an outgoing action edge
router.post('/nodes/:nodeId/actions', async (req: Request, res: Response) => {
  try {
    const { nodeId } = req.params;
    const operatorId = extractOperatorId(req);
    const input = createEdgeSchema.parse(req.body);

    // Verify from node exists
    const fromNode = await graphStore.getNode(nodeId);
    if (!fromNode) {
      return res.status(404).json({
        success: false,
        error: `Source node ${nodeId} not found`,
      });
    }

    // Verify to node exists if specified
    if (input.toNodeId) {
      const toNode = await graphStore.getNode(input.toNodeId);
      if (!toNode) {
        return res.status(404).json({
          success: false,
          error: `Target node ${input.toNodeId} not found`,
        });
      }
    }

    // Create action edge
    const edge: ActionEdge = {
      id: uuidv4(),
      fromNodeId: nodeId,
      toNodeId: input.toNodeId,
      action: input.action,
      guard: input.guard || {},
      notes: input.notes || '',
      createdAt: new Date().toISOString(),
      createdBy: operatorId,
      confidence: 1.0, // Initial confidence, will be updated based on success rate
    };

    // Store edge in graph store
    await graphStore.addEdge(edge, `Action added from node: ${nodeId}`);

    res.status(201).json({
      success: true,
      data: edge,
    });
  } catch (error) {
    console.error('Failed to create action edge:', error);
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// GET /ui-graph - Download the current UI graph snapshot
router.get('/', async (req: Request, res: Response) => {
  try {
    const includeArtifacts = req.query.includeArtifacts === 'true';

    const graph = await graphStore.getLatestGraph();
    if (!graph) {
      return res.status(404).json({
        success: false,
        error: 'No graph available',
      });
    }

    let responseGraph = graph;

    // Optionally include artifact paths and checksums
    if (includeArtifacts) {
      responseGraph = {
        ...graph,
        nodes: graph.nodes.map(node => ({
          ...node,
          artifacts: {
            screenshotPath: node.samples.screenshotPath,
            xmlPath: node.samples.xmlPath,
            metadataPath: node.samples.metadataPath,
            checksum: node.samples.checksum,
          },
        })),
      };
    }

    res.json({
      success: true,
      data: responseGraph,
    });
  } catch (error) {
    console.error('Failed to get graph:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// GET /ui-graph/versions - List available graph versions
router.get('/versions', async (req: Request, res: Response) => {
  try {
    const versions = await graphStore.listVersions();

    res.json({
      success: true,
      data: versions,
    });
  } catch (error) {
    console.error('Failed to list graph versions:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// GET /ui-graph/versions/:version - Get specific graph version
router.get('/versions/:version', async (req: Request, res: Response) => {
  try {
    const { version } = req.params;

    const graph = await graphStore.getGraph(version);
    if (!graph) {
      return res.status(404).json({
        success: false,
        error: `Graph version ${version} not found`,
      });
    }

    res.json({
      success: true,
      data: graph,
    });
  } catch (error) {
    console.error('Failed to get graph version:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// GET /ui-graph/search - Search nodes by criteria
router.get('/search', async (req: Request, res: Response) => {
  try {
    const searchSchema = z.object({
      activity: z.string().optional(),
      hasText: z.string().optional(),
      nameContains: z.string().optional(),
      status: z.enum(['active', 'deprecated', 'duplicate']).optional(),
    });

    const criteria = searchSchema.parse(req.query);

    const nodes = await graphStore.searchNodes(criteria);

    res.json({
      success: true,
      data: nodes,
    });
  } catch (error) {
    console.error('Failed to search nodes:', error);
    res.status(400).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// GET /ui-graph/edges/:edgeId - Get specific edge
router.get('/edges/:edgeId', async (req: Request, res: Response) => {
  try {
    const { edgeId } = req.params;

    const edge = await graphStore.getEdge(edgeId);
    if (!edge) {
      return res.status(404).json({
        success: false,
        error: `Edge ${edgeId} not found`,
      });
    }

    res.json({
      success: true,
      data: edge,
    });
  } catch (error) {
    console.error('Failed to get edge:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// Health check endpoint
router.get('/health', (req: Request, res: Response) => {
  res.json({
    success: true,
    service: 'ui-graph',
    timestamp: new Date().toISOString(),
  });
});

export default router;