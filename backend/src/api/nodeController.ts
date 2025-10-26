/**
 * Node Controller
 *
 * Controller for managing individual screen node operations.
 * Provides CRUD operations for nodes with proper validation and error handling.
 */

import { Request, Response } from 'express';
import { graphStore } from '../services/graphStore';
import { captureService } from '../services/captureService';
import { artifactStorage } from '../services/artifactStore';
import { z } from 'zod';
import type { ScreenNode } from '../types/uiGraph';

// Validation schemas
const updateNodeSchema = z.object({
  name: z.string().min(3).max(80).optional(),
  hints: z.array(z.string()).max(10).optional(),
  status: z.enum(['active', 'deprecated', 'duplicate']).optional(),
  startStateTag: z.enum(['clean', 'logged_out_home', 'logged_in_no_rental', 'logged_in_with_rental', 'other']).optional(),
});

const searchNodesSchema = z.object({
  activity: z.string().optional(),
  nameContains: z.string().optional(),
  status: z.enum(['active', 'deprecated', 'duplicate']).optional(),
  startStateTag: z.enum(['clean', 'logged_out_home', 'logged_in_no_rental', 'logged_in_with_rental', 'other']).optional(),
  hasText: z.string().optional(),
  limit: z.number().int().min(1).max(100).optional(),
  offset: z.number().int().min(0).optional(),
});

/**
 * Get a single node by ID
 * GET /api/nodes/:id
 */
export const getNodeController = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const includeArtifacts = req.query.includeArtifacts === 'true';
    const validateArtifacts = req.query.validateArtifacts === 'true';

    // Validate node ID format
    if (!id || typeof id !== 'string' || id.length !== 32) {
      return res.status(400).json({
        success: false,
        error: 'Invalid node ID format. Expected 32-character hash.',
      });
    }

    // Get node from graph store
    const node = await graphStore.getNode(id);
    if (!node) {
      return res.status(404).json({
        success: false,
        error: `Node with ID ${id} not found`,
      });
    }

    let responseNode: any = { ...node };

    // Include artifact details if requested
    if (includeArtifacts) {
      try {
        const artifactBundle = await artifactStorage.loadBundle(id);
        if (artifactBundle) {
          responseNode.artifacts = {
            screenshotPath: artifactBundle.screenshotPath,
            xmlPath: artifactBundle.xmlPath,
            metadataPath: artifactBundle.metadataPath,
            checksum: artifactBundle.checksum,
            size: await artifactBundle.getTotalSize(),
          };
        }
      } catch (artifactError) {
        console.warn(`Failed to load artifacts for node ${id}:`, artifactError);
        responseNode.artifacts = null;
      }
    }

    // Validate artifacts if requested
    if (validateArtifacts) {
      try {
        const validation = await captureService.validateArtifacts(id);
        responseNode.validation = validation;
      } catch (validationError) {
        console.warn(`Failed to validate artifacts for node ${id}:`, validationError);
        responseNode.validation = {
          valid: false,
          issues: ['Validation failed'],
          checksumValid: false,
        };
      }
    }

    // Add related nodes information
    const incomingEdges = await graphStore.getIncomingEdges(id);
    const outgoingEdges = await graphStore.getOutgoingEdges(id);

    responseNode.related = {
      incomingEdges: incomingEdges.length,
      outgoingEdges: outgoingEdges.length,
      incomingEdgeIds: incomingEdges.map(e => e.id),
      outgoingEdgeIds: outgoingEdges.map(e => e.id),
    };

    res.json({
      success: true,
      data: responseNode,
    });
  } catch (error) {
    console.error('Failed to get node:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
};

/**
 * Update a node
 * PUT /api/nodes/:id
 */
export const updateNodeController = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const update = updateNodeSchema.parse(req.body);
    const operatorId = req.headers['x-operator-id'] as string || 'unknown';

    // Validate node ID format
    if (!id || typeof id !== 'string' || id.length !== 32) {
      return res.status(400).json({
        success: false,
        error: 'Invalid node ID format. Expected 32-character hash.',
      });
    }

    // Get existing node
    const existingNode = await graphStore.getNode(id);
    if (!existingNode) {
      return res.status(404).json({
        success: false,
        error: `Node with ID ${id} not found`,
      });
    }

    // Create updated node with only mutable fields
    const updatedNode: ScreenNode = {
      ...existingNode,
      name: update.name ?? existingNode.name,
      hints: update.hints ?? existingNode.hints,
      status: update.status ?? existingNode.status,
      startStateTag: update.startStateTag ?? existingNode.startStateTag,
      // Update metadata timestamp
      metadata: {
        ...existingNode.metadata,
        lastModifiedAt: new Date().toISOString(),
        lastModifiedBy: operatorId,
      },
    };

    // Store updated node
    await graphStore.updateNode(updatedNode);

    res.json({
      success: true,
      data: updatedNode,
      message: `Node ${updatedNode.name} updated successfully`,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request data',
        details: error.errors,
      });
    }

    console.error('Failed to update node:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
};

/**
 * Delete a node
 * DELETE /api/nodes/:id
 */
export const deleteNodeController = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const force = req.query.force === 'true';
    const operatorId = req.headers['x-operator-id'] as string || 'unknown';

    // Validate node ID format
    if (!id || typeof id !== 'string' || id.length !== 32) {
      return res.status(400).json({
        success: false,
        error: 'Invalid node ID format. Expected 32-character hash.',
      });
    }

    // Check if node exists
    const existingNode = await graphStore.getNode(id);
    if (!existingNode) {
      return res.status(404).json({
        success: false,
        error: `Node with ID ${id} not found`,
      });
    }

    // Check for dependencies unless force delete
    if (!force) {
      const incomingEdges = await graphStore.getIncomingEdges(id);
      const outgoingEdges = await graphStore.getOutgoingEdges(id);

      if (incomingEdges.length > 0 || outgoingEdges.length > 0) {
        return res.status(409).json({
          success: false,
          error: 'Cannot delete node with existing edges',
          details: {
            incomingEdges: incomingEdges.length,
            outgoingEdges: outgoingEdges.length,
            message: 'Use ?force=true to delete anyway and remove associated edges',
          },
        });
      }
    }

    // Delete artifacts
    try {
      await artifactStorage.deleteBundle(id);
    } catch (artifactError) {
      console.warn(`Failed to delete artifacts for node ${id}:`, artifactError);
      // Continue with node deletion even if artifacts fail
    }

    // Delete node from graph store (this should also remove edges)
    await graphStore.deleteNode(id);

    res.json({
      success: true,
      message: `Node ${existingNode.name} deleted successfully`,
      deletedNode: {
        id,
        name: existingNode.name,
        deletedBy: operatorId,
        deletedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error('Failed to delete node:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
};

/**
 * List nodes with filtering and pagination
 * GET /api/nodes
 */
export const listNodesController = async (req: Request, res: Response) => {
  try {
    const query = searchNodesSchema.parse(req.query);
    const limit = query.limit || 20;
    const offset = query.offset || 0;

    // Get all nodes from graph store
    const allNodes = await graphStore.getAllNodes();

    // Apply filters
    let filteredNodes = allNodes;

    if (query.activity) {
      filteredNodes = filteredNodes.filter(node =>
        node.signature.activity.toLowerCase().includes(query.activity!.toLowerCase())
      );
    }

    if (query.nameContains) {
      filteredNodes = filteredNodes.filter(node =>
        node.name.toLowerCase().includes(query.nameContains!.toLowerCase())
      );
    }

    if (query.status) {
      filteredNodes = filteredNodes.filter(node => node.status === query.status);
    }

    if (query.startStateTag) {
      filteredNodes = filteredNodes.filter(node => node.startStateTag === query.startStateTag);
    }

    if (query.hasText) {
      filteredNodes = filteredNodes.filter(node =>
        node.signature.requiredTexts.some(text =>
          text.toLowerCase().includes(query.hasText!.toLowerCase())
        ) ||
        node.hints.some(hint =>
          hint.toLowerCase().includes(query.hasText!.toLowerCase())
        )
      );
    }

    // Sort by capture timestamp (newest first)
    filteredNodes.sort((a, b) =>
      new Date(b.metadata.captureTimestamp).getTime() - new Date(a.metadata.captureTimestamp).getTime()
    );

    // Apply pagination
    const total = filteredNodes.length;
    const paginatedNodes = filteredNodes.slice(offset, offset + limit);

    // Add summary information for each node
    const nodesWithSummary = await Promise.all(
      paginatedNodes.map(async (node) => {
        const [incomingEdges, outgoingEdges] = await Promise.all([
          graphStore.getIncomingEdges(node.id),
          graphStore.getOutgoingEdges(node.id),
        ]);

        return {
          ...node,
          summary: {
            incomingEdges: incomingEdges.length,
            outgoingEdges: outgoingEdges.length,
            selectorCount: node.selectors.length,
            hasReliableSelectors: node.selectors.some(s => s.confidence >= 0.6),
            artifactSize: await artifactStorage.getBundleSize(node.id),
          },
        };
      })
    );

    res.json({
      success: true,
      data: {
        nodes: nodesWithSummary,
        pagination: {
          total,
          limit,
          offset,
          hasMore: offset + limit < total,
        },
      },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request parameters',
        details: error.errors,
      });
    }

    console.error('Failed to list nodes:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
};

/**
 * Get node statistics
 * GET /api/nodes/stats
 */
export const getNodeStatsController = async (req: Request, res: Response) => {
  try {
    const allNodes = await graphStore.getAllNodes();

    // Calculate statistics
    const stats = {
      total: allNodes.length,
      byStatus: {
        active: allNodes.filter(n => n.status === 'active').length,
        deprecated: allNodes.filter(n => n.status === 'deprecated').length,
        duplicate: allNodes.filter(n => n.status === 'duplicate').length,
      },
      byStartState: {
        clean: allNodes.filter(n => n.startStateTag === 'clean').length,
        logged_out_home: allNodes.filter(n => n.startStateTag === 'logged_out_home').length,
        logged_in_no_rental: allNodes.filter(n => n.startStateTag === 'logged_in_no_rental').length,
        logged_in_with_rental: allNodes.filter(n => n.startStateTag === 'logged_in_with_rental').length,
        other: allNodes.filter(n => n.startStateTag === 'other').length,
        none: allNodes.filter(n => !n.startStateTag).length,
      },
      averageSelectors: Math.round(
        allNodes.reduce((sum, node) => sum + node.selectors.length, 0) / (allNodes.length || 1)
      ),
      nodesWithReliableSelectors: allNodes.filter(n =>
        n.selectors.some(s => s.confidence >= 0.6)
      ).length,
      totalArtifactSize: 0,
      averageArtifactSize: 0,
    };

    // Calculate artifact sizes
    let totalArtifactSize = 0;
    for (const node of allNodes) {
      try {
        const size = await artifactStorage.getBundleSize(node.id);
        totalArtifactSize += size;
      } catch {
        // Skip if artifact size cannot be determined
      }
    }

    stats.totalArtifactSize = totalArtifactSize;
    stats.averageArtifactSize = allNodes.length > 0 ? Math.round(totalArtifactSize / allNodes.length) : 0;

    res.json({
      success: true,
      data: stats,
    });
  } catch (error) {
    console.error('Failed to get node statistics:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
};