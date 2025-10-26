/**
 * Nodes API Routes
 *
 * Express routes for individual node operations including:
 * - CRUD operations for screen nodes
 * - Node search and filtering
 * - Artifact management
 * - Node statistics
 */

import { Router } from 'express';
import {
  getNodeController,
  updateNodeController,
  deleteNodeController,
  listNodesController,
  getNodeStatsController,
} from '../nodeController';

const router = Router();

// GET /nodes - List nodes with filtering and pagination
router.get('/', listNodesController);

// GET /nodes/stats - Get node statistics
router.get('/stats', getNodeStatsController);

// GET /nodes/:id - Get a specific node
router.get('/:id', getNodeController);

// PUT /nodes/:id - Update a node
router.put('/:id', updateNodeController);

// DELETE /nodes/:id - Delete a node
router.delete('/:id', deleteNodeController);

export default router;