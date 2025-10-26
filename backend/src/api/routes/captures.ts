/**
 * Captures API Routes
 *
 * Routes for screen capture and action recording endpoints.
 * Handles UI graph node capture and action edge creation.
 */

import { Router } from 'express';
import {
  captureAction,
  batchCaptureAction,
  getAction,
  updateAction,
  deleteAction,
} from '../captureController';

const router = Router();

/**
 * POST /api/captures/action
 * Record an action and optionally execute it to capture destination
 */
router.post('/action', captureAction);

/**
 * POST /api/captures/action/batch
 * Create multiple actions in batch
 */
router.post('/action/batch', batchCaptureAction);

/**
 * GET /api/captures/action/:edgeId
 * Get action details
 */
router.get('/action/:edgeId', getAction);

/**
 * PUT /api/captures/action/:edgeId
 * Update action details
 */
router.put('/action/:edgeId', updateAction);

/**
 * DELETE /api/captures/action/:edgeId
 * Delete an action edge
 */
router.delete('/action/:edgeId', deleteAction);

export default router;