import { Request, Response } from 'express';
import * as appsRepo from '../../../services/apps/appsRepository';

/**
 * Update Handler for APK Entries
 *
 * PATCH /apps/:id - Update display name or pin state
 */

export async function updateHandler(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const { displayName, pinned } = req.body;

    const existing = appsRepo.getEntryById(id);
    if (!existing) {
      res.status(404).json({ error: 'APK entry not found' });
      return;
    }

    // Build update object
    const updates: { displayName?: string; pinned?: boolean } = {};
    if (displayName !== undefined) {
      updates.displayName = String(displayName);
    }
    if (pinned !== undefined) {
      updates.pinned = Boolean(pinned);
    }

    // Apply updates
    const updated = await appsRepo.updateEntry(id, updates);

    if (!updated) {
      res.status(404).json({ error: 'APK entry not found' });
      return;
    }

    res.status(200).json(updated);
  } catch (error) {
    console.error('[UpdateHandler] Failed to update APK entry:', error);
    res.status(500).json({
      error: 'Failed to update APK entry',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}
