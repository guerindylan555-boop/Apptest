import { Request, Response } from 'express';
import * as appsRepo from '../../../services/apps/appsRepository';

/**
 * Delete Handler for APK Entries
 *
 * DELETE /apps/:id - Remove APK entry and all associated artifacts
 */

export async function deleteHandler(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;

    const existing = appsRepo.getEntryById(id);
    if (!existing) {
      res.status(404).json({ error: 'APK entry not found' });
      return;
    }

    // Prevent deletion of pinned entries (safety check)
    if (existing.pinned) {
      res.status(400).json({
        error: 'Cannot delete pinned entry',
        message: 'Unpin the entry before deleting'
      });
      return;
    }

    const deleted = await appsRepo.deleteEntry(id);

    if (!deleted) {
      res.status(404).json({ error: 'APK entry not found' });
      return;
    }

    res.status(204).send();
  } catch (error) {
    console.error('[DeleteHandler] Failed to delete APK entry:', error);
    res.status(500).json({
      error: 'Failed to delete APK entry',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}
