import { Request, Response } from 'express';
import { getRecentActivity } from '../../../state/appsStore';

/**
 * Activity Feed Handler
 *
 * GET /apps/activity - Get recent activity log entries
 */

export async function activityHandler(req: Request, res: Response): Promise<void> {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
    const activity = getRecentActivity(Math.min(limit, 100)); // Cap at 100

    res.status(200).json(activity);
  } catch (error) {
    console.error('[ActivityHandler] Failed to fetch activity:', error);
    res.status(500).json({
      error: 'Failed to fetch activity',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}
