import { Request, Response } from 'express';
import * as logcatService from '../../../services/apps/logcatService';
import * as appsStore from '../../../state/appsStore';
import type { LogcatStartRequest, LogcatControlRequest } from '../../../types/apps';

/**
 * Logcat Routes
 *
 * Manages logcat capture sessions
 */

/**
 * POST /logcat/sessions - Start a new logcat capture
 */
export async function startLogcatHandler(req: Request, res: Response): Promise<void> {
  try {
    const body: LogcatStartRequest = req.body;

    const capture = await logcatService.startCapture({
      packages: body.packageFilters,
      tags: body.tagFilters
    });

    // Log activity
    const filterDesc = [
      ...(body.packageFilters || []).map(p => `pkg:${p}`),
      ...(body.tagFilters || []).map(t => `tag:${t}`)
    ].join(', ');

    await appsStore.logActivity({
      type: 'logcat',
      message: `Started logcat capture${filterDesc ? ` (${filterDesc})` : ''}`,
      entityId: capture.id
    });

    res.status(201).json(capture);
  } catch (error) {
    console.error('[LogcatRoutes] Failed to start capture:', error);
    res.status(500).json({
      error: 'Failed to start logcat capture',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * PATCH /logcat/sessions/:id - Control a logcat session (pause/resume/stop)
 */
export async function controlLogcatHandler(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const body: LogcatControlRequest = req.body;

    let capture;
    switch (body.action) {
      case 'pause':
        capture = await logcatService.pauseCapture(id);
        break;
      case 'resume':
        capture = await logcatService.resumeCapture(id);
        break;
      case 'stop':
        capture = await logcatService.stopCapture(id);
        await appsStore.logActivity({
          type: 'logcat',
          message: 'Stopped logcat capture',
          entityId: id
        });
        break;
      default:
        res.status(400).json({ error: 'Invalid action' });
        return;
    }

    if (!capture) {
      res.status(404).json({ error: 'Capture session not found' });
      return;
    }

    res.status(200).json(capture);
  } catch (error) {
    console.error('[LogcatRoutes] Failed to control capture:', error);
    res.status(500).json({
      error: 'Failed to control logcat session',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * GET /logcat/sessions/:id - Download captured logs
 */
export async function downloadLogcatHandler(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;

    const content = await logcatService.readCaptureFile(id);
    if (!content) {
      res.status(404).json({ error: 'Capture file not found' });
      return;
    }

    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="logcat-${id}.txt"`);
    res.status(200).send(content);
  } catch (error) {
    console.error('[LogcatRoutes] Failed to download capture:', error);
    res.status(500).json({
      error: 'Failed to download logcat capture',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * GET /logcat/sessions - List all capture sessions
 */
export async function listLogcatHandler(req: Request, res: Response): Promise<void> {
  try {
    const captures = logcatService.getAllCaptures();
    res.status(200).json(captures);
  } catch (error) {
    console.error('[LogcatRoutes] Failed to list captures:', error);
    res.status(500).json({
      error: 'Failed to list logcat sessions',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}
