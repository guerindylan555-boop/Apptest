import { Request, Response } from 'express';
import { isFridaEnabled } from '../../../config';
import * as fridaController from '../../../services/apps/fridaController';
import * as appsStore from '../../../state/appsStore';
import type { FridaServerRequest, FridaAttachRequest } from '../../../types/apps';

/**
 * Frida Routes
 *
 * Feature-flagged routes for Frida instrumentation.
 * Requires ENABLE_FRIDA=true environment variable.
 */

/**
 * Middleware to check if Frida is enabled
 */
function checkFridaEnabled(req: Request, res: Response, next: Function): void {
  if (!isFridaEnabled()) {
    res.status(403).json({
      error: 'Frida features are disabled',
      message: 'Set ENABLE_FRIDA=true to enable Frida instrumentation'
    });
    return;
  }
  next();
}

/**
 * POST /frida/server - Start or stop frida-server
 */
export async function fridaServerHandler(req: Request, res: Response): Promise<void> {
  try {
    const body: FridaServerRequest = req.body;
    const action = body.action;

    if (action !== 'start' && action !== 'stop') {
      res.status(400).json({ error: 'Invalid action. Must be "start" or "stop"' });
      return;
    }

    const result = action === 'start'
      ? await fridaController.startFridaServer()
      : await fridaController.stopFridaServer();

    // Log activity
    await appsStore.logFrida(
      action,
      null,
      result.success ? 'success' : 'failed',
      result.message
    );

    if (!result.success) {
      res.status(400).json({ error: result.message });
      return;
    }

    const state = fridaController.getSessionState();
    res.status(200).json(state);
  } catch (error) {
    console.error('[FridaRoutes] Server control failed:', error);
    res.status(500).json({
      error: 'Frida server control failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * GET /frida/server - Get frida-server status
 */
export async function fridaServerStatusHandler(req: Request, res: Response): Promise<void> {
  try {
    const state = fridaController.getSessionState();
    res.status(200).json(state);
  } catch (error) {
    console.error('[FridaRoutes] Failed to get status:', error);
    res.status(500).json({
      error: 'Failed to get Frida status',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * POST /frida/attach - Attach to a process and optionally load script
 */
export async function fridaAttachHandler(req: Request, res: Response): Promise<void> {
  try {
    const body: FridaAttachRequest = req.body;
    const { packageName, scriptPath } = body;

    if (!packageName) {
      res.status(400).json({ error: 'packageName is required' });
      return;
    }

    const result = await fridaController.attachToProcess(packageName, scriptPath);

    // Log activity
    await appsStore.logFrida(
      'attach',
      packageName,
      result.success ? 'success' : 'failed',
      result.message
    );

    if (!result.success) {
      res.status(400).json({
        status: 'failed',
        message: result.message,
        scriptPath: null
      });
      return;
    }

    res.status(200).json({
      status: 'attached',
      message: result.message,
      scriptPath: scriptPath || null
    });
  } catch (error) {
    console.error('[FridaRoutes] Attach failed:', error);
    res.status(500).json({
      error: 'Frida attach failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * POST /frida/detach - Detach from current process
 */
export async function fridaDetachHandler(req: Request, res: Response): Promise<void> {
  try {
    const result = await fridaController.detach();

    // Log activity
    await appsStore.logFrida(
      'detach',
      null,
      result.success ? 'success' : 'failed',
      result.message
    );

    res.status(200).json({ message: result.message });
  } catch (error) {
    console.error('[FridaRoutes] Detach failed:', error);
    res.status(500).json({
      error: 'Frida detach failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * GET /frida/processes - List running processes
 */
export async function fridaProcessesHandler(req: Request, res: Response): Promise<void> {
  try {
    const processes = await fridaController.listProcesses();
    res.status(200).json({ processes });
  } catch (error) {
    console.error('[FridaRoutes] Failed to list processes:', error);
    res.status(500).json({
      error: 'Failed to list processes',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

// Export middleware
export { checkFridaEnabled };
