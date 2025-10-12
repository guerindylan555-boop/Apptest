import { Request, Response } from 'express';
import * as proxyService from '../../../services/apps/proxyService';
import * as appsStore from '../../../state/appsStore';
import type { ProxyToggleRequest } from '../../../types/apps';

/**
 * Proxy Routes
 *
 * Controls HTTP proxy settings on the emulator
 */

/**
 * POST /proxy/toggle - Enable or disable proxy
 */
export async function toggleProxyHandler(req: Request, res: Response): Promise<void> {
  try {
    const body: ProxyToggleRequest = req.body;

    const result = body.enabled
      ? await proxyService.enableProxy(body.host || '127.0.0.1', body.port || 8080)
      : await proxyService.disableProxy();

    // Log activity
    await appsStore.logActivity({
      type: 'proxy',
      message: result.message,
      entityId: null,
      metadata: { enabled: body.enabled, host: body.host, port: body.port }
    });

    if (!result.success) {
      res.status(400).json({ error: result.message });
      return;
    }

    const state = proxyService.getProxyState();
    res.status(200).json(state);
  } catch (error) {
    console.error('[ProxyRoutes] Failed to toggle proxy:', error);
    res.status(500).json({
      error: 'Failed to toggle proxy',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * GET /proxy/status - Get current proxy state
 */
export async function proxyStatusHandler(req: Request, res: Response): Promise<void> {
  try {
    const state = proxyService.getProxyState();
    res.status(200).json(state);
  } catch (error) {
    console.error('[ProxyRoutes] Failed to get proxy status:', error);
    res.status(500).json({
      error: 'Failed to get proxy status',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}
