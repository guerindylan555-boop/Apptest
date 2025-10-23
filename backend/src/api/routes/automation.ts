import express from 'express';
import { getStartupLogs, getProxyCaptureLog } from '../../services/autoStartup';
import { logger } from '../../services/logger';
import { runUiDiscovery } from '../../services/uiDiscovery';

const router = express.Router();

/**
 * GET /automation/logs/startup
 * Get auto-startup logs
 */
router.get('/logs/startup', async (req, res) => {
  try {
    const logs = await getStartupLogs();
    res.type('text/plain').send(logs);
  } catch (error) {
    logger.error('Failed to get startup logs', { error });
    res.status(500).json({ error: 'Failed to retrieve startup logs' });
  }
});

/**
 * GET /automation/logs/proxy
 * Get proxy capture logs
 */
router.get('/logs/proxy', async (req, res) => {
  try {
    const logs = await getProxyCaptureLog();
    res.type('text/plain').send(logs);
  } catch (error) {
    logger.error('Failed to get proxy logs', { error });
    res.status(500).json({ error: 'Failed to retrieve proxy logs' });
  }
});

router.post('/ui-discovery/run', async (req, res) => {
  try {
    const result = await runUiDiscovery({
      serial: typeof req.body?.serial === 'string' ? req.body.serial : undefined,
      maxDepth:
        typeof req.body?.maxDepth === 'number' && Number.isFinite(req.body.maxDepth)
          ? Math.max(0, Math.floor(req.body.maxDepth))
          : undefined,
      maxActionsPerScreen:
        typeof req.body?.maxActionsPerScreen === 'number' && Number.isFinite(req.body.maxActionsPerScreen)
          ? Math.max(1, Math.floor(req.body.maxActionsPerScreen))
          : undefined
    });
    res.status(201).json(result);
  } catch (error) {
    logger.error('UI discovery run failed', { error: (error as Error).message });
    res.status(500).json({ error: { code: 'UI_DISCOVERY_FAILED', message: (error as Error).message } });
  }
});

export default router;
