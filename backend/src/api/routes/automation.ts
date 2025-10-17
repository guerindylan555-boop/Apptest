import express from 'express';
import { getStartupLogs, getProxyCaptureLog } from '../../services/autoStartup';
import { logger } from '../../services/logger';

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

export default router;
