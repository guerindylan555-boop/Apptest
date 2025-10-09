import type { Request, Response } from 'express';
import { stopEmulator } from '../../services/emulatorLifecycle';
import { sessionStore } from '../../state/sessionStore';
import { logger } from '../../services/logger';

export const emulatorStopHandler = async (req: Request, res: Response) => {
  const session = sessionStore.getSession();
  if (session.state === 'Stopped') {
    return res.status(200).json({ state: 'Stopped', message: 'Emulator already stopped' });
  }
  const force = Boolean(req.body?.force);

  logger.info('Stop request received', { force });

  try {
    await stopEmulator(force);
    return res.status(202).json({
      state: 'Stopping',
      message: force ? 'Force stop executed' : 'Stop sequence initiated'
    });
  } catch (error) {
    const message = (error as Error).message;
    if (message === 'Force stop required') {
      logger.warn('Force stop required', { force });
      return res.status(409).json({
        error: {
          code: 'FORCE_STOP_REQUIRED',
          message,
          hint: 'Re-run stop with { force: true } to terminate the emulator process.'
        }
      });
    }
    logger.error('emulator/stop failed', { error: message, force });
    return res.status(500).json({
      error: {
        code: 'STOP_FAILED',
        message
      }
    });
  }
};
