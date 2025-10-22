import type { Request, Response } from 'express';
import { stopEmulator, startEmulator } from '../../services/emulatorLifecycle';
import { sessionStore } from '../../state/sessionStore';
import { logger } from '../../services/logger';

export const emulatorRestartHandler = async (_req: Request, res: Response) => {
  const current = sessionStore.getSession();
  if (current.state === 'Booting') {
    return res.status(409).json({
      error: {
        code: 'INVALID_STATE',
        message: 'Cannot restart while emulator is booting'
      }
    });
  }

  try {
    try {
      await stopEmulator(false);
    } catch (error) {
      const message = (error as Error).message;
      if (message === 'Force stop required') {
        logger.warn('Graceful stop failed during restart; forcing termination');
        await stopEmulator(true);
      } else {
        throw error;
      }
    }

    await startEmulator();

    return res.status(202).json({
      state: 'Booting',
      message: 'Restart sequence initiated'
    });
  } catch (error) {
    logger.error('emulator/restart failed', { error: (error as Error).message });
    return res.status(500).json({
      error: {
        code: 'RESTART_FAILED',
        message: (error as Error).message
      }
    });
  }
};
