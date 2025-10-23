import type { Request, Response } from 'express';
import { stopEmulator } from '../../services/emulatorLifecycle';
import { sessionStore } from '../../state/sessionStore';
import { logger } from '../../services/logger';

const EXTERNAL_MODE = process.env.EXTERNAL_EMULATOR === 'true';

export const emulatorStopHandler = async (req: Request, res: Response) => {
  if (EXTERNAL_MODE) {
    return res.status(405).json({
      error: {
        code: 'UNSUPPORTED_OPERATION',
        message: 'Stop is disabled; the external emulator runs continuously.'
      }
    });
  }
  const session = sessionStore.getSession();
  if (session.state === 'Stopped') {
    return res.status(200).json({ state: 'Stopped', message: 'Emulator already stopped' });
  }
  const force = Boolean(req.body?.force);

  try {
    await stopEmulator(force);
    return res.status(202).json({ state: 'Stopping', message: force ? 'Force stop executed' : 'Stop sequence initiated' });
  } catch (error) {
    const message = (error as Error).message;
    if (message === 'Force stop required') {
      return res.status(409).json({
        error: {
          code: 'FORCE_STOP_REQUIRED',
          message,
          hint: 'Re-run stop with { force: true } to terminate the emulator process.'
        }
      });
    }
    logger.error('emulator/stop failed', { error: message });
    return res.status(500).json({
      error: {
        code: 'STOP_FAILED',
        message
      }
    });
  }
};
