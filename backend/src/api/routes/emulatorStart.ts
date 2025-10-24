import type { Request, Response } from 'express';
import { startEmulator } from '../../services/emulatorLifecycle';
import { sessionStore } from '../../state/sessionStore';
import { logger } from '../../services/logger';

const EXTERNAL_MODE = process.env.EXTERNAL_EMULATOR === 'true';

export const emulatorStartHandler = async (_req: Request, res: Response) => {
  const session = sessionStore.getSession();
  if (EXTERNAL_MODE && session.state === 'Running') {
    return res.status(200).json({
      state: 'Running',
      message: 'External emulator is already running'
    });
  }
  if (session.state === 'Booting' || session.state === 'Running' || session.state === 'Stopping') {
    return res.status(409).json({
      error: {
        code: 'INVALID_STATE',
        message: `Cannot start emulator while ${session.state.toLowerCase()}`
      }
    });
  }

  try {
    await startEmulator();
    return res.status(202).json({ state: 'Booting', message: 'Emulator boot initiated' });
  } catch (error) {
    logger.error('emulator/start failed', { error: (error as Error).message });
    return res.status(500).json({
      error: {
        code: 'BOOT_FAILED',
        message: (error as Error).message
      }
    });
  }
};
