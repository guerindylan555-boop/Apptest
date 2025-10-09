import type { Request, Response } from 'express';
import { startEmulator } from '../../services/emulatorLifecycle';
import { sessionStore } from '../../state/sessionStore';
import { logger } from '../../services/logger';

export const emulatorStartHandler = async (_req: Request, res: Response) => {
  const session = sessionStore.getSession();
  if (session.state === 'Booting' || session.state === 'Running' || session.state === 'Stopping') {
    const hint = session.state === 'Running'
      ? 'Emulator is already running. Use the stop endpoint first if needed.'
      : `Wait for the current operation to complete: ${session.state}`;

    return res.status(409).json({
      error: {
        code: 'INVALID_STATE',
        message: `Cannot start emulator while ${session.state.toLowerCase()}`,
        hint
      }
    });
  }

  try {
    await startEmulator();
    return res.status(202).json({ state: 'Booting', message: 'Emulator boot initiated' });
  } catch (error) {
    const message = (error as Error).message;
    logger.error('emulator/start failed', { error: message });

    // Provide specific hints based on common boot failure patterns
    let hint = 'Check emulator configuration and Android SDK setup.';
    if (message.includes('timeout')) {
      hint = 'Boot is taking too long. Try increasing EMULATOR_BOOT_TIMEOUT_MS or check system resources.';
    } else if (message.includes('AVD') || message.includes('image')) {
      hint = 'Verify the Android Virtual Device configuration and system images.';
    } else if (message.includes('port') || message.includes('5554')) {
      hint = 'Check if another emulator is using the console/ADB ports.';
    }

    return res.status(500).json({
      error: {
        code: 'BOOT_FAILED',
        message,
        hint
      }
    });
  }
};
