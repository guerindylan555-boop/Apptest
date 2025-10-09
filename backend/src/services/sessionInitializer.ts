import { exec } from 'child_process';
import { promisify } from 'util';
import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import { ensureStreamer } from './streamerService';

const execAsync = promisify(exec);

/**
 * Check for already-running emulators and reconnect to them on backend startup.
 * This handles the case where the backend restarts but the emulator is still running.
 */
export const initializeSession = async (): Promise<void> => {
  try {
    // Check if there's a running emulator
    const { stdout } = await execAsync('adb devices');
    const lines = stdout.split('\n').slice(1); // Skip header line

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && trimmed.includes('emulator-') && trimmed.includes('\tdevice')) {
        const serial = trimmed.split('\t')[0];
        logger.info('Detected running emulator on startup', { serial });

        // Check if it's fully booted
        const { stdout: bootStatus } = await execAsync(`adb -s ${serial} shell getprop sys.boot_completed`);
        if (bootStatus.trim() === '1') {
          logger.info('Reconnecting to running emulator', { serial });

          // Extract ports from serial (format: emulator-<console_port>)
          const consolePort = parseInt(serial.split('-')[1], 10);
          const adbPort = consolePort + 1;

          // Update session state
          sessionStore.transition('Booting');
          sessionStore.setBootStarted(0, { console: consolePort, adb: adbPort });
          sessionStore.setBootCompleted();
          sessionStore.transition('Running', { streamToken: undefined });

          // Start the stream bridge
          await ensureStreamer(serial);

          logger.info('Successfully reconnected to emulator', { serial });
          return;
        }
      }
    }

    logger.info('No running emulator detected on startup');
  } catch (error) {
    logger.warn('Failed to check for running emulators on startup', { error: (error as Error).message });
  }
};
