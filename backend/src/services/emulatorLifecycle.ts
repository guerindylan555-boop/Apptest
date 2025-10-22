import type { ChildProcess } from 'child_process';
import { readFileSync } from 'fs';
import net from 'net';
import { launchEmulator, adbWaitForDevice, adbGetProp, adbEmu, adb } from './androidCli';
import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import type { EmulatorSession } from '../types/session';
import { emulatorLogBuffer } from './logStreams';
import { attachProcessLoggers } from './logBuffer';
import { ensureStreamer, handleEmulatorStopped } from './streamerService';

const CONSOLE_PORT = Number.parseInt(process.env.EMULATOR_CONSOLE_PORT ?? '5554', 10);
const ADB_PORT = Number.parseInt(process.env.EMULATOR_ADB_PORT ?? '5555', 10);
const ADB_SERVER_PORT = Number.parseInt(
  process.env.ADB_SERVER_PORT ?? process.env.ANDROID_ADB_SERVER_PORT ?? '5555',
  10
);
const BOOT_TIMEOUT_MS = Number.parseInt(process.env.EMULATOR_BOOT_TIMEOUT_MS ?? '90000', 10);
const BOOT_POLL_INTERVAL_MS = 2_000;
const EMULATOR_SERIAL = `emulator-${CONSOLE_PORT}`;

let emulatorProcess: ChildProcess | undefined;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const handleProcessExit = (code: number | null, signal: NodeJS.Signals | null) => {
  logger.warn('Emulator process exited', { code, signal });
  emulatorProcess = undefined;
  emulatorLogBuffer.flushRemainder('[emulator]');
  handleEmulatorStopped().catch((error) => {
    logger.error('Failed to stop streamer after emulator exit', { error: (error as Error).message });
  });
  const current = sessionStore.getSession();
  if (current.state === 'Running' || current.state === 'Booting') {
    sessionStore.recordError({
      code: 'EMULATOR_EXIT',
      message: 'Emulator process exited unexpectedly',
      occurredAt: new Date().toISOString()
    });
  } else {
    sessionStore.reset();
  }
};

export const startEmulator = async (): Promise<EmulatorSession> => {
  const session = sessionStore.getSession();
  if (session.state === 'Booting' || session.state === 'Running' || session.state === 'Stopping') {
    throw new Error(`Cannot start emulator while in state ${session.state}`);
  }

  const startServerResult = await adb(['-P', ADB_SERVER_PORT.toString(), 'start-server']).catch(
    (error: Error) => {
      logger.error('Failed to start adb server', { error: error.message });
      throw error;
    }
  );
  if (startServerResult.code !== 0) {
    logger.warn('adb start-server exited with non-zero code', startServerResult);
  }

  // External emulator mode: emulator is already running on host
  const externalMode = process.env.EXTERNAL_EMULATOR === 'true';
  if (externalMode) {
    logger.info('External emulator mode: assuming emulator is already running');
    sessionStore.transition('Booting');
    sessionStore.setBootStarted(undefined, { console: CONSOLE_PORT, adb: ADB_PORT });
    sessionStore.setBootCompleted();
    sessionStore.transition('Running', { streamToken: undefined });
    logger.info('External emulator detected as running');
    return sessionStore.getSession();
  }

  if (emulatorProcess) {
    logger.warn('Emulator process handle exists; attempting restart');
    emulatorProcess.kill('SIGKILL');
    emulatorProcess = undefined;
  }

  sessionStore.transition('Booting');

  const args = [
    `@${session.avdName}`,
    '-no-window',
    '-no-boot-anim',
    '-no-snapshot',
    '-no-snapshot-load',
    '-no-metrics-collection',
    '-memory',
    '4096',
    '-gpu',
    'swiftshader_indirect',
    '-no-audio',
    '-writable-system',  // Allow system partition modifications
    '-ports',
    `${CONSOLE_PORT},${ADB_PORT}`
  ];

  logger.info('Launching emulator', { args });

  emulatorProcess = launchEmulator(args, {
    env: process.env
  });
  attachProcessLoggers(emulatorProcess, emulatorLogBuffer, 'emulator');

  const pid = emulatorProcess.pid ?? undefined;
  sessionStore.setBootStarted(pid ?? 0, { console: CONSOLE_PORT, adb: ADB_PORT });

  emulatorProcess.on('exit', handleProcessExit);

  try {
    const waitResult = await adbWaitForDevice(EMULATOR_SERIAL, { timeoutMs: BOOT_TIMEOUT_MS });
    if (waitResult.code !== 0) {
      throw new Error(`adb wait-for-device failed: ${waitResult.stderr}`);
    }

    const bootStart = Date.now();
    let bootCompleted = false;
    while (Date.now() - bootStart < BOOT_TIMEOUT_MS) {
      const propResult = await adbGetProp(EMULATOR_SERIAL, 'sys.boot_completed');
      if (propResult.stdout.trim() === '1') {
        bootCompleted = true;
        break;
      }
      await delay(BOOT_POLL_INTERVAL_MS);
    }

    if (!bootCompleted) {
      throw new Error('Boot completion timed out');
    }

    sessionStore.setBootCompleted();
    const updated = sessionStore.getSession();
    const bootStartedAt = updated.bootStartedAt ? new Date(updated.bootStartedAt).getTime() : Date.now();
    logger.info('Emulator boot duration', {
      ms: Date.now() - bootStartedAt
    });
    sessionStore.transition('Running', { streamToken: undefined });
    logger.info('Emulator boot completed');
    await ensureStreamer().catch((error) => {
      logger.error('Failed to start streamer', { error: (error as Error).message });
    });

    // Run startup automation in background
    if (!externalMode) {
      import('./autoStartup').then(({ runStartupAutomation }) => {
        logger.info('Starting auto-startup automation...');
        runStartupAutomation().catch(error => {
          logger.error('Auto-startup automation failed', { error: error.message });
        });
      }).catch(error => {
        logger.error('Failed to load auto-startup module', { error: error.message });
      });
    }

    return sessionStore.getSession();
  } catch (error) {
    logger.error('Failed to start emulator', { error: (error as Error).message });
    emulatorProcess?.kill('SIGKILL');
    emulatorProcess = undefined;
    emulatorLogBuffer.flushRemainder('[emulator]');
    await handleEmulatorStopped().catch(() => undefined);
    sessionStore.recordError({
      code: 'BOOT_FAILED',
      message: (error as Error).message,
      hint: 'Check emulator images and ensure Android SDK tools are installed.',
      occurredAt: new Date().toISOString()
    });
    throw error;
  }
};

export const getEmulatorSerial = () => EMULATOR_SERIAL;

export const getEmulatorProcess = () => emulatorProcess;

export const markHealthUnreachable = () => {
  sessionStore.markHealthUnreachable();
};

const readConsoleAuthToken = () => {
  try {
    const tokenPath = process.env.EMULATOR_CONSOLE_AUTH_TOKEN ??
      `${process.env.HOME ?? ''}/.emulator_console_auth_token`;
    return readFileSync(tokenPath, 'utf8').trim();
  } catch (error) {
    logger.warn('Unable to read emulator console auth token', { error: (error as Error).message });
    return undefined;
  }
};

const consoleKill = (): Promise<boolean> => {
  return new Promise((resolve) => {
    const socket = net.createConnection(CONSOLE_PORT, '127.0.0.1');
    let authenticated = false;
    const token = readConsoleAuthToken();

    const cleanup = (success: boolean) => {
      socket.removeAllListeners();
      socket.end();
      resolve(success);
    };

    socket.on('error', () => cleanup(false));

    socket.on('data', (buf) => {
      const message = buf.toString();
      if (!authenticated && token && message.includes('Authentication required')) {
        socket.write(`auth ${token}\n`);
      } else if (!authenticated && message.includes('OK')) {
        authenticated = true;
        socket.write('kill\n');
      } else if (message.includes('closed') || message.includes('disconnected')) {
        cleanup(true);
      }
    });

    setTimeout(() => cleanup(false), 3_000);
  });
};

const adbKill = async () => {
  const result = await adbEmu(EMULATOR_SERIAL, 'kill');
  return result.code === 0;
};

const killProcess = () => {
  if (!emulatorProcess) {
    return true;
  }
  logger.warn('Force killing emulator process');
  emulatorProcess.kill('SIGKILL');
  emulatorProcess = undefined;
  emulatorLogBuffer.flushRemainder('[emulator]');
  return true;
};

const processKill = () => {
  return killProcess();
};

const waitForShutdown = async () => {
  const start = Date.now();
  while (Date.now() - start < 15_000) {
    const result = await adbGetProp(EMULATOR_SERIAL, 'sys.boot_completed');
    if (result.code !== 0) {
      return true;
    }
    await delay(1_000);
  }
  return false;
};

export const stopEmulator = async (force = false): Promise<EmulatorSession> => {
  const session = sessionStore.getSession();
  if (session.state === 'Stopped') {
    return session;
  }
  if (session.state === 'Booting') {
    logger.warn('Stop requested while booting');
  }

  // External emulator mode: don't actually stop the host emulator
  const externalMode = process.env.EXTERNAL_EMULATOR === 'true';
  if (externalMode) {
    logger.info('External emulator mode: marking as stopped without killing host emulator');
    sessionStore.reset();
    await handleEmulatorStopped().catch((error) => {
      logger.error('Failed to stop streamer', { error: (error as Error).message });
    });
    return sessionStore.getSession();
  }

  sessionStore.markStopping();

  let success = false;

  if (!force) {
    if (await consoleKill()) {
      success = true;
    } else if (await adbKill()) {
      success = true;
    } else {
      sessionStore.requireForceStop('Invoke POST /emulator/stop with force=true to hard kill the emulator process.');
      throw new Error('Force stop required');
    }
  } else {
    success = processKill();
  }

  if (success) {
    await waitForShutdown().catch(() => undefined);
    sessionStore.reset();
    sessionStore.clearForceStopFlag();
    logger.info('Emulator stopped');
    await handleEmulatorStopped().catch((error) => {
      logger.error('Failed to stop streamer', { error: (error as Error).message });
    });
    return sessionStore.getSession();
  }

  const error = {
    code: 'STOP_FAILED',
    message: 'Unable to stop emulator',
    hint: 'Attempt manual kill via adb or verify console auth token.',
    occurredAt: new Date().toISOString()
  };
  sessionStore.recordError(error);
  throw new Error(error.message);
};
