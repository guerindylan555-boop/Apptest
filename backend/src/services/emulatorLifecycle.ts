import type { ChildProcess } from 'child_process';
import { readFileSync } from 'fs';
import * as net from 'net';
import { launchEmulator, adbWaitForDevice, adbGetProp, adbEmu, adb } from './androidCli';
import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import { handleEmulatorStopped } from './streamerService';
import type { EmulatorSession } from '../types/session';

const CONSOLE_PORT = Number.parseInt(process.env.EMULATOR_CONSOLE_PORT ?? '5554', 10);
const ADB_PORT = Number.parseInt(process.env.EMULATOR_ADB_PORT ?? '5555', 10);
const BOOT_TIMEOUT_MS = Number.parseInt(process.env.EMULATOR_BOOT_TIMEOUT_MS ?? '60000', 10);
const BOOT_POLL_INTERVAL_MS = 2_000;
const EMULATOR_SERIAL = `emulator-${CONSOLE_PORT}`;

let emulatorProcess: ChildProcess | undefined;
let discoveredSerial: string | undefined;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const findRunningEmulator = async (): Promise<string | null> => {
  try {
    const result = await adb(['devices']);
    const lines = result.stdout.split('\n').slice(1); // Skip header line
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && trimmed.includes('emulator-') && trimmed.includes('\tdevice')) {
        const serial = trimmed.split('\t')[0];
        logger.info('Found running emulator', { serial });
        return serial;
      }
    }
    return null;
  } catch (error) {
    logger.error('Failed to check for running emulators', { error: (error as Error).message });
    return null;
  }
};

const handleProcessExit = (code: number | null, signal: NodeJS.Signals | null) => {
  logger.warn('Emulator process exited', { code, signal });
  emulatorProcess = undefined;
  discoveredSerial = undefined;
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

  // First check if there's already a running emulator
  const runningSerial = await findRunningEmulator();
  if (runningSerial) {
    discoveredSerial = runningSerial;
    logger.info('Using existing running emulator', { serial: runningSerial });
    sessionStore.transition('Booting');

    try {
      // Check if the existing emulator is fully booted
      const propResult = await adbGetProp(runningSerial, 'sys.boot_completed');
      if (propResult.stdout.trim() === '1') {
        sessionStore.setBootCompleted();
        sessionStore.transition('Running', { streamToken: undefined });
        logger.info('Connected to already running emulator');
        return sessionStore.getSession();
      } else {
        // Wait for boot to complete
        const bootStart = Date.now();
        let bootCompleted = false;
        while (Date.now() - bootStart < BOOT_TIMEOUT_MS) {
          const propResult = await adbGetProp(runningSerial, 'sys.boot_completed');
          if (propResult.stdout.trim() === '1') {
            bootCompleted = true;
            break;
          }
          await delay(BOOT_POLL_INTERVAL_MS);
        }

        if (!bootCompleted) {
          throw new Error('Boot completion timed out for existing emulator');
        }

        sessionStore.setBootCompleted();
        sessionStore.transition('Running', { streamToken: undefined });
        logger.info('Existing emulator boot completed');
        return sessionStore.getSession();
      }
    } catch (error) {
      logger.error('Failed to use existing emulator', { error: (error as Error).message });
      discoveredSerial = undefined;
      sessionStore.recordError({
        code: 'BOOT_FAILED',
        message: (error as Error).message,
        hint: 'Existing emulator is not responding properly.',
        occurredAt: new Date().toISOString()
      });
      throw error;
    }
  }

  // No running emulator found, launch a new one
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
    '-no-snapshot-load',
    '-gpu',
    'swiftshader_indirect',
    '-no-audio',
    '-ports',
    `${CONSOLE_PORT},${ADB_PORT}`
  ];

  logger.info('Launching emulator', { args });

  emulatorProcess = launchEmulator(args, {
    env: process.env
  });

  // Store the serial for this emulator
  discoveredSerial = EMULATOR_SERIAL;

  const pid = emulatorProcess.pid ?? undefined;
  sessionStore.setBootStarted(pid ?? 0, { console: CONSOLE_PORT, adb: ADB_PORT });

  emulatorProcess.stdout?.on('data', (chunk) => {
    logger.debug('emulator stdout', { chunk: chunk.toString() });
  });

  emulatorProcess.stderr?.on('data', (chunk) => {
    logger.warn('emulator stderr', { chunk: chunk.toString() });
  });

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
    return sessionStore.getSession();
  } catch (error) {
    logger.error('Failed to start emulator', { error: (error as Error).message });
    emulatorProcess?.kill('SIGKILL');
    emulatorProcess = undefined;
    discoveredSerial = undefined;
    sessionStore.recordError({
      code: 'BOOT_FAILED',
      message: (error as Error).message,
      hint: 'Check emulator images and ensure Android SDK tools are installed.',
      occurredAt: new Date().toISOString()
    });
    throw error;
  }
};

export const getEmulatorSerial = async (): Promise<string> => {
  // Return discovered serial if we have it
  if (discoveredSerial) {
    return discoveredSerial;
  }
  // Try to find a running emulator
  const runningSerial = await findRunningEmulator();
  if (runningSerial) {
    discoveredSerial = runningSerial;
    return runningSerial;
  }
  // Fallback to the default serial
  return EMULATOR_SERIAL;
};

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

const processKill = () => {
  if (!emulatorProcess) {
    return true;
  }
  logger.warn('Force killing emulator process');
  emulatorProcess.kill('SIGKILL');
  emulatorProcess = undefined;
  return true;
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
    await handleEmulatorStopped();
    discoveredSerial = undefined;
    sessionStore.reset();
    sessionStore.clearForceStopFlag();
    logger.info('Emulator stopped');
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
