import { spawnSync, type ChildProcess } from 'child_process';
import { readFileSync } from 'fs';
import net from 'net';
import { launchEmulator, adbGetProp, adbEmu, adb } from './androidCli';
import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import type { EmulatorSession } from '../types/session';
import { emulatorLogBuffer } from './logStreams';
import { attachProcessLoggers } from './logBuffer';

const CONSOLE_PORT = Number.parseInt(process.env.EMULATOR_CONSOLE_PORT ?? '5554', 10);
const ADB_PORT = Number.parseInt(process.env.EMULATOR_ADB_PORT ?? '5555', 10);
const ADB_SERVER_PORT = Number.parseInt(
  process.env.ADB_SERVER_PORT ?? process.env.ANDROID_ADB_SERVER_PORT ?? '5037',
  10
);
const ANDROID_SDK_ROOT = process.env.ANDROID_SDK_ROOT ?? '/opt/android-sdk';
const ANDROID_AVD_HOME = process.env.ANDROID_AVD_HOME ?? `${ANDROID_SDK_ROOT}/avd`;
const BOOT_TIMEOUT_MS = Number.parseInt(process.env.EMULATOR_BOOT_TIMEOUT_MS ?? '90000', 10);
const BOOT_POLL_INTERVAL_MS = 2_000;
const EXTERNAL_MODE = process.env.EXTERNAL_EMULATOR === 'true';
const EMULATOR_SERIAL = EXTERNAL_MODE
  ? `${process.env.EXTERNAL_EMULATOR_HOST ?? 'emulator'}:${process.env.EXTERNAL_EMULATOR_ADB_PORT ?? `${ADB_PORT}`}`
  : `emulator-${CONSOLE_PORT}`;
const EXTERNAL_EMULATOR_HOST = process.env.EXTERNAL_EMULATOR_HOST ?? 'emulator';
const EXTERNAL_EMULATOR_ADB_PORT = Number.parseInt(
  process.env.EXTERNAL_EMULATOR_ADB_PORT ?? `${ADB_PORT}`,
  10
);
const EXTERNAL_EMULATOR_CONSOLE_PORT = Number.parseInt(
  process.env.EXTERNAL_EMULATOR_CONSOLE_PORT ?? `${CONSOLE_PORT}`,
  10
);

let emulatorProcess: ChildProcess | undefined;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const cleanupEmulatorState = (avdName: string) => {
  logger.info('Performing pre-launch emulator cleanup');

  spawnSync('pkill', ['-f', 'emulator'], { stdio: 'ignore' });
  spawnSync('pkill', ['-9', '-f', 'emulator'], { stdio: 'ignore' });
  spawnSync('pkill', ['-f', 'qemu-system'], { stdio: 'ignore' });
  spawnSync('pkill', ['-9', '-f', 'qemu-system'], { stdio: 'ignore' });

  const avdDir = `${ANDROID_AVD_HOME}/${avdName}.avd`;
  const cleanupLocks = [
    `rm -f ${avdDir}/*.lock`,
    `rm -f ${avdDir}/hardware-qemu.ini.lock`,
    `rm -f ${avdDir}/snapshots/*.lock`,
    `rm -f ${avdDir}/cache.img.lock`,
    `rm -f ${avdDir}/multiinstance.lock`
  ].join(' && ');
  spawnSync('sh', ['-c', cleanupLocks], { stdio: 'ignore' });

  // Only disconnect old device connections, don't kill the server
  // The server will be restarted with verification in startEmulator
  spawnSync('adb', ['disconnect'], { stdio: 'ignore' });
  process.env.ANDROID_SERIAL = `emulator-${CONSOLE_PORT}`;
};

const ensureAdbServer = async () => {
  logger.info('Ensuring ADB server is running');
  const startServer = spawnSync('adb', ['start-server'], {
    encoding: 'utf8'
  });
  if (startServer.status !== 0) {
    logger.warn('adb start-server exited with non-zero code', {
      status: startServer.status,
      stderr: startServer.stderr?.toString().trim()
    });
  }

  await delay(2000);
  for (let attempt = 0; attempt < 5; attempt++) {
    const checkDevices = spawnSync('adb', ['devices'], { encoding: 'utf8' });
    if (checkDevices.status === 0) {
      logger.info('ADB server verified and responsive');
      return;
    }
    logger.warn(`ADB server not responding, retry ${attempt + 1}/5`);
    await delay(1000);
  }

  throw new Error('ADB server failed to start');
};

const connectToExternalEmulator = async () => {
  const target = `${EXTERNAL_EMULATOR_HOST}:${EXTERNAL_EMULATOR_ADB_PORT}`;
  logger.info('Connecting to external emulator', { target });

  await ensureAdbServer();

  const connectResult = spawnSync('adb', ['connect', target], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  if (connectResult.status === 0) {
    logger.info('adb connect succeeded', { output: connectResult.stdout?.trim() });
  } else {
    logger.warn('adb connect failed', {
      status: connectResult.status,
      stdout: connectResult.stdout?.trim(),
      stderr: connectResult.stderr?.trim()
    });
  }

  const start = Date.now();
  const deadline = 15_000;
  while (Date.now() - start < deadline) {
    const devices = spawnSync('adb', ['devices'], { encoding: 'utf8' });
    const stdout = devices.stdout ?? '';
    if (stdout.includes(`${target}\tdevice`)) {
      logger.info('External emulator reported as device', { serial: target });
      process.env.ANDROID_SERIAL = target;
      return;
    }
    await delay(1_000);
  }

  throw new Error(`External emulator at ${target} did not appear in adb devices`);
};

const handleProcessExit = (code: number | null, signal: NodeJS.Signals | null) => {
  logger.warn('Emulator process exited', { code, signal });
  emulatorProcess = undefined;
  emulatorLogBuffer.flushRemainder('[emulator]');
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

  // External emulator mode: emulator is already running on host
  if (EXTERNAL_MODE) {
    logger.info('External emulator mode enabled — connecting to existing instance', {
      host: EXTERNAL_EMULATOR_HOST,
      adbPort: EXTERNAL_EMULATOR_ADB_PORT
    });
    sessionStore.transition('Booting');
    sessionStore.setBootStarted(undefined, {
      console: EXTERNAL_EMULATOR_CONSOLE_PORT,
      adb: EXTERNAL_EMULATOR_ADB_PORT
    });
    await connectToExternalEmulator();
    sessionStore.setBootCompleted();
    sessionStore.transition('Running', { streamToken: undefined });
    logger.info('External emulator connection established');

    // Run startup automation for external emulator
    import('./autoStartup').then(({ runStartupAutomation }) => {
      logger.info('Starting auto-startup automation for external emulator...');
      runStartupAutomation().catch(error => {
        logger.error('Auto-startup automation failed for external emulator', { error: error.message });
      });
    }).catch(error => {
      logger.error('Failed to load auto-startup module for external emulator', { error: error.message });
    });

    return sessionStore.getSession();
  }

  cleanupEmulatorState(session.avdName);

  await ensureAdbServer();

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
    '-memory',
    '4096',
    '-cores',
    '4',
    '-gpu',
    'swiftshader_indirect',
    '-no-audio',
    '-no-metrics',
    '-netfast',
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
    await waitForEmulatorReady();

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

    // Run startup automation in background
    if (!EXTERNAL_MODE) {
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

const waitForEmulatorReady = async () => {
  await delay(5_000);
  const emulatorSerial = `emulator-${CONSOLE_PORT}`;

  // Connect ADB to the emulator's ADB port
  logger.info('Connecting ADB to emulator', { host: '127.0.0.1', port: ADB_PORT });
  const connectResult = spawnSync('adb', ['connect', `127.0.0.1:${ADB_PORT}`], {
    encoding: 'utf8',
    stdio: 'pipe'
  });
  if (connectResult.status === 0) {
    logger.info('ADB connect command succeeded', { output: connectResult.stdout?.trim() });
  } else {
    logger.warn('ADB connect command failed', {
      status: connectResult.status,
      stdout: connectResult.stdout?.trim(),
      stderr: connectResult.stderr?.trim()
    });
  }

  const start = Date.now();
  while (Date.now() - start < BOOT_TIMEOUT_MS) {
    const devicesResult = spawnSync('adb', ['devices'], { encoding: 'utf8' });
    const stdout = devicesResult.stdout ?? '';
    logger.debug('adb devices output', { stdout });

    if (stdout.includes(`${emulatorSerial}\toffline`)) {
      logger.info('ADB reports emulator offline; attempting reconnection');
      spawnSync('adb', ['reconnect', 'offline'], { stdio: 'ignore' });
      await delay(BOOT_POLL_INTERVAL_MS);
      continue;
    }

    if (stdout.includes(`${emulatorSerial}\tdevice`)) {
      logger.info('Emulator reported as online device', { serial: emulatorSerial });
      spawnSync('adb', ['-s', emulatorSerial, 'shell', 'settings', 'put', 'system', 'screen_off_timeout', '2147483647'], { stdio: 'ignore' });
      spawnSync('adb', ['-s', emulatorSerial, 'shell', 'logcat', '-G', '2M'], { stdio: 'ignore' });
      return;
    }

    await delay(BOOT_POLL_INTERVAL_MS);
  }

  throw new Error('ADB device did not reach online state in time');
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
  const avdName = session.avdName;
  if (session.state === 'Stopped') {
    return session;
  }
  if (session.state === 'Booting') {
    logger.warn('Stop requested while booting');
  }

  // External emulator mode: don't actually stop the host emulator
  if (EXTERNAL_MODE) {
    const target = `${EXTERNAL_EMULATOR_HOST}:${EXTERNAL_EMULATOR_ADB_PORT}`;
    logger.info('External emulator mode: disconnecting adb and marking session stopped', { target });
    spawnSync('adb', ['disconnect', target], { stdio: 'ignore' });
    sessionStore.reset();
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
    cleanupEmulatorState(avdName);
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
