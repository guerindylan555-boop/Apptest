import type { ChildProcess } from 'child_process';
import { spawn } from 'child_process';
import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import { getEmulatorSerial } from './emulatorLifecycle';

const STREAM_HOST = process.env.STREAM_HOST ?? '127.0.0.1';
const STREAM_PORT = Number.parseInt(process.env.STREAM_PORT ?? '8081', 10);

let streamerProcess: ChildProcess | undefined;

const buildStreamArgs = (serial: string) => [
  '--address',
  STREAM_HOST,
  '--port',
  String(STREAM_PORT),
  '--serial',
  serial,
  '--disable-control',
  '--codec-options',
  'profile=1,level=2'
];

export const ensureStreamer = (serial = getEmulatorSerial()) => {
  if (streamerProcess && !streamerProcess.killed) {
    return;
  }

  logger.info('Starting ws-scrcpy streamer', { port: STREAM_PORT });
  streamerProcess = spawn(process.env.SCRCPY_WEB ?? 'ws-scrcpy', buildStreamArgs(serial), {
    stdio: ['ignore', 'pipe', 'pipe']
  });

  streamerProcess.stdout?.on('data', (chunk) => {
    logger.info('ws-scrcpy stdout', { chunk: chunk.toString() });
  });

  streamerProcess.stderr?.on('data', (chunk) => {
    logger.warn('ws-scrcpy stderr', { chunk: chunk.toString() });
  });

  streamerProcess.on('exit', (code, signal) => {
    logger.warn('ws-scrcpy exited', { code, signal });
    streamerProcess = undefined;
  });
};

export const stopStreamer = () => {
  if (!streamerProcess) {
    return;
  }
  logger.info('Stopping ws-scrcpy process');
  streamerProcess.removeAllListeners('exit');
  streamerProcess.kill('SIGTERM');
  streamerProcess = undefined;
};

export const handleEmulatorStopped = () => {
  stopStreamer();
};

export const issueStreamTicket = () => {
  const session = sessionStore.getSession();
  if (session.state !== 'Running') {
    throw new Error('Stream tickets available only in Running state');
  }
  ensureStreamer();
  const record = sessionStore.generateStreamTicket(getEmulatorSerial());
  const url = `ws://${STREAM_HOST}:${STREAM_PORT}/stream/${record.token}`;
  return {
    token: record.token,
    url,
    expiresAt: new Date(record.expiresAt).toISOString()
  };
};

export const isStreamerActive = () => Boolean(streamerProcess && !streamerProcess.killed);
