import { spawn, type ChildProcess } from 'child_process';
import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import { streamConfig } from '../config/stream';
import { streamerLogBuffer } from './logStreams';
import { attachProcessLoggers } from './logBuffer';

type StreamTicketOptions = {
  requestHost?: string;
  protocol?: string;
};

const PLACEHOLDER_HOSTS = new Set(['127.0.0.1', '0.0.0.0', 'localhost', 'host.docker.internal']);
const DEFAULT_HTTP_PORT = 80;
const DEFAULT_HTTPS_PORT = 443;

const CONSOLE_PORT = Number.parseInt(process.env.EMULATOR_CONSOLE_PORT ?? '5554', 10);
const EMULATOR_SERIAL = `emulator-${CONSOLE_PORT}`;
const STREAM_PORT = Number.parseInt(process.env.WS_SCRCPY_PORT ?? streamConfig.port.toString(), 10);
const STREAMER_BIN = process.env.WS_SCRCPY_BIN ?? 'ws-scrcpy';
const STREAMER_CWD = process.env.WS_SCRCPY_CWD;
const ADB_SERVER_PORT = process.env.ADB_SERVER_PORT ?? process.env.ANDROID_ADB_SERVER_PORT ?? '5555';
const ADB_SERVER_HOST = process.env.ADB_SERVER_HOST ?? '127.0.0.1';

let streamerProcess: ChildProcess | undefined;
let startPromise: Promise<void> | null = null;

const parseHostHeader = (value?: string) => {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }

  if (trimmed.startsWith('[')) {
    const closingIndex = trimmed.indexOf(']');
    if (closingIndex > 0) {
      return trimmed.slice(1, closingIndex);
    }
  }

  return trimmed.split(':')[0];
};

const resolveStreamHost = (requestHost?: string) => {
  const configuredHost = (process.env.WS_SCRCPY_HOST ?? streamConfig.host)?.toString().trim();
  const fallbackHost = parseHostHeader(requestHost);

  if (!configuredHost || PLACEHOLDER_HOSTS.has(configuredHost)) {
    return fallbackHost ?? configuredHost ?? '127.0.0.1';
  }

  return configuredHost;
};

const resolveStreamPort = () => STREAM_PORT.toString();

const normaliseProtocol = (value?: string) => {
  if (!value) {
    return 'http';
  }
  const lower = value.replace(/:$/, '').toLowerCase();
  return lower === 'https' ? 'https' : 'http';
};

const buildHttpUrl = (protocol: string, host: string, port: string, hash: string) => {
  const numericPort = Number.parseInt(port, 10);
  const omitPort =
    (protocol === 'http' && numericPort === DEFAULT_HTTP_PORT) ||
    (protocol === 'https' && numericPort === DEFAULT_HTTPS_PORT);
  const authority = omitPort ? host : `${host}:${port}`;
  if (!hash) {
    return `${protocol}://${authority}/`;
  }
  return `${protocol}://${authority}/#!${hash}`;
};

const buildWsUrl = (protocol: string, host: string, port: string) => {
  const wsProtocol = protocol === 'https' ? 'wss' : 'ws';
  return new URL(`${wsProtocol}://${host}:${port}/`);
};

const resolvePlayer = (protocol: string, host: string) => {
  const configured =
    process.env.WS_SCRCPY_PLAYER?.trim() || streamConfig.player?.toString().trim() || 'webcodecs';

  if (process.env.WS_SCRCPY_PLAYER) {
    return configured;
  }

  const secureContext = protocol === 'https' || PLACEHOLDER_HOSTS.has(host);

  if (!secureContext && configured === 'webcodecs') {
    return 'tinyh264';
  }

  return configured;
};

const spawnStreamer = () =>
  new Promise<void>((resolve, reject) => {
    if (streamerProcess && !streamerProcess.killed) {
      resolve();
      return;
    }

    logger.info('Starting ws-scrcpy streamer', {
      bin: STREAMER_BIN,
      port: STREAM_PORT,
      adbPort: ADB_SERVER_PORT
    });

    const env = {
      ...process.env,
      WS_SCRCPY_PORT: STREAM_PORT.toString(),
      ADB_SERVER_SOCKET: `tcp:${ADB_SERVER_HOST}:${ADB_SERVER_PORT}`,
      ANDROID_ADB_SERVER_PORT: ADB_SERVER_PORT,
      ADB_SERVER_PORT: ADB_SERVER_PORT
    };

    const child = spawn(STREAMER_BIN, [], {
      cwd: STREAMER_CWD,
      env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    streamerProcess = child;
    attachProcessLoggers(child, streamerLogBuffer, 'ws-scrcpy');

    child.once('error', (error) => {
      streamerProcess = undefined;
      logger.error('ws-scrcpy failed to start', { error: (error as Error).message });
      startPromise = null;
      reject(error);
    });

    child.once('exit', (code, signal) => {
      streamerProcess = undefined;
      logger.warn('ws-scrcpy exited', { code, signal });
      startPromise = null;
    });

    // Give the process a moment to bind
    setTimeout(resolve, 1500);
  });

export const ensureStreamer = async () => {
  if (streamerProcess && !streamerProcess.killed) {
    return;
  }
  if (!startPromise) {
    startPromise = spawnStreamer();
  }
  return startPromise;
};

export const stopStreamer = async () => {
  if (!streamerProcess) {
    return;
  }
  logger.info('Stopping ws-scrcpy streamer');
  streamerProcess.removeAllListeners('exit');
  streamerProcess.kill('SIGTERM');
  streamerProcess = undefined;
  startPromise = null;
};

export const handleEmulatorStopped = async () => {
  await stopStreamer();
};

export const issueStreamTicket = async (options?: StreamTicketOptions) => {
  const session = sessionStore.getSession();
  if (session.state !== 'Running') {
    throw new Error('Stream tickets available only in Running state');
  }

  await ensureStreamer();

  const protocol = normaliseProtocol(options?.protocol);
  const streamHost = resolveStreamHost(options?.requestHost);
  const streamPort = resolveStreamPort();
  const player = resolvePlayer(protocol, streamHost);
  const remote = process.env.WS_SCRCPY_REMOTE ?? streamConfig.remote;

  const proxyUrl = buildWsUrl(protocol, streamHost, streamPort);
  proxyUrl.searchParams.set('action', 'proxy-adb');
  proxyUrl.searchParams.set('remote', remote);
  proxyUrl.searchParams.set('udid', EMULATOR_SERIAL);

  const hashParams = new URLSearchParams({
    action: 'stream',
    udid: EMULATOR_SERIAL,
    player,
    ws: proxyUrl.toString(),
    embedded: '1',
    autoplay: '1'
  });

  const hashString = hashParams.toString().replace(/%253A/g, '%3A');
  const httpUrl = buildHttpUrl(protocol, streamHost, streamPort, hashString);

  const record = sessionStore.generateStreamTicket(EMULATOR_SERIAL);
  return {
    token: record.token,
    url: httpUrl,
    expiresAt: new Date(record.expiresAt).toISOString()
  };
};

export const isStreamerActive = () => Boolean(streamerProcess && !streamerProcess.killed);

export const getStreamerProcess = () => streamerProcess;
