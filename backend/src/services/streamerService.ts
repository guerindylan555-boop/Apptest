import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import { getEmulatorSerial } from './emulatorLifecycle';
import { streamConfig } from '../config/stream';

type StreamTicketOptions = {
  requestHost?: string;
  protocol?: string;
};

const PLACEHOLDER_HOSTS = new Set(['127.0.0.1', '0.0.0.0', 'localhost', 'host.docker.internal']);
const DEFAULT_HTTP_PORT = 80;
const DEFAULT_HTTPS_PORT = 443;

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

const resolveStreamPort = () => {
  const envPort = process.env.WS_SCRCPY_PORT;
  if (envPort && envPort.trim().length > 0) {
    return envPort.trim();
  }
  return streamConfig.port.toString();
};

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

export const ensureStreamer = async (serial?: string, options?: StreamTicketOptions) => {
  const emulatorSerial = serial || (await getEmulatorSerial());
  const protocol = normaliseProtocol(options?.protocol);
  const host = resolveStreamHost(options?.requestHost);
  const port = resolveStreamPort();

  logger.info('Stream available via ws-scrcpy server', {
    httpUrl: buildHttpUrl(protocol, host, port, ''),
    serial: emulatorSerial
  });
};

export const stopStreamer = async () => {
  logger.info('Streamer managed externally (ws-scrcpy); nothing to stop');
};

export const handleEmulatorStopped = async () => {
  await stopStreamer();
};

export const issueStreamTicket = async (options?: StreamTicketOptions) => {
  const session = sessionStore.getSession();
  if (session.state !== 'Running') {
    throw new Error('Stream tickets available only in Running state');
  }
  await ensureStreamer(undefined, options);
  const emulatorSerial = await getEmulatorSerial();

  const protocol = normaliseProtocol(options?.protocol);
  const streamHost = resolveStreamHost(options?.requestHost);
  const streamPort = resolveStreamPort();
  const player = resolvePlayer(protocol, streamHost);
  const remote = process.env.WS_SCRCPY_REMOTE ?? streamConfig.remote;

  const proxyUrl = buildWsUrl(protocol, streamHost, streamPort);
  proxyUrl.searchParams.set('action', 'proxy-adb');
  proxyUrl.searchParams.set('remote', remote);
  proxyUrl.searchParams.set('udid', emulatorSerial);

  const hashParams = new URLSearchParams({
    action: 'stream',
    udid: emulatorSerial,
    player,
    ws: proxyUrl.toString(),
    embedded: '1',
    autoplay: '1'
  });

  const hashString = hashParams.toString().replace(/%253A/g, '%3A');
  const httpUrl = buildHttpUrl(protocol, streamHost, streamPort, hashString);

  const record = sessionStore.generateStreamTicket(emulatorSerial);
  return {
    token: record.token,
    url: httpUrl,
    expiresAt: new Date(record.expiresAt).toISOString()
  };
};

export const isStreamerActive = () => true;
