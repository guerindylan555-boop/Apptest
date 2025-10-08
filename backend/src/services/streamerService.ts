import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import { getEmulatorSerial } from './emulatorLifecycle';
import { streamConfig } from '../config/stream';

export const ensureStreamer = async (serial?: string) => {
  const emulatorSerial = serial || await getEmulatorSerial();
  logger.info('Stream available via ws-scrcpy server', {
    httpUrl: `http://${streamConfig.host}:8000`,
    serial: emulatorSerial
  });
};

export const stopStreamer = async () => {
  logger.info('Streamer managed externally (ws-scrcpy); nothing to stop');
};

export const handleEmulatorStopped = async () => {
  await stopStreamer();
};

export const issueStreamTicket = async () => {
  const session = sessionStore.getSession();
  if (session.state !== 'Running') {
    throw new Error('Stream tickets available only in Running state');
  }
  await ensureStreamer();
  const emulatorSerial = await getEmulatorSerial();

  const streamHost = process.env.WS_SCRCPY_HOST ?? streamConfig.host;
  const streamPort = process.env.WS_SCRCPY_PORT ?? '8000';
  const player = process.env.WS_SCRCPY_PLAYER ?? 'broadway';
  const remote = process.env.WS_SCRCPY_REMOTE ?? 'tcp:27183';

  const proxyUrl = new URL(`ws://${streamHost}:${streamPort}/`);
  proxyUrl.searchParams.set('action', 'proxy-adb');
  proxyUrl.searchParams.set('remote', remote);
  proxyUrl.searchParams.set('udid', emulatorSerial);

  const hashParams = new URLSearchParams({
    action: 'stream',
    udid: emulatorSerial,
    player,
    ws: proxyUrl.toString()
  });

  const httpUrl = `http://${streamHost}:${streamPort}/#!${hashParams.toString()}`;

  const record = sessionStore.generateStreamTicket(emulatorSerial, httpUrl);
  return {
    token: record.token,
    url: httpUrl,
    expiresAt: new Date(record.expiresAt).toISOString()
  };
};

export const isStreamerActive = () => true;
