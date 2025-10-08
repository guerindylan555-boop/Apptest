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

  const streamHost = process.env.WS_SCRCPY_HOST ?? '127.0.0.1';
  const streamPort = process.env.WS_SCRCPY_PORT ?? '8000';
  const player = process.env.WS_SCRCPY_PLAYER ?? 'mse';
  const query = new URLSearchParams({
    action: 'stream',
    udid: emulatorSerial,
    player
  });

  const httpUrl = `http://${streamHost}:${streamPort}/?${query.toString()}`;

  const record = sessionStore.generateStreamTicket(emulatorSerial, httpUrl);
  return {
    token: record.token,
    url: httpUrl,
    expiresAt: new Date(record.expiresAt).toISOString()
  };
};

export const isStreamerActive = () => true;
