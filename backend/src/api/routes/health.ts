import type { Request, Response } from 'express';
import { sessionStore } from '../../state/sessionStore';
import type { HealthResponse } from '../../types/health';
import { isStreamerActive } from '../../services/streamerService';

const buildHealthPayload = async (): Promise<HealthResponse> => {
  const session = sessionStore.getSession();
  const bootElapsedMs = session.bootStartedAt
    ? Date.now() - new Date(session.bootStartedAt).getTime()
    : undefined;
  const streamerActive = await isStreamerActive();

  return {
    state: session.state,
    avd: session.avdName,
    bootElapsedMs,
    pid: session.pid,
    ports: session.ports,
    streamAttached: Boolean(session.streamToken),
    streamerActive,
    lastError: session.lastError,
    forceStopRequired: session.forceStopRequired,
    timestamps: {
      bootStartedAt: session.bootStartedAt,
      bootCompletedAt: session.bootCompletedAt
    }
  };
};

export const healthHandler = async (_req: Request, res: Response) => {
  const payload = await buildHealthPayload();
  res.status(200).json(payload);
};
