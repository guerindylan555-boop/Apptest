import type { Request, Response } from 'express';
import { sessionStore } from '../../state/sessionStore';
import type { HealthResponse } from '../../types/health';

const buildHealthPayload = (): HealthResponse => {
  const session = sessionStore.getSession();
  const bootElapsedMs = session.bootStartedAt
    ? Date.now() - new Date(session.bootStartedAt).getTime()
    : undefined;

  return {
    state: session.state,
    avd: session.avdName,
    bootElapsedMs,
    pid: session.pid,
    ports: session.ports,
    streamAttached: Boolean(session.streamToken),
    lastError: session.lastError,
    forceStopRequired: session.forceStopRequired,
    timestamps: {
      bootStartedAt: session.bootStartedAt,
      bootCompletedAt: session.bootCompletedAt
    }
  };
};

export const healthHandler = (_req: Request, res: Response) => {
  const payload = buildHealthPayload();
  res.status(200).json(payload);
};
