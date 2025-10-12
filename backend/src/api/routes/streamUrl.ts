import type { Request, Response } from 'express';
import { sessionStore } from '../../state/sessionStore';
import { issueStreamTicket } from '../../services/streamerService';

export const streamUrlHandler = async (_req: Request, res: Response) => {
  const session = sessionStore.getSession();
  if (session.state !== 'Running') {
    return res.status(409).json({
      error: {
        code: 'NOT_RUNNING',
        message: 'Stream is available only when the emulator is running'
      }
    });
  }

  try {
    const ticket = await issueStreamTicket();
    return res.status(200).json(ticket);
  } catch (error) {
    return res.status(500).json({
      error: {
        code: 'STREAM_ERROR',
        message: (error as Error).message
      }
    });
  }
};
