import type { Request, Response } from 'express';
import { sessionStore } from '../../state/sessionStore';
import { issueStreamTicket } from '../../services/streamerService';
import { logger } from '../../services/logger';

export const streamUrlHandler = async (_req: Request, res: Response) => {
  const session = sessionStore.getSession();
  if (session.state !== 'Running') {
    const hint = session.state === 'Error'
      ? 'Resolve the current error and try starting the emulator again.'
      : 'Wait for the emulator to finish starting, then try again.';

    return res.status(409).json({
      error: {
        code: 'STREAM_NOT_AVAILABLE',
        message: `Stream is not available in ${session.state} state`,
        hint
      }
    });
  }

  try {
    const ticket = await issueStreamTicket();
    return res.status(200).json(ticket);
  } catch (error) {
    const message = (error as Error).message;
    logger.error('Stream ticket issuance failed', { error: message });

    // Provide specific hints based on common failure patterns
    let hint = 'Check that the ws-scrcpy bridge is properly configured.';
    if (message.includes('bridge') || message.includes('ws-scrcpy')) {
      hint = 'Ensure the ws-scrcpy bridge process is running and accessible.';
    } else if (message.includes('emulator') || message.includes('adb')) {
      hint = 'Verify the emulator device is responsive via ADB.';
    }

    return res.status(500).json({
      error: {
        code: 'STREAM_TICKET_FAILED',
        message: 'Failed to issue stream ticket',
        hint
      }
    });
  }
};
