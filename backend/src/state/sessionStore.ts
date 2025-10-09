import { randomUUID } from 'crypto';
import { logger } from '../services/logger';
import type { EmulatorSession, EmulatorState, SessionError } from '../types/session';

interface InternalStreamTicket {
  token: string;
  emulatorSerial: string;
  expiresAt: number;
}

const STREAM_TTL_MS = 60_000;
const AVD_NAME = process.env.AVD_NAME ?? 'autoapp-local';

class SessionStore {
  private session: EmulatorSession = {
    avdName: AVD_NAME,
    state: 'Stopped',
    forceStopRequired: false
  };

  private streamTicket?: InternalStreamTicket;

  getSession(): EmulatorSession {
    return { ...this.session };
  }

  transition(nextState: EmulatorState, patch: Partial<EmulatorSession> = {}) {
    logger.info('Session transition', { from: this.session.state, to: nextState });
    this.session = {
      ...this.session,
      ...patch,
      state: nextState
    };
    if (nextState !== 'Error') {
      this.session.lastError = undefined;
    }
    if (nextState !== 'Running') {
      this.streamTicket = undefined;
      this.session.streamToken = undefined;
      this.session.streamBridgeUrl = undefined;
      this.session.streamTicketExpiresAt = undefined;
      this.session.forceStopRequired = false;
    }
  }

  markStopping() {
    this.transition('Stopping');
  }

  setBootStarted(pid: number | undefined, ports: { console: number; adb: number }) {
    this.session.bootStartedAt = new Date().toISOString();
    this.session.pid = pid;
    this.session.ports = ports;
  }

  setBootCompleted() {
    this.session.bootCompletedAt = new Date().toISOString();
  }

  recordError(error: SessionError) {
    logger.error('Session error recorded', { error });
    this.session.lastError = error;
    this.session.state = 'Error';
  }

  markHealthUnreachable() {
    this.recordError({
      code: 'HEALTH_UNREACHABLE',
      message: 'Health checks failed to confirm emulator availability',
      hint: 'Verify backend service is running and reachable at http://127.0.0.1:8080/api/health.',
      occurredAt: new Date().toISOString()
    });
  }

  requireForceStop(hint?: string) {
    this.session.forceStopRequired = true;
    this.recordError({
      code: 'FORCE_STOP_REQUIRED',
      message: 'Standard stop sequence failed; force stop required.',
      hint,
      occurredAt: new Date().toISOString()
    });
  }

  clearForceStopFlag() {
    this.session.forceStopRequired = false;
  }

  clearError() {
    this.session.lastError = undefined;
  }

  generateStreamTicket(emulatorSerial: string, bridgeUrl?: string) {
    const token = randomUUID();
    const expiresAt = Date.now() + STREAM_TTL_MS;
    this.streamTicket = { token, emulatorSerial, expiresAt };
    this.session.streamToken = token;
    this.session.streamBridgeUrl = bridgeUrl;
    this.session.streamTicketExpiresAt = new Date(expiresAt).toISOString();
    return { token, expiresAt, emulatorSerial, bridgeUrl };
  }

  consumeStreamTicket(token: string) {
    if (!this.streamTicket) {
      return undefined;
    }
    if (this.streamTicket.token !== token) {
      return undefined;
    }
    if (Date.now() > this.streamTicket.expiresAt) {
      logger.warn('Stream ticket expired', { token });
      this.streamTicket = undefined;
      this.session.streamToken = undefined;
      this.session.streamBridgeUrl = undefined;
      this.session.streamTicketExpiresAt = undefined;
      return undefined;
    }
    const ticket = this.streamTicket;
    this.streamTicket = undefined;
    this.session.streamToken = undefined;
    this.session.streamBridgeUrl = undefined;
    this.session.streamTicketExpiresAt = undefined;
    return ticket;
  }

  reset() {
    logger.info('Resetting session to Stopped');
    this.session = {
      avdName: AVD_NAME,
      state: 'Stopped',
      forceStopRequired: false
    };
    this.streamTicket = undefined;
    delete this.session.bootStartedAt;
    delete this.session.bootCompletedAt;
    delete this.session.pid;
    delete this.session.ports;
    delete this.session.streamToken;
    delete this.session.streamBridgeUrl;
    delete this.session.streamTicketExpiresAt;
    delete this.session.lastError;
  }
}

export const sessionStore = new SessionStore();
