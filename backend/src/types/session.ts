export type EmulatorState =
  | 'Stopped'
  | 'Booting'
  | 'Running'
  | 'Stopping'
  | 'Error';

export interface SessionError {
  code: string;
  message: string;
  hint?: string;
  occurredAt: string;
}

export interface StreamTicket {
  token: string;
  url: string;
  expiresAt: string;
  emulatorSerial: string;
}

export interface SessionPorts {
  console: number;
  adb: number;
}

export interface EmulatorSession {
  avdName: string;
  state: EmulatorState;
  bootStartedAt?: string;
  bootCompletedAt?: string;
  pid?: number;
  ports?: SessionPorts;
  lastError?: SessionError;
  streamToken?: string;
  forceStopRequired?: boolean;
  streamBridgeUrl?: string;
  streamTicketExpiresAt?: string;
}
