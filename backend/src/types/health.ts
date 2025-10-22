import type { EmulatorState, SessionError, SessionPorts } from './session';

export interface HealthResponse {
  state: EmulatorState;
  avd: string;
  bootElapsedMs?: number;
  pid?: number;
  ports?: SessionPorts;
  streamAttached: boolean;
  streamerActive?: boolean;
  lastError?: SessionError;
  forceStopRequired?: boolean;
  timestamps: {
    bootStartedAt?: string;
    bootCompletedAt?: string;
  };
}
