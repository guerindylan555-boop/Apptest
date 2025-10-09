const API_BASE = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:7070/api';

type EmulatorState = 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';

export interface HealthPayload {
  state: EmulatorState;
  avd: string;
  bootElapsedMs?: number;
  pid?: number;
  ports?: { console: number; adb: number };
  streamAttached: boolean;
  lastError?: { code: string; message: string; hint?: string; occurredAt: string };
  forceStopRequired?: boolean;
  timestamps: {
    bootStartedAt?: string;
    bootCompletedAt?: string;
  };
}

export interface StreamTicket {
  url: string;
  token: string;
  expiresAt: string;
}

const request = async <T>(path: string, options?: RequestInit): Promise<T> => {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {})
    }
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(payload.error?.message ?? 'Request failed');
  }

  return payload as T;
};

export const startEmulator = () =>
  request<{ state: EmulatorState; message: string }>('/emulator/start', {
    method: 'POST'
  });

export const stopEmulator = (force = false) =>
  request<{ state: EmulatorState; message: string }>('/emulator/stop', {
    method: 'POST',
    body: JSON.stringify({ force })
  });

export const fetchHealth = () => request<HealthPayload>('/health', { method: 'GET' });

export const fetchStreamUrl = () => request<StreamTicket>('/stream/url', { method: 'GET' });
