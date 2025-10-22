const deriveDefaultBackendUrl = () => {
  if (typeof window === 'undefined') {
    return 'http://127.0.0.1:3001/api';
  }

  const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
  const hostname = window.location.hostname;
  const backendPort = protocol === 'https:' ? '443' : '3001';
  const portSegment = backendPort ? `:${backendPort}` : '';

  return `${protocol}//${hostname}${portSegment}/api`;
};

const normaliseBaseUrl = (url: string) => url.replace(/\/+$/, '');

// Lazy evaluation: compute at runtime, not build time
const getApiBase = () => {
  return normaliseBaseUrl(import.meta.env.VITE_BACKEND_URL ?? deriveDefaultBackendUrl());
};

type EmulatorState = 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';

export interface HealthPayload {
  state: EmulatorState;
  avd: string;
  bootElapsedMs?: number;
  pid?: number;
  ports?: { console: number; adb: number };
  streamAttached: boolean;
  streamerActive?: boolean;
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
  const response = await fetch(`${getApiBase()}${path}`, {
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

export const restartEmulator = () =>
  request<{ state: EmulatorState; message: string }>('/emulator/restart', {
    method: 'POST'
  });

export const fetchHealth = () => request<HealthPayload>('/health', { method: 'GET' });

export const fetchStreamUrl = () => request<StreamTicket>('/stream/url', { method: 'GET' });

export const fetchLogs = (target: 'emulator' | 'streamer', limit?: number) => {
  const query = limit ? `?limit=${limit}` : '';
  return request<{ target: string; lines: string[] }>(`/logs/${target}${query}`, {
    method: 'GET'
  });
};
