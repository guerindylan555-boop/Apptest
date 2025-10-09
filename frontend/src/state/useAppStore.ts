import { create } from 'zustand';
import type { StreamTicket } from '../services/backendClient';

type EmulatorState = 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';

interface AppState {
  emulatorState: EmulatorState;
  isTransitioning: boolean;
  streamTicket?: StreamTicket;
  lastError?: { code: string; message: string; hint?: string };
  forceStopRequired: boolean;
  pid?: number;
  bootElapsedMs?: number;
  ports?: { console: number; adb: number };
  setState: (state: Partial<AppState>) => void;
  setTransitioning: (flag: boolean) => void;
  reset(): void;
}

export const useAppStore = create<AppState>((set) => ({
  emulatorState: 'Stopped',
  isTransitioning: false,
  streamTicket: undefined,
  lastError: undefined,
  forceStopRequired: false,
  pid: undefined,
  bootElapsedMs: undefined,
  ports: undefined,
  setState: (state) => set(state),
  setTransitioning: (flag) => set({ isTransitioning: flag }),
  reset: () =>
    set({
      emulatorState: 'Stopped',
      isTransitioning: false,
      streamTicket: undefined,
      lastError: undefined,
      forceStopRequired: false,
      pid: undefined,
      bootElapsedMs: undefined,
      ports: undefined
    })
}));
