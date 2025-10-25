import { create } from 'zustand';

/**
 * Feature Flags Store
 *
 * Manages feature flag state on the frontend, synchronized with backend configuration.
 * Primarily used to gate Frida instrumentation features pending governance approval.
 */

export interface FeatureFlagsState {
  /** Enable Frida server controls and script injection */
  enableFrida: boolean;

  /** Enable Discovery Panel for UI graph functionality */
  enableDiscoveryPanel: boolean;

  /** Enable GPS Controller panel */
  enableGpsPanel: boolean;

  /** Whether feature flags have been loaded from backend */
  loaded: boolean;

  /** Set feature flags state */
  setFlags: (flags: Partial<Omit<FeatureFlagsState, 'setFlags' | 'loaded'>>) => void;

  /** Mark flags as loaded */
  setLoaded: () => void;
}

/**
 * Feature flags store
 *
 * Default state has all optional features disabled until loaded from backend.
 */
export const useFeatureFlagsStore = create<FeatureFlagsState>((set) => ({
  enableFrida: false,
  enableDiscoveryPanel: true, // Enable by default for UI graph functionality
  enableGpsPanel: false,
  loaded: false,

  setFlags: (flags) => set((state) => ({ ...state, ...flags })),

  setLoaded: () => set({ loaded: true })
}));

/**
 * Hook to check if Frida features are enabled
 */
export function useFridaEnabled(): boolean {
  return useFeatureFlagsStore((state) => state.enableFrida);
}

/**
 * Hook to check if Discovery Panel is enabled
 */
export function useDiscoveryPanel(): boolean {
  return useFeatureFlagsStore((state) => state.enableDiscoveryPanel);
}

/**
 * Hook to check if GPS Panel is enabled
 */
export function useGpsPanel(): boolean {
  return useFeatureFlagsStore((state) => state.enableGpsPanel);
}
