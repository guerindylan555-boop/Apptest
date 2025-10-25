/**
 * Test file to verify Zustand store functionality
 * This file can be used during development to test store operations
 */

import {
  useDiscoveryStore,
  useFlowStore,
  useWebRTCStore,
  useSettingsStore,
  useSelectedFlow,
  useSelectedExecution,
  useConnectionQuality
} from './index';

/**
 * Test function to verify store operations
 */
export function testStoreFunctionality() {
  console.log('Testing Zustand stores...');

  // Test Discovery Store
  const discoveryStore = useDiscoveryStore.getState();
  console.log('Discovery Store Initial State:', {
    currentGraph: discoveryStore.currentGraph,
    capturedStates: discoveryStore.capturedStates.length,
    isCapturing: discoveryStore.isCapturing,
    connectionStatus: discoveryStore.connectionStatus
  });

  // Test Flow Store
  const flowStore = useFlowStore.getState();
  console.log('Flow Store Initial State:', {
    flows: flowStore.flows.length,
    selectedFlowId: flowStore.selectedFlowId,
    executions: flowStore.executions.length,
    isExecuting: flowStore.isExecuting
  });

  // Test WebRTC Store
  const webrtcStore = useWebRTCStore.getState();
  console.log('WebRTC Store Initial State:', {
    connectionState: webrtcStore.status.connectionState,
    isConnected: webrtcStore.isConnected,
    connectionQuality: webrtcStore.connectionQuality
  });

  // Test Settings Store
  const settingsStore = useSettingsStore.getState();
  console.log('Settings Store Initial State:', {
    theme: settingsStore.settings.ui.theme,
    language: settingsStore.settings.ui.language,
    autoCapture: settingsStore.settings.capture.autoCapture
  });

  console.log('All stores initialized successfully!');
}

/**
 * Test store interactions
 */
export function testStoreInteractions() {
  // Test Discovery Store interactions
  const discoveryStore = useDiscoveryStore.getState();
  discoveryStore.setLoading(true);
  discoveryStore.setConnectionStatus('connecting');

  // Test Flow Store interactions
  const flowStore = useFlowStore.getState();
  flowStore.setLoading(true);
  flowStore.setExecuting(false);

  // Test WebRTC Store interactions
  const webrtcStore = useWebRTCStore.getState();
  webrtcStore.setConnected(true);
  webrtcStore.setConnectionQuality('good');

  // Test Settings Store interactions
  const settingsStore = useSettingsStore.getState();
  settingsStore.updateSettings({
    ui: { theme: 'dark' }
  });

  console.log('Store interactions tested successfully!');
}

// Export test functions for development use
export default {
  testStoreFunctionality,
  testStoreInteractions
};