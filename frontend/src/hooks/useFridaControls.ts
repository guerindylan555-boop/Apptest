import { useState, useEffect } from 'react';
import { useFridaEnabled } from '../state/featureFlagsStore';

/**
 * Frida Controls Hook
 *
 * Provides Frida server and attach functionality (feature-flagged)
 */

const BACKEND_URL = window.__RUNTIME_CONFIG__?.BACKEND_URL || 'http://127.0.0.1:3001/api';

export interface FridaSession {
  active: boolean;
  serverPid: number | null;
  attachedPackage: string | null;
  scriptPath: string | null;
  lastOutputLines: string[];
  updatedAt: string;
}

export function useFridaControls() {
  const fridaEnabled = useFridaEnabled();
  const [session, setSession] = useState<FridaSession | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [processes, setProcesses] = useState<string[]>([]);

  // Load session status
  useEffect(() => {
    if (!fridaEnabled) return;

    async function loadStatus() {
      try {
        const response = await fetch(`${BACKEND_URL}/apps/frida/server`);
        if (response.ok) {
          const data = await response.json();
          setSession(data);
        }
      } catch (err) {
        // Silently fail if Frida not available
      }
    }

    loadStatus();
  }, [fridaEnabled]);

  const startServer = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${BACKEND_URL}/apps/frida/server`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'start' })
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || data.message || 'Failed to start Frida server');
        return false;
      }

      setSession(data);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start Frida server');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const stopServer = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${BACKEND_URL}/apps/frida/server`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'stop' })
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || data.message || 'Failed to stop Frida server');
        return false;
      }

      setSession(data);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop Frida server');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const attachToProcess = async (packageName: string, scriptPath?: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${BACKEND_URL}/apps/frida/attach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packageName, scriptPath })
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.message || 'Failed to attach to process');
        return false;
      }

      // Reload session status
      const statusResponse = await fetch(`${BACKEND_URL}/apps/frida/server`);
      if (statusResponse.ok) {
        const statusData = await statusResponse.json();
        setSession(statusData);
      }

      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to attach to process');
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const listProcesses = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/frida/processes`);
      if (response.ok) {
        const data = await response.json();
        setProcesses(data.processes || []);
      }
    } catch (err) {
      // Silently fail
    }
  };

  return {
    session,
    isLoading,
    error,
    processes,
    fridaEnabled,
    startServer,
    stopServer,
    attachToProcess,
    listProcesses
  };
}
