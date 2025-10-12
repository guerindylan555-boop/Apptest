import { useState, useEffect, useCallback } from 'react';

const BACKEND_URL = window.__RUNTIME_CONFIG__?.BACKEND_URL || 'http://localhost:3001/api';

interface LogCapture {
  id: string;
  apkId: string | null;
  filters: {
    packages: string[];
    tags: string[];
  };
  status: 'active' | 'paused' | 'stopped';
  startedAt: string;
  endedAt: string | null;
  filePath: string | null;
  sizeBytes: number;
  downloaded: boolean;
}

interface ProxyState {
  enabled: boolean;
  host: string;
  port: number;
}

interface DeviceToolsState {
  logcatSessions: LogCapture[];
  proxyState: ProxyState;
  isLoading: boolean;
  error: string | null;
}

interface DeviceToolsActions {
  // Logcat actions
  startLogcatCapture: (filters: { packages?: string[]; tags?: string[] }) => Promise<LogCapture | null>;
  stopLogcatCapture: (sessionId: string) => Promise<void>;
  downloadLogcatCapture: (sessionId: string) => Promise<string | null>;

  // Proxy actions
  enableProxy: (host: string, port: number) => Promise<void>;
  disableProxy: () => Promise<void>;

  // Shared actions
  refreshStatus: () => Promise<void>;
  clearError: () => void;
}

/**
 * Device Tools Hook
 *
 * Provides unified access to device instrumentation tools (logcat, proxy)
 */
export function useDeviceTools(): DeviceToolsState & DeviceToolsActions {
  const [logcatSessions, setLogcatSessions] = useState<LogCapture[]>([]);
  const [proxyState, setProxyState] = useState<ProxyState>({
    enabled: false,
    host: '127.0.0.1',
    port: 8080
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch logcat sessions
  const fetchLogcatSessions = useCallback(async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions`);
      if (!response.ok) throw new Error('Failed to fetch logcat sessions');
      const data = await response.json();
      setLogcatSessions(data);
    } catch (err) {
      console.error('Failed to fetch logcat sessions:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch logcat sessions');
    }
  }, []);

  // Fetch proxy status
  const fetchProxyStatus = useCallback(async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/proxy/status`);
      if (!response.ok) throw new Error('Failed to fetch proxy status');
      const data = await response.json();
      setProxyState(data);
    } catch (err) {
      console.error('Failed to fetch proxy status:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch proxy status');
    }
  }, []);

  // Refresh all device tool status
  const refreshStatus = useCallback(async () => {
    await Promise.all([
      fetchLogcatSessions(),
      fetchProxyStatus()
    ]);
  }, [fetchLogcatSessions, fetchProxyStatus]);

  // Start logcat capture
  const startLogcatCapture = useCallback(async (
    filters: { packages?: string[]; tags?: string[] }
  ): Promise<LogCapture | null> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          packageFilters: filters.packages || [],
          tagFilters: filters.tags || []
        })
      });

      if (!response.ok) throw new Error('Failed to start logcat capture');

      const capture = await response.json();
      setLogcatSessions(prev => [...prev, capture]);
      return capture;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start logcat capture';
      console.error(message, err);
      setError(message);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Stop logcat capture
  const stopLogcatCapture = useCallback(async (sessionId: string): Promise<void> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions/${sessionId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'stop' })
      });

      if (!response.ok) throw new Error('Failed to stop logcat capture');

      await fetchLogcatSessions();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to stop logcat capture';
      console.error(message, err);
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, [fetchLogcatSessions]);

  // Download logcat capture
  const downloadLogcatCapture = useCallback(async (sessionId: string): Promise<string | null> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions/${sessionId}`);
      if (!response.ok) throw new Error('Failed to download logcat capture');

      const content = await response.text();

      // Trigger browser download
      const blob = new Blob([content], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `logcat-${sessionId}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      return content;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to download logcat capture';
      console.error(message, err);
      setError(message);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Enable proxy
  const enableProxy = useCallback(async (host: string, port: number): Promise<void> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/apps/proxy/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: true, host, port })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to enable proxy');
      }

      const data = await response.json();
      setProxyState(data);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to enable proxy';
      console.error(message, err);
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Disable proxy
  const disableProxy = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(`${BACKEND_URL}/apps/proxy/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: false })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to disable proxy');
      }

      const data = await response.json();
      setProxyState(data);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to disable proxy';
      console.error(message, err);
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Clear error
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Auto-refresh on mount and interval
  useEffect(() => {
    refreshStatus();
    const interval = setInterval(refreshStatus, 5000);
    return () => clearInterval(interval);
  }, [refreshStatus]);

  return {
    // State
    logcatSessions,
    proxyState,
    isLoading,
    error,

    // Actions
    startLogcatCapture,
    stopLogcatCapture,
    downloadLogcatCapture,
    enableProxy,
    disableProxy,
    refreshStatus,
    clearError
  };
}
