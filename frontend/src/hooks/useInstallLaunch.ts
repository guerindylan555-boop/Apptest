import { useState } from 'react';

/**
 * Install & Launch Hook
 *
 * Provides install/launch functionality for APK entries
 */

const BACKEND_URL = window.__RUNTIME_CONFIG__?.BACKEND_URL || 'http://127.0.0.1:3001/api';

export interface InstallLaunchOptions {
  allowDowngrade?: boolean;
  autoGrantPermissions?: boolean;
}

export interface InstallLaunchResult {
  status: 'success' | 'failed';
  launchResolution: string;
  message: string;
  installLogPath: string | null;
}

export function useInstallLaunch() {
  const [isInstalling, setIsInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InstallLaunchResult | null>(null);

  const installAndLaunch = async (
    apkId: string,
    options: InstallLaunchOptions = {}
  ): Promise<InstallLaunchResult> => {
    setIsInstalling(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(`${BACKEND_URL}/apps/${apkId}/install-launch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(options)
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMsg = data.message || data.error || 'Install/launch failed';
        setError(errorMsg);
        throw new Error(errorMsg);
      }

      setResult(data);
      return data;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMessage);
      throw err;
    } finally {
      setIsInstalling(false);
    }
  };

  const clearResult = () => {
    setResult(null);
    setError(null);
  };

  return {
    installAndLaunch,
    isInstalling,
    error,
    result,
    clearResult
  };
}
