import { exec } from 'child_process';
import { promisify } from 'util';
import type { ProxyState } from '../../types/apps';

const execAsync = promisify(exec);

/**
 * Proxy Toggle Service
 *
 * Manages HTTP proxy settings on the emulator for network interception.
 * Typically used with mitmproxy for traffic analysis.
 */

/** Current proxy state */
let currentProxyState: ProxyState = {
  enabled: false,
  host: '127.0.0.1',
  port: 8080
};

/**
 * Enable HTTP proxy on the emulator
 */
export async function enableProxy(
  host: string = '127.0.0.1',
  port: number = 8080
): Promise<{ success: boolean; message: string }> {
  try {
    // Set global HTTP proxy using adb shell settings
    const commands = [
      `adb shell settings put global http_proxy ${host}:${port}`,
      // Also set for secure settings (some apps check this)
      `adb shell settings put global https_proxy ${host}:${port}`
    ];

    for (const cmd of commands) {
      await execAsync(cmd, { timeout: 5000 });
    }

    currentProxyState = {
      enabled: true,
      host,
      port
    };

    console.log(`[ProxyService] Enabled proxy: ${host}:${port}`);
    return {
      success: true,
      message: `Proxy enabled: ${host}:${port}`
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Failed to enable proxy'
    };
  }
}

/**
 * Disable HTTP proxy on the emulator
 */
export async function disableProxy(): Promise<{ success: boolean; message: string }> {
  try {
    // Clear proxy settings
    const commands = [
      'adb shell settings put global http_proxy :0',
      'adb shell settings put global https_proxy :0'
    ];

    for (const cmd of commands) {
      await execAsync(cmd, { timeout: 5000 });
    }

    currentProxyState = {
      enabled: false,
      host: '127.0.0.1',
      port: 8080
    };

    console.log('[ProxyService] Disabled proxy');
    return {
      success: true,
      message: 'Proxy disabled'
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Failed to disable proxy'
    };
  }
}

/**
 * Get current proxy state
 */
export function getProxyState(): ProxyState {
  return { ...currentProxyState };
}
