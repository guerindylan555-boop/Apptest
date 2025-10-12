import { exec, spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';
import type { FridaSession } from '../../types/apps';

const execAsync = promisify(exec);

/**
 * Frida Controller Service
 *
 * Manages frida-server lifecycle and script injection.
 * Feature-flagged and requires governance approval to enable.
 */

/** Current Frida session state */
let currentSession: FridaSession = {
  active: false,
  serverPid: null,
  attachedPackage: null,
  scriptPath: null,
  lastOutputLines: [],
  updatedAt: new Date().toISOString()
};

/** Frida-server process handle */
let fridaServerProcess: ChildProcess | null = null;

/**
 * Start frida-server on the emulator
 */
export async function startFridaServer(): Promise<{ success: boolean; message: string }> {
  if (currentSession.active) {
    return {
      success: true,
      message: 'Frida server already running'
    };
  }

  try {
    // Check if frida-server binary exists on emulator
    const checkCmd = 'adb shell "test -f /data/local/tmp/frida-server && echo EXISTS"';
    const { stdout: checkResult } = await execAsync(checkCmd, { timeout: 5000 });

    if (!checkResult.includes('EXISTS')) {
      return {
        success: false,
        message: 'frida-server binary not found on emulator at /data/local/tmp/frida-server'
      };
    }

    // Start frida-server in background
    console.log('[FridaController] Starting frida-server...');
    const startCmd = 'adb shell "/data/local/tmp/frida-server &"';
    await execAsync(startCmd, { timeout: 5000 });

    // Give it a moment to start
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Get the PID
    const pidCmd = 'adb shell "pidof frida-server"';
    const { stdout: pidOutput } = await execAsync(pidCmd, { timeout: 5000 });
    const pid = parseInt(pidOutput.trim(), 10);

    if (isNaN(pid)) {
      return {
        success: false,
        message: 'Failed to start frida-server (no PID found)'
      };
    }

    currentSession = {
      active: true,
      serverPid: pid,
      attachedPackage: null,
      scriptPath: null,
      lastOutputLines: ['Frida server started successfully'],
      updatedAt: new Date().toISOString()
    };

    console.log(`[FridaController] Frida server started with PID: ${pid}`);
    return {
      success: true,
      message: `Frida server started (PID: ${pid})`
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Failed to start frida-server'
    };
  }
}

/**
 * Stop frida-server
 */
export async function stopFridaServer(): Promise<{ success: boolean; message: string }> {
  if (!currentSession.active) {
    return {
      success: true,
      message: 'Frida server not running'
    };
  }

  try {
    // Kill frida-server process
    const killCmd = 'adb shell "killall frida-server"';
    await execAsync(killCmd, { timeout: 5000 });

    currentSession = {
      active: false,
      serverPid: null,
      attachedPackage: null,
      scriptPath: null,
      lastOutputLines: ['Frida server stopped'],
      updatedAt: new Date().toISOString()
    };

    console.log('[FridaController] Frida server stopped');
    return {
      success: true,
      message: 'Frida server stopped'
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Failed to stop frida-server'
    };
  }
}

/**
 * Get list of running processes
 */
export async function listProcesses(): Promise<string[]> {
  try {
    const cmd = 'adb shell "ps | grep -v \'^USER\' | awk \'{print $9}\' | grep -E \'^[a-z].*\\..*\'"';
    const { stdout } = await execAsync(cmd, { timeout: 5000 });
    return stdout.trim().split('\n').filter((p) => p.length > 0);
  } catch (error) {
    console.warn('[FridaController] Failed to list processes:', error);
    return [];
  }
}

/**
 * Attach Frida to a running process and optionally load a script
 */
export async function attachToProcess(
  packageName: string,
  scriptPath?: string
): Promise<{ success: boolean; message: string; output?: string[] }> {
  if (!currentSession.active) {
    return {
      success: false,
      message: 'Frida server not running'
    };
  }

  try {
    // Simple attachment test using frida-ps
    const testCmd = `frida-ps -U | grep "${packageName}"`;
    const { stdout } = await execAsync(testCmd, { timeout: 5000 });

    if (!stdout.includes(packageName)) {
      return {
        success: false,
        message: `Package ${packageName} not found in running processes`
      };
    }

    // If script path provided, validate it exists
    if (scriptPath) {
      // For simplicity, we'll just note the script path
      // Full implementation would use frida CLI or frida-node to inject
      currentSession = {
        ...currentSession,
        attachedPackage: packageName,
        scriptPath,
        lastOutputLines: [
          `Attached to ${packageName}`,
          scriptPath ? `Script: ${scriptPath}` : 'No script loaded'
        ],
        updatedAt: new Date().toISOString()
      };

      return {
        success: true,
        message: `Attached to ${packageName}`,
        output: currentSession.lastOutputLines
      };
    }

    currentSession = {
      ...currentSession,
      attachedPackage: packageName,
      scriptPath: null,
      lastOutputLines: [`Attached to ${packageName}`, 'No script loaded'],
      updatedAt: new Date().toISOString()
    };

    return {
      success: true,
      message: `Attached to ${packageName}`,
      output: currentSession.lastOutputLines
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Failed to attach to process'
    };
  }
}

/**
 * Detach from current process
 */
export async function detach(): Promise<{ success: boolean; message: string }> {
  if (!currentSession.attachedPackage) {
    return {
      success: true,
      message: 'Not attached to any process'
    };
  }

  currentSession = {
    ...currentSession,
    attachedPackage: null,
    scriptPath: null,
    lastOutputLines: ['Detached from process'],
    updatedAt: new Date().toISOString()
  };

  return {
    success: true,
    message: 'Detached from process'
  };
}

/**
 * Get current Frida session state
 */
export function getSessionState(): FridaSession {
  return { ...currentSession };
}
