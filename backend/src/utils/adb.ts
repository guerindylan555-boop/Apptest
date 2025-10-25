/**
 * ADB Connection Utilities
 *
 * ADB command execution with connection pooling and error handling.
 * Optimized for sub-1s capture performance.
 */

import { spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';
import { ADBConfig } from '../types/graph';

export class ADBConnection {
  private config: ADBConfig;
  private connectionPool: ChildProcess[] = [];
  private activeConnections = 0;

  constructor(config: ADBConfig) {
    this.config = config;
  }

  /**
   * Execute ADB command with automatic retry logic
   */
  async executeCommand(
    command: string[],
    timeout?: number
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    const cmdTimeout = timeout || this.config.timeout;
    let attempts = 0;

    while (attempts < this.config.maxRetries) {
      try {
        return await this._executeWithTimeout(command, cmdTimeout);
      } catch (error) {
        attempts++;
        if (attempts >= this.config.maxRetries) {
          throw new Error(`ADB command failed after ${attempts} attempts: ${error}`);
        }

        // Exponential backoff
        const delay = Math.pow(2, attempts) * 100;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    throw new Error('ADB command execution failed');
  }

  /**
   * Execute command with timeout
   */
  private async _executeWithTimeout(
    command: string[],
    timeout: number
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return new Promise((resolve, reject) => {
      const args = ['-s', this.config.serial, ...command];
      const child = spawn('adb', args);

      let stdout = '';
      let stderr = '';
      let isCompleted = false;

      // Set up timeout
      const timeoutId = setTimeout(() => {
        if (!isCompleted) {
          child.kill('SIGKILL');
          reject(new Error(`ADB command timed out after ${timeout}ms`));
        }
      }, timeout);

      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      child.on('close', (code) => {
        if (isCompleted) return;
        isCompleted = true;
        clearTimeout(timeoutId);

        resolve({
          stdout: stdout.trim(),
          stderr: stderr.trim(),
          exitCode: code || 0
        });
      });

      child.on('error', (error) => {
        if (isCompleted) return;
        isCompleted = true;
        clearTimeout(timeoutId);
        reject(error);
      });
    });
  }

  /**
   * Get current activity name
   */
  async getCurrentActivity(): Promise<string | null> {
    try {
      const { stdout } = await this.executeCommand([
        'shell', 'dumpsys', 'activity', 'activities'
      ]);

      const match = stdout.match(/topResumedActivity:.*?([^/]+)\/([^/]+)/);
      return match ? `${match[1]}/${match[2]}` : null;
    } catch (error) {
      throw new Error(`Failed to get current activity: ${error}`);
    }
  }

  /**
   * Get UI hierarchy XML
   */
  async getUIHierarchy(): Promise<string> {
    try {
      const { stdout } = await this.executeCommand([
        'exec-out', 'uiautomator', 'dump', '/dev/tty'
      ]);

      if (!stdout || stdout.includes('ERROR')) {
        throw new Error('UI hierarchy dump failed');
      }

      return stdout;
    } catch (error) {
      throw new Error(`Failed to get UI hierarchy: ${error}`);
    }
  }

  /**
   * Capture screenshot as PNG buffer
   */
  async captureScreenshot(): Promise<Buffer> {
    try {
      const { stdout } = await this.executeCommand([
        'exec-out', 'screencap', '-p'
      ]);

      return Buffer.from(stdout, 'binary');
    } catch (error) {
      throw new Error(`Failed to capture screenshot: ${error}`);
    }
  }

  /**
   * Tap on coordinates
   */
  async tap(x: number, y: number): Promise<void> {
    try {
      await this.executeCommand(['shell', 'input', 'tap', x.toString(), y.toString()]);
    } catch (error) {
      throw new Error(`Failed to tap at (${x}, ${y}): ${error}`);
    }
  }

  /**
   * Type text
   */
  async type(text: string): Promise<void> {
    try {
      await this.executeCommand(['shell', 'input', 'text', text]);
    } catch (error) {
      throw new Error(`Failed to type text: ${error}`);
    }
  }

  /**
   * Swipe gesture
   */
  async swipe(
    startX: number, startY: number,
    endX: number, endY: number,
    duration: number = 300
  ): Promise<void> {
    try {
      await this.executeCommand([
        'shell', 'input', 'swipe',
        startX.toString(), startY.toString(),
        endX.toString(), endY.toString(),
        duration.toString()
      ]);
    } catch (error) {
      throw new Error(`Failed to swipe: ${error}`);
    }
  }

  /**
   * Press back button
   */
  async pressBack(): Promise<void> {
    try {
      await this.executeCommand(['shell', 'input', 'keyevent', 'KEYCODE_BACK']);
    } catch (error) {
      throw new Error(`Failed to press back: ${error}`);
    }
  }

  /**
   * Check if device is connected
   */
  async isDeviceConnected(): Promise<boolean> {
    try {
      const { stdout } = await this.executeCommand(['devices']);
      return stdout.includes(this.config.serial);
    } catch (error) {
      return false;
    }
  }

  /**
   * Get device properties
   */
  async getDeviceProperties(): Promise<Record<string, string>> {
    try {
      const { stdout } = await this.executeCommand(['shell', 'getprop']);
      const properties: Record<string, string> = {};

      stdout.split('\n').forEach(line => {
        const match = line.match(/^\[(.+?)\]: \[(.+?)\]$/);
        if (match) {
          properties[match[1]] = match[2];
        }
      });

      return properties;
    } catch (error) {
      throw new Error(`Failed to get device properties: ${error}`);
    }
  }

  /**
   * Wait for device to be ready
   */
  async waitForDevice(timeout: number = 30000): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      if (await this.isDeviceConnected()) {
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    throw new Error(`Device not connected after ${timeout}ms`);
  }

  /**
   * Cleanup resources
   */
  close(): void {
    this.connectionPool.forEach(child => {
      if (!child.killed) {
        child.kill();
      }
    });
    this.connectionPool = [];
    this.activeConnections = 0;
  }
}

/**
 * Create ADB connection from environment variables
 */
export function createADBConnection(): ADBConnection {
  const config: ADBConfig = {
    host: process.env.ADB_HOST || 'host.docker.internal',
    port: parseInt(process.env.ADB_PORT || '5555'),
    serial: process.env.ANDROID_SERIAL || 'emulator-5554',
    timeout: parseInt(process.env.SNAPSHOT_TIMEOUT_MS || '5000'),
    maxRetries: 3,
    poolSize: 5
  };

  return new ADBConnection(config);
}