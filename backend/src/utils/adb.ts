/**
 * ADB/UIAutomator Integration Utility
 *
 * Provides Android Debug Bridge and UIAutomator integration
 * for screen capture, XML dump extraction, and device control.
 */

import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

export interface ADBDevice {
  id: string;
  model: string;
  emulator: boolean;
  status: 'device' | 'offline' | 'unauthorized';
  product: string;
}

export interface ScreenCaptureOptions {
  deviceId?: string;
  format?: 'png' | 'jpg';
  quality?: number;
  timeout?: number;
}

export interface XMLDumpOptions {
  deviceId?: string;
  timeout?: number;
  compression?: boolean;
}

export interface DeviceInfo {
  model: string;
  manufacturer: string;
  version: string;
  sdk: string;
  screen: {
    width: number;
    height: number;
    density: number;
  };
  app?: {
    packageName: string;
    version: string;
    activity: string;
  };
}

export class ADBUtils {
  private static instance: ADBUtils;
  private emulatorDeviceId: string = 'emulator-5554'; // Default emulator ID

  private constructor() {}

  /**
   * Get singleton instance
   */
  static getInstance(): ADBUtils {
    if (!ADBUtils.instance) {
      ADBUtils.instance = new ADBUtils();
    }
    return ADBUtils.instance;
  }

  /**
   * Set emulator device ID
   */
  setEmulatorDeviceId(deviceId: string): void {
    this.emulatorDeviceId = deviceId;
  }

  /**
   * Get emulator device ID
   */
  getEmulatorDeviceId(): string {
    return this.emulatorDeviceId;
  }

  /**
   * Check if ADB is available
   */
  async isAdbAvailable(): Promise<boolean> {
    try {
      await execAsync('adb version');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * List connected devices
   */
  async listDevices(): Promise<ADBDevice[]> {
    try {
      const { stdout } = await execAsync('adb devices -l');
      const lines = stdout.trim().split('\n').slice(1); // Skip header line

      const devices: ADBDevice[] = [];

      for (const line of lines) {
        if (!line.trim()) continue;

        const parts = line.trim().split(/\s+/);
        const deviceId = parts[0];
        const status = parts[1] as 'device' | 'offline' | 'unauthorized';

        // Parse device properties
        const properties: Record<string, string> = {};
        for (let i = 2; i < parts.length; i++) {
          const part = parts[i];
          if (part.includes(':')) {
            const [key, value] = part.split(':');
            properties[key] = value;
          }
        }

        devices.push({
          id: deviceId,
          model: properties.model || 'Unknown',
          emulator: deviceId.startsWith('emulator-'),
          status,
          product: properties.product || 'Unknown'
        });
      }

      return devices;
    } catch (error) {
      throw new Error(`Failed to list devices: ${error}`);
    }
  }

  /**
   * Check if emulator is connected
   */
  async isEmulatorConnected(): Promise<boolean> {
    try {
      const devices = await this.listDevices();
      const emulator = devices.find(d => d.id === this.emulatorDeviceId);
      return emulator?.status === 'device';
    } catch (error) {
      return false;
    }
  }

  /**
   * Wait for emulator to be ready
   */
  async waitForEmulator(timeoutMs: number = 30000): Promise<boolean> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      if (await this.isEmulatorConnected()) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    return false;
  }

  /**
   * Capture screen
   */
  async captureScreen(options: ScreenCaptureOptions = {}): Promise<Buffer> {
    const {
      deviceId = this.emulatorDeviceId,
      format = 'png',
      quality = 90,
      timeout = 10000
    } = options;

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Screen capture timeout after ${timeout}ms`));
      }, timeout);

      // Execute ADB screen capture command
      const args = [
        '-s', deviceId,
        'shell', 'screencap', '-p'
      ];

      if (format === 'jpg') {
        args.push('--format', 'jpg', '--quality', quality.toString());
      }

      const process = spawn('adb', args);
      const chunks: Buffer[] = [];

      process.stdout.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });

      process.stderr.on('data', (data: Buffer) => {
        console.error(`ADB screen capture error: ${data.toString()}`);
      });

      process.on('close', (code: number) => {
        clearTimeout(timeoutId);

        if (code === 0) {
          resolve(Buffer.concat(chunks));
        } else {
          reject(new Error(`Screen capture failed with code ${code}`));
        }
      });

      process.on('error', (error: Error) => {
        clearTimeout(timeoutId);
        reject(new Error(`Screen capture process error: ${error.message}`));
      });
    });
  }

  /**
   * Capture screen to file
   */
  async captureScreenToFile(
    filePath: string,
    options: ScreenCaptureOptions = {}
  ): Promise<string> {
    const imageData = await this.captureScreen(options);

    // Ensure directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });

    // Write image file
    await fs.writeFile(filePath, imageData);

    return filePath;
  }

  /**
   * Get UI XML dump
   */
  async getXMLDump(options: XMLDumpOptions = {}): Promise<any> {
    const {
      deviceId = this.emulatorDeviceId,
      timeout = 10000
    } = options;

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`XML dump timeout after ${timeout}ms`));
      }, timeout);

      // Execute UIAutomator dump command
      const process = spawn('adb', [
        '-s', deviceId,
        'shell', 'uiautomator', 'dump'
      ]);

      let stderrData = '';

      process.stderr.on('data', (data: Buffer) => {
        stderrData += data.toString();
      });

      process.on('close', async (code: number) => {
        clearTimeout(timeoutId);

        if (code === 0) {
          try {
            // Pull the XML file from device
            const { stdout: xmlData } = await execAsync(`adb -s ${deviceId} shell cat /sdcard/window_dump.xml`);

            // Clean up the dump file on device
            await execAsync(`adb -s ${deviceId} shell rm /sdcard/window_dump.xml`);

            // Parse XML (return as string, let caller parse with proper XML parser)
            resolve(xmlData);
          } catch (error) {
            reject(new Error(`Failed to retrieve XML dump: ${error}`));
          }
        } else {
          reject(new Error(`UIAutomator dump failed with code ${code}: ${stderrData}`));
        }
      });

      process.on('error', (error: Error) => {
        clearTimeout(timeoutId);
        reject(new Error(`UIAutomator dump process error: ${error.message}`));
      });
    });
  }

  /**
   * Get device information
   */
  async getDeviceInfo(deviceId?: string): Promise<DeviceInfo> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      // Get basic device properties
      const { stdout: properties } = await execAsync(
        `adb -s ${targetDeviceId} shell getprop`
      );

      const props: Record<string, string> = {};
      properties.split('\n').forEach(line => {
        const match = line.match(/^\[(.+?)\]: \[(.+?)\]$/);
        if (match) {
          props[match[1]] = match[2];
        }
      });

      // Parse screen dimensions
      const wmSize = await execAsync(`adb -s ${targetDeviceId} shell wm size`);
      const sizeMatch = wmSize.stdout.match(/Physical size: (\d+)x(\d+)/);
      const width = sizeMatch ? parseInt(sizeMatch[1]) : 1080;
      const height = sizeMatch ? parseInt(sizeMatch[2]) : 1920;

      const wmDensity = await execAsync(`adb -s ${targetDeviceId} shell wm density`);
      const densityMatch = wmDensity.stdout.match(/Physical density: (\d+)/);
      const density = densityMatch ? parseInt(densityMatch[1]) : 420;

      const deviceInfo: DeviceInfo = {
        model: props['ro.product.model'] || 'Unknown',
        manufacturer: props['ro.product.manufacturer'] || 'Unknown',
        version: props['ro.build.version.release'] || 'Unknown',
        sdk: props['ro.build.version.sdk'] || 'Unknown',
        screen: {
          width,
          height,
          density
        }
      };

      return deviceInfo;
    } catch (error) {
      throw new Error(`Failed to get device info: ${error}`);
    }
  }

  /**
   * Get current app information
   */
  async getCurrentAppInfo(deviceId?: string): Promise<DeviceInfo['app']> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      // Get current focus window
      const { stdout: dumpsys } = await execAsync(
        `adb -s ${targetDeviceId} shell dumpsys window windows`
      );

      // Parse current activity
      const activityMatch = dumpsys.match(/mCurrentFocus=Window\{[^}]+([^ }]+)/);
      const activity = activityMatch ? activityMatch[1] : '';

      // Extract package name
      const packageMatch = activity.match(/^([^\/]+)/);
      const packageName = packageMatch ? packageMatch[1] : '';

      if (packageName) {
        try {
          // Get app version
          const { stdout: versionInfo } = await execAsync(
            `adb -s ${targetDeviceId} shell dumpsys package ${packageName} | grep versionName`
          );
          const versionMatch = versionInfo.match(/versionName=([^\\n]+)/);
          const version = versionMatch ? versionMatch[1] : 'Unknown';

          return {
            packageName,
            version,
            activity
          };
        } catch {
          return {
            packageName,
            version: 'Unknown',
            activity
          };
        }
      }

      return undefined;
    } catch (error) {
      throw new Error(`Failed to get current app info: ${error}`);
    }
  }

  /**
   * Perform tap action
   */
  async tap(x: number, y: number, deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(`adb -s ${targetDeviceId} shell input tap ${x} ${y}`);
    } catch (error) {
      throw new Error(`Failed to perform tap at (${x}, ${y}): ${error}`);
    }
  }

  /**
   * Perform swipe action
   */
  async swipe(
    x1: number, y1: number, x2: number, y2: number,
    duration: number = 300,
    deviceId?: string
  ): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(
        `adb -s ${targetDeviceId} shell input swipe ${x1} ${y1} ${x2} ${y2} ${duration}`
      );
    } catch (error) {
      throw new Error(`Failed to perform swipe from (${x1}, ${y1}) to (${x2}, ${y2}): ${error}`);
    }
  }

  /**
   * Type text
   */
  async typeText(text: string, deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      // Escape special characters for shell
      const escapedText = text.replace(/'/g, "\\'");
      await execAsync(`adb -s ${targetDeviceId} shell input text '${escapedText}'`);
    } catch (error) {
      throw new Error(`Failed to type text '${text}': ${error}`);
    }
  }

  /**
   * Press key
   */
  async pressKey(keyCode: number, deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(`adb -s ${targetDeviceId} shell input keyevent ${keyCode}`);
    } catch (error) {
      throw new Error(`Failed to press key ${keyCode}: ${error}`);
    }
  }

  /**
   * Press back button
   */
  async pressBack(deviceId?: string): Promise<void> {
    await this.pressKey(4, deviceId); // KEYCODE_BACK = 4
  }

  /**
   * Press home button
   */
  async pressHome(deviceId?: string): Promise<void> {
    await this.pressKey(3, deviceId); // KEYCODE_HOME = 3
  }

  /**
   * Start app
   */
  async startApp(packageName: string, activity?: string, deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      if (activity) {
        await execAsync(
          `adb -s ${targetDeviceId} shell am start -n ${packageName}/${activity}`
        );
      } else {
        await execAsync(
          `adb -s ${targetDeviceId} shell monkey -p ${packageName} -c android.intent.category.LAUNCHER 1`
        );
      }
    } catch (error) {
      throw new Error(`Failed to start app ${packageName}: ${error}`);
    }
  }

  /**
   * Force stop app
   */
  async forceStopApp(packageName: string, deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(`adb -s ${targetDeviceId} shell am force-stop ${packageName}`);
    } catch (error) {
      throw new Error(`Failed to force stop app ${packageName}: ${error}`);
    }
  }

  /**
   * Clear app data
   */
  async clearAppData(packageName: string, deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(`adb -s ${targetDeviceId} shell pm clear ${packageName}`);
    } catch (error) {
      throw new Error(`Failed to clear app data for ${packageName}: ${error}`);
    }
  }

  /**
   * Install APK
   */
  async installApk(apkPath: string, deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(`adb -s ${targetDeviceId} install "${apkPath}"`);
    } catch (error) {
      throw new Error(`Failed to install APK ${apkPath}: ${error}`);
    }
  }

  /**
   * Check if app is installed
   */
  async isAppInstalled(packageName: string, deviceId?: string): Promise<boolean> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      const { stdout } = await execAsync(
        `adb -s ${targetDeviceId} shell pm list packages | grep ${packageName}`
      );
      return stdout.includes(packageName);
    } catch {
      return false;
    }
  }

  /**
   * Wait for app to be in foreground
   */
  async waitForApp(packageName: string, timeoutMs: number = 10000, deviceId?: string): Promise<boolean> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const appInfo = await this.getCurrentAppInfo(targetDeviceId);
        if (appInfo?.packageName === packageName) {
          return true;
        }
      } catch {
        // Ignore errors and retry
      }

      await new Promise(resolve => setTimeout(resolve, 500));
    }

    return false;
  }

  /**
   * Get logcat output
   */
  async getLogcat(filter?: string, lines: number = 100, deviceId?: string): Promise<string> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      let command = `adb -s ${targetDeviceId} logcat -d -t ${lines}`;
      if (filter) {
        command += ` ${filter}`;
      }

      const { stdout } = await execAsync(command);
      return stdout;
    } catch (error) {
      throw new Error(`Failed to get logcat output: ${error}`);
    }
  }

  /**
   * Clear logcat
   */
  async clearLogcat(deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(`adb -s ${targetDeviceId} logcat -c`);
    } catch (error) {
      throw new Error(`Failed to clear logcat: ${error}`);
    }
  }

  /**
   * Reboot device
   */
  async reboot(deviceId?: string): Promise<void> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;

    try {
      await execAsync(`adb -s ${targetDeviceId} reboot`);
    } catch (error) {
      throw new Error(`Failed to reboot device: ${error}`);
    }
  }

  /**
   * Check connection health
   */
  async checkHealth(deviceId?: string): Promise<{
    connected: boolean;
    responsive: boolean;
    appRunning?: boolean;
    issues: string[];
  }> {
    const targetDeviceId = deviceId || this.emulatorDeviceId;
    const issues: string[] = [];

    try {
      // Check if device is connected
      const devices = await this.listDevices();
      const device = devices.find(d => d.id === targetDeviceId);

      if (!device) {
        issues.push('Device not found');
        return {
          connected: false,
          responsive: false,
          issues
        };
      }

      if (device.status !== 'device') {
        issues.push(`Device status: ${device.status}`);
        return {
          connected: true,
          responsive: false,
          issues
        };
      }

      // Check responsiveness by getting device info
      try {
        await this.getDeviceInfo(targetDeviceId);
      } catch (error) {
        issues.push('Device not responsive');
        return {
          connected: true,
          responsive: false,
          issues
        };
      }

      return {
        connected: true,
        responsive: true,
        issues
      };
    } catch (error) {
      issues.push(`Health check failed: ${error}`);
      return {
        connected: false,
        responsive: false,
        issues
      };
    }
  }
}

// Export singleton instance
export const adb = ADBUtils.getInstance();