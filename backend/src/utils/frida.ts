/**
 * Frida Hook Integration Utility
 *
 * Provides Frida dynamic instrumentation capabilities for
 * advanced app introspection, SSL pinning bypass, and API monitoring.
 */

import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

export interface FridaDevice {
  id: string;
  name: string;
  type: 'local' | 'remote' | 'usb';
  arch: string;
  system: string;
}

export interface FridaProcess {
  pid: number;
  name: string;
  identifier: string;
}

export interface HookScript {
  name: string;
  content: string;
  enabled: boolean;
  description?: string;
}

export interface FridaSessionOptions {
  deviceId?: string;
  processName?: string;
  scriptPath?: string;
  timeout?: number;
  persist?: boolean;
}

export interface FridaMessage {
  type: 'send' | 'log' | 'error' | 'result';
  payload: any;
  timestamp: number;
}

export class FridaUtils {
  private static instance: FridaUtils;
  private activeSessions: Map<string, any> = new Map();
  private messageHandlers: Map<string, (message: FridaMessage) => void> = new Map();

  private constructor() {}

  /**
   * Get singleton instance
   */
  static getInstance(): FridaUtils {
    if (!FridaUtils.instance) {
      FridaUtils.instance = new FridaUtils();
    }
    return FridaUtils.instance;
  }

  /**
   * Check if Frida is available
   */
  async isFridaAvailable(): Promise<boolean> {
    try {
      await execAsync('frida --version');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if Frida server is running on device
   */
  async isFridaServerRunning(deviceId?: string): Promise<boolean> {
    try {
      const args = deviceId ? ['-D', deviceId, 'ps'] : ['ps'];
      const { stdout } = await execAsync(`frida ${args.join(' ')}`);
      return true; // If command succeeds, server is running
    } catch (error) {
      return false;
    }
  }

  /**
   * List connected Frida devices
   */
  async listDevices(): Promise<FridaDevice[]> {
    try {
      const { stdout } = await execAsync('frida-ls-devices');
      const lines = stdout.trim().split('\n').slice(1); // Skip header

      const devices: FridaDevice[] = [];

      for (const line of lines) {
        if (!line.trim()) continue;

        const parts = line.trim().split(/\s+/);
        const id = parts[0];
        const type = parts[1] as 'local' | 'remote' | 'usb';
        const name = parts.slice(2).join(' ');

        // Get additional device info
        try {
          const { stdout: info } = await execAsync(`frida -D ${id} -e "System.arch"`);
          const arch = info.trim();

          const { stdout: sysInfo } = await execAsync(`frida -D ${id} -e "System.name"`);
          const system = sysInfo.trim();

          devices.push({
            id,
            name,
            type,
            arch,
            system
          });
        } catch {
          // Fallback if we can't get detailed info
          devices.push({
            id,
            name,
            type,
            arch: 'unknown',
            system: 'unknown'
          });
        }
      }

      return devices;
    } catch (error) {
      throw new Error(`Failed to list Frida devices: ${error}`);
    }
  }

  /**
   * List running processes on device
   */
  async listProcesses(deviceId?: string): Promise<FridaProcess[]> {
    try {
      const args = deviceId ? ['-D', deviceId, 'ps'] : ['ps'];
      const { stdout } = await execAsync(`frida ${args.join(' ')}`);
      const lines = stdout.trim().split('\n').slice(1); // Skip header

      const processes: FridaProcess[] = [];

      for (const line of lines) {
        if (!line.trim()) continue;

        const parts = line.trim().split(/\s+/);
        const pid = parseInt(parts[0]);
        const name = parts[1];
        const identifier = parts.slice(2).join(' ');

        processes.push({
          pid,
          name,
          identifier
        });
      }

      return processes;
    } catch (error) {
      throw new Error(`Failed to list processes: ${error}`);
    }
  }

  /**
   * Find process by name or package
   */
  async findProcess(processName: string, deviceId?: string): Promise<FridaProcess | null> {
    const processes = await this.listProcesses(deviceId);
    return processes.find(p =>
      p.name.includes(processName) ||
      p.identifier.includes(processName)
    ) || null;
  }

  /**
   * Create default hook scripts
   */
  createDefaultHooks(): HookScript[] {
    return [
      {
        name: 'ssl-bypass',
        content: `
// SSL Pinning Bypass Hook
Java.perform(function() {
    console.log("[*] SSL Bypass Hook Loaded");

    // Hook SSLContext
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[+] SSLContext.init() called with custom trust manager");
        this.init(keyManager, trustManager, secureRandom);
    };

    // Hook OkHttp3
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 CertificatePinner.check() bypassed for: " + hostname);
            return;
        };
        console.log("[+] OkHttp3 CertificatePinner hooked");
    } catch (e) {
        console.log("[-] OkHttp3 not found or already hooked");
    }

    // Hook TrustManager
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[+] X509TrustManager.checkServerTrusted() bypassed");
            return;
        };
        console.log("[+] X509TrustManager hooked");
    } catch (e) {
        console.log("[-] X509TrustManager not found or already hooked");
    }
});
        `,
        enabled: true,
        description: 'Bypass SSL certificate pinning for HTTPS inspection'
      },

      {
        name: 'http-monitor',
        content: `
// HTTP Traffic Monitor Hook
Java.perform(function() {
    console.log("[*] HTTP Monitor Hook Loaded");

    // Hook OkHttp3
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Call = Java.use("okhttp3.Call");

        Call.execute.implementation = function() {
            var request = this.request();
            var url = request.url().toString();
            var method = request.method();

            console.log("[+] HTTP Request: " + method + " " + url);

            // Log headers
            var headers = request.headers();
            var headerNames = headers.names();
            for (var i = 0; i < headerNames.size(); i++) {
                var name = headerNames.get(i);
                var value = headers.get(name);
                console.log("    " + name + ": " + value);
            }

            // Log body if present
            var body = request.body();
            if (body) {
                var buffer = Java.array('byte', body.contentLength());
                var sink = new Java.use("okio.Buffer");
                body.writeTo(sink);
                sink.read(buffer);
                var bodyStr = Java.use("java.lang.String").$new(buffer);
                console.log("    Body: " + bodyStr);
            }

            var response = this.execute();

            console.log("[+] HTTP Response: " + response.code() + " " + response.message());

            return response;
        };

        console.log("[+] OkHttp3 Request/Response hooked");
    } catch (e) {
        console.log("[-] OkHttp3 not found or already hooked");
    }

    // Hook HttpURLConnection
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");

        HttpURLConnection.getResponseCode.implementation = function() {
            var url = this.getURL().toString();
            var method = this.getRequestMethod();

            console.log("[+] HttpURLConnection Request: " + method + " " + url);

            var responseCode = this.getResponseCode();
            console.log("[+] HttpURLConnection Response: " + responseCode);

            return responseCode;
        };

        console.log("[+] HttpURLConnection hooked");
    } catch (e) {
        console.log("[-] HttpURLConnection not found or already hooked");
    }
});
        `,
        enabled: true,
        description: 'Monitor HTTP/HTTPS requests and responses'
      },

      {
        name: 'api-interceptor',
        content: `
// API Interceptor Hook for MaynDrive
Java.perform(function() {
    console.log("[*] API Interceptor Hook Loaded");

    // Hook Retrofit/OkHttp for MaynDrive API calls
    try {
        var Interceptor = Java.use("okhttp3.Interceptor");
        var Chain = Java.use("okhttp3.Interceptor$Chain");

        // This is a simplified interceptor - in practice you'd need to hook specific
        // MaynDrive classes or methods based on the app's architecture
        console.log("[+] API Interceptor framework loaded");
    } catch (e) {
        console.log("[-] API Interceptor setup failed: " + e);
    }

    // Hook common Android networking classes
    try {
        var URL = Java.use("java.net.URL");
        var URLConnection = Java.use("java.net.URLConnection");

        URLConnection.connect.implementation = function() {
            var url = this.getURL().toString();

            // Log MaynDrive API calls
            if (url.includes("mayndrive") || url.includes("api")) {
                console.log("[+] API Connection: " + url);
            }

            this.connect();
        };

        console.log("[+] URLConnection hooked for API monitoring");
    } catch (e) {
        console.log("[-] URLConnection hook failed: " + e);
    }
});
        `,
        enabled: false,
        description: 'Intercept MaynDrive API calls for analysis'
      }
    ];
  }

  /**
   * Save hook script to file
   */
  async saveHookScript(script: HookScript, scriptsDir: string = 'scripts/hooks'): Promise<string> {
    await fs.mkdir(scriptsDir, { recursive: true });
    const scriptPath = path.join(scriptsDir, `${script.name}.js`);
    await fs.writeFile(scriptPath, script.content, 'utf8');
    return scriptPath;
  }

  /**
   * Load hook script from file
   */
  async loadHookScript(scriptName: string, scriptsDir: string = 'scripts/hooks'): Promise<HookScript | null> {
    const scriptPath = path.join(scriptsDir, `${scriptName}.js`);
    try {
      const content = await fs.readFile(scriptPath, 'utf8');
      return {
        name: scriptName,
        content,
        enabled: true
      };
    } catch {
      return null;
    }
  }

  /**
   * Attach Frida to process with script
   */
  async attachToProcess(
    processName: string,
    scriptPath: string,
    options: FridaSessionOptions = {}
  ): Promise<string> {
    const {
      deviceId,
      timeout = 30000,
      persist = false
    } = options;

    const sessionId = `${processName}-${Date.now()}`;

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Frida attachment timeout after ${timeout}ms`));
      }, timeout);

      const args = [];

      if (deviceId) {
        args.push('-D', deviceId);
      }

      if (persist) {
        args.push('-f', processName);
      } else {
        args.push('-p', processName.toString());
      }

      args.push('-l', scriptPath);

      const process = spawn('frida', args);
      let sessionIdToResolve = sessionId;

      const messageHandler = (data: Buffer) => {
        try {
          const messages = data.toString().split('\n').filter(line => line.trim());

          for (const messageStr of messages) {
            if (messageStr.startsWith('[*]')) {
              // Script loaded successfully
              clearTimeout(timeoutId);
              this.activeSessions.set(sessionIdToResolve, process);
              resolve(sessionIdToResolve);
            }
          }
        } catch (error) {
          console.error('Error parsing Frida message:', error);
        }
      };

      process.stdout.on('data', messageHandler);
      process.stderr.on('data', (data: Buffer) => {
        console.error(`Frida stderr: ${data.toString()}`);
      });

      process.on('close', (code: number) => {
        clearTimeout(timeoutId);
        this.activeSessions.delete(sessionIdToResolve);

        if (code !== 0) {
          reject(new Error(`Frida process exited with code ${code}`));
        }
      });

      process.on('error', (error: Error) => {
        clearTimeout(timeoutId);
        reject(new Error(`Frida process error: ${error.message}`));
      });
    });
  }

  /**
   * Detach Frida from process
   */
  async detachFromProcess(sessionId: string): Promise<void> {
    const process = this.activeSessions.get(sessionId);
    if (process) {
      process.kill();
      this.activeSessions.delete(sessionId);
    }
  }

  /**
   * Get list of active sessions
   */
  getActiveSessions(): string[] {
    return Array.from(this.activeSessions.keys());
  }

  /**
   * Execute Frida script and get result
   */
  async executeScript(
    script: string,
    processName: string,
    options: FridaSessionOptions = {}
  ): Promise<any> {
    const { deviceId, timeout = 10000 } = options;

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Frida script execution timeout after ${timeout}ms`));
      }, timeout);

      const args = [];

      if (deviceId) {
        args.push('-D', deviceId);
      }

      args.push('-p', processName.toString());
      args.push('-e', script);

      execAsync(`frida ${args.join(' ')}`)
        .then(({ stdout }) => {
          clearTimeout(timeoutId);

          try {
            const result = JSON.parse(stdout.trim());
            resolve(result);
          } catch {
            resolve(stdout.trim());
          }
        })
        .catch((error) => {
          clearTimeout(timeoutId);
          reject(new Error(`Frida script execution failed: ${error}`));
        });
    });
  }

  /**
   * Spawn app with Frida
   */
  async spawnApp(
    packageName: string,
    scriptPath: string,
    options: FridaSessionOptions = {}
  ): Promise<string> {
    const { deviceId, timeout = 30000 } = options;

    const sessionId = `spawn-${packageName}-${Date.now()}`;

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Frida spawn timeout after ${timeout}ms`));
      }, timeout);

      const args = [];

      if (deviceId) {
        args.push('-D', deviceId);
      }

      args.push('-f', packageName);
      args.push('-l', scriptPath);

      const process = spawn('frida', args);

      process.stdout.on('data', (data: Buffer) => {
        const output = data.toString();

        if (output.includes('[*]')) {
          // App spawned successfully
          clearTimeout(timeoutId);
          this.activeSessions.set(sessionId, process);
          resolve(sessionId);
        }
      });

      process.stderr.on('data', (data: Buffer) => {
        console.error(`Frida spawn stderr: ${data.toString()}`);
      });

      process.on('close', (code: number) => {
        clearTimeout(timeoutId);
        this.activeSessions.delete(sessionId);

        if (code !== 0) {
          reject(new Error(`Frida spawn process exited with code ${code}`));
        }
      });

      process.on('error', (error: Error) => {
        clearTimeout(timeoutId);
        reject(new Error(`Frida spawn process error: ${error.message}`));
      });
    });
  }

  /**
   * Kill all Frida sessions
   */
  async killAllSessions(): Promise<void> {
    for (const [sessionId, process] of this.activeSessions) {
      try {
        process.kill();
      } catch (error) {
        console.warn(`Failed to kill session ${sessionId}: ${error}`);
      }
    }
    this.activeSessions.clear();
  }

  /**
   * Get Frida version
   */
  async getFridaVersion(): Promise<string> {
    try {
      const { stdout } = await execAsync('frida --version');
      return stdout.trim();
    } catch (error) {
      throw new Error(`Failed to get Frida version: ${error}`);
    }
  }

  /**
   * Check if process is running
   */
  async isProcessRunning(processName: string, deviceId?: string): Promise<boolean> {
    const processes = await this.listProcesses(deviceId);
    return processes.some(p =>
      p.name.includes(processName) ||
      p.identifier.includes(processName)
    );
  }

  /**
   * Start Frida server on device
   */
  async startFridaServer(deviceId?: string): Promise<void> {
    try {
      const command = deviceId
        ? `adb -s ${deviceId} shell "frida-server &"`
        : 'adb shell "frida-server &"';

      await execAsync(command);

      // Give server time to start
      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (error) {
      throw new Error(`Failed to start Frida server: ${error}`);
    }
  }

  /**
   * Stop Frida server on device
   */
  async stopFridaServer(deviceId?: string): Promise<void> {
    try {
      const command = deviceId
        ? `adb -s ${deviceId} shell "pkill frida-server"`
        : 'adb shell "pkill frida-server"';

      await execAsync(command);
    } catch (error) {
      throw new Error(`Failed to stop Frida server: ${error}`);
    }
  }

  /**
   * Check health of Frida setup
   */
  async checkHealth(deviceId?: string): Promise<{
    fridaAvailable: boolean;
    serverRunning: boolean;
    devicesConnected: number;
    processesFound: number;
    activeSessions: number;
    issues: string[];
  }> {
    const issues: string[] = [];

    // Check if Frida is available
    const fridaAvailable = await this.isFridaAvailable();
    if (!fridaAvailable) {
      issues.push('Frida CLI not available');
    }

    // Check if server is running
    let serverRunning = false;
    try {
      serverRunning = await this.isFridaServerRunning(deviceId);
      if (!serverRunning) {
        issues.push('Frida server not running on device');
      }
    } catch {
      issues.push('Failed to check Frida server status');
    }

    // Check devices
    let devicesConnected = 0;
    try {
      const devices = await this.listDevices();
      devicesConnected = devices.length;
      if (devicesConnected === 0) {
        issues.push('No Frida devices found');
      }
    } catch {
      issues.push('Failed to list Frida devices');
    }

    // Check processes
    let processesFound = 0;
    try {
      const processes = await this.listProcesses(deviceId);
      processesFound = processes.length;
    } catch {
      issues.push('Failed to list processes');
    }

    return {
      fridaAvailable,
      serverRunning,
      devicesConnected,
      processesFound,
      activeSessions: this.activeSessions.size,
      issues
    };
  }
}

// Export singleton instance
export const frida = FridaUtils.getInstance();