import { exec } from 'child_process';
import { promisify } from 'util';
import { readdir } from 'fs/promises';
import path from 'path';
import { logger } from './logger';
import { appPaths } from '../config/appPaths';
import { getEmulatorSerial } from './emulatorLifecycle';
import { installFromFile, installService } from './apps/installService';
import { launchApp } from './apps/launchService';
import { startProxyCapture } from './apps/proxyService';

const execAsync = promisify(exec);

/**
 * Auto-startup service
 * Runs after emulator boots to automatically:
 * - Install certificates
 * - Install and launch apps from library
 * - Start proxy capture
 * - Set up logging
 */

const STARTUP_LOG_FILE = path.join(appPaths.logsDir, 'auto-startup.log');
const PROXY_CAPTURE_LOG = path.join(appPaths.logsDir, 'proxy-capture.log');

/**
 * Log to both console and startup log file
 */
async function logStartup(message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logEntry = `[${timestamp}] ${message} ${data ? JSON.stringify(data) : ''}`;
  logger.info(message, data);

  try {
    await execAsync(`echo "${logEntry}" >> ${STARTUP_LOG_FILE}`);
  } catch (error) {
    logger.warn('Failed to write to startup log', { error });
  }
}

/**
 * Install mitmproxy CA certificate on the emulator
 */
async function installCertificate(serial: string): Promise<void> {
  await logStartup('Installing CA certificate...');

  try {
    // Check if certificate exists
    const certCheck = await execAsync('ls /root/.mitmproxy/mitmproxy-ca-cert.cer 2>/dev/null || echo "not found"');

    if (certCheck.stdout.includes('not found')) {
      await logStartup('Certificate not found, generating...');
      // Generate certificate by starting mitmproxy briefly
      await execAsync('timeout 5 mitmdump || true');
    }

    // Convert cert to Android format (hash-based filename)
    const certPath = '/root/.mitmproxy/mitmproxy-ca-cert.pem';
    const { stdout: certHash } = await execAsync(`openssl x509 -inform PEM -subject_hash_old -in ${certPath} | head -1`);
    const hash = certHash.trim();
    const androidCertName = `${hash}.0`;

    // Copy cert to proper format
    await execAsync(`cp ${certPath} /tmp/${androidCertName}`);

    // Push certificate to emulator
    await execAsync(`adb -s ${serial} root || true`);
    await execAsync(`adb -s ${serial} wait-for-device`);
    await execAsync(`adb -s ${serial} remount || true`);
    await execAsync(`adb -s ${serial} push /tmp/${androidCertName} /system/etc/security/cacerts/`);
    await execAsync(`adb -s ${serial} shell chmod 644 /system/etc/security/cacerts/${androidCertName}`);
    await execAsync(`adb -s ${serial} reboot`);

    // Wait for reboot
    await new Promise(resolve => setTimeout(resolve, 30000));
    await execAsync(`adb -s ${serial} wait-for-device`);

    await logStartup('CA certificate installed successfully');
  } catch (error) {
    await logStartup('Failed to install CA certificate', { error: (error as Error).message });
    throw error;
  }
}

/**
 * Extract and install XAPK file
 */
async function installXAPK(xapkPath: string, serial: string): Promise<string | null> {
  await logStartup(`Installing XAPK: ${xapkPath}`);

  try {
    const xapkName = path.basename(xapkPath, '.xapk');
    const extractDir = `/tmp/xapk_${Date.now()}`;

    // Extract XAPK (it's a ZIP file)
    await execAsync(`mkdir -p ${extractDir}`);
    await execAsync(`unzip -q "${xapkPath}" -d ${extractDir}`);

    // Find all APK files in the extracted directory
    const { stdout } = await execAsync(`find ${extractDir} -name "*.apk"`);
    const apkFiles = stdout.trim().split('\n').filter(Boolean);

    if (apkFiles.length === 0) {
      throw new Error('No APK files found in XAPK');
    }

    await logStartup(`Found ${apkFiles.length} APK file(s) in XAPK`);

    // Install all APKs (base + splits)
    for (const apkFile of apkFiles) {
      await logStartup(`Installing ${path.basename(apkFile)}...`);
      await execAsync(`adb -s ${serial} install -r "${apkFile}"`);
    }

    // Get package name from manifest
    const baseApk = apkFiles.find(f => f.includes('base.apk')) || apkFiles[0];
    const { stdout: packageInfo } = await execAsync(`aapt dump badging "${baseApk}" | grep package:`);
    const packageMatch = packageInfo.match(/name='([^']+)'/);
    const packageName = packageMatch ? packageMatch[1] : null;

    // Cleanup
    await execAsync(`rm -rf ${extractDir}`);

    await logStartup(`XAPK installed successfully`, { packageName });
    return packageName;
  } catch (error) {
    await logStartup(`Failed to install XAPK`, { error: (error as Error).message });
    throw error;
  }
}

/**
 * Start proxy capture and log to file
 */
async function startProxyCaptureWithLogging(serial: string): Promise<void> {
  await logStartup('Starting proxy capture...');

  try {
    // Set up proxy on emulator
    await execAsync(`adb -s ${serial} shell settings put global http_proxy localhost:8080`);

    // Start mitmproxy with logging
    const mitmproxyCmd = `mitmdump --set block_global=false -w ${PROXY_CAPTURE_LOG} > /dev/null 2>&1 &`;
    await execAsync(mitmproxyCmd);

    await logStartup('Proxy capture started', { logFile: PROXY_CAPTURE_LOG });
  } catch (error) {
    await logStartup('Failed to start proxy capture', { error: (error as Error).message });
    // Don't throw - proxy is optional
  }
}

/**
 * Main startup automation function
 * Called after emulator boots
 */
export async function runStartupAutomation(): Promise<void> {
  const serial = getEmulatorSerial();

  await logStartup('=== Starting Auto-Startup Automation ===', { serial });

  try {
    // Step 1: Install CA certificate
    await installCertificate(serial);

    // Step 2: Find and install XAPK files from library
    const libraryFiles = await readdir(appPaths.libraryDir);
    const xapkFiles = libraryFiles.filter(f => f.endsWith('.xapk'));

    let installedPackages: string[] = [];

    for (const xapkFile of xapkFiles) {
      const xapkPath = path.join(appPaths.libraryDir, xapkFile);
      const packageName = await installXAPK(xapkPath, serial);
      if (packageName) {
        installedPackages.push(packageName);
      }
    }

    // Step 3: Start proxy capture
    await startProxyCaptureWithLogging(serial);

    // Step 4: Launch first installed app
    if (installedPackages.length > 0) {
      const firstPackage = installedPackages[0];
      await logStartup(`Launching app: ${firstPackage}`);

      try {
        // Get main activity
        const { stdout } = await execAsync(`adb -s ${serial} shell cmd package resolve-activity --brief ${firstPackage} | tail -n 1`);
        const activity = stdout.trim();

        if (activity && !activity.includes('No activity')) {
          await execAsync(`adb -s ${serial} shell am start -n ${activity}`);
          await logStartup('App launched successfully', { activity });
        }
      } catch (error) {
        await logStartup('Failed to launch app', { error: (error as Error).message });
      }
    }

    await logStartup('=== Auto-Startup Automation Complete ===', {
      installedApps: installedPackages.length,
      proxyActive: true
    });
  } catch (error) {
    await logStartup('Auto-Startup Automation Failed', { error: (error as Error).message });
    throw error;
  }
}

/**
 * Get startup logs
 */
export async function getStartupLogs(): Promise<string> {
  try {
    const { stdout } = await execAsync(`cat ${STARTUP_LOG_FILE} 2>/dev/null || echo "No startup logs found"`);
    return stdout;
  } catch (error) {
    return `Error reading startup logs: ${(error as Error).message}`;
  }
}

/**
 * Get proxy capture logs
 */
export async function getProxyCaptureLog(): Promise<string> {
  try {
    const { stdout } = await execAsync(`cat ${PROXY_CAPTURE_LOG} 2>/dev/null || echo "No proxy capture logs found"`);
    return stdout;
  } catch (error) {
    return `Error reading proxy logs: ${(error as Error).message}`;
  }
}
