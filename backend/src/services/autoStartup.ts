import { exec } from 'child_process';
import { promisify } from 'util';
import { readdir } from 'fs/promises';
import path from 'path';
import { logger } from './logger';
import { appPaths } from '../config/appPaths';
import { getEmulatorSerial } from './emulatorLifecycle';
import { enableProxy } from './apps/proxyService';

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
 * Set up GPS location services
 * Configures location provider and sets initial GPS location
 */
async function setupGPSLocation(serial: string): Promise<void> {
  await logStartup('Setting up GPS location services...');

  try {
    // Check if emulator is ready for GPS commands
    const bootCheck = await execAsync(`adb -s ${serial} shell getprop sys.boot_completed`);
    if (bootCheck.stdout.trim() !== '1') {
      throw new Error('Emulator not fully booted');
    }

    // Enable location providers
    await execAsync(`adb -s ${serial} shell settings put secure location_providers_allowed +gps`);
    await execAsync(`adb -s ${serial} shell settings put secure location_providers_allowed +network`);
    await logStartup('Location providers enabled');

    // Set initial GPS location (Tours, France)
    const CONTAINER_ID = "3c75e7304ff6";
    const AUTH_TOKEN = "v0y2z0gSoz7JAyqD";
    const TARGET_LAT = "47.3878278";
    const TARGET_LNG = "0.6737631";
    const TARGET_ALT = "120";

    // Use Docker container approach for GPS commands
    const gpsCommand = `docker exec -i ${CONTAINER_ID} bash -lc 'printf "auth %s\\r\\ngeo fix %s %s %s\\r\\nquit\\r\\n" "$(cat ~/.emulator_console_auth_token)" | nc -w 2 localhost 5556'`;
    const fullCommand = gpsCommand
      .replace('%s', AUTH_TOKEN)
      .replace('%s', TARGET_LNG)
      .replace('%s', TARGET_LAT)
      .replace('%s', TARGET_ALT);

    await execAsync(fullCommand);
    await logStartup('GPS location set to Tours, France', { lat: TARGET_LAT, lng: TARGET_LNG, alt: TARGET_ALT });

    // Verify GPS is working
    const { stdout: gpsStatus } = await execAsync(`adb -s ${serial} shell dumpsys location | grep -A5 "gps provider"`);

    if (gpsStatus.includes('enabled=true') && gpsStatus.includes('last location=Location[gps')) {
      await logStartup('✅ GPS setup completed successfully');

      // Start GPS daemon for real-time updates
      const daemonCommand = `
        # Create GPS control directory
        mkdir -p /tmp/gps_control

        # Write current location file
        echo "lat=${TARGET_LAT}" > /tmp/gps_control/current_location.txt
        echo "lng=${TARGET_LNG}" >> /tmp/gps_control/current_location.txt
        echo "alt=${TARGET_ALT}" >> /tmp/gps_control/current_location.txt

        # Start GPS daemon
        while true; do
          if [ -f "/tmp/gps_control/update_location.txt" ]; then
            # Read new coordinates
            . /tmp/gps_control/update_location.txt

            # Update GPS location
            docker exec -i ${CONTAINER_ID} bash -lc 'printf "auth %s\\r\\ngeo fix %s %s %s\\r\\nquit\\r\\n" "\$(cat ~/.emulator_console_auth_token)" | nc -w 2 localhost 5556' \
              -- "${AUTH_TOKEN}" "\${lng}" "\${lat}" "\${alt}"

            # Update current location file
            echo "lat=\${lat}" > /tmp/gps_control/current_location.txt
            echo "lng=\${lng}" >> /tmp/gps_control/current_location.txt
            echo "alt=\${alt}" >> /tmp/gps_control/current_location.txt

            # Remove update file
            rm -f /tmp/gps_control/update_location.txt

            echo "GPS location updated to: \${lat}, \${lng}, \${alt}"
          fi
          sleep 1
        done
      `;

      await execAsync(`nohup bash -c '${daemonCommand}' > /tmp/gps_control/daemon.log 2>&1 &`);
      await logStartup('GPS daemon started for real-time updates');

    } else {
      throw new Error('GPS verification failed');
    }

  } catch (error) {
    throw new Error(`GPS setup failed: ${(error as Error).message}`);
  }
}

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
 * Uses user certificate store (no root required)
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

    // Convert cert to DER format for Android
    const certPath = '/root/.mitmproxy/mitmproxy-ca-cert.cer';
    const derCertPath = '/tmp/mitmproxy-cert.crt';

    await execAsync(`openssl x509 -inform PEM -outform DER -in ${certPath} -out ${derCertPath}`);

    // Push certificate to SD card
    await execAsync(`adb -s ${serial} push ${derCertPath} /sdcard/mitmproxy-cert.crt`);

    // Install certificate via settings command (user certificate store)
    // This doesn't require root and works on all Android versions
    await execAsync(`adb -s ${serial} shell am start -a android.credentials.INSTALL -t "application/x-x509-ca-cert" -d file:///sdcard/mitmproxy-cert.crt`);

    await logStartup('CA certificate installation initiated - user must confirm');

    // Clean up
    await execAsync(`adb -s ${serial} shell rm /sdcard/mitmproxy-cert.crt`);

  } catch (error) {
    await logStartup('Failed to install CA certificate (non-fatal)', { error: (error as Error).message });
    // Don't throw - certificate installation is optional
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

    // Install all APKs together using install-multiple (required for split APKs)
    const apkList = apkFiles.map(f => `"${f}"`).join(' ');
    await logStartup(`Installing all APKs together...`);
    await execAsync(`adb -s ${serial} install-multiple -r ${apkList}`);

    // Get package name from manifest
    const baseApk = apkFiles.find(f => f.includes('base.apk')) || apkFiles[0];
    const { stdout: packageInfo } = await execAsync(`aapt dump badging "${baseApk}" | grep package:`);
    const packageMatch = packageInfo.match(/name='([^']+)'/);
    const packageName = packageMatch ? packageMatch[1] : null;

    // Cleanup
    await execAsync(`rm -rf ${extractDir}`).catch(() => {});

    await logStartup(`XAPK installed successfully`, { packageName });
    return packageName;
  } catch (error) {
    await logStartup(`Failed to install XAPK`, { error: (error as Error).message });
    return null;
  }
}

/**
 * Start proxy capture and log to file
 */
async function startProxyCaptureWithLogging(serial: string): Promise<void> {
  await logStartup('Starting proxy capture...');

  try {
    // Enable proxy on emulator
    const result = await enableProxy('localhost', 8080);

    if (!result.success) {
      throw new Error(result.message);
    }

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

  let installedPackages: string[] = [];

  try {
    // Step 1: Install CA certificate (non-fatal)
    try {
      await installCertificate(serial);
    } catch (error) {
      await logStartup('Skipping certificate installation', { error: (error as Error).message });
    }

    // Step 2: Find and install XAPK files from library
    try {
      const libraryFiles = await readdir(appPaths.libraryDir);
      const xapkFiles = libraryFiles.filter(f => f.endsWith('.xapk'));

      await logStartup(`Found ${xapkFiles.length} XAPK file(s) to install`);

      for (const xapkFile of xapkFiles) {
        try {
          const xapkPath = path.join(appPaths.libraryDir, xapkFile);
          const packageName = await installXAPK(xapkPath, serial);
          if (packageName) {
            installedPackages.push(packageName);
          }
        } catch (error) {
          await logStartup(`Failed to install ${xapkFile}`, { error: (error as Error).message });
        }
      }
    } catch (error) {
      await logStartup('Failed to scan library directory', { error: (error as Error).message });
    }

    // Step 3: Set up GPS location services
    try {
      await setupGPSLocation(serial);
    } catch (error) {
      await logStartup('Skipping GPS setup', { error: (error as Error).message });
    }

    // Step 4: Start proxy capture (non-fatal)
    try {
      await startProxyCaptureWithLogging(serial);
    } catch (error) {
      await logStartup('Skipping proxy capture', { error: (error as Error).message });
    }

    // Step 5: Launch first installed app
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
      success: true
    });
  } catch (error) {
    await logStartup('Auto-Startup Automation had errors', { error: (error as Error).message });
    // Don't throw - automation failures shouldn't crash the backend
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
