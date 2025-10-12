import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * APK Install Service
 *
 * Orchestrates APK installation to the emulator using adb.
 * Supports downgrade and auto-grant permissions.
 */

export interface InstallOptions {
  /** Allow downgrade installation */
  allowDowngrade?: boolean;
  /** Auto-grant runtime permissions */
  autoGrantPermissions?: boolean;
}

export interface InstallResult {
  success: boolean;
  message: string;
  output?: string;
}

/**
 * Install an APK onto the connected emulator
 */
export async function installApk(
  apkPath: string,
  options: InstallOptions = {}
): Promise<InstallResult> {
  try {
    const flags: string[] = ['-r']; // Always reinstall

    if (options.allowDowngrade) {
      flags.push('-d'); // Allow version code downgrade
    }

    if (options.autoGrantPermissions) {
      flags.push('-g'); // Grant all runtime permissions
    }

    const command = `adb install ${flags.join(' ')} "${apkPath}"`;
    console.log(`[InstallService] Running: ${command}`);

    const { stdout, stderr } = await execAsync(command, {
      timeout: 60000, // 60 second timeout
      maxBuffer: 1024 * 1024 * 5 // 5MB buffer
    });

    const output = stdout + stderr;

    // Check for success
    if (output.includes('Success')) {
      return {
        success: true,
        message: 'APK installed successfully',
        output
      };
    }

    // Check for common errors
    if (output.includes('INSTALL_FAILED_VERSION_DOWNGRADE')) {
      return {
        success: false,
        message: 'Installation failed: Version downgrade not allowed (enable "Allow downgrade" option)',
        output
      };
    }

    if (output.includes('INSTALL_FAILED_ALREADY_EXISTS')) {
      return {
        success: false,
        message: 'Installation failed: App already exists with same version',
        output
      };
    }

    if (output.includes('INSTALL_FAILED')) {
      const match = output.match(/INSTALL_FAILED_[A-Z_]+/);
      const errorCode = match ? match[0] : 'UNKNOWN';
      return {
        success: false,
        message: `Installation failed: ${errorCode}`,
        output
      };
    }

    // Unknown failure
    return {
      success: false,
      message: 'Installation failed with unknown error',
      output
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    // Check for common exec errors
    if (errorMessage.includes('device offline')) {
      return {
        success: false,
        message: 'Installation failed: Emulator is offline'
      };
    }

    if (errorMessage.includes('no devices')) {
      return {
        success: false,
        message: 'Installation failed: No emulator connected'
      };
    }

    return {
      success: false,
      message: `Installation failed: ${errorMessage}`
    };
  }
}

/**
 * Uninstall an APK from the emulator
 */
export async function uninstallApk(packageName: string): Promise<InstallResult> {
  try {
    const command = `adb uninstall "${packageName}"`;
    console.log(`[InstallService] Running: ${command}`);

    const { stdout, stderr } = await execAsync(command, {
      timeout: 30000,
      maxBuffer: 1024 * 512
    });

    const output = stdout + stderr;

    if (output.includes('Success')) {
      return {
        success: true,
        message: 'APK uninstalled successfully',
        output
      };
    }

    return {
      success: false,
      message: 'Uninstallation failed',
      output
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Uninstallation failed'
    };
  }
}
