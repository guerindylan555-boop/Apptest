import { exec } from 'child_process';
import { promisify } from 'util';
import { LaunchResolution } from '../../types/apps';

const execAsync = promisify(exec);

/**
 * App Launch Service
 *
 * Handles launching installed apps with multiple fallback strategies:
 * 1. Explicit activity (if provided)
 * 2. Resolved launchable activity (via package manager)
 * 3. Monkey tool (random UI interaction)
 */

export interface LaunchResult {
  success: boolean;
  resolution: LaunchResolution;
  message: string;
  output?: string;
}

/**
 * Launch an installed app using the best available strategy
 */
export async function launchApp(
  packageName: string,
  explicitActivity: string | null
): Promise<LaunchResult> {
  // Strategy 1: Use explicit activity if provided
  if (explicitActivity) {
    const result = await launchViaActivity(packageName, explicitActivity);
    if (result.success) {
      return {
        ...result,
        resolution: LaunchResolution.Explicit
      };
    }
    console.warn('[LaunchService] Explicit activity failed, trying resolution...');
  }

  // Strategy 2: Resolve launchable activity via package manager
  const resolvedActivity = await resolveMainActivity(packageName);
  if (resolvedActivity) {
    const result = await launchViaActivity(packageName, resolvedActivity);
    if (result.success) {
      return {
        ...result,
        resolution: LaunchResolution.Resolved,
        message: `Launched via resolved activity: ${resolvedActivity}`
      };
    }
    console.warn('[LaunchService] Resolved activity failed, trying Monkey...');
  }

  // Strategy 3: Use Monkey as fallback
  const monkeyResult = await launchViaMonkey(packageName);
  return {
    ...monkeyResult,
    resolution: monkeyResult.success ? LaunchResolution.Monkey : LaunchResolution.Failed
  };
}

/**
 * Launch app via explicit activity using am start
 */
async function launchViaActivity(
  packageName: string,
  activity: string
): Promise<{ success: boolean; message: string; output?: string }> {
  try {
    // Construct full activity name if not fully qualified
    const fullActivity = activity.startsWith(packageName) ? activity : `${packageName}/${activity}`;

    const command = `adb shell am start -n "${fullActivity}"`;
    console.log(`[LaunchService] Running: ${command}`);

    const { stdout, stderr } = await execAsync(command, {
      timeout: 10000,
      maxBuffer: 1024 * 512
    });

    const output = stdout + stderr;

    if (output.includes('Starting:') || output.includes('Status: ok')) {
      return {
        success: true,
        message: `Launched via activity: ${activity}`,
        output
      };
    }

    return {
      success: false,
      message: `Failed to launch activity: ${activity}`,
      output
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Activity launch failed'
    };
  }
}

/**
 * Resolve the main launchable activity for a package
 */
async function resolveMainActivity(packageName: string): Promise<string | null> {
  try {
    const command = `adb shell cmd package resolve-activity --brief "${packageName}" | tail -n 1`;
    console.log(`[LaunchService] Resolving activity: ${command}`);

    const { stdout } = await execAsync(command, {
      timeout: 5000,
      maxBuffer: 1024 * 512
    });

    const activity = stdout.trim();

    // Check if we got a valid activity name
    if (activity && activity.includes('/') && !activity.includes('No activity')) {
      console.log(`[LaunchService] Resolved activity: ${activity}`);
      return activity;
    }

    return null;
  } catch (error) {
    console.warn('[LaunchService] Failed to resolve activity:', error);
    return null;
  }
}

/**
 * Launch app via Monkey tool (generates random UI events)
 */
async function launchViaMonkey(
  packageName: string
): Promise<{ success: boolean; message: string; output?: string }> {
  try {
    // Use monkey with minimal events to just launch the app
    const command = `adb shell monkey -p "${packageName}" -c android.intent.category.LAUNCHER 1`;
    console.log(`[LaunchService] Running: ${command}`);

    const { stdout, stderr } = await execAsync(command, {
      timeout: 10000,
      maxBuffer: 1024 * 512
    });

    const output = stdout + stderr;

    // Check for success indicators
    if (
      output.includes('Events injected:') &&
      !output.includes('crash') &&
      !output.includes('Exception')
    ) {
      return {
        success: true,
        message: 'Launched via Monkey tool',
        output
      };
    }

    return {
      success: false,
      message: 'Monkey launch failed',
      output
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Monkey launch failed'
    };
  }
}

/**
 * Stop a running app
 */
export async function stopApp(packageName: string): Promise<{success: boolean; message: string}> {
  try {
    const command = `adb shell am force-stop "${packageName}"`;
    console.log(`[LaunchService] Running: ${command}`);

    await execAsync(command, {
      timeout: 5000,
      maxBuffer: 1024 * 512
    });

    return {
      success: true,
      message: `Stopped ${packageName}`
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Failed to stop app'
    };
  }
}
