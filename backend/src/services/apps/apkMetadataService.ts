import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * APK Metadata Extraction Service
 *
 * Extracts metadata from APK files using aapt2 (Android Asset Packaging Tool).
 * Provides package identifiers, versioning, SDK targets, and launchable activities.
 */

export interface ApkMetadata {
  packageName: string;
  versionName: string | null;
  versionCode: string | null;
  minSdk: number | null;
  targetSdk: number | null;
  launchableActivity: string | null;
  applicationLabel: string | null;
  signerDigest: string;
  warnings: string[];
}

/**
 * Extract metadata from an APK file using aapt2
 */
export async function extractMetadata(apkPath: string): Promise<ApkMetadata> {
  const warnings: string[] = [];

  try {
    // Run aapt2 dump badging
    const { stdout } = await execAsync(`aapt2 dump badging "${apkPath}"`, {
      maxBuffer: 1024 * 1024 * 5 // 5MB buffer
    });

    // Parse the output
    const metadata: ApkMetadata = {
      packageName: extractField(stdout, /package: name='([^']+)'/) || 'unknown',
      versionName: extractField(stdout, /versionName='([^']+)'/),
      versionCode: extractField(stdout, /versionCode='([^']+)'/),
      minSdk: extractNumericField(stdout, /sdkVersion:'(\d+)'/),
      targetSdk: extractNumericField(stdout, /targetSdkVersion:'(\d+)'/),
      launchableActivity: extractLaunchableActivity(stdout),
      applicationLabel: extractField(stdout, /application-label:'([^']+)'/),
      signerDigest: await extractSignerDigest(apkPath),
      warnings
    };

    // Add warnings for missing critical fields
    if (!metadata.launchableActivity) {
      warnings.push('No launchable activity found - app may not be launchable');
    }

    if (!metadata.targetSdk) {
      warnings.push('Target SDK not specified');
    }

    return metadata;
  } catch (error) {
    throw new Error(`Failed to extract APK metadata: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

/**
 * Extract a single field from aapt2 output using regex
 */
function extractField(output: string, pattern: RegExp): string | null {
  const match = output.match(pattern);
  return match ? match[1] : null;
}

/**
 * Extract a numeric field from aapt2 output
 */
function extractNumericField(output: string, pattern: RegExp): number | null {
  const value = extractField(output, pattern);
  return value ? parseInt(value, 10) : null;
}

/**
 * Extract the launchable activity from aapt2 output
 */
function extractLaunchableActivity(output: string): string | null {
  // Look for launchable-activity
  const match = output.match(/launchable-activity: name='([^']+)'/);
  if (match) {
    return match[1];
  }

  // Fallback: look for main activity with launcher intent
  const lines = output.split('\n');
  let currentActivity: string | null = null;

  for (const line of lines) {
    const activityMatch = line.match(/name='([^']+)'/);
    if (activityMatch && line.includes('activity')) {
      currentActivity = activityMatch[1];
    }

    if (
      currentActivity &&
      line.includes('android.intent.action.MAIN') &&
      line.includes('android.intent.category.LAUNCHER')
    ) {
      return currentActivity;
    }
  }

  return null;
}

/**
 * Extract signer certificate digest from APK
 */
async function extractSignerDigest(apkPath: string): Promise<string> {
  try {
    // Use apksigner to get certificate info
    const { stdout } = await execAsync(`apksigner verify --print-certs "${apkPath}"`, {
      maxBuffer: 1024 * 1024
    });

    // Extract SHA-256 digest
    const match = stdout.match(/SHA-256 digest: ([a-fA-F0-9]+)/);
    if (match) {
      // Return shortened version (first 16 chars)
      return match[1].substring(0, 16).toLowerCase();
    }

    return 'unknown';
  } catch (error) {
    console.warn('[ApkMetadataService] Failed to extract signer digest:', error);
    return 'unknown';
  }
}

/**
 * Validate that an APK file is readable and parseable
 */
export async function validateApk(apkPath: string): Promise<{ valid: boolean; error?: string }> {
  try {
    await execAsync(`aapt2 dump badging "${apkPath}"`, {
      maxBuffer: 1024 * 512
    });
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Unknown validation error'
    };
  }
}
