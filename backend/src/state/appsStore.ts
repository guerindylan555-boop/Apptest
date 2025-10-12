import * as fs from 'fs/promises';
import { appPaths } from '../config';
import type { ActivityLogEntry } from '../types/apps';

/**
 * Apps Activity Log Store
 *
 * Manages persistent activity log for APK operations (upload, install, launch, etc.)
 * Stored as newline-delimited JSON for efficient appending.
 */

/** In-memory cache of recent activity (last 100 entries) */
let recentActivity: ActivityLogEntry[] = [];

/**
 * Initialize the activity log
 */
export async function initializeActivityLog(): Promise<void> {
  try {
    // Ensure logs directory exists
    await fs.mkdir(appPaths.logsDir, { recursive: true });

    // Load recent entries if log exists
    try {
      const logData = await fs.readFile(appPaths.activityLogFile, 'utf-8');
      const lines = logData.trim().split('\n').filter((line) => line.length > 0);

      // Load last 100 entries
      recentActivity = lines
        .slice(-100)
        .map((line) => JSON.parse(line) as ActivityLogEntry);

      console.log(`[AppsStore] Loaded ${recentActivity.length} recent activity entries`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        console.log('[AppsStore] No existing activity log found, starting fresh');
      } else {
        throw err;
      }
    }
  } catch (error) {
    console.error('[AppsStore] Failed to initialize activity log:', error);
    throw error;
  }
}

/**
 * Append an activity log entry
 */
export async function logActivity(entry: Omit<ActivityLogEntry, 'timestamp'>): Promise<void> {
  const fullEntry: ActivityLogEntry = {
    ...entry,
    timestamp: new Date().toISOString()
  };

  // Add to in-memory cache
  recentActivity.push(fullEntry);
  if (recentActivity.length > 100) {
    recentActivity.shift(); // Keep only last 100
  }

  // Append to file (newline-delimited JSON)
  const line = JSON.stringify(fullEntry) + '\n';
  await fs.appendFile(appPaths.activityLogFile, line, 'utf-8');
}

/**
 * Get recent activity entries
 */
export function getRecentActivity(limit: number = 50): ActivityLogEntry[] {
  return recentActivity.slice(-limit).reverse(); // Most recent first
}

/**
 * Log APK upload event
 */
export async function logUpload(
  apkId: string,
  displayName: string,
  packageName: string,
  deduplicated: boolean
): Promise<void> {
  await logActivity({
    type: 'upload',
    message: deduplicated
      ? `Duplicate APK detected: ${displayName} (${packageName})`
      : `Uploaded APK: ${displayName} (${packageName})`,
    entityId: apkId,
    metadata: { displayName, packageName, deduplicated }
  });
}

/**
 * Log APK install event
 */
export async function logInstall(
  apkId: string,
  displayName: string,
  status: 'success' | 'failed',
  message: string
): Promise<void> {
  await logActivity({
    type: 'install',
    message: `Install ${status}: ${displayName} - ${message}`,
    entityId: apkId,
    metadata: { displayName, status }
  });
}

/**
 * Log app launch event
 */
export async function logLaunch(
  apkId: string,
  displayName: string,
  resolution: string,
  status: 'success' | 'failed'
): Promise<void> {
  await logActivity({
    type: 'launch',
    message: `Launch ${status}: ${displayName} via ${resolution}`,
    entityId: apkId,
    metadata: { displayName, resolution, status }
  });
}

/**
 * Log Frida operation
 */
export async function logFrida(
  action: string,
  packageName: string | null,
  status: 'success' | 'failed',
  message: string
): Promise<void> {
  await logActivity({
    type: 'frida',
    message: `Frida ${action}: ${message}`,
    entityId: packageName,
    metadata: { action, packageName, status }
  });
}

/**
 * Log retention sweep
 */
export async function logRetention(deletedCount: number, deletedIds: string[]): Promise<void> {
  await logActivity({
    type: 'retention',
    message: `Retention sweep completed: ${deletedCount} entries deleted`,
    entityId: null,
    metadata: { deletedCount, deletedIds }
  });
}

/**
 * Log error event
 */
export async function logError(message: string, details?: Record<string, unknown>): Promise<void> {
  await logActivity({
    type: 'error',
    message,
    entityId: null,
    metadata: details
  });
}
