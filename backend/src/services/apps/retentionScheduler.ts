import * as appsRepo from './appsRepository';
import { logger } from '../logger';

/**
 * Retention Scheduler
 *
 * Automatically sweeps unpinned APK entries older than 30 days.
 * Runs daily at midnight (configurable via RETENTION_CRON_SCHEDULE).
 */

const RETENTION_DAYS_THRESHOLD = 30;
const DEFAULT_SCHEDULE_HOUR = 0; // Midnight

let schedulerInterval: NodeJS.Timeout | null = null;

/**
 * Run retention sweep - delete unpinned entries older than threshold
 */
export async function runRetentionSweep(): Promise<{
  deletedCount: number;
  deletedIds: string[];
  durationMs: number;
}> {
  const startTime = Date.now();
  logger.info('[RetentionScheduler] Starting retention sweep', {
    threshold: `${RETENTION_DAYS_THRESHOLD} days`
  });

  try {
    // Find entries eligible for deletion
    const entriesToDelete = appsRepo.findEntriesForRetention(RETENTION_DAYS_THRESHOLD);

    if (entriesToDelete.length === 0) {
      logger.info('[RetentionScheduler] No entries eligible for deletion');
      return {
        deletedCount: 0,
        deletedIds: [],
        durationMs: Date.now() - startTime
      };
    }

    logger.info(`[RetentionScheduler] Found ${entriesToDelete.length} entries to delete`);

    // Delete each entry
    const deletedIds: string[] = [];
    for (const entry of entriesToDelete) {
      try {
        const deleted = await appsRepo.deleteEntry(entry.id);
        if (deleted) {
          deletedIds.push(entry.id);
          logger.info(`[RetentionScheduler] Deleted entry: ${entry.displayName} (${entry.id})`);
        }
      } catch (error) {
        logger.error(`[RetentionScheduler] Failed to delete entry ${entry.id}`, { error });
      }
    }

    const durationMs = Date.now() - startTime;
    logger.info('[RetentionScheduler] Retention sweep completed', {
      deletedCount: deletedIds.length,
      durationMs
    });

    return {
      deletedCount: deletedIds.length,
      deletedIds,
      durationMs
    };
  } catch (error) {
    logger.error('[RetentionScheduler] Retention sweep failed', { error });
    throw error;
  }
}

/**
 * Calculate milliseconds until next scheduled run (midnight)
 */
function getMillisecondsUntilNextRun(): number {
  const now = new Date();
  const nextRun = new Date();
  nextRun.setHours(DEFAULT_SCHEDULE_HOUR, 0, 0, 0);

  // If we've passed today's scheduled time, schedule for tomorrow
  if (now.getHours() >= DEFAULT_SCHEDULE_HOUR) {
    nextRun.setDate(nextRun.getDate() + 1);
  }

  return nextRun.getTime() - now.getTime();
}

/**
 * Schedule the next retention sweep
 */
function scheduleNextRun(): void {
  const msUntilNext = getMillisecondsUntilNextRun();
  const nextRunDate = new Date(Date.now() + msUntilNext);

  logger.info('[RetentionScheduler] Next sweep scheduled', {
    nextRun: nextRunDate.toISOString(),
    msUntilNext
  });

  schedulerInterval = setTimeout(async () => {
    try {
      await runRetentionSweep();
    } catch (error) {
      logger.error('[RetentionScheduler] Scheduled sweep failed', { error });
    }

    // Schedule next run (24 hours from now)
    scheduleNextRun();
  }, msUntilNext);
}

/**
 * Start the retention scheduler
 */
export function startScheduler(): void {
  if (schedulerInterval) {
    logger.warn('[RetentionScheduler] Scheduler already running');
    return;
  }

  logger.info('[RetentionScheduler] Starting scheduler', {
    threshold: `${RETENTION_DAYS_THRESHOLD} days`,
    schedule: `Daily at ${DEFAULT_SCHEDULE_HOUR}:00`
  });

  scheduleNextRun();
}

/**
 * Stop the retention scheduler
 */
export function stopScheduler(): void {
  if (schedulerInterval) {
    clearTimeout(schedulerInterval);
    schedulerInterval = null;
    logger.info('[RetentionScheduler] Scheduler stopped');
  }
}

/**
 * Get scheduler status
 */
export function getSchedulerStatus(): {
  running: boolean;
  threshold: number;
  schedule: string;
} {
  return {
    running: schedulerInterval !== null,
    threshold: RETENTION_DAYS_THRESHOLD,
    schedule: `Daily at ${DEFAULT_SCHEDULE_HOUR}:00`
  };
}
