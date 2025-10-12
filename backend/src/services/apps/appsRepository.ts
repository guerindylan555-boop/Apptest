import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import { appPaths } from '../../config';
import type { ApkEntry } from '../../types/apps';

/**
 * APK Repository
 *
 * Manages filesystem-based storage and indexing of APK files.
 * Provides CRUD operations with deduplication via SHA-256 hashing.
 */

/** In-memory cache of APK entries, hydrated from disk at startup */
let apkIndex: Map<string, ApkEntry> = new Map();

/**
 * Initialize the repository by loading the index from disk
 */
export async function initializeRepository(): Promise<void> {
  try {
    // Ensure directory structure exists
    await fs.mkdir(appPaths.libraryDir, { recursive: true });
    await fs.mkdir(appPaths.logsDir, { recursive: true });
    await fs.mkdir(appPaths.scriptsDir, { recursive: true });

    // Load existing index if it exists
    const indexPath = appPaths.metadataIndexFile;
    try {
      const indexData = await fs.readFile(indexPath, 'utf-8');
      const entries: ApkEntry[] = JSON.parse(indexData);
      apkIndex = new Map(entries.map((entry) => [entry.id, entry]));
      console.log(`[AppsRepository] Loaded ${apkIndex.size} APK entries from index`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        console.log('[AppsRepository] No existing index found, starting fresh');
      } else {
        throw err;
      }
    }
  } catch (error) {
    console.error('[AppsRepository] Failed to initialize repository:', error);
    throw error;
  }
}

/**
 * Persist the in-memory index to disk
 */
async function saveIndex(): Promise<void> {
  const entries = Array.from(apkIndex.values());
  await fs.writeFile(
    appPaths.metadataIndexFile,
    JSON.stringify(entries, null, 2),
    'utf-8'
  );
}

/**
 * Calculate SHA-256 hash of a file
 */
export async function calculateFileHash(filePath: string): Promise<string> {
  const fileBuffer = await fs.readFile(filePath);
  const hash = crypto.createHash('sha256');
  hash.update(fileBuffer);
  return hash.digest('hex');
}

/**
 * Check if an APK with the given SHA-256 hash already exists
 */
export function findByHash(sha256: string): ApkEntry | undefined {
  return Array.from(apkIndex.values()).find((entry) => entry.sha256 === sha256);
}

/**
 * Get all APK entries, optionally filtered and sorted
 */
export function getAllEntries(options?: {
  search?: string;
  sortBy?: 'uploadedAt' | 'lastUsedAt' | 'displayName' | 'packageName';
  sortOrder?: 'asc' | 'desc';
}): ApkEntry[] {
  let entries = Array.from(apkIndex.values());

  // Apply search filter
  if (options?.search) {
    const searchLower = options.search.toLowerCase();
    entries = entries.filter(
      (entry) =>
        entry.displayName.toLowerCase().includes(searchLower) ||
        entry.packageName.toLowerCase().includes(searchLower)
    );
  }

  // Apply sorting
  if (options?.sortBy) {
    entries.sort((a, b) => {
      const aVal = a[options.sortBy!];
      const bVal = b[options.sortBy!];

      if (aVal === null && bVal === null) return 0;
      if (aVal === null) return 1;
      if (bVal === null) return -1;

      let comparison = 0;
      if (typeof aVal === 'string' && typeof bVal === 'string') {
        comparison = aVal.localeCompare(bVal);
      } else if (aVal < bVal) {
        comparison = -1;
      } else if (aVal > bVal) {
        comparison = 1;
      }

      return options.sortOrder === 'desc' ? -comparison : comparison;
    });
  }

  return entries;
}

/**
 * Get a single APK entry by ID
 */
export function getEntryById(id: string): ApkEntry | undefined {
  return apkIndex.get(id);
}

/**
 * Create a new APK entry
 */
export async function createEntry(entry: ApkEntry): Promise<ApkEntry> {
  apkIndex.set(entry.id, entry);
  await saveIndex();
  return entry;
}

/**
 * Update an existing APK entry
 */
export async function updateEntry(
  id: string,
  updates: Partial<ApkEntry>
): Promise<ApkEntry | null> {
  const existing = apkIndex.get(id);
  if (!existing) {
    return null;
  }

  const updated = { ...existing, ...updates };
  apkIndex.set(id, updated);
  await saveIndex();
  return updated;
}

/**
 * Delete an APK entry and its associated files
 */
export async function deleteEntry(id: string): Promise<boolean> {
  const entry = apkIndex.get(id);
  if (!entry) {
    return false;
  }

  // Delete the APK file
  try {
    await fs.unlink(entry.filePath);
  } catch (err) {
    console.warn(`[AppsRepository] Failed to delete APK file: ${entry.filePath}`, err);
  }

  // Delete associated artifacts
  for (const logPath of entry.artifacts.installLogs) {
    try {
      await fs.unlink(logPath);
    } catch (err) {
      console.warn(`[AppsRepository] Failed to delete install log: ${logPath}`, err);
    }
  }

  for (const capturePath of entry.artifacts.logcatCaptures) {
    try {
      await fs.unlink(capturePath);
    } catch (err) {
      console.warn(`[AppsRepository] Failed to delete logcat capture: ${capturePath}`, err);
    }
  }

  // Remove from index
  apkIndex.delete(id);
  await saveIndex();
  return true;
}

/**
 * Find entries eligible for retention cleanup (older than daysThreshold, not pinned)
 */
export function findEntriesForRetention(daysThreshold: number): ApkEntry[] {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - daysThreshold);
  const cutoffTime = cutoffDate.getTime();

  return Array.from(apkIndex.values()).filter((entry) => {
    if (entry.pinned) {
      return false;
    }

    const entryDate = new Date(entry.lastUsedAt || entry.uploadedAt);
    return entryDate.getTime() < cutoffTime;
  });
}

/**
 * Store uploaded APK file and return the storage path
 */
export async function storeApkFile(
  fileBuffer: Buffer,
  originalFilename: string,
  sha256: string
): Promise<string> {
  // Use first 8 chars of hash as part of filename to avoid collisions
  const hashPrefix = sha256.substring(0, 8);
  const sanitizedFilename = originalFilename.replace(/[^a-zA-Z0-9._-]/g, '_');
  const storagePath = path.join(appPaths.libraryDir, `${hashPrefix}_${sanitizedFilename}`);

  await fs.writeFile(storagePath, fileBuffer);
  return storagePath;
}
