/**
 * JSON File Storage Service with Optimistic Locking
 *
 * Provides atomic file operations with conflict detection and resolution
 * for concurrent access to JSON files. Used by graph and flow storage services.
 */

import { promises as fs } from 'fs';
import { createHash } from 'crypto';
import { join, resolve, dirname, basename } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { logger } from './logger';

// Types for the service
export interface VersionMetadata {
  version: string;
  hash: string;
  lastModified: string;
  createdBy?: string;
  comment?: string;
}

export interface StorageResult<T> {
  data: T;
  metadata: VersionMetadata;
  success: boolean;
}

export interface ListResult {
  files: string[];
  count: number;
  totalSize: number;
}

export interface StorageOptions {
  includeMetadata?: boolean;
  validateSchema?: boolean;
  createIfMissing?: boolean;
}

export interface CreateOptions extends StorageOptions {
  overwrite?: boolean;
  createdBy?: string;
  comment?: string;
}

export interface UpdateOptions extends StorageOptions {
  expectedVersion: string;
  expectedHash?: string;
  force?: boolean;
  updatedBy?: string;
  comment?: string;
}

export interface DeleteOptions {
  expectedVersion: string;
  expectedHash?: string;
  force?: boolean;
  deletedBy?: string;
  reason?: string;
}

export interface BackupResult {
  backupPath: string;
  originalHash: string;
  timestamp: string;
  success: boolean;
}

// Custom error types
export class StorageError extends Error {
  constructor(
    message: string,
    public code: string,
    public path?: string,
    public version?: string
  ) {
    super(message);
    this.name = 'StorageError';
  }
}

export class ConflictError extends StorageError {
  constructor(
    message: string,
    path: string,
    public currentVersion: string,
    public expectedVersion: string
  ) {
    super(message, 'CONFLICT', path, expectedVersion);
    this.name = 'ConflictError';
  }
}

export class ValidationError extends StorageError {
  constructor(message: string, path?: string) {
    super(message, 'VALIDATION_ERROR', path);
    this.name = 'ValidationError';
  }
}

// Environment configuration
const STORAGE_CONFIG = {
  GRAPH_ROOT: process.env.GRAPH_ROOT || resolve(process.cwd(), 'data/graphs'),
  FLOW_ROOT: process.env.FLOW_ROOT || resolve(process.cwd(), 'data/flows'),
  BACKUP_ENABLED: process.env.BACKUP_ENABLED !== 'false',
  BACKUP_ROOT: process.env.BACKUP_ROOT || resolve(process.cwd(), 'data/backups'),
  VALIDATION_ENABLED: process.env.VALIDATION_ENABLED !== 'false',
  MAX_BACKUPS: parseInt(process.env.MAX_BACKUPS || '10'),
  LOCK_TIMEOUT: parseInt(process.env.LOCK_TIMEOUT || '30000'), // 30 seconds
};

export class JsonStorageService {
  private lockFiles = new Map<string, { timestamp: number; owner: string }>();

  constructor() {
    this.ensureDirectories();
  }

  /**
   * Ensure required directories exist
   */
  private ensureDirectories(): void {
    const dirs = [
      STORAGE_CONFIG.GRAPH_ROOT,
      STORAGE_CONFIG.FLOW_ROOT,
      STORAGE_CONFIG.BACKUP_ROOT
    ];

    dirs.forEach(dir => {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
        logger.info(`Created storage directory: ${dir}`);
      }
    });
  }

  /**
   * Get the appropriate root directory based on file path
   */
  private getRootDirectory(path: string): string {
    if (path.includes('graph') || path.includes('/ui/')) {
      return STORAGE_CONFIG.GRAPH_ROOT;
    }
    if (path.includes('flow') || path.includes('/automation/')) {
      return STORAGE_CONFIG.FLOW_ROOT;
    }
    return dirname(path);
  }

  /**
   * Generate SHA-256 hash of JSON data
   */
  private generateHash(data: any): string {
    const jsonString = JSON.stringify(data, null, 2);
    return createHash('sha256').update(jsonString).digest('hex');
  }

  /**
   * Generate version string using timestamp and hash
   */
  private generateVersion(hash: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    return `${timestamp}-${hash.substring(0, 8)}`;
  }

  /**
   * Extract data from file (strip metadata if present)
   */
  private extractData(content: any): any {
    if (content && typeof content === 'object' && content.__version_metadata) {
      const { __version_metadata, ...data } = content;
      return data;
    }
    return content;
  }

  /**
   * Merge data with metadata
   */
  private mergeWithMetadata(data: any, metadata: VersionMetadata): any {
    return {
      ...data,
      __version_metadata: metadata
    };
  }

  /**
   * Acquire file lock for atomic operations
   */
  private async acquireLock(filePath: string, owner: string = 'system'): Promise<void> {
    const lockPath = `${filePath}.lock`;
    const now = Date.now();

    // Ensure the directory exists for the lock file
    await fs.mkdir(dirname(lockPath), { recursive: true });

    // Check if lock already exists and is stale
    if (this.lockFiles.has(lockPath)) {
      const lock = this.lockFiles.get(lockPath)!;
      if (now - lock.timestamp > STORAGE_CONFIG.LOCK_TIMEOUT) {
        logger.warn(`Removing stale lock: ${lockPath}`, { owner: lock.owner });
        this.lockFiles.delete(lockPath);
        try {
          await fs.unlink(lockPath);
        } catch (error) {
          // Lock file might have been removed already
        }
      } else {
        throw new StorageError(
          `File is locked by another operation: ${lock.owner}`,
          'LOCKED',
          filePath
        );
      }
    }

    // Create new lock
    this.lockFiles.set(lockPath, { timestamp: now, owner });

    try {
      await fs.writeFile(lockPath, JSON.stringify({
        owner,
        timestamp: now,
        pid: process.pid
      }));
    } catch (error) {
      this.lockFiles.delete(lockPath);
      throw new StorageError(
        `Failed to acquire lock: ${error}`,
        'LOCK_ERROR',
        filePath
      );
    }
  }

  /**
   * Release file lock
   */
  private async releaseLock(filePath: string): Promise<void> {
    const lockPath = `${filePath}.lock`;
    this.lockFiles.delete(lockPath);

    try {
      await fs.unlink(lockPath);
    } catch (error) {
      // Lock file might have been removed already
      logger.warn(`Failed to remove lock file: ${lockPath}`, { error });
    }
  }

  /**
   * Validate JSON structure
   */
  private validateJSON(data: any): void {
    if (data === null || data === undefined) {
      throw new ValidationError('Data cannot be null or undefined');
    }

    if (typeof data === 'object') {
      // Check for circular references
      try {
        JSON.stringify(data);
      } catch (error) {
        throw new ValidationError('Data contains circular references');
      }
    }
  }

  /**
   * Create backup of file before modification
   */
  private async createBackup(filePath: string): Promise<BackupResult> {
    if (!STORAGE_CONFIG.BACKUP_ENABLED) {
      return {
        backupPath: '',
        originalHash: '',
        timestamp: new Date().toISOString(),
        success: false
      };
    }

    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const data = JSON.parse(content);
      const hash = this.generateHash(data);
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName = `${basename(filePath, '.json')}.${timestamp}.json`;
      const backupPath = join(STORAGE_CONFIG.BACKUP_ROOT, fileName);

      await fs.writeFile(backupPath, content);

      // Clean up old backups
      await this.cleanupBackups(filePath);

      logger.info(`Created backup: ${backupPath}`, { originalPath: filePath, hash });

      return {
        backupPath,
        originalHash: hash,
        timestamp,
        success: true
      };
    } catch (error) {
      logger.error(`Failed to create backup: ${filePath}`, { error });
      return {
        backupPath: '',
        originalHash: '',
        timestamp: new Date().toISOString(),
        success: false
      };
    }
  }

  /**
   * Clean up old backup files
   */
  private async cleanupBackups(originalPath: string): Promise<void> {
    try {
      const baseName = basename(originalPath, '.json');
      const files = await fs.readdir(STORAGE_CONFIG.BACKUP_ROOT);
      const backupFiles = files
        .filter(f => f.startsWith(`${baseName}.`) && f.endsWith('.json'))
        .map(f => ({
          name: f,
          path: join(STORAGE_CONFIG.BACKUP_ROOT, f),
          time: fs.stat(join(STORAGE_CONFIG.BACKUP_ROOT, f)).then(s => s.mtime)
        }));

      // Sort by time and keep only the most recent ones
      const sortedFiles = await Promise.all(
        backupFiles.map(async f => ({ ...f, time: await f.time }))
      );
      sortedFiles.sort((a, b) => b.time.getTime() - a.time.getTime());

      const filesToDelete = sortedFiles.slice(STORAGE_CONFIG.MAX_BACKUPS);

      for (const file of filesToDelete) {
        await fs.unlink(file.path);
        logger.debug(`Deleted old backup: ${file.path}`);
      }
    } catch (error) {
      logger.warn('Failed to cleanup old backups', { error, originalPath });
    }
  }

  /**
   * Create a new JSON file
   */
  async create<T>(
    path: string,
    data: T,
    options: CreateOptions = {}
  ): Promise<StorageResult<T>> {
    const {
      includeMetadata = true,
      validateSchema = STORAGE_CONFIG.VALIDATION_ENABLED,
      overwrite = false,
      createdBy = 'system',
      comment
    } = options;

    const fullPath = resolve(this.getRootDirectory(path), path);

    logger.info(`Creating file: ${path}`, { fullPath, createdBy, overwrite });

    try {
      // Validate data
      if (validateSchema) {
        this.validateJSON(data);
      }

      // Check if file already exists
      if (!overwrite && existsSync(fullPath)) {
        throw new StorageError(
          `File already exists: ${path}`,
          'EXISTS',
          path
        );
      }

      await this.acquireLock(fullPath, 'create');

      try {
        // Create backup if overwriting
        if (overwrite && existsSync(fullPath)) {
          await this.createBackup(fullPath);
        }

        // Generate metadata
        const hash = this.generateHash(data);
        const version = this.generateVersion(hash);
        const metadata: VersionMetadata = {
          version,
          hash,
          lastModified: new Date().toISOString(),
          createdBy,
          comment
        };

        // Prepare content
        const content = includeMetadata
          ? this.mergeWithMetadata(data, metadata)
          : data;

        // Write file atomically
        const tempPath = `${fullPath}.tmp.${Date.now()}`;
        await fs.writeFile(tempPath, JSON.stringify(content, null, 2));
        await fs.rename(tempPath, fullPath);

        logger.info(`Successfully created file: ${path}`, {
          version,
          hash,
          createdBy
        });

        return {
          data,
          metadata,
          success: true
        };
      } finally {
        await this.releaseLock(fullPath);
      }
    } catch (error) {
      logger.error(`Failed to create file: ${path}`, { error });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to create file: ${error}`,
        'CREATE_ERROR',
        path
      );
    }
  }

  /**
   * Read a JSON file with metadata
   */
  async read<T>(
    path: string,
    options: StorageOptions = {}
  ): Promise<StorageResult<T>> {
    const {
      includeMetadata = true,
      validateSchema = STORAGE_CONFIG.VALIDATION_ENABLED
    } = options;

    const fullPath = resolve(this.getRootDirectory(path), path);

    logger.debug(`Reading file: ${path}`, { fullPath });

    try {
      if (!existsSync(fullPath)) {
        throw new StorageError(
          `File not found: ${path}`,
          'NOT_FOUND',
          path
        );
      }

      const content = await fs.readFile(fullPath, 'utf-8');
      const parsed = JSON.parse(content);

      // Extract metadata and data
      const metadata = parsed.__version_metadata as VersionMetadata || {
        version: 'unknown',
        hash: this.generateHash(parsed),
        lastModified: (await fs.stat(fullPath)).mtime.toISOString()
      };

      const data = this.extractData(parsed);

      // Validate data
      if (validateSchema) {
        this.validateJSON(data);
      }

      logger.debug(`Successfully read file: ${path}`, {
        version: metadata.version,
        hash: metadata.hash
      });

      return {
        data: data as T,
        metadata,
        success: true
      };
    } catch (error) {
      if (error instanceof StorageError) {
        throw error;
      }
      logger.error(`Failed to read file: ${path}`, { error });
      throw new StorageError(
        `Failed to read file: ${error}`,
        'READ_ERROR',
        path
      );
    }
  }

  /**
   * Update a JSON file with optimistic locking
   */
  async update<T>(
    path: string,
    data: T,
    options: UpdateOptions
  ): Promise<StorageResult<T>> {
    const {
      includeMetadata = true,
      validateSchema = STORAGE_CONFIG.VALIDATION_ENABLED,
      expectedVersion,
      expectedHash,
      force = false,
      updatedBy = 'system',
      comment
    } = options;

    const fullPath = resolve(this.getRootDirectory(path), path);

    logger.info(`Updating file: ${path}`, {
      fullPath,
      expectedVersion,
      updatedBy,
      force
    });

    try {
      // Validate data
      if (validateSchema) {
        this.validateJSON(data);
      }

      if (!existsSync(fullPath)) {
        throw new StorageError(
          `File not found: ${path}`,
          'NOT_FOUND',
          path
        );
      }

      await this.acquireLock(fullPath, 'update');

      try {
        // Read current file
        const current = await this.read(path, { includeMetadata: true });

        // Check for conflicts unless force is enabled
        if (!force) {
          if (current.metadata.version !== expectedVersion) {
            throw new ConflictError(
              `Version conflict: expected ${expectedVersion}, found ${current.metadata.version}`,
              path,
              current.metadata.version,
              expectedVersion
            );
          }

          if (expectedHash && current.metadata.hash !== expectedHash) {
            throw new ConflictError(
              `Hash conflict: expected ${expectedHash}, found ${current.metadata.hash}`,
              path,
              current.metadata.version,
              expectedVersion
            );
          }
        }

        // Create backup
        await this.createBackup(fullPath);

        // Generate new metadata
        const hash = this.generateHash(data);
        const version = this.generateVersion(hash);
        const metadata: VersionMetadata = {
          version,
          hash,
          lastModified: new Date().toISOString(),
          createdBy: updatedBy,
          comment
        };

        // Prepare content
        const content = includeMetadata
          ? this.mergeWithMetadata(data, metadata)
          : data;

        // Write file atomically
        const tempPath = `${fullPath}.tmp.${Date.now()}`;
        await fs.writeFile(tempPath, JSON.stringify(content, null, 2));
        await fs.rename(tempPath, fullPath);

        logger.info(`Successfully updated file: ${path}`, {
          oldVersion: current.metadata.version,
          newVersion: version,
          hash,
          updatedBy
        });

        return {
          data,
          metadata,
          success: true
        };
      } finally {
        await this.releaseLock(fullPath);
      }
    } catch (error) {
      logger.error(`Failed to update file: ${path}`, { error });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to update file: ${error}`,
        'UPDATE_ERROR',
        path
      );
    }
  }

  /**
   * Delete a JSON file with version check
   */
  async delete(
    path: string,
    options: DeleteOptions
  ): Promise<{ success: boolean; deletedPath: string }> {
    const {
      expectedVersion,
      expectedHash,
      force = false,
      deletedBy = 'system',
      reason
    } = options;

    const fullPath = resolve(this.getRootDirectory(path), path);

    logger.info(`Deleting file: ${path}`, {
      fullPath,
      expectedVersion,
      deletedBy,
      reason,
      force
    });

    try {
      if (!existsSync(fullPath)) {
        throw new StorageError(
          `File not found: ${path}`,
          'NOT_FOUND',
          path
        );
      }

      await this.acquireLock(fullPath, 'delete');

      try {
        // Read current file for version check
        const current = await this.read(path, { includeMetadata: true });

        // Check for conflicts unless force is enabled
        if (!force) {
          if (current.metadata.version !== expectedVersion) {
            throw new ConflictError(
              `Version conflict: expected ${expectedVersion}, found ${current.metadata.version}`,
              path,
              current.metadata.version,
              expectedVersion
            );
          }

          if (expectedHash && current.metadata.hash !== expectedHash) {
            throw new ConflictError(
              `Hash conflict: expected ${expectedHash}, found ${current.metadata.hash}`,
              path,
              current.metadata.version,
              expectedVersion
            );
          }
        }

        // Create backup before deletion
        const backup = await this.createBackup(fullPath);

        // Delete the file
        await fs.unlink(fullPath);

        logger.info(`Successfully deleted file: ${path}`, {
          version: current.metadata.version,
          deletedBy,
          reason,
          backupPath: backup.backupPath
        });

        return {
          success: true,
          deletedPath: fullPath
        };
      } finally {
        await this.releaseLock(fullPath);
      }
    } catch (error) {
      logger.error(`Failed to delete file: ${path}`, { error });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to delete file: ${error}`,
        'DELETE_ERROR',
        path
      );
    }
  }

  /**
   * List files in a directory
   */
  async list(directory: string): Promise<ListResult> {
    const fullPath = resolve(this.getRootDirectory(directory), directory);

    logger.debug(`Listing files in: ${directory}`, { fullPath });

    try {
      if (!existsSync(fullPath)) {
        throw new StorageError(
          `Directory not found: ${directory}`,
          'NOT_FOUND',
          directory
        );
      }

      const entries = await fs.readdir(fullPath, { withFileTypes: true });
      const files: string[] = [];
      let totalSize = 0;

      for (const entry of entries) {
        if (entry.isFile() && entry.name.endsWith('.json')) {
          const filePath = join(fullPath, entry.name);
          const stat = await fs.stat(filePath);
          files.push(entry.name);
          totalSize += stat.size;
        }
      }

      logger.debug(`Listed files in: ${directory}`, { count: files.length, totalSize });

      return {
        files,
        count: files.length,
        totalSize
      };
    } catch (error) {
      if (error instanceof StorageError) {
        throw error;
      }
      logger.error(`Failed to list directory: ${directory}`, { error });
      throw new StorageError(
        `Failed to list directory: ${error}`,
        'LIST_ERROR',
        directory
      );
    }
  }

  /**
   * Create a backup of a file
   */
  async backup(path: string): Promise<BackupResult> {
    const fullPath = resolve(this.getRootDirectory(path), path);

    logger.info(`Creating backup of: ${path}`, { fullPath });

    try {
      if (!existsSync(fullPath)) {
        throw new StorageError(
          `File not found: ${path}`,
          'NOT_FOUND',
          path
        );
      }

      const backup = await this.createBackup(fullPath);

      if (backup.success) {
        logger.info(`Successfully created backup: ${path}`, {
          backupPath: backup.backupPath,
          hash: backup.originalHash
        });
      }

      return backup;
    } catch (error) {
      logger.error(`Failed to create backup: ${path}`, { error });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to create backup: ${error}`,
        'BACKUP_ERROR',
        path
      );
    }
  }

  /**
   * Get storage statistics
   */
  async getStats(directory?: string): Promise<{
    totalFiles: number;
    totalSize: number;
    lastModified: string;
  }> {
    const rootDir = directory ? resolve(this.getRootDirectory(directory), directory) : STORAGE_CONFIG.GRAPH_ROOT;

    try {
      let totalFiles = 0;
      let totalSize = 0;
      let lastModified = new Date(0);

      const scanDirectory = async (dir: string) => {
        const entries = await fs.readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = join(dir, entry.name);

          if (entry.isDirectory()) {
            await scanDirectory(fullPath);
          } else if (entry.isFile() && entry.name.endsWith('.json')) {
            const stat = await fs.stat(fullPath);
            totalFiles++;
            totalSize += stat.size;

            if (stat.mtime > lastModified) {
              lastModified = stat.mtime;
            }
          }
        }
      };

      if (existsSync(rootDir)) {
        await scanDirectory(rootDir);
      }

      return {
        totalFiles,
        totalSize,
        lastModified: lastModified.toISOString()
      };
    } catch (error) {
      logger.error(`Failed to get stats for: ${directory}`, { error });
      throw new StorageError(
        `Failed to get stats: ${error}`,
        'STATS_ERROR',
        directory
      );
    }
  }
}

// Export singleton instance
export const jsonStorage = new JsonStorageService();

// Export types for external use - removed duplicate exports to avoid conflicts