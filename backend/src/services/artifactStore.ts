/**
 * Artifact Storage Service
 *
 * Manages filesystem-based storage for screen capture artifacts
 * including screenshots, XML dumps, and metadata with size tracking.
 */

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { ArtifactBundleEntity } from '../models/ArtifactBundle';

export interface ArtifactStorageOptions {
  baseDir?: string;
  maxSizePerBundle?: number;
  maxTotalSize?: number;
  enableCompression?: boolean;
}

export interface ArtifactStorageStats {
  totalBundles: number;
  totalSize: number;
  averageSize: number;
  largestBundle: string;
  smallestBundle: string;
  bundlesExceedingLimit: number;
  compressionSavings: number;
}

export interface CleanupOptions {
  olderThanDays?: number;
  largerThanMB?: number;
  keepLatest?: number;
  dryRun?: boolean;
}

export class ArtifactStorageService {
  private baseDir: string;
  private maxSizePerBundle: number;
  private maxTotalSize: number;
  private enableCompression: boolean;

  constructor(options: ArtifactStorageOptions = {}) {
    this.baseDir = options.baseDir || 'var/captures';
    this.maxSizePerBundle = options.maxSizePerBundle || (1024 * 1024); // 1MB default
    this.maxTotalSize = options.maxTotalSize || (100 * 1024 * 1024); // 100MB default
    this.enableCompression = options.enableCompression || false;

    this.ensureDirectory();
  }

  /**
   * Initialize storage directory
   */
  private async ensureDirectory(): Promise<void> {
    await fs.mkdir(this.baseDir, { recursive: true });
  }

  /**
   * Get node directory path
   */
  private getNodeDir(nodeId: string): string {
    return path.join(this.baseDir, nodeId);
  }

  /**
   * Get artifact file paths for a node
   */
  private getArtifactPaths(nodeId: string): {
    screenshot: string;
    xml: string;
    metadata: string;
    checksum: string;
  } {
    const nodeDir = this.getNodeDir(nodeId);
    return {
      screenshot: path.join(nodeDir, 'screenshot.png'),
      xml: path.join(nodeDir, 'ui.xml'),
      metadata: path.join(nodeDir, 'metadata.json'),
      checksum: path.join(nodeDir, 'checksum.txt')
    };
  }

  /**
   * Ensure node directory exists
   */
  private async ensureNodeDir(nodeId: string): Promise<void> {
    const nodeDir = this.getNodeDir(nodeId);
    await fs.mkdir(nodeDir, { recursive: true });
  }

  /**
   * Calculate file checksum
   */
  private async calculateFileChecksum(filePath: string): Promise<string> {
    try {
      const data = await fs.readFile(filePath);
      return crypto.createHash('sha256').update(data).digest('hex');
    } catch (error) {
      throw new Error(`Failed to calculate checksum for ${filePath}: ${error}`);
    }
  }

  /**
   * Store screenshot image
   */
  async storeScreenshot(nodeId: string, imageData: Buffer, format: string = 'png'): Promise<string> {
    await this.ensureNodeDir(nodeId);
    const { screenshot } = this.getArtifactPaths(nodeId);

    // Validate file size
    if (imageData.length > this.maxSizePerBundle) {
      throw new Error(`Screenshot size (${imageData.length} bytes) exceeds limit (${this.maxSizePerBundle} bytes)`);
    }

    // Store file
    await fs.writeFile(screenshot, imageData);

    return screenshot;
  }

  /**
   * Store XML dump
   */
  async storeXmlDump(nodeId: string, xmlData: string): Promise<string> {
    await this.ensureNodeDir(nodeId);
    const { xml } = this.getArtifactPaths(nodeId);

    // Validate size
    const bufferSize = Buffer.byteLength(xmlData, 'utf8');
    if (bufferSize > this.maxSizePerBundle) {
      throw new Error(`XML dump size (${bufferSize} bytes) exceeds limit (${this.maxSizePerBundle} bytes)`);
    }

    // Store file
    await fs.writeFile(xml, xmlData, 'utf8');

    return xml;
  }

  /**
   * Store metadata
   */
  async storeMetadata(nodeId: string, metadata: any): Promise<string> {
    await this.ensureNodeDir(nodeId);
    const { metadata: metadataPath } = this.getArtifactPaths(nodeId);

    const metadataJson = JSON.stringify(metadata, null, 2);
    await fs.writeFile(metadataPath, metadataJson, 'utf8');

    return metadataPath;
  }

  /**
   * Store complete artifact bundle
   */
  async storeBundle(
    nodeId: string,
    screenshotData: Buffer,
    xmlData: string,
    metadata: any = {}
  ): Promise<ArtifactBundleEntity> {
    await this.ensureNodeDir(nodeId);

    // Store individual files
    const screenshotPath = await this.storeScreenshot(nodeId, screenshotData);
    const xmlPath = await this.storeXmlDump(nodeId, xmlData);
    const metadataPath = await this.storeMetadata(nodeId, metadata);

    // Create artifact bundle
    const bundle = await ArtifactBundleEntity.fromFiles(
      screenshotPath,
      xmlPath,
      metadataPath,
      this.baseDir
    );

    // Store checksum file
    const { checksum } = this.getArtifactPaths(nodeId);
    await fs.writeFile(checksum, bundle.checksum, 'utf8');

    return bundle;
  }

  /**
   * Load artifact bundle for node
   */
  async loadBundle(nodeId: string): Promise<ArtifactBundleEntity | null> {
    const { screenshot, xml, metadata } = this.getArtifactPaths(nodeId);

    try {
      // Check if files exist
      await fs.access(screenshot);
      await fs.access(xml);

      // Metadata is optional
      try {
        await fs.access(metadata);
      } catch {
        // Metadata file doesn't exist, that's okay
      }

      // Create bundle
      const bundle = await ArtifactBundleEntity.fromFiles(
        screenshot,
        xml,
        metadata,
        this.baseDir
      );

      return bundle;
    } catch (error) {
      console.warn(`Failed to load artifact bundle for node ${nodeId}: ${error}`);
      return null;
    }
  }

  /**
   * Verify artifact bundle integrity
   */
  async verifyBundle(nodeId: string): Promise<{
    valid: boolean;
    issues: string[];
    actualChecksum?: string;
    expectedChecksum?: string;
  }> {
    const bundle = await this.loadBundle(nodeId);
    if (!bundle) {
      return {
        valid: false,
        issues: ['Bundle not found or incomplete']
      };
    }

    const issues: string[] = [];

    // Validate checksum
    const { checksum: checksumFile } = this.getArtifactPaths(nodeId);
    try {
      const expectedChecksum = (await fs.readFile(checksumFile, 'utf8')).trim();
      const actualChecksum = await bundle.generateChecksum();

      if (actualChecksum !== expectedChecksum) {
        issues.push(`Checksum mismatch: expected ${expectedChecksum}, got ${actualChecksum}`);
      }

      return {
        valid: issues.length === 0,
        issues,
        actualChecksum,
        expectedChecksum
      };
    } catch (error) {
      issues.push(`Failed to verify checksum: ${error}`);
      return {
        valid: false,
        issues
      };
    }
  }

  /**
   * Delete artifact bundle
   */
  async deleteBundle(nodeId: string): Promise<void> {
    const nodeDir = this.getNodeDir(nodeId);

    try {
      // Remove entire directory and contents
      await fs.rm(nodeDir, { recursive: true, force: true });
    } catch (error) {
      console.warn(`Failed to delete artifact bundle for node ${nodeId}: ${error}`);
      throw error;
    }
  }

  /**
   * Get bundle size
   */
  async getBundleSize(nodeId: string): Promise<number> {
    const bundle = await this.loadBundle(nodeId);
    if (!bundle) return 0;

    return await bundle.getTotalSize();
  }

  /**
   * Check if bundle exceeds size limit
   */
  async bundleExceedsLimit(nodeId: string, limit?: number): Promise<boolean> {
    const size = await this.getBundleSize(nodeId);
    const sizeLimit = limit || this.maxSizePerBundle;
    return size > sizeLimit;
  }

  /**
   * List all stored node IDs
   */
  async listNodeIds(): Promise<string[]> {
    try {
      const entries = await fs.readdir(this.baseDir, { withFileTypes: true });
      return entries
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name)
        .sort();
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  /**
   * Get storage statistics
   */
  async getStatistics(): Promise<ArtifactStorageStats> {
    const nodeIds = await this.listNodeIds();
    let totalSize = 0;
    let maxSize = 0;
    let minSize = Infinity;
    let largestBundle = '';
    let smallestBundle = '';
    let bundlesExceedingLimit = 0;

    for (const nodeId of nodeIds) {
      const size = await this.getBundleSize(nodeId);
      totalSize += size;

      if (size > maxSize) {
        maxSize = size;
        largestBundle = nodeId;
      }

      if (size < minSize && size > 0) {
        minSize = size;
        smallestBundle = nodeId;
      }

      if (size > this.maxSizePerBundle) {
        bundlesExceedingLimit++;
      }
    }

    const averageSize = nodeIds.length > 0 ? totalSize / nodeIds.length : 0;

    return {
      totalBundles: nodeIds.length,
      totalSize,
      averageSize: Math.round(averageSize),
      largestBundle,
      smallestBundle,
      bundlesExceedingLimit,
      compressionSavings: 0 // TODO: Implement if compression is enabled
    };
  }

  /**
   * Cleanup old or large artifacts
   */
  async cleanup(options: CleanupOptions = {}): Promise<{
    deleted: string[];
    totalFreed: number;
    errors: string[];
  }> {
    const {
      olderThanDays = 30,
      largerThanMB = 5,
      keepLatest = 10,
      dryRun = false
    } = options;

    const nodeIds = await this.listNodeIds();
    const deleted: string[] = [];
    const errors: string[] = [];
    let totalFreed = 0;

    // Sort by modification time (oldest first)
    const nodesWithTime: Array<{ nodeId: string; mtime: Date }> = [];

    for (const nodeId of nodeIds) {
      try {
        const nodeDir = this.getNodeDir(nodeId);
        const stats = await fs.stat(nodeDir);
        nodesWithTime.push({ nodeId, mtime: stats.mtime });
      } catch (error) {
        errors.push(`Failed to stat directory for ${nodeId}: ${error}`);
      }
    }

    nodesWithTime.sort((a, b) => a.mtime.getTime() - b.mtime.getTime());

    // Apply cleanup criteria
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - olderThanDays);
    const sizeLimitBytes = largerThanMB * 1024 * 1024;

    for (let i = 0; i < nodesWithTime.length; i++) {
      const { nodeId, mtime } = nodesWithTime[i];

      // Keep the latest N nodes
      if (i >= nodesWithTime.length - keepLatest) {
        continue;
      }

      let shouldDelete = false;
      let reason = '';

      // Check age
      if (mtime < cutoffDate) {
        shouldDelete = true;
        reason = `older than ${olderThanDays} days`;
      }

      // Check size
      const size = await this.getBundleSize(nodeId);
      if (size > sizeLimitBytes) {
        shouldDelete = true;
        reason = `larger than ${largerThanMB}MB (${Math.round(size / 1024 / 1024)}MB)`;
      }

      if (shouldDelete) {
        try {
          if (!dryRun) {
            await this.deleteBundle(nodeId);
          }
          deleted.push(`${nodeId} (${reason})`);
          totalFreed += size;
        } catch (error) {
          errors.push(`Failed to delete ${nodeId}: ${error}`);
        }
      }
    }

    return {
      deleted,
      totalFreed,
      errors
    };
  }

  /**
   * Optimize storage by compressing large bundles
   */
  async optimize(): Promise<{
    compressed: string[];
    compressionRatio: number;
    errors: string[];
  }> {
    // TODO: Implement compression optimization
    // This would involve compressing large XML files or images
    return {
      compressed: [],
      compressionRatio: 0,
      errors: []
    };
  }

  /**
   * Move artifacts between storage locations
   */
  async moveBundle(nodeId: string, targetBaseDir: string): Promise<string> {
    const targetService = new ArtifactStorageService({ baseDir: targetBaseDir });
    const bundle = await this.loadBundle(nodeId);

    if (!bundle) {
      throw new Error(`Artifact bundle not found for node ${nodeId}`);
    }

    // Read files
    const sourcePaths = bundle.getAbsolutePaths(this.baseDir);
    const screenshotData = await fs.readFile(sourcePaths.screenshotPath);
    const xmlData = await fs.readFile(sourcePaths.xmlPath, 'utf8');

    let metadataData = {};
    if (sourcePaths.metadataPath) {
      try {
        const metadataContent = await fs.readFile(sourcePaths.metadataPath, 'utf8');
        metadataData = JSON.parse(metadataContent);
      } catch {
        // Metadata is optional
      }
    }

    // Store in target location
    await targetService.storeBundle(nodeId, screenshotData, xmlData, metadataData);

    // Delete from source
    await this.deleteBundle(nodeId);

    return path.join(targetBaseDir, nodeId);
  }

  /**
   * Export artifacts to archive
   */
  async exportToArchive(nodeId: string, outputPath: string): Promise<void> {
    // TODO: Implement archive export (tar.gz format)
    // This would create a compressed archive of all artifacts for a node
    throw new Error('Archive export not yet implemented');
  }

  /**
   * Import artifacts from archive
   */
  async importFromArchive(archivePath: string): Promise<string> {
    // TODO: Implement archive import
    // This would extract artifacts from a compressed archive
    throw new Error('Archive import not yet implemented');
  }

  /**
   * Check total storage usage
   */
  async getTotalUsage(): Promise<number> {
    const stats = await this.getStatistics();
    return stats.totalSize;
  }

  /**
   * Check if storage exceeds total limit
   */
  async exceedsTotalLimit(): Promise<boolean> {
    const totalUsage = await this.getTotalUsage();
    return totalUsage > this.maxTotalSize;
  }

  /**
   * Get health status
   */
  async getHealthStatus(): Promise<{
    healthy: boolean;
    issues: string[];
    recommendations: string[];
  }> {
    const stats = await this.getStatistics();
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Check for bundles exceeding size limit
    if (stats.bundlesExceedingLimit > 0) {
      issues.push(`${stats.bundlesExceedingLimit} bundles exceed size limit`);
      recommendations.push('Run cleanup to remove large bundles');
    }

    // Check total storage usage
    if (stats.totalSize > this.maxTotalSize) {
      issues.push(`Total storage usage (${Math.round(stats.totalSize / 1024 / 1024)}MB) exceeds limit`);
      recommendations.push('Run cleanup to free up space');
    }

    // Check for very large bundles
    if (stats.largestBundle && stats.averageSize > this.maxSizePerBundle * 0.8) {
      issues.push('Average bundle size is close to limit');
      recommendations.push('Consider optimizing artifact capture process');
    }

    return {
      healthy: issues.length === 0,
      issues,
      recommendations
    };
  }
}

// Export singleton instance
export const artifactStorage = new ArtifactStorageService();