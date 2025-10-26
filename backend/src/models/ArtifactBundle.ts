/**
 * ArtifactBundle Entity
 *
 * Handles artifact storage, checksum validation, and file management
 * for screen captures (screenshots, XML dumps, metadata).
 */

import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { ArtifactBundle } from '../types/uiGraph';

export interface ArtifactBundleOptions {
  screenshotPath?: string;
  xmlPath?: string;
  metadataPath?: string;
  baseDir?: string;
  generateChecksums?: boolean;
}

export class ArtifactBundleEntity implements ArtifactBundle {
  screenshotPath: string;
  xmlPath: string;
  metadataPath?: string;
  checksum: string;

  constructor(screenshotPath: string, xmlPath: string, metadataPath?: string) {
    this.screenshotPath = screenshotPath;
    this.xmlPath = xmlPath;
    this.metadataPath = metadataPath;
    this.checksum = ''; // Will be set during validation
  }

  /**
   * Create artifact bundle from capture files
   */
  static async fromFiles(
    screenshotPath: string,
    xmlPath: string,
    metadataPath?: string,
    baseDir: string = 'var/captures'
  ): Promise<ArtifactBundleEntity> {
    // Normalize paths to be relative to base directory
    const normalizedScreenshot = path.relative(baseDir, screenshotPath);
    const normalizedXml = path.relative(baseDir, xmlPath);
    const normalizedMetadata = metadataPath ? path.relative(baseDir, metadataPath) : undefined;

    const bundle = new ArtifactBundleEntity(
      normalizedScreenshot,
      normalizedXml,
      normalizedMetadata
    );

    // Generate checksum from all files
    await bundle.generateChecksum();

    return bundle;
  }

  /**
   * Generate checksum from all artifact files
   */
  async generateChecksum(): Promise<string> {
    const hash = crypto.createHash('sha256');

    try {
      // Add screenshot file content to hash
      if (this.screenshotPath) {
        const screenshotContent = await this.readFileContent(this.screenshotPath);
        hash.update(screenshotContent);
      }

      // Add XML file content to hash
      if (this.xmlPath) {
        const xmlContent = await this.readFileContent(this.xmlPath);
        hash.update(xmlContent);
      }

      // Add metadata file content to hash (if exists)
      if (this.metadataPath) {
        try {
          const metadataContent = await this.readFileContent(this.metadataPath);
          hash.update(metadataContent);
        } catch (error) {
          // Metadata file is optional, don't fail if missing
          console.warn(`Metadata file not found: ${this.metadataPath}`);
        }
      }

      this.checksum = hash.digest('hex');
      return this.checksum;

    } catch (error) {
      throw new Error(`Failed to generate artifact checksum: ${error}`);
    }
  }

  /**
   * Read file content for checksum calculation
   */
  private async readFileContent(filePath: string): Promise<Buffer> {
    const fullPath = path.resolve('var/captures', filePath);
    return await fs.readFile(fullPath);
  }

  /**
   * Validate artifact bundle integrity
   */
  async validate(): Promise<boolean> {
    if (!this.checksum) {
      throw new Error('No checksum available for validation');
    }

    try {
      // Generate fresh checksum from current files
      const currentChecksum = await this.regenerateChecksum();
      return currentChecksum === this.checksum;
    } catch (error) {
      console.error(`Artifact validation failed: ${error}`);
      return false;
    }
  }

  /**
   * Regenerate checksum without updating the instance
   */
  private async regenerateChecksum(): Promise<string> {
    const hash = crypto.createHash('sha256');

    // Add screenshot file content to hash
    if (this.screenshotPath) {
      const screenshotContent = await this.readFileContent(this.screenshotPath);
      hash.update(screenshotContent);
    }

    // Add XML file content to hash
    if (this.xmlPath) {
      const xmlContent = await this.readFileContent(this.xmlPath);
      hash.update(xmlContent);
    }

    // Add metadata file content to hash (if exists)
    if (this.metadataPath) {
      try {
        const metadataContent = await this.readFileContent(this.metadataPath);
        hash.update(metadataContent);
      } catch (error) {
        // Metadata file is optional
      }
    }

    return hash.digest('hex');
  }

  /**
   * Get total size of all artifacts in bytes
   */
  async getTotalSize(): Promise<number> {
    let totalSize = 0;

    try {
      if (this.screenshotPath) {
        const screenshotStat = await this.getFileStat(this.screenshotPath);
        totalSize += screenshotStat.size;
      }

      if (this.xmlPath) {
        const xmlStat = await this.getFileStat(this.xmlPath);
        totalSize += xmlStat.size;
      }

      if (this.metadataPath) {
        try {
          const metadataStat = await this.getFileStat(this.metadataPath);
          totalSize += metadataStat.size;
        } catch (error) {
          // Metadata file is optional
        }
      }
    } catch (error) {
      console.error(`Failed to calculate artifact bundle size: ${error}`);
    }

    return totalSize;
  }

  /**
   * Get file statistics
   */
  private async getFileStat(filePath: string): Promise<{ size: number; mtime: Date }> {
    const fullPath = path.resolve('var/captures', filePath);
    const stat = await fs.stat(fullPath);
    return {
      size: stat.size,
      mtime: stat.mtime
    };
  }

  /**
   * Check if artifact bundle exceeds size limit (default 1MB per spec)
   */
  async exceedsSizeLimit(limitBytes: number = 1024 * 1024): Promise<boolean> {
    const totalSize = await this.getTotalSize();
    return totalSize > limitBytes;
  }

  /**
   * Get file paths with absolute directories
   */
  getAbsolutePaths(baseDir: string = 'var/captures'): {
    screenshotPath: string;
    xmlPath: string;
    metadataPath?: string;
  } {
    return {
      screenshotPath: path.resolve(baseDir, this.screenshotPath),
      xmlPath: path.resolve(baseDir, this.xmlPath),
      metadataPath: this.metadataPath ? path.resolve(baseDir, this.metadataPath) : undefined
    };
  }

  /**
   * Copy artifact bundle to new location
   */
  async copyTo(newBaseDir: string, newNodeId: string): Promise<ArtifactBundleEntity> {
    const newPaths = {
      screenshot: path.join(newBaseDir, newNodeId, 'screenshot.png'),
      xml: path.join(newBaseDir, newNodeId, 'ui.xml'),
      metadata: this.metadataPath ? path.join(newBaseDir, newNodeId, 'metadata.json') : undefined
    };

    // Ensure target directory exists
    await fs.mkdir(path.dirname(newPaths.screenshot), { recursive: true });

    // Copy files
    await this.copyFile(this.screenshotPath, newPaths.screenshot);
    await this.copyFile(this.xmlPath, newPaths.xml);

    if (this.metadataPath) {
      await this.copyFile(this.metadataPath, newPaths.metadata!);
    }

    // Create new artifact bundle with copied files
    const newBundle = await ArtifactBundleEntity.fromFiles(
      newPaths.screenshot,
      newPaths.xml,
      newPaths.metadata,
      newBaseDir
    );

    return newBundle;
  }

  /**
   * Copy file to new location
   */
  private async copyFile(srcPath: string, destPath: string): Promise<void> {
    const fullSrcPath = path.resolve('var/captures', srcPath);
    const fullDestPath = path.resolve('var/captures', destPath);

    await fs.copyFile(fullSrcPath, fullDestPath);
  }

  /**
   * Delete artifact bundle files
   */
  async delete(): Promise<void> {
    const absolutePaths = this.getAbsolutePaths();

    try {
      if (this.screenshotPath) {
        await fs.unlink(absolutePaths.screenshotPath);
      }

      if (this.xmlPath) {
        await fs.unlink(absolutePaths.xmlPath);
      }

      if (this.metadataPath) {
        try {
          await fs.unlink(absolutePaths.metadataPath!);
        } catch (error) {
          // Metadata file is optional, don't fail if already deleted
        }
      }
    } catch (error) {
      console.error(`Failed to delete artifact bundle files: ${error}`);
      throw error;
    }
  }

  /**
   * Check if all artifact files exist
   */
  async exists(): Promise<boolean> {
    const absolutePaths = this.getAbsolutePaths();

    try {
      // Check required files
      if (this.screenshotPath) {
        await fs.access(absolutePaths.screenshotPath);
      }

      if (this.xmlPath) {
        await fs.access(absolutePaths.xmlPath);
      }

      // Check optional metadata file
      if (this.metadataPath) {
        try {
          await fs.access(absolutePaths.metadataPath!);
        } catch (error) {
          // Metadata file is optional
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get metadata information about the artifact bundle
   */
  async getMetadata(): Promise<{
    totalSize: number;
    fileCount: number;
    checksumValid: boolean;
    exceedsSizeLimit: boolean;
    lastModified: Date;
  }> {
    const totalSize = await this.getTotalSize();
    const checksumValid = await this.validate();
    const exceedsSizeLimit = await this.exceedsSizeLimit();

    // Get latest modification time
    let lastModified = new Date(0);
    try {
      const absolutePaths = this.getAbsolutePaths();

      if (this.screenshotPath) {
        const screenshotStat = await this.getFileStat(this.screenshotPath);
        lastModified = new Date(Math.max(lastModified.getTime(), screenshotStat.mtime.getTime()));
      }

      if (this.xmlPath) {
        const xmlStat = await this.getFileStat(this.xmlPath);
        lastModified = new Date(Math.max(lastModified.getTime(), xmlStat.mtime.getTime()));
      }
    } catch (error) {
      console.warn(`Failed to get artifact modification times: ${error}`);
    }

    return {
      totalSize,
      fileCount: (this.metadataPath ? 3 : 2),
      checksumValid,
      exceedsSizeLimit,
      lastModified
    };
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): ArtifactBundle {
    return {
      screenshotPath: this.screenshotPath,
      xmlPath: this.xmlPath,
      metadataPath: this.metadataPath,
      checksum: this.checksum
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: ArtifactBundle): ArtifactBundleEntity {
    const entity = Object.create(ArtifactBundleEntity.prototype);
    Object.assign(entity, data);
    return entity;
  }
}