import { Request, Response } from 'express';
import multer from 'multer';
import { randomUUID } from 'crypto';
import * as fs from 'fs/promises';
import * as appsRepo from '../../../services/apps/appsRepository';
import * as metadataService from '../../../services/apps/apkMetadataService';
import * as appsStore from '../../../state/appsStore';
import type { ApkEntry } from '../../../types/apps';

/**
 * Upload Handler for APK Files
 *
 * Handles multipart file uploads, deduplicates by SHA-256 hash,
 * extracts metadata, and stores APK entries in the library.
 */

// Configure multer for memory storage (we'll handle disk storage ourselves)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB max file size
  },
  fileFilter: (req, file, cb) => {
    // Only accept .apk files
    if (file.originalname.toLowerCase().endsWith('.apk')) {
      cb(null, true);
    } else {
      cb(new Error('Only .apk files are allowed'));
    }
  }
});

/**
 * POST /apps - Upload APK file
 */
export const uploadMiddleware = upload.single('file');

export async function uploadHandler(req: Request, res: Response): Promise<void> {
  try {
    if (!req.file) {
      res.status(400).json({ error: 'No file uploaded' });
      return;
    }

    const fileBuffer = req.file.buffer;
    const originalFilename = req.file.originalname;

    // Calculate SHA-256 hash
    const sha256 = await calculateBufferHash(fileBuffer);

    // Check for duplicate
    const existing = appsRepo.findByHash(sha256);
    if (existing) {
      console.log(`[UploadHandler] Duplicate APK detected: ${sha256}`);
      await appsStore.logUpload(existing.id, existing.displayName, existing.packageName, true);
      res.status(200).json({
        ...existing,
        _deduplicated: true,
        _message: 'APK already exists in library (deduplicated by hash)'
      });
      return;
    }

    // Store the APK file
    const storagePath = await appsRepo.storeApkFile(fileBuffer, originalFilename, sha256);

    // Extract metadata
    let metadata;
    try {
      metadata = await metadataService.extractMetadata(storagePath);
    } catch (error) {
      // Clean up the stored file if metadata extraction fails
      await fs.unlink(storagePath).catch(() => {});
      throw new Error(`Metadata extraction failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    }

    // Create APK entry
    const entry: ApkEntry = {
      id: randomUUID(),
      sha256,
      filePath: storagePath,
      displayName: metadata.applicationLabel || originalFilename.replace('.apk', ''),
      packageName: metadata.packageName,
      versionName: metadata.versionName,
      versionCode: metadata.versionCode,
      minSdk: metadata.minSdk,
      targetSdk: metadata.targetSdk,
      launchableActivity: metadata.launchableActivity,
      signerDigest: metadata.signerDigest,
      sizeBytes: fileBuffer.length,
      uploadedAt: new Date().toISOString(),
      lastUsedAt: null,
      pinned: false,
      metadataWarnings: metadata.warnings,
      artifacts: {
        installLogs: [],
        logcatCaptures: [],
        fridaScripts: []
      }
    };

    // Save to repository
    const savedEntry = await appsRepo.createEntry(entry);

    console.log(`[UploadHandler] New APK uploaded: ${savedEntry.packageName} (${savedEntry.id})`);

    // Log activity
    await appsStore.logUpload(savedEntry.id, savedEntry.displayName, savedEntry.packageName, false);

    // Return 202 Accepted with the entry
    res.status(202).json(savedEntry);
  } catch (error) {
    console.error('[UploadHandler] Upload failed:', error);
    res.status(500).json({
      error: 'Upload failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}

/**
 * Calculate SHA-256 hash of a buffer
 */
async function calculateBufferHash(buffer: Buffer): Promise<string> {
  const crypto = await import('crypto');
  const hash = crypto.createHash('sha256');
  hash.update(buffer);
  return hash.digest('hex');
}
