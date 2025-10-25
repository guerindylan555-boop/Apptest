/**
 * Screenshot Capture Utilities
 *
 * Utilities for capturing screenshots directly via ADB as a fallback
 * when UI capture service doesn't provide screenshot buffers.
 */

import { createADBConnection, ADBConnection } from './adb';
import { promises as fs } from 'fs';
import * as path from 'path';

/**
 * Capture screenshot directly via ADB
 */
export async function captureDirectScreenshot(): Promise<Buffer> {
  const adb = createADBConnection();

  try {
    // Check if device is connected
    const connected = await adb.isDeviceConnected();
    if (!connected) {
      throw new Error('No device connected for screenshot capture');
    }

    // Capture screenshot to device
    const devicePath = '/sdcard/screenshot_temp.png';
    await adb.executeCommand(['screencap', '-p', devicePath]);

    // Pull screenshot from device
    const localTempPath = path.join('/tmp', `screenshot_${Date.now()}.png`);
    await adb.executeCommand(['pull', devicePath, localTempPath]);

    // Read screenshot buffer
    const buffer = await fs.readFile(localTempPath);

    // Clean up temporary files
    await Promise.all([
      adb.executeCommand(['rm', devicePath]),
      fs.unlink(localTempPath).catch(() => {}) // Ignore errors on local cleanup
    ]);

    return buffer;
  } finally {
    adb.close();
  }
}

/**
 * Validate screenshot buffer
 */
export function validateScreenshotBuffer(buffer: Buffer): {
  isValid: boolean;
  format?: string;
  dimensions?: { width: number; height: number };
  error?: string;
} {
  try {
    // Check minimum size
    if (buffer.length < 100) {
      return {
        isValid: false,
        error: 'Screenshot buffer too small'
      };
    }

    // Check for PNG signature
    if (buffer.length >= 8 &&
        buffer[0] === 0x89 && buffer[1] === 0x50 &&
        buffer[2] === 0x4E && buffer[3] === 0x47) {
      return {
        isValid: true,
        format: 'png',
        dimensions: extractPNGDimensions(buffer)
      };
    }

    // Check for JPEG signature
    if (buffer.length >= 3 &&
        buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
      return {
        isValid: true,
        format: 'jpeg',
        dimensions: extractJPEGDimensions(buffer)
      };
    }

    return {
      isValid: false,
      error: 'Unknown image format'
    };
  } catch (error) {
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Unknown validation error'
    };
  }
}

/**
 * Extract dimensions from PNG buffer
 */
function extractPNGDimensions(buffer: Buffer): { width: number; height: number } | undefined {
  try {
    // PNG dimensions are in IHDR chunk (starts at byte 8)
    if (buffer.length < 24) return undefined;

    const width = buffer.readUInt32BE(16);
    const height = buffer.readUInt32BE(20);

    return { width, height };
  } catch {
    return undefined;
  }
}

/**
 * Extract dimensions from JPEG buffer
 */
function extractJPEGDimensions(buffer: Buffer): { width: number; height: number } | undefined {
  try {
    // JPEG dimensions are in SOF0 marker (0xFF 0xC0)
    let offset = 2;

    while (offset < buffer.length - 9) {
      if (buffer[offset] === 0xFF && buffer[offset + 1] === 0xC0) {
        const height = buffer.readUInt16BE(offset + 5);
        const width = buffer.readUInt16BE(offset + 7);
        return { width, height };
      }

      // Skip to next marker
      const length = buffer.readUInt16BE(offset + 2);
      offset += length + 2;
    }

    return undefined;
  } catch {
    return undefined;
  }
}