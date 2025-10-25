/**
 * Screenshot Storage Service Usage Examples
 *
 * Demonstrates how to use the screenshot storage service for various operations
 */

import { screenshotStorage, ScreenshotStorageService } from './screenshot-storage';
import { promises as fs } from 'fs';
import * as path from 'path';

/**
 * Example 1: Basic screenshot capture
 */
async function basicScreenshotCapture() {
  console.log('=== Basic Screenshot Capture ===');

  try {
    // Capture a screenshot for a specific package and activity
    const result = await screenshotStorage.captureScreenshot(
      'com.example.app',
      'MainActivity',
      {
        format: 'png',
        compression: 'medium',
        quality: 85,
        tags: ['example', 'main-screen'],
        generatePreview: true
      }
    );

    console.log('Screenshot captured successfully:');
    console.log(`  ID: ${result.metadata.id}`);
    console.log(`  Format: ${result.metadata.format}`);
    console.log(`  Size: ${result.metadata.fileSize} bytes`);
    console.log(`  Dimensions: ${result.metadata.dimensions.width}x${result.metadata.dimensions.height}`);
    console.log(`  Content Hash: ${result.metadata.contentHash}`);
    console.log(`  Screenshot ID: ${result.screenshotId}`);

    return result.metadata.id;

  } catch (error) {
    console.error('Failed to capture screenshot:', error);
    return null;
  }
}

/**
 * Example 2: Search and retrieve screenshots
 */
async function searchAndRetrieveScreenshots() {
  console.log('\n=== Search and Retrieve Screenshots ===');

  try {
    // Search for screenshots with specific criteria
    const searchResults = await screenshotStorage.searchScreenshots({
      packageName: 'com.example.app',
      format: 'png',
      limit: 10,
      sortBy: 'capturedAt',
      sortOrder: 'desc'
    });

    console.log(`Found ${searchResults.total} screenshots`);
    console.log(`Returned ${searchResults.screenshots.length} results`);

    for (const screenshot of searchResults.screenshots) {
      console.log(`  - ${screenshot.id}: ${screenshot.packageName}/${screenshot.activityName}`);
      console.log(`    Format: ${screenshot.format}, Size: ${screenshot.fileSize} bytes`);
      console.log(`    Captured: ${screenshot.capturedAt}`);

      // Retrieve the actual screenshot file
      const screenshotData = await screenshotStorage.getScreenshot(screenshot.id, {
        includePreview: true,
        includeMetadata: true
      });

      if (screenshotData.buffer) {
        console.log(`    ✓ Retrieved ${screenshotData.buffer.length} bytes`);
      }
      if (screenshotData.preview) {
        console.log(`    ✓ Preview available: ${screenshotData.preview.length} bytes`);
      }
    }

  } catch (error) {
    console.error('Failed to search screenshots:', error);
  }
}

/**
 * Example 3: Screenshot comparison
 */
async function compareScreenshots(screenshotId1: string, screenshotId2: string) {
  console.log('\n=== Screenshot Comparison ===');

  try {
    const comparisonResult = await screenshotStorage.compareScreenshots(
      screenshotId1,
      screenshotId2,
      {
        algorithm: 'pixel',
        outputFormat: 'png',
        highlightColor: [255, 0, 0],
        sensitivity: 0.1,
        sideBySide: true,
        includeMetadata: true
      }
    );

    console.log('Comparison completed:');
    console.log(`  Difference: ${comparisonResult.metadata.differencePercentage.toFixed(2)}%`);
    console.log(`  Different pixels: ${comparisonResult.metadata.differingPixels}`);
    console.log(`  Total pixels: ${comparisonResult.metadata.totalPixels}`);
    console.log(`  Algorithm: ${comparisonResult.metadata.algorithm}`);
    console.log(`  Processing time: ${comparisonResult.metadata.processingTime}ms`);

    if (comparisonResult.metadata.structuralSimilarity !== undefined) {
      console.log(`  Structural similarity: ${comparisonResult.metadata.structuralSimilarity.toFixed(4)}`);
    }

    if (comparisonResult.sideBySide) {
      console.log(`  ✓ Side-by-side comparison generated: ${comparisonResult.sideBySide.length} bytes`);
    }

    if (comparisonResult.comparison) {
      console.log(`  Screenshot 1: ${comparisonResult.comparison.screenshot1.packageName}/${comparisonResult.comparison.screenshot1.activityName}`);
      console.log(`  Screenshot 2: ${comparisonResult.comparison.screenshot2.packageName}/${comparisonResult.comparison.screenshot2.activityName}`);
    }

    return comparisonResult;

  } catch (error) {
    console.error('Failed to compare screenshots:', error);
    return null;
  }
}

/**
 * Example 4: Batch operations
 */
async function batchOperations() {
  console.log('\n=== Batch Operations ===');

  try {
    // Search for screenshots to process
    const searchResults = await screenshotStorage.searchScreenshots({
      packageName: 'com.example.app',
      limit: 5
    });

    if (searchResults.screenshots.length === 0) {
      console.log('No screenshots found for batch operations');
      return;
    }

    const screenshotIds = searchResults.screenshots.map(s => s.id);
    console.log(`Processing ${screenshotIds.length} screenshots in batch`);

    // Batch delete with progress tracking
    const deleteResult = await screenshotStorage.batchDeleteScreenshots(screenshotIds, {
      concurrency: 2,
      continueOnError: true,
      onProgress: (completed, total, current) => {
        console.log(`  Progress: ${completed}/${total} - Processing ${current}`);
      }
    });

    console.log('Batch deletion completed:');
    console.log(`  Successful: ${deleteResult.successCount}`);
    console.log(`  Failed: ${deleteResult.failureCount}`);
    console.log(`  Processing time: ${deleteResult.processingTime}ms`);

    if (deleteResult.failed.length > 0) {
      console.log('Failed operations:');
      deleteResult.failed.forEach(failure => {
        console.log(`  - ${failure.id}: ${failure.error}`);
      });
    }

  } catch (error) {
    console.error('Batch operations failed:', error);
  }
}

/**
 * Example 5: Storage statistics and cleanup
 */
async function statisticsAndCleanup() {
  console.log('\n=== Storage Statistics and Cleanup ===');

  try {
    // Get storage statistics
    const stats = await screenshotStorage.getStorageStats();

    console.log('Storage Statistics:');
    console.log(`  Total screenshots: ${stats.totalScreenshots}`);
    console.log(`  Total storage used: ${(stats.totalStorageUsed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  Average file size: ${(stats.averageFileSize / 1024).toFixed(2)} KB`);
    console.log(`  Storage by format:`);
    Object.entries(stats.storageByFormat).forEach(([format, size]) => {
      if (size > 0) {
        console.log(`    ${format}: ${(size / 1024 / 1024).toFixed(2)} MB`);
      }
    });
    console.log(`  Deduplication savings:`);
    console.log(`    Duplicate files: ${stats.deduplicationSavings.duplicateFiles}`);
    console.log(`    Space saved: ${(stats.deduplicationSavings.spaceSaved / 1024 / 1024).toFixed(2)} MB`);
    console.log(`    Deduplication ratio: ${(stats.deduplicationSavings.deduplicationRatio * 100).toFixed(2)}%`);
    console.log(`  Preview storage: ${(stats.previewStorageUsed / 1024 / 1024).toFixed(2)} MB`);

    if (stats.totalScreenshots > 0) {
      console.log(`  Oldest screenshot: ${stats.oldestScreenshot.capturedAt} (${stats.oldestScreenshot.id})`);
      console.log(`  Newest screenshot: ${stats.newestScreenshot.capturedAt} (${stats.newestScreenshot.id})`);
      console.log(`  Largest file: ${stats.largestFile.filename} (${(stats.largestFile.size / 1024).toFixed(2)} KB)`);
      console.log(`  Smallest file: ${stats.smallestFile.filename} (${(stats.smallestFile.size / 1024).toFixed(2)} KB)`);
    }

    // Run cleanup (dry run)
    console.log('\nRunning cleanup (dry run)...');
    const cleanupResult = await screenshotStorage.cleanupOldScreenshots({
      retentionDays: 7,
      dryRun: true
    });

    console.log('Cleanup results (dry run):');
    console.log(`  Screenshots to delete: ${cleanupResult.deletedScreenshots.length}`);
    console.log(`  Space to be freed: ${(cleanupResult.spaceFreed / 1024 / 1024).toFixed(2)} MB`);

    if (cleanupResult.errors.length > 0) {
      console.log(' Errors:');
      cleanupResult.errors.forEach(error => console.log(`  - ${error}`));
    }

  } catch (error) {
    console.error('Statistics or cleanup failed:', error);
  }
}

/**
 * Example 6: Export functionality
 */
async function exportScreenshots() {
  console.log('\n=== Export Screenshots ===');

  try {
    // Get recent screenshots
    const searchResults = await screenshotStorage.searchScreenshots({
      limit: 10,
      sortBy: 'capturedAt',
      sortOrder: 'desc'
    });

    if (searchResults.screenshots.length === 0) {
      console.log('No screenshots to export');
      return;
    }

    const screenshotIds = searchResults.screenshots.map(s => s.id);

    // Export screenshots
    const exportResult = await screenshotStorage.exportScreenshots(screenshotIds, {
      format: 'zip',
      includeMetadata: true,
      includePreviews: true
    });

    console.log('Export completed:');
    console.log(`  Archive path: ${exportResult.archivePath}`);
    console.log(`  Archive size: ${(exportResult.size / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  Screenshots exported: ${exportResult.screenshotCount}`);

  } catch (error) {
    console.error('Export failed:', error);
  }
}

/**
 * Main example runner
 */
async function runExamples() {
  console.log('Screenshot Storage Service Examples\n');

  // Example 1: Basic capture
  const screenshotId1 = await basicScreenshotCapture();
  if (!screenshotId1) {
    console.log('Skipping remaining examples due to capture failure');
    return;
  }

  // Wait a moment and capture another screenshot for comparison
  await new Promise(resolve => setTimeout(resolve, 1000));
  const screenshotId2 = await basicScreenshotCapture();

  // Example 2: Search and retrieve
  await searchAndRetrieveScreenshots();

  // Example 3: Comparison (if we have two screenshots)
  if (screenshotId1 && screenshotId2 && screenshotId1 !== screenshotId2) {
    await compareScreenshots(screenshotId1, screenshotId2);
  }

  // Example 4: Statistics
  await statisticsAndCleanup();

  // Example 5: Export
  await exportScreenshots();

  // Example 6: Batch operations (cleanup)
  // Uncomment to test batch deletion
  // await batchOperations();

  console.log('\n=== Examples Complete ===');
}

// Run examples if this file is executed directly
if (require.main === module) {
  runExamples().catch(error => {
    console.error('Examples failed:', error);
    process.exit(1);
  });
}

export {
  basicScreenshotCapture,
  searchAndRetrieveScreenshots,
  compareScreenshots,
  batchOperations,
  statisticsAndCleanup,
  exportScreenshots
};