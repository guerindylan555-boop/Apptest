# Screenshot Storage Service (T037)

Comprehensive screenshot capture, storage, and management service for UI states. Implements efficient screenshot storage with deduplication, multiple format support, compression, metadata management, and advanced features like comparison and diff generation.

## Features

### Core Functionality
- **Screenshot Capture**: Integration with UI capture service for coordinated screenshots
- **Efficient Storage**: Content-based deduplication to save storage space
- **Multiple Formats**: Support for PNG, JPG, and WebP with quality settings
- **Compression**: Configurable compression levels (none, low, medium, high, maximum)
- **Metadata Management**: Comprehensive metadata tracking with size, format, and dimensions

### Advanced Features
- **Fast Retrieval**: Sub-50ms retrieval times with caching and preview generation
- **Automated Cleanup**: Configurable retention policies with automatic cleanup
- **Screenshot Comparison**: Pixel, structural, and perceptual diff algorithms
- **Batch Operations**: Bulk upload, processing, and cleanup capabilities
- **Export/Import**: Archive creation for screenshot data migration
- **Health Monitoring**: Built-in health checks and performance metrics

### Performance
- Optimized for 10,000+ screenshots
- Sub-50ms retrieval times
- Efficient storage utilization with deduplication
- Background processing for intensive operations

## Installation

The service is automatically initialized when imported:

```typescript
import { screenshotStorage } from './services/screenshot-storage';
```

## Basic Usage

### Capture a Screenshot

```typescript
import { screenshotStorage } from './services/screenshot-storage';

// Basic capture
const result = await screenshotStorage.captureScreenshot(
  'com.example.app',
  'MainActivity'
);

console.log('Screenshot captured:', result.metadata.id);
```

### Advanced Capture Options

```typescript
const result = await screenshotStorage.captureScreenshot(
  'com.example.app',
  'MainActivity',
  {
    format: 'png',
    compression: 'medium',
    quality: 85,
    force: false,
    generatePreview: true,
    tags: ['main-screen', 'example'],
    metadata: {
      deviceModel: 'Pixel 6',
      testScenario: 'login-flow'
    }
  }
);
```

### Retrieve Screenshots

```typescript
// Get screenshot with preview and metadata
const screenshot = await screenshotStorage.getScreenshot('screenshot-id', {
  includePreview: true,
  includeMetadata: true
});

console.log('Buffer size:', screenshot.buffer?.length);
console.log('Preview size:', screenshot.preview?.length);
```

### Search Screenshots

```typescript
// Search with filters
const results = await screenshotStorage.searchScreenshots({
  packageName: 'com.example.app',
  format: 'png',
  tags: ['main-screen'],
  capturedAfter: '2023-01-01T00:00:00Z',
  limit: 20,
  sortBy: 'capturedAt',
  sortOrder: 'desc'
});

console.log(`Found ${results.total} screenshots`);
```

## Advanced Usage

### Screenshot Comparison

```typescript
const comparison = await screenshotStorage.compareScreenshots(
  'screenshot-1',
  'screenshot-2',
  {
    algorithm: 'pixel',
    outputFormat: 'png',
    highlightColor: [255, 0, 0],
    sensitivity: 0.1,
    sideBySide: true,
    includeMetadata: true
  }
);

console.log(`Difference: ${comparison.metadata.differencePercentage}%`);
```

### Batch Operations

```typescript
// Batch delete with progress tracking
const result = await screenshotStorage.batchDeleteScreenshots(
  ['id1', 'id2', 'id3'],
  {
    concurrency: 5,
    continueOnError: true,
    onProgress: (completed, total, current) => {
      console.log(`Progress: ${completed}/${total} - ${current}`);
    }
  }
);

console.log(`Deleted: ${result.successCount}, Failed: ${result.failureCount}`);
```

### Storage Statistics

```typescript
const stats = await screenshotStorage.getStorageStats();

console.log(`Total screenshots: ${stats.totalScreenshots}`);
console.log(`Storage used: ${(stats.totalStorageUsed / 1024 / 1024).toFixed(2)} MB`);
console.log(`Deduplication ratio: ${(stats.deduplicationSavings.deduplicationRatio * 100).toFixed(2)}%`);
```

### Automated Cleanup

```typescript
// Cleanup old screenshots (dry run)
const cleanup = await screenshotStorage.cleanupOldScreenshots({
  retentionDays: 30,
  dryRun: true
});

console.log(`Would delete ${cleanup.deletedScreenshots.length} screenshots`);
console.log(`Would free ${(cleanup.spaceFreed / 1024 / 1024).toFixed(2)} MB`);
```

## Configuration

Environment variables:

```bash
# Storage configuration
SCREENSHOT_STORAGE_DIR=/var/autoapp/screenshots
SCREENSHOT_DEFAULT_FORMAT=png
SCREENSHOT_DEFAULT_COMPRESSION=medium
SCREENSHOT_DEFAULT_QUALITY=85
SCREENSHOT_MAX_SIZE=10485760

# Feature flags
SCREENSHOT_ENABLE_DEDUP=true
SCREENSHOT_ENABLE_PREVIEWS=true
SCREENSHOT_ENABLE_AUTO_CLEANUP=true

# Cleanup configuration
SCREENSHOT_RETENTION_DAYS=30
SCREENSHOT_CLEANUP_INTERVAL=24

# Preview configuration
SCREENSHOT_PREVIEW_WIDTH=300
SCREENSHOT_PREVIEW_HEIGHT=200
```

## Directory Structure

```
var/autoapp/screenshots/
├── previews/              # Generated preview images
├── metadata/              # Screenshot metadata files
│   ├── index.json         # Metadata index
│   ├── {id}.json         # Individual screenshot metadata
├── exports/               # Exported archives
├── temp/                  # Temporary files
└── {package}/             # Organized by package
    └── {activity}/
        └── screenshots/   # Actual screenshot files
            └── {id}.{format}
```

## API Reference

### Main Service Class: ScreenshotStorageService

#### Methods

- `captureScreenshot(packageName, activityName, options?)` - Capture and store a new screenshot
- `getScreenshot(screenshotId, options?)` - Retrieve a screenshot by ID
- `searchScreenshots(options?)` - Search screenshots with filters
- `compareScreenshots(id1, id2, options?)` - Compare two screenshots
- `deleteScreenshot(screenshotId)` - Delete a screenshot
- `batchDeleteScreenshots(ids, options?)` - Delete multiple screenshots
- `getStorageStats()` - Get storage statistics
- `cleanupOldScreenshots(options?)` - Cleanup old screenshots
- `exportScreenshots(ids, options?)` - Export screenshots to archive
- `healthCheck()` - Service health check

### Types

#### ScreenshotMetadata
```typescript
interface ScreenshotMetadata {
  id: string;
  contentHash: string;
  filename: string;
  format: 'png' | 'jpg' | 'jpeg' | 'webp';
  dimensions: { width: number; height: number };
  fileSize: number;
  compressionLevel: 'none' | 'low' | 'medium' | 'high' | 'maximum';
  quality?: number;
  packageName: string;
  activityName: string;
  stateId?: string;
  capturedAt: string;
  modifiedAt: string;
  tags?: string[];
  metadata?: Record<string, any>;
}
```

#### CaptureScreenshotOptions
```typescript
interface CaptureScreenshotOptions {
  format?: ScreenshotFormat;
  compression?: CompressionLevel;
  quality?: number;
  force?: boolean;
  generatePreview?: boolean;
  tags?: string[];
  metadata?: Record<string, any>;
  uiCaptureOptions?: UICaptureOptions;
}
```

#### ScreenshotSearchOptions
```typescript
interface ScreenshotSearchOptions {
  packageName?: string;
  activityName?: string;
  stateId?: string;
  format?: ScreenshotFormat;
  tags?: string[];
  capturedAfter?: string;
  capturedBefore?: string;
  minSize?: number;
  maxSize?: number;
  includePreviews?: boolean;
  limit?: number;
  offset?: number;
  sortBy?: 'capturedAt' | 'fileSize' | 'dimensions' | 'packageName';
  sortOrder?: 'asc' | 'desc';
}
```

## Error Handling

The service provides specific error types:

```typescript
import {
  ScreenshotStorageError,
  ScreenshotNotFoundError,
  ScreenshotFormatError,
  ScreenshotSizeError
} from './services/screenshot-storage';

try {
  await screenshotStorage.getScreenshot('non-existent');
} catch (error) {
  if (error instanceof ScreenshotNotFoundError) {
    console.log('Screenshot not found:', error.screenshotId);
  } else if (error instanceof ScreenshotStorageError) {
    console.log('Storage error:', error.code, error.message);
  }
}
```

## Performance Considerations

1. **Deduplication**: Content-based hashing prevents duplicate storage
2. **Caching**: Metadata is cached in memory for fast access
3. **Previews**: Small previews are generated for quick display
4. **Background Processing**: Intensive operations run in background
5. **Batch Operations**: Efficient handling of multiple items

## Integration Examples

### With UI Capture Service

```typescript
import { uiCaptureService } from './ui-capture';
import { screenshotStorage } from './screenshot-storage';

// Capture UI state and screenshot together
const uiState = await uiCaptureService.captureState();
const screenshot = await screenshotStorage.captureScreenshot(
  uiState.state.package,
  uiState.state.activity,
  {
    stateId: uiState.state.id,
    metadata: {
      captureMethod: uiState.state.metadata.captureMethod,
      captureDuration: uiState.state.metadata.captureDuration
    }
  }
);
```

### With Graph Service

```typescript
// Store screenshots with graph states
for (const state of graphStates) {
  const screenshot = await screenshotStorage.captureScreenshot(
    state.package,
    state.activity,
    {
      stateId: state.id,
      tags: ['graph-state', state.package]
    }
  );

  // Associate screenshot with state
  state.screenshot = screenshot.metadata.id;
}
```

## Testing

Run the test suite:

```bash
npm test -- screenshot-storage.test.ts
```

Run examples:

```bash
ts-node src/services/screenshot-storage.example.ts
```

## Troubleshooting

### Common Issues

1. **Device Not Connected**: Ensure Android device is connected via ADB
2. **Storage Permissions**: Check write permissions for storage directory
3. **Memory Issues**: Monitor memory usage with large screenshot sets
4. **Sharp Library**: Ensure Sharp is properly installed for image processing

### Debug Mode

Enable debug logging:

```typescript
import { createServiceLogger } from './logger';
const logger = createServiceLogger('screenshot-storage');
logger.setLevel('debug');
```

### Health Check

Monitor service health:

```typescript
const health = await screenshotStorage.healthCheck();
console.log('Service healthy:', health.healthy);
console.log('Details:', health.details);
```

## License

This service is part of the AutoApp UI Map & Intelligent Flow Engine project.