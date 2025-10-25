# JSON Storage Service with Optimistic Locking

## Overview

The JSON Storage Service provides atomic file operations with optimistic locking for concurrent access to JSON files. This service is designed for the AutoApp UI Map & Intelligent Flow Engine to handle persistent storage of UI graphs and flow definitions with proper conflict resolution for collaboration scenarios.

## Features

### Core Functionality
- **Atomic Operations**: All file operations are atomic to prevent data corruption
- **Optimistic Locking**: Version-based conflict detection and resolution
- **Automatic Backups**: Time-stamped backups before any modification
- **Structured Logging**: Comprehensive logging for all operations
- **JSON Validation**: Schema validation and circular reference detection
- **Directory Management**: Automatic directory creation for file paths

### Optimistic Locking
- Version tracking using SHA-256 hash + timestamp
- Conflict detection on updates and deletes
- Force update capability for administrative operations
- Stale lock detection and cleanup

### Backup and Recovery
- Automatic backup creation before modifications
- Configurable backup retention (default: 10 backups per file)
- Timestamp-based backup naming
- Backup path tracking

## API Reference

### Methods

#### `create<T>(path, data, options?)`
Creates a new JSON file with metadata.

**Parameters:**
- `path`: File path relative to storage root
- `data`: JSON data to store
- `options`: Create options (optional)
  - `overwrite`: Allow overwriting existing files (default: false)
  - `createdBy`: User/agent creating the file
  - `comment`: Creation description
  - `validateSchema`: Enable JSON validation (default: true)

**Returns:** `Promise<StorageResult<T>>`

#### `read<T>(path, options?)`
Reads a JSON file with metadata.

**Parameters:**
- `path`: File path to read
- `options`: Read options (optional)
  - `includeMetadata`: Include version metadata (default: true)
  - `validateSchema`: Enable JSON validation (default: true)

**Returns:** `Promise<StorageResult<T>>`

#### `update<T>(path, data, options)`
Updates a JSON file with version checking.

**Parameters:**
- `path`: File path to update
- `data`: New JSON data
- `options`: Update options (required)
  - `expectedVersion`: Expected version for conflict detection
  - `expectedHash`: Optional expected hash for additional verification
  - `force`: Force update ignoring conflicts (default: false)
  - `updatedBy`: User/agent updating the file
  - `comment`: Update description

**Returns:** `Promise<StorageResult<T>>`

#### `delete(path, options)`
Deletes a JSON file with version checking.

**Parameters:**
- `path`: File path to delete
- `options`: Delete options (required)
  - `expectedVersion`: Expected version for conflict detection
  - `expectedHash`: Optional expected hash for additional verification
  - `force`: Force delete ignoring conflicts (default: false)
  - `deletedBy`: User/agent deleting the file
  - `reason`: Deletion reason

**Returns:** `Promise<{ success: boolean; deletedPath: string }>`

#### `list(directory)`
Lists JSON files in a directory.

**Parameters:**
- `directory`: Directory path to list

**Returns:** `Promise<ListResult>`

#### `backup(path)`
Creates a backup of an existing file.

**Parameters:**
- `path`: File path to backup

**Returns:** `Promise<BackupResult>`

#### `getStats(directory?)`
Gets storage statistics for a directory.

**Parameters:**
- `directory`: Directory path (optional, defaults to graphs root)

**Returns:** `Promise<{ totalFiles: number; totalSize: number; lastModified: string }>`

### Types

#### `VersionMetadata`
```typescript
interface VersionMetadata {
  version: string;
  hash: string;
  lastModified: string;
  createdBy?: string;
  comment?: string;
}
```

#### `StorageResult<T>`
```typescript
interface StorageResult<T> {
  data: T;
  metadata: VersionMetadata;
  success: boolean;
}
```

#### `ListResult`
```typescript
interface ListResult {
  files: string[];
  count: number;
  totalSize: number;
}
```

## Configuration

Environment variables control service behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `GRAPH_ROOT` | `./data/graphs` | Root directory for graph files |
| `FLOW_ROOT` | `./data/flows` | Root directory for flow files |
| `BACKUP_ENABLED` | `true` | Enable automatic backups |
| `BACKUP_ROOT` | `./data/backups` | Root directory for backups |
| `VALIDATION_ENABLED` | `true` | Enable JSON validation |
| `MAX_BACKUPS` | `10` | Maximum backups per file |
| `LOCK_TIMEOUT` | `30000` | Lock timeout in milliseconds |

## Error Handling

The service provides specific error types:

- `StorageError`: Base storage error
- `ConflictError`: Version/hash conflict
- `ValidationError`: JSON validation failure

### Error Codes

| Code | Description |
|------|-------------|
| `EXISTS` | File already exists |
| `NOT_FOUND` | File or directory not found |
| `CONFLICT` | Version or hash conflict |
| `VALIDATION_ERROR` | JSON validation failed |
| `LOCK_ERROR` | Lock acquisition failed |
| `LOCKED` | File is locked by another operation |

## Usage Examples

### Basic File Operations
```typescript
import { jsonStorage } from './services/json-storage';

// Create a new file
const result = await jsonStorage.create('my-graph.json', {
  nodes: [{ id: '1', type: 'screen' }],
  edges: []
}, {
  createdBy: 'user-123',
  comment: 'Initial graph creation'
});

// Read the file
const readResult = await jsonStorage.read('my-graph.json');

// Update the file
await jsonStorage.update('my-graph.json', updatedData, {
  expectedVersion: readResult.metadata.version,
  updatedBy: 'user-123',
  comment: 'Added new node'
});
```

### Conflict Handling
```typescript
try {
  await jsonStorage.update('graph.json', data, {
    expectedVersion: expectedVersion
  });
} catch (error) {
  if (error instanceof ConflictError) {
    console.log(`Conflict detected: ${error.currentVersion} vs ${error.expectedVersion}`);
    // Handle conflict (merge, reload, or force update)
  }
}
```

### Force Operations
```typescript
// Force update when conflicts are acceptable
await jsonStorage.update('graph.json', data, {
  expectedVersion: 'old-version',
  force: true,
  updatedBy: 'admin',
  comment: 'Administrative override'
});
```

## File Structure

### Stored Files
Files are stored with embedded metadata:
```json
{
  "your": "data",
  "goes": "here",
  "__version_metadata": {
    "version": "2025-10-25T16-52-44-912Z-3f683be3",
    "hash": "3f683be3...",
    "lastModified": "2025-10-25T16:52:44.912Z",
    "createdBy": "user-123",
    "comment": "File creation"
  }
}
```

### Backup Files
Backups are stored in the backup directory with timestamped names:
```
data/backups/
├── my-graph.2025-10-25T16-52-44-913Z.json
├── my-graph.2025-10-25T16-50-12-123Z.json
└── ...
```

## Performance Considerations

- **Lock Management**: Locks are kept in memory and have configurable timeouts
- **Atomic Writes**: Files are written to temporary locations and renamed
- **Backup Cleanup**: Old backups are automatically cleaned up
- **Directory Creation**: Directories are created on-demand as needed

## Security Notes

- File operations respect system permissions
- Lock files prevent concurrent modifications
- Version metadata tracks modification history
- Backups provide recovery options

## Integration with Graph and Flow Services

This service is designed to be used by:
- `GraphService`: For UI graph persistence
- `FlowService`: For flow definition persistence

Both services should:
1. Use the same instance of `JsonStorageService`
2. Handle conflicts appropriately
3. Include meaningful metadata (user, comment)
4. Implement proper error handling

## Logging

All operations are logged with structured data:
- Operation type
- File path
- Version information
- User/agent information
- Success/failure status
- Performance metrics

## Testing

Run the demo script to verify functionality:
```bash
npx ts-node src/demo-json-storage.ts
```

This demonstrates all core features including conflict detection and recovery.