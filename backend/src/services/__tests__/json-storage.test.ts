/**
 * JSON Storage Service Tests
 *
 * Comprehensive test suite for the JSON file storage service with optimistic locking
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import { JsonStorageService, StorageError, ConflictError } from '../json-storage';

describe('JsonStorageService', () => {
  let service: JsonStorageService;
  const testDir = 'test-storage';
  const testFile = 'test.json';
  const testPath = join(testDir, testFile);

  beforeAll(async () => {
    service = new JsonStorageService();

    // Ensure test directory exists
    try {
      await fs.mkdir(testDir, { recursive: true });
    } catch (error) {
      // Directory might already exist
    }
  });

  afterAll(async () => {
    // Clean up test files
    try {
      const files = await fs.readdir(testDir);
      for (const file of files) {
        await fs.unlink(join(testDir, file));
      }
      await fs.rmdir(testDir);
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  beforeEach(async () => {
    // Clean up before each test
    try {
      const files = await fs.readdir(testDir);
      for (const file of files) {
        if (file !== '.gitkeep') {
          await fs.unlink(join(testDir, file));
        }
      }
    } catch (error) {
      // Directory might not exist or be empty
    }
  });

  describe('create()', () => {
    test('should create a new file with metadata', async () => {
      const testData = { name: 'test', value: 123 };

      const result = await service.create(testPath, testData, {
        createdBy: 'test-user',
        comment: 'Test file creation'
      });

      expect(result.success).toBe(true);
      expect(result.data).toEqual(testData);
      expect(result.metadata.version).toBeDefined();
      expect(result.metadata.hash).toBeDefined();
      expect(result.metadata.createdBy).toBe('test-user');
      expect(result.metadata.comment).toBe('Test file creation');
    });

    test('should fail when file already exists and overwrite is false', async () => {
      const testData = { name: 'test', value: 123 };

      // Create file first
      await service.create(testPath, testData);

      // Try to create again without overwrite
      await expect(
        service.create(testPath, testData)
      ).rejects.toThrow(StorageError);
    });

    test('should overwrite existing file when overwrite is true', async () => {
      const initialData = { name: 'initial', value: 123 };
      const newData = { name: 'updated', value: 456 };

      // Create initial file
      await service.create(testPath, initialData);

      // Overwrite with new data
      const result = await service.create(testPath, newData, { overwrite: true });

      expect(result.success).toBe(true);
      expect(result.data).toEqual(newData);
      expect(result.metadata.version).not.toBe(initialData);
    });

    test('should validate JSON data when validation is enabled', async () => {
      const invalidData = { circular: {} };
      (invalidData as any).circular.ref = invalidData.circular;

      await expect(
        service.create(testPath, invalidData, { validateSchema: true })
      ).rejects.toThrow(StorageError);
    });
  });

  describe('read()', () => {
    test('should read existing file with metadata', async () => {
      const testData = { name: 'test', value: 123 };

      // Create file first
      const createResult = await service.create(testPath, testData);

      // Read the file
      const readResult = await service.read(testPath);

      expect(readResult.success).toBe(true);
      expect(readResult.data).toEqual(testData);
      expect(readResult.metadata).toEqual(createResult.metadata);
    });

    test('should fail when file does not exist', async () => {
      await expect(
        service.read('nonexistent.json')
      ).rejects.toThrow(StorageError);
    });
  });

  describe('update()', () => {
    test('should update file with correct version', async () => {
      const initialData = { name: 'initial', value: 123 };
      const updatedData = { name: 'updated', value: 456 };

      // Create file first
      const createResult = await service.create(testPath, initialData);

      // Update with correct version
      const updateResult = await service.update(testPath, updatedData, {
        expectedVersion: createResult.metadata.version,
        updatedBy: 'updater',
        comment: 'Test update'
      });

      expect(updateResult.success).toBe(true);
      expect(updateResult.data).toEqual(updatedData);
      expect(updateResult.metadata.version).not.toBe(createResult.metadata.version);
      expect(updateResult.metadata.hash).not.toBe(createResult.metadata.hash);
    });

    test('should fail with version conflict', async () => {
      const initialData = { name: 'initial', value: 123 };
      const updatedData = { name: 'updated', value: 456 };

      // Create file first
      await service.create(testPath, initialData);

      // Try to update with wrong version
      await expect(
        service.update(testPath, updatedData, {
          expectedVersion: 'wrong-version'
        })
      ).rejects.toThrow(ConflictError);
    });

    test('should force update when force is true', async () => {
      const initialData = { name: 'initial', value: 123 };
      const updatedData = { name: 'updated', value: 456 };

      // Create file first
      await service.create(testPath, initialData);

      // Force update with wrong version
      const result = await service.update(testPath, updatedData, {
        expectedVersion: 'wrong-version',
        force: true
      });

      expect(result.success).toBe(true);
      expect(result.data).toEqual(updatedData);
    });
  });

  describe('delete()', () => {
    test('should delete file with correct version', async () => {
      const testData = { name: 'test', value: 123 };

      // Create file first
      const createResult = await service.create(testPath, testData);

      // Delete with correct version
      const result = await service.delete(testPath, {
        expectedVersion: createResult.metadata.version,
        deletedBy: 'deleter',
        reason: 'Test deletion'
      });

      expect(result.success).toBe(true);

      // Verify file is deleted
      await expect(
        service.read(testPath)
      ).rejects.toThrow(StorageError);
    });

    test('should fail with version conflict', async () => {
      const testData = { name: 'test', value: 123 };

      // Create file first
      await service.create(testPath, testData);

      // Try to delete with wrong version
      await expect(
        service.delete(testPath, {
          expectedVersion: 'wrong-version'
        })
      ).rejects.toThrow(ConflictError);
    });

    test('should force delete when force is true', async () => {
      const testData = { name: 'test', value: 123 };

      // Create file first
      await service.create(testPath, testData);

      // Force delete with wrong version
      const result = await service.delete(testPath, {
        expectedVersion: 'wrong-version',
        force: true
      });

      expect(result.success).toBe(true);
    });
  });

  describe('list()', () => {
    test('should list files in directory', async () => {
      // Create test files
      await service.create(join(testDir, 'file1.json'), { name: 'file1' });
      await service.create(join(testDir, 'file2.json'), { name: 'file2' });

      const result = await service.list(testDir);

      expect(result.count).toBe(2);
      expect(result.files).toContain('file1.json');
      expect(result.files).toContain('file2.json');
      expect(result.totalSize).toBeGreaterThan(0);
    });
  });

  describe('backup()', () => {
    test('should create backup of existing file', async () => {
      const testData = { name: 'test', value: 123 };

      // Create file first
      await service.create(testPath, testData);

      // Create backup
      const result = await service.backup(testPath);

      expect(result.success).toBe(true);
      expect(result.backupPath).toBeDefined();
      expect(result.originalHash).toBeDefined();
      expect(result.timestamp).toBeDefined();
    });

    test('should fail when file does not exist', async () => {
      await expect(
        service.backup('nonexistent.json')
      ).rejects.toThrow(StorageError);
    });
  });
});

// Helper function to get directory name
function dirname(path: string): string {
  return path.split('/').slice(0, -1).join('/');
}