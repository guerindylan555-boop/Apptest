/**
 * JSON Storage Service Demo
 *
 * Demonstrates the functionality of the JSON storage service with optimistic locking
 */

import { jsonStorage, StorageError, ConflictError } from './services/json-storage';

async function demo() {
  console.log('🚀 JSON Storage Service Demo\n');

  const testPath = 'demo/test-graph.json';
  const testData = {
    name: 'Demo Graph',
    version: '1.0.0',
    nodes: [
      { id: 'node1', type: 'screen', label: 'Home Screen' },
      { id: 'node2', type: 'screen', label: 'Settings Screen' }
    ],
    edges: [
      { from: 'node1', to: 'node2', action: 'click_settings' }
    ]
  };

  try {
    // 1. Create a new file
    console.log('📝 Creating new file...');
    const createResult = await jsonStorage.create(testPath, testData, {
      createdBy: 'demo-user',
      comment: 'Initial graph creation'
    });
    console.log('✅ File created successfully');
    console.log(`   Version: ${createResult.metadata.version}`);
    console.log(`   Hash: ${createResult.metadata.hash}`);
    console.log(`   Created by: ${createResult.metadata.createdBy}\n`);

    // 2. Read the file
    console.log('📖 Reading file...');
    const readResult = await jsonStorage.read(testPath);
    console.log('✅ File read successfully');
    console.log(`   Nodes count: ${(readResult.data as any).nodes.length}`);
    console.log(`   Edges count: ${(readResult.data as any).edges.length}\n`);

    // 3. Update the file
    console.log('✏️  Updating file...');
    const updatedData = {
      ...testData,
      nodes: [
        ...testData.nodes,
        { id: 'node3', type: 'screen', label: 'Profile Screen' }
      ],
      edges: [
        ...testData.edges,
        { from: 'node1', to: 'node3', action: 'click_profile' }
      ]
    };

    const updateResult = await jsonStorage.update(testPath, updatedData, {
      expectedVersion: readResult.metadata.version,
      updatedBy: 'demo-user',
      comment: 'Added profile screen'
    });
    console.log('✅ File updated successfully');
    console.log(`   New version: ${updateResult.metadata.version}`);
    console.log(`   Nodes count: ${(updateResult.data as any).nodes.length}\n`);

    // 4. Create backup
    console.log('💾 Creating backup...');
    const backupResult = await jsonStorage.backup(testPath);
    console.log('✅ Backup created successfully');
    console.log(`   Backup path: ${backupResult.backupPath}\n`);

    // 5. Get statistics for the graphs directory
    console.log('📊 Getting statistics...');
    const stats = await jsonStorage.getStats();
    console.log('✅ Statistics retrieved');
    console.log(`   Total files: ${stats.totalFiles}`);
    console.log(`   Total size: ${stats.totalSize} bytes`);
    console.log(`   Last modified: ${stats.lastModified}\n`);

    // 6. Demonstrate conflict detection
    console.log('⚠️  Demonstrating conflict detection...');
    try {
      await jsonStorage.update(testPath, { test: 'conflict' }, {
        expectedVersion: 'wrong-version'
      });
    } catch (error) {
      if (error instanceof ConflictError) {
        console.log('✅ Conflict detected and handled correctly');
        console.log(`   Current version: ${error.currentVersion}`);
        console.log(`   Expected version: ${error.expectedVersion}\n`);
      }
    }

    // 7. Clean up - delete the file
    console.log('🗑️  Cleaning up...');
    const deleteResult = await jsonStorage.delete(testPath, {
      expectedVersion: updateResult.metadata.version,
      deletedBy: 'demo-user',
      reason: 'Demo cleanup'
    });
    console.log('✅ File deleted successfully\n');

    console.log('🎉 Demo completed successfully!');

  } catch (error) {
    if (error instanceof StorageError) {
      console.error(`❌ Storage Error: ${error.message}`);
      console.error(`   Code: ${error.code}`);
      console.error(`   Path: ${error.path}`);
    } else {
      console.error('❌ Unexpected error:', error);
    }
    process.exit(1);
  }
}

// Run the demo
if (require.main === module) {
  demo().catch(console.error);
}

export { demo };