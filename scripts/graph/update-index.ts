#!/usr/bin/env node

/**
 * Artifact Integrity CLI - Graph Index Updater
 *
 * Recalculates checksums and syncs var/graphs/index.json during capture sessions.
 * Validates artifact integrity and provides reporting on graph state.
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import { program } from 'commander';

interface GraphIndexMetadata {
  version: string;
  lastUpdated: string;
  checksum: string;
  totalNodes: number;
  totalEdges: number;
}

interface GraphIndex {
  metadata: GraphIndexMetadata;
  nodes: string[];
  edges: string[];
  graphs: Array<{
    version: string;
    timestamp: string;
    path: string;
    checksum: string;
    description: string;
  }>;
}

interface ChecksumResult {
  valid: boolean;
  expected?: string;
  actual?: string;
  path: string;
}

class GraphIndexer {
  private readonly graphsDir: string;
  private readonly capturesDir: string;
  private readonly indexPath: string;

  constructor(baseDir: string = 'var') {
    this.graphsDir = join(baseDir, 'graphs');
    this.capturesDir = join(baseDir, 'captures');
    this.indexPath = join(this.graphsDir, 'index.json');
  }

  /**
   * Update the graph index with current artifacts
   */
  async updateIndex(): Promise<void> {
    console.log('🔍 Updating graph index...');

    try {
      // Scan for all graph versions
      const graphVersions = await this.scanGraphVersions();
      console.log(`Found ${graphVersions.length} graph versions`);

      // Scan for all capture artifacts
      const captureArtifacts = await this.scanCaptureArtifacts();
      console.log(`Found ${Object.keys(captureArtifacts).length} capture directories`);

      // Load existing index or create new one
      let index: GraphIndex;
      try {
        const indexContent = await fs.readFile(this.indexPath, 'utf8');
        index = JSON.parse(indexContent);
        console.log('Loaded existing index');
      } catch {
        index = this.createEmptyIndex();
        console.log('Created new index');
      }

      // Update index with current state
      index = await this.updateIndexWithScans(index, graphVersions, captureArtifacts);

      // Save updated index
      await fs.writeFile(this.indexPath, JSON.stringify(index, null, 2), 'utf8');
      console.log('✅ Graph index updated successfully');

      // Print summary
      this.printIndexSummary(index);

    } catch (error) {
      console.error('❌ Failed to update graph index:', error);
      process.exit(1);
    }
  }

  /**
   * Validate integrity of all artifacts
   */
  async validateIntegrity(): Promise<void> {
    console.log('🔒 Validating artifact integrity...');

    try {
      const index = await this.loadIndex();
      const issues: string[] = [];

      // Validate checksums for all graphs
      for (const graph of index.graphs) {
        const graphPath = join(this.graphsDir, graph.version, 'ui-graph.json');
        const checksumValid = await this.validateFileChecksum(graphPath, graph.checksum);

        if (!checksumValid.valid) {
          issues.push(`Graph ${graph.version}: checksum mismatch`);
        }
      }

      // Validate capture artifacts
      const captureDirs = await this.scanCaptureArtifacts();
      for (const [nodeId, artifacts] of Object.entries(captureDirs)) {
        if (artifacts.checksumFile) {
          const storedChecksums = await this.loadStoredChecksums(artifacts.checksumFile);

          // Validate screenshot
          if (artifacts.screenshot) {
            const actualChecksum = await this.calculateFileChecksum(artifacts.screenshot);
            if (storedChecksums.screenshot !== actualChecksum) {
              issues.push(`Node ${nodeId}: screenshot checksum mismatch`);
            }
          }

          // Validate XML dump
          if (artifacts.xml) {
            const actualChecksum = await this.calculateFileChecksum(artifacts.xml);
            if (storedChecksums.xml !== actualChecksum) {
              issues.push(`Node ${nodeId}: XML dump checksum mismatch`);
            }
          }

          // Validate metadata
          if (artifacts.metadata && storedChecksums.metadata) {
            const actualChecksum = await this.calculateFileChecksum(artifacts.metadata);
            if (storedChecksums.metadata !== actualChecksum) {
              issues.push(`Node ${nodeId}: metadata checksum mismatch`);
            }
          }
        }
      }

      if (issues.length === 0) {
        console.log('✅ All artifact checksums are valid');
      } else {
        console.log('❌ Found integrity issues:');
        issues.forEach(issue => console.log(`  - ${issue}`));
        process.exit(1);
      }

    } catch (error) {
      console.error('❌ Failed to validate integrity:', error);
      process.exit(1);
    }
  }

  /**
   * Generate integrity report
   */
  async generateReport(): Promise<void> {
    console.log('📊 Generating integrity report...');

    try {
      const index = await this.loadIndex();
      const captureArtifacts = await this.scanCaptureArtifacts();

      const report = {
        generatedAt: new Date().toISOString(),
        summary: {
          totalGraphVersions: index.graphs.length,
          totalCaptures: Object.keys(captureArtifacts).length,
          latestGraphVersion: index.graphs.sort((a, b) =>
            new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
          )[0]?.version || 'none',
          indexLastUpdated: index.metadata.lastUpdated,
        },
        captures: Object.entries(captureArtifacts).map(([nodeId, artifacts]) => ({
          nodeId,
          hasScreenshot: !!artifacts.screenshot,
          hasXml: !!artifacts.xml,
          hasMetadata: !!artifacts.metadata,
          hasChecksums: !!artifacts.checksumFile,
        })),
        graphs: index.graphs.map(graph => ({
          version: graph.version,
          timestamp: graph.timestamp,
          description: graph.description,
          nodeCount: 0, // Would need to parse graph to count nodes
          edgeCount: 0, // Would need to parse graph to count edges
        })),
      };

      console.log(JSON.stringify(report, null, 2));

    } catch (error) {
      console.error('❌ Failed to generate report:', error);
      process.exit(1);
    }
  }

  /**
   * Clean up old graph versions
   */
  async cleanup(keepCount: number = 10): Promise<void> {
    console.log(`🧹 Cleaning up old graph versions (keeping latest ${keepCount})...`);

    try {
      const index = await this.loadIndex();
      const sortedVersions = index.graphs.sort((a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );

      if (sortedVersions.length <= keepCount) {
        console.log('✅ No cleanup needed');
        return;
      }

      const versionsToDelete = sortedVersions.slice(keepCount);
      console.log(`Deleting ${versionsToDelete.length} old versions...`);

      for (const version of versionsToDelete) {
        const versionDir = join(this.graphsDir, version.version);
        try {
          await fs.rm(versionDir, { recursive: true, force: true });
          console.log(`Deleted: ${version.version}`);
        } catch (error) {
          console.warn(`Warning: Failed to delete ${version.version}:`, error);
        }
      }

      // Update index to remove deleted versions
      index.graphs = index.graphs.filter(g =>
        !versionsToDelete.some(v => v.version === g.version)
      );

      await fs.writeFile(this.indexPath, JSON.stringify(index, null, 2), 'utf8');
      console.log('✅ Cleanup completed successfully');

    } catch (error) {
      console.error('❌ Cleanup failed:', error);
      process.exit(1);
    }
  }

  /**
   * Private helper methods
   */
  private async scanGraphVersions(): Promise<string[]> {
    try {
      const entries = await fs.readdir(this.graphsDir, { withFileTypes: true });
      return entries
        .filter(entry => entry.isDirectory() && entry.name !== 'templates')
        .map(entry => entry.name);
    } catch {
      return [];
    }
  }

  private async scanCaptureArtifacts(): Promise<Record<string, {
    screenshot?: string;
    xml?: string;
    metadata?: string;
    checksumFile?: string;
  }>> {
    try {
      const nodeDirs = await fs.readdir(this.capturesDir, { withFileTypes: true });
      const artifacts: Record<string, any> = {};

      for (const nodeDir of nodeDirs.filter(entry => entry.isDirectory())) {
        const nodePath = join(this.capturesDir, nodeDir.name);
        const files = await fs.readdir(nodePath);

        artifacts[nodeDir.name] = {
          screenshot: files.includes('screenshot.png') ? join(nodePath, 'screenshot.png') : undefined,
          xml: files.includes('ui.xml') ? join(nodePath, 'ui.xml') : undefined,
          metadata: files.includes('metadata.json') ? join(nodePath, 'metadata.json') : undefined,
          checksumFile: files.includes('checksums.json') ? join(nodePath, 'checksums.json') : undefined,
        };
      }

      return artifacts;
    } catch {
      return {};
    }
  }

  private createEmptyIndex(): GraphIndex {
    return {
      metadata: {
        version: '1.0.0',
        lastUpdated: new Date().toISOString(),
        checksum: '',
        totalNodes: 0,
        totalEdges: 0,
      },
      nodes: [],
      edges: [],
      graphs: [],
    };
  }

  private async loadIndex(): Promise<GraphIndex> {
    try {
      const content = await fs.readFile(this.indexPath, 'utf8');
      return JSON.parse(content);
    } catch (error) {
      console.error('Failed to load index:', error);
      process.exit(1);
    }
  }

  private async updateIndexWithScans(
    index: GraphIndex,
    graphVersions: string[],
    captureArtifacts: Record<string, any>
  ): Promise<GraphIndex> {
    // Update graph entries
    const updatedGraphs = await Promise.all(
      graphVersions.map(async (version) => {
        const graphPath = join(this.graphsDir, version, 'ui-graph.json');
        const checksum = await this.calculateFileChecksum(graphPath);

        const existing = index.graphs.find(g => g.version === version);
        return {
          version,
          timestamp: existing?.timestamp || new Date().toISOString(),
          path: graphPath,
          checksum,
          description: existing?.description || `Graph version ${version}`,
        };
      })
    );

    // Update metadata
    const totalNodes = Object.keys(captureArtifacts).length;
    const totalEdges = await this.calculateTotalEdges();
    const indexChecksum = await this.calculateIndexChecksum(updatedGraphs, totalNodes, totalEdges);

    return {
      metadata: {
        ...index.metadata,
        lastUpdated: new Date().toISOString(),
        checksum: indexChecksum,
        totalNodes,
        totalEdges,
      },
      nodes: Object.keys(captureArtifacts),
      edges: index.edges, // Would need to parse graphs to get edge IDs
      graphs: updatedGraphs,
    };
  }

  private async calculateTotalEdges(): Promise<number> {
    // This is a simplified implementation
    // In a real scenario, you'd parse each graph file to count edges
    return 0;
  }

  private async calculateIndexChecksum(
    graphs: Array<{ checksum: string }>,
    totalNodes: number,
    totalEdges: number
  ): Promise<string> {
    const data = JSON.stringify({ graphs, totalNodes, totalEdges });
    return createHash('sha256').update(data).digest('hex');
  }

  private async calculateFileChecksum(filePath: string): Promise<string> {
    try {
      const content = await fs.readFile(filePath);
      return createHash('sha256').update(content).digest('hex');
    } catch {
      return '';
    }
  }

  private async validateFileChecksum(filePath: string, expectedChecksum: string): Promise<ChecksumResult> {
    try {
      const actualChecksum = await this.calculateFileChecksum(filePath);
      return {
        valid: actualChecksum === expectedChecksum,
        expected: expectedChecksum,
        actual: actualChecksum,
        path: filePath,
      };
    } catch {
      return {
        valid: false,
        expected,
        path: filePath,
      };
    }
  }

  private async loadStoredChecksums(checksumFile: string): Promise<Record<string, string>> {
    try {
      const content = await fs.readFile(checksumFile, 'utf8');
      return JSON.parse(content);
    } catch {
      return {};
    }
  }

  private printIndexSummary(index: GraphIndex): void {
    console.log('\n📈 Index Summary:');
    console.log(`  Total Nodes: ${index.metadata.totalNodes}`);
    console.log(`  Total Edges: ${index.metadata.totalEdges}`);
    console.log(`  Graph Versions: ${index.graphs.length}`);
    console.log(`  Last Updated: ${index.metadata.lastUpdated}`);

    if (index.graphs.length > 0) {
      const latest = index.graphs.sort((a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      )[0];
      console.log(`  Latest Version: ${latest.version}`);
    }
  }
}

// CLI setup
program
  .name('update-index')
  .description('Artifact integrity CLI for UI graph management')
  .version('1.0.0');

program
  .command('update')
  .description('Update graph index with current artifacts')
  .action(async () => {
    const indexer = new GraphIndexer();
    await indexer.updateIndex();
  });

program
  .command('validate')
  .description('Validate integrity of all artifacts')
  .action(async () => {
    const indexer = new GraphIndexer();
    await indexer.validateIntegrity();
  });

program
  .command('report')
  .description('Generate detailed integrity report')
  .action(async () => {
    const indexer = new GraphIndexer();
    await indexer.generateReport();
  });

program
  .command('cleanup')
  .description('Clean up old graph versions')
  .option('-k, --keep <number>', 'Number of versions to keep', '10')
  .action(async (options) => {
    const keepCount = parseInt(options.keep);
    const indexer = new GraphIndexer();
    await indexer.cleanup(keepCount);
  });

// Parse and execute
if (require.main === module) {
  program.parse();
}

export { GraphIndexer };