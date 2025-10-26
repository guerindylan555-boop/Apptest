/**
 * Graph Storage Service
 *
 * Provides JSON-based persistence for UI graph data including
 * nodes, edges, and metadata with versioning and integrity checks.
 */

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { ScreenNodeEntity } from '../models/ScreenNode';
import { ActionEdgeEntity } from '../models/ActionEdge';
import { StartStateProfileEntity } from '../models/StartStateProfile';
import { UIGraph, GraphIndex } from '../types/uiGraph';

export interface GraphStorageOptions {
  baseDir?: string;
  currentVersion?: string;
  autoBackup?: boolean;
  maxVersions?: number;
}

export interface GraphStatistics {
  totalNodes: number;
  totalEdges: number;
  activeNodes: number;
  deprecatedNodes: number;
  duplicateNodes: number;
  averageNodeDegree: number;
  isolatedNodes: number;
  largestConnectedComponent: number;
}

export class GraphStorageService {
  private baseDir: string;
  private currentVersion: string;
  private autoBackup: boolean;
  private maxVersions: number;

  // Cache for performance
  private cache: {
    graph?: UIGraph;
    index?: GraphIndex;
    lastLoaded?: Date;
  } = {};

  constructor(options: GraphStorageOptions = {}) {
    this.baseDir = options.baseDir || 'var/graphs';
    this.currentVersion = options.currentVersion || this.generateVersion();
    this.autoBackup = options.autoBackup !== false;
    this.maxVersions = options.maxVersions || 10;

    this.ensureDirectories();
  }

  /**
   * Initialize storage directories
   */
  private async ensureDirectories(): Promise<void> {
    await fs.mkdir(this.baseDir, { recursive: true });
    await fs.mkdir(path.join(this.baseDir, 'versions'), { recursive: true });
    await fs.mkdir(path.join(this.baseDir, 'backups'), { recursive: true });
  }

  /**
   * Generate version identifier (timestamp-based)
   */
  private generateVersion(): string {
    const now = new Date();
    return `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`;
  }

  /**
   * Get current graph file path
   */
  private getCurrentGraphPath(): string {
    return path.join(this.baseDir, 'ui-graph.json');
  }

  /**
   * Get versioned graph file path
   */
  private getVersionGraphPath(version: string): string {
    return path.join(this.baseDir, 'versions', `ui-graph-${version}.json`);
  }

  /**
   * Get index file path
   */
  private getIndexFilePath(): string {
    return path.join(this.baseDir, 'index.json');
  }

  /**
   * Create backup of current graph
   */
  private async createBackup(): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(this.baseDir, 'backups', `ui-graph-backup-${timestamp}.json`);

    try {
      const currentPath = this.getCurrentGraphPath();
      await fs.copyFile(currentPath, backupPath);
      return backupPath;
    } catch (error) {
      console.warn(`Failed to create backup: ${error}`);
      throw error;
    }
  }

  /**
   * Clean up old versions and backups
   */
  private async cleanup(): Promise<void> {
    try {
      // Clean up old versions
      const versionsDir = path.join(this.baseDir, 'versions');
      const versionFiles = await fs.readdir(versionsDir);

      if (versionFiles.length > this.maxVersions) {
        // Sort by filename (which includes timestamp) and keep only the latest
        const sortedFiles = versionFiles.sort().reverse();
        const filesToDelete = sortedFiles.slice(this.maxVersions);

        for (const file of filesToDelete) {
          await fs.unlink(path.join(versionsDir, file));
        }
      }

      // Clean up old backups (keep 20 most recent)
      const backupsDir = path.join(this.baseDir, 'backups');
      const backupFiles = await fs.readdir(backupsDir);

      if (backupFiles.length > 20) {
        const sortedFiles = backupFiles.sort().reverse();
        const filesToDelete = sortedFiles.slice(20);

        for (const file of filesToDelete) {
          await fs.unlink(path.join(backupsDir, file));
        }
      }
    } catch (error) {
      console.warn(`Failed to cleanup old files: ${error}`);
    }
  }

  /**
   * Calculate graph checksum for integrity verification
   */
  private calculateGraphChecksum(graph: UIGraph): string {
    const graphData = JSON.stringify(graph, null, 2);
    return crypto.createHash('sha256').update(graphData).digest('hex');
  }

  /**
   * Load graph from storage with integrity check
   */
  async loadGraph(forceReload: boolean = false): Promise<UIGraph> {
    // Return from cache if available and not forced to reload
    if (!forceReload && this.cache.graph && this.cache.lastLoaded) {
      const cacheAge = Date.now() - this.cache.lastLoaded.getTime();
      if (cacheAge < 5 * 60 * 1000) { // 5 minutes cache
        return this.cache.graph;
      }
    }

    const graphPath = this.getCurrentGraphPath();

    try {
      const data = await fs.readFile(graphPath, 'utf8');
      const graph: UIGraph = JSON.parse(data);

      // Verify integrity
      if (graph.metadata.checksum) {
        const calculatedChecksum = this.calculateGraphChecksum(graph);
        if (calculatedChecksum !== graph.metadata.checksum) {
          console.warn(`Graph integrity check failed for ${graphPath}`);
          // Could try to restore from backup here
        }
      }

      // Update cache
      this.cache.graph = graph;
      this.cache.lastLoaded = new Date();

      return graph;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        // File doesn't exist, create empty graph
        const emptyGraph = this.createEmptyGraph();
        await this.saveGraph(emptyGraph);
        return emptyGraph;
      }
      throw new Error(`Failed to load graph: ${error}`);
    }
  }

  /**
   * Create empty graph structure
   */
  private createEmptyGraph(): UIGraph {
    return {
      metadata: {
        version: this.currentVersion,
        lastUpdated: new Date().toISOString(),
        checksum: '',
        totalNodes: 0,
        totalEdges: 0
      },
      nodes: [],
      edges: []
    };
  }

  /**
   * Save graph to storage with integrity checksum
   */
  async saveGraph(graph: UIGraph, createVersion: boolean = true): Promise<void> {
    // Update metadata
    graph.metadata.lastUpdated = new Date().toISOString();
    graph.metadata.totalNodes = graph.nodes.length;
    graph.metadata.totalEdges = graph.edges.length;
    graph.metadata.checksum = this.calculateGraphChecksum(graph);

    // Create backup if auto backup enabled
    if (this.autoBackup) {
      try {
        await this.createBackup();
      } catch (error) {
        console.warn(`Failed to create backup before save: ${error}`);
      }
    }

    // Save current version
    const currentPath = this.getCurrentGraphPath();
    const graphData = JSON.stringify(graph, null, 2);
    await fs.writeFile(currentPath, graphData, 'utf8');

    // Create versioned copy if requested
    if (createVersion) {
      const versionPath = this.getVersionGraphPath(this.currentVersion);
      await fs.writeFile(versionPath, graphData, 'utf8');
    }

    // Update cache
    this.cache.graph = graph;
    this.cache.lastLoaded = new Date();

    // Update index
    await this.updateIndex(graph);

    // Cleanup old files
    await this.cleanup();
  }

  /**
   * Update graph index
   */
  private async updateIndex(graph: UIGraph): Promise<void> {
    const indexPath = this.getIndexFilePath();

    try {
      let index: GraphIndex;

      try {
        const indexData = await fs.readFile(indexPath, 'utf8');
        index = JSON.parse(indexData);
      } catch (error) {
        // Create new index if doesn't exist
        index = {
          metadata: {
            version: '1.0.0',
            lastUpdated: new Date().toISOString(),
            checksum: '',
            totalNodes: 0,
            totalEdges: 0
          },
          nodes: [],
          edges: [],
          graphs: []
        };
      }

      // Update index metadata
      index.metadata.lastUpdated = new Date().toISOString();
      index.metadata.totalNodes = graph.nodes.length;
      index.metadata.totalEdges = graph.edges.length;
      index.metadata.checksum = this.calculateGraphChecksum(graph);

      // Update node and edge lists
      index.nodes = graph.nodes.map(node => node.id);
      index.edges = graph.edges.map(edge => edge.id);

      // Add version to history
      const versionEntry = {
        version: this.currentVersion,
        timestamp: graph.metadata.lastUpdated,
        path: `versions/ui-graph-${this.currentVersion}.json`,
        checksum: graph.metadata.checksum,
        description: `Graph with ${graph.nodes.length} nodes and ${graph.edges.length} edges`
      };

      // Remove existing entry for this version
      index.graphs = index.graphs.filter(g => g.version !== this.currentVersion);
      index.graphs.push(versionEntry);

      // Sort by timestamp (newest first)
      index.graphs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      // Save index
      const indexData = JSON.stringify(index, null, 2);
      await fs.writeFile(indexPath, indexData, 'utf8');

    } catch (error) {
      console.error(`Failed to update graph index: ${error}`);
    }
  }

  /**
   * Load graph index
   */
  async loadIndex(): Promise<GraphIndex> {
    const indexPath = this.getIndexFilePath();

    try {
      const data = await fs.readFile(indexPath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        // Return empty index if doesn't exist
        return {
          metadata: {
            version: '1.0.0',
            lastUpdated: new Date().toISOString(),
            checksum: '',
            totalNodes: 0,
            totalEdges: 0
          },
          nodes: [],
          edges: [],
          graphs: []
        };
      }
      throw new Error(`Failed to load graph index: ${error}`);
    }
  }

  /**
   * Load specific version of graph
   */
  async loadVersion(version: string): Promise<UIGraph> {
    const versionPath = this.getVersionGraphPath(version);

    try {
      const data = await fs.readFile(versionPath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      throw new Error(`Failed to load graph version ${version}: ${error}`);
    }
  }

  /**
   * Restore graph from backup
   */
  async restoreFromBackup(backupPath: string): Promise<UIGraph> {
    try {
      const data = await fs.readFile(backupPath, 'utf8');
      const graph: UIGraph = JSON.parse(data);

      // Update version and save as current
      this.currentVersion = this.generateVersion();
      await this.saveGraph(graph, false);

      return graph;
    } catch (error) {
      throw new Error(`Failed to restore from backup: ${error}`);
    }
  }

  /**
   * Get list of available versions
   */
  async getAvailableVersions(): Promise<Array<{
    version: string;
    timestamp: string;
    path: string;
    checksum: string;
    description: string;
  }>> {
    const index = await this.loadIndex();
    return index.graphs;
  }

  /**
   * Get list of available backups
   */
  async getAvailableBackups(): Promise<Array<{
    filename: string;
    path: string;
    size: number;
    created: Date;
  }>> {
    const backupsDir = path.join(this.baseDir, 'backups');

    try {
      const files = await fs.readdir(backupsDir);
      const backups = [];

      for (const file of files) {
        if (file.startsWith('ui-graph-backup-') && file.endsWith('.json')) {
          const filePath = path.join(backupsDir, file);
          const stats = await fs.stat(filePath);

          backups.push({
            filename: file,
            path: filePath,
            size: stats.size,
            created: stats.mtime
          });
        }
      }

      return backups.sort((a, b) => b.created.getTime() - a.created.getTime());
    } catch (error) {
      console.warn(`Failed to list backups: ${error}`);
      return [];
    }
  }

  /**
   * Add node to graph
   */
  async addNode(node: ScreenNodeEntity): Promise<void> {
    const graph = await this.loadGraph();

    // Check if node already exists
    const existingIndex = graph.nodes.findIndex(n => n.id === node.id);
    if (existingIndex >= 0) {
      graph.nodes[existingIndex] = node.toJSON();
    } else {
      graph.nodes.push(node.toJSON());
    }

    await this.saveGraph(graph);
  }

  /**
   * Update node in graph
   */
  async updateNode(node: ScreenNodeEntity): Promise<void> {
    const graph = await this.loadGraph();

    const index = graph.nodes.findIndex(n => n.id === node.id);
    if (index < 0) {
      throw new Error(`Node ${node.id} not found in graph`);
    }

    graph.nodes[index] = node.toJSON();
    await this.saveGraph(graph);
  }

  /**
   * Remove node from graph
   */
  async removeNode(nodeId: string): Promise<void> {
    const graph = await this.loadGraph();

    // Remove node
    graph.nodes = graph.nodes.filter(n => n.id !== nodeId);

    // Remove edges referencing this node
    graph.edges = graph.edges.filter(e => e.fromNodeId !== nodeId && e.toNodeId !== nodeId);

    await this.saveGraph(graph);
  }

  /**
   * Add edge to graph
   */
  async addEdge(edge: ActionEdgeEntity): Promise<void> {
    const graph = await this.loadGraph();

    // Check if edge already exists
    const existingIndex = graph.edges.findIndex(e => e.id === edge.id);
    if (existingIndex >= 0) {
      graph.edges[existingIndex] = edge.toJSON();
    } else {
      graph.edges.push(edge.toJSON());
    }

    await this.saveGraph(graph);
  }

  /**
   * Update edge in graph
   */
  async updateEdge(edge: ActionEdgeEntity): Promise<void> {
    const graph = await this.loadGraph();

    const index = graph.edges.findIndex(e => e.id === edge.id);
    if (index < 0) {
      throw new Error(`Edge ${edge.id} not found in graph`);
    }

    graph.edges[index] = edge.toJSON();
    await this.saveGraph(graph);
  }

  /**
   * Remove edge from graph
   */
  async removeEdge(edgeId: string): Promise<void> {
    const graph = await this.loadGraph();
    graph.edges = graph.edges.filter(e => e.id !== edgeId);
    await this.saveGraph(graph);
  }

  /**
   * Get node by ID
   */
  async getNode(nodeId: string): Promise<ScreenNodeEntity | null> {
    const graph = await this.loadGraph();
    const nodeData = graph.nodes.find(n => n.id === nodeId);

    if (!nodeData) return null;

    return ScreenNodeEntity.fromJSON(nodeData);
  }

  /**
   * Get edge by ID
   */
  async getEdge(edgeId: string): Promise<ActionEdgeEntity | null> {
    const graph = await this.loadGraph();
    const edgeData = graph.edges.find(e => e.id === edgeId);

    if (!edgeData) return null;

    return ActionEdgeEntity.fromJSON(edgeData);
  }

  /**
   * Get nodes by status
   */
  async getNodesByStatus(status: string): Promise<ScreenNodeEntity[]> {
    const graph = await this.loadGraph();
    const nodes = graph.nodes.filter(n => n.status === status);
    return nodes.map(node => ScreenNodeEntity.fromJSON(node));
  }

  /**
   * Get edges from node
   */
  async getEdgesFromNode(nodeId: string): Promise<ActionEdgeEntity[]> {
    const graph = await this.loadGraph();
    const edges = graph.edges.filter(e => e.fromNodeId === nodeId);
    return edges.map(edge => ActionEdgeEntity.fromJSON(edge));
  }

  /**
   * Get edges to node
   */
  async getEdgesToNode(nodeId: string): Promise<ActionEdgeEntity[]> {
    const graph = await this.loadGraph();
    const edges = graph.edges.filter(e => e.toNodeId === nodeId);
    return edges.map(edge => ActionEdgeEntity.fromJSON(edge));
  }

  /**
   * Get graph statistics
   */
  async getStatistics(): Promise<GraphStatistics> {
    const graph = await this.loadGraph();

    const activeNodes = graph.nodes.filter(n => n.status === 'active').length;
    const deprecatedNodes = graph.nodes.filter(n => n.status === 'deprecated').length;
    const duplicateNodes = graph.nodes.filter(n => n.status === 'duplicate').length;

    // Calculate node degrees (number of connections)
    const nodeDegrees = new Map<string, number>();

    graph.nodes.forEach(node => {
      nodeDegrees.set(node.id, 0);
    });

    graph.edges.forEach(edge => {
      if (edge.fromNodeId) {
        nodeDegrees.set(edge.fromNodeId, (nodeDegrees.get(edge.fromNodeId) || 0) + 1);
      }
      if (edge.toNodeId) {
        nodeDegrees.set(edge.toNodeId, (nodeDegrees.get(edge.toNodeId) || 0) + 1);
      }
    });

    const degrees = Array.from(nodeDegrees.values());
    const averageDegree = degrees.length > 0 ? degrees.reduce((sum, degree) => sum + degree, 0) / degrees.length : 0;
    const isolatedNodes = degrees.filter(degree => degree === 0).length;

    // Calculate largest connected component (simplified)
    const largestComponent = this.calculateLargestConnectedComponent(graph);

    return {
      totalNodes: graph.nodes.length,
      totalEdges: graph.edges.length,
      activeNodes,
      deprecatedNodes,
      duplicateNodes,
      averageNodeDegree: Math.round(averageDegree * 100) / 100,
      isolatedNodes,
      largestConnectedComponent: largestComponent
    };
  }

  /**
   * Calculate largest connected component size
   */
  private calculateLargestConnectedComponent(graph: UIGraph): number {
    // Simplified implementation - uses adjacency list
    const adjacency = new Map<string, string[]>();

    // Initialize adjacency list
    graph.nodes.forEach(node => {
      adjacency.set(node.id, []);
    });

    // Add edges
    graph.edges.forEach(edge => {
      if (edge.fromNodeId && edge.toNodeId) {
        adjacency.get(edge.fromNodeId)?.push(edge.toNodeId);
        adjacency.get(edge.toNodeId)?.push(edge.fromNodeId);
      }
    });

    const visited = new Set<string>();
    let maxComponentSize = 0;

    // DFS to find connected components
    const dfs = (nodeId: string, component: string[] = []): string[] => {
      if (visited.has(nodeId)) return component;

      visited.add(nodeId);
      component.push(nodeId);

      const neighbors = adjacency.get(nodeId) || [];
      neighbors.forEach(neighbor => {
        if (!visited.has(neighbor)) {
          dfs(neighbor, component);
        }
      });

      return component;
    };

    // Find all components
    graph.nodes.forEach(node => {
      if (!visited.has(node.id)) {
        const component = dfs(node.id);
        maxComponentSize = Math.max(maxComponentSize, component.length);
      }
    });

    return maxComponentSize;
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache = {};
  }
}

// Export singleton instance
export const graphStore = new GraphStorageService();