/**
 * Graph Store Service
 *
 * Manages versioned UI graph storage under var/graphs/<timestamp>/.
 * Handles graph indexing, node/edge lookups, and graph evolution tracking.
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import type { ScreenNode, ActionEdge, UIGraph, GraphIndex } from '../../types/uiGraph';
import { validateUIGraph, validateGraphIndex, serializeUIGraph, serializeGraphIndex } from '../../utils/validation/uiGraphSchema';

interface GraphVersion {
  version: string;
  timestamp: string;
  description?: string;
  checksum: string;
}

interface GraphStoreOptions {
  baseDir?: string;
  maxVersions?: number;
}

export class GraphStore {
  private readonly baseDir: string;
  private readonly maxVersions: number;
  private readonly graphsDir: string;
  private readonly indexPath: string;

  constructor(options: GraphStoreOptions = {}) {
    this.baseDir = options.baseDir || 'var';
    this.maxVersions = options.maxVersions || 50;
    this.graphsDir = join(this.baseDir, 'graphs');
    this.indexPath = join(this.graphsDir, 'index.json');
  }

  /**
   * Initialize graph store and ensure index exists
   */
  async initialize(): Promise<void> {
    try {
      await fs.mkdir(this.graphsDir, { recursive: true });

      // Initialize index if it doesn't exist
      try {
        await fs.access(this.indexPath);
      } catch {
        await this.createInitialIndex();
      }
    } catch (error) {
      throw new Error(`Failed to initialize graph store: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Store a new graph version
   */
  async storeGraph(graph: UIGraph, description?: string): Promise<string> {
    try {
      // Validate graph before storing
      const validation = validateUIGraph(graph);
      if (!validation.success) {
        throw new Error(`Invalid graph format: ${validation.error.message}`);
      }

      // Generate version and create directory
      const version = this.generateVersion();
      const versionDir = join(this.graphsDir, version);
      await fs.mkdir(versionDir, { recursive: true });

      // Store graph file
      const graphPath = join(versionDir, 'ui-graph.json');
      const serializedGraph = serializeUIGraph(graph);
      await fs.writeFile(graphPath, serializedGraph, 'utf8');

      // Calculate checksum
      const checksum = this.calculateFileChecksum(graphPath);

      // Update index
      await this.updateIndex({
        version,
        timestamp: new Date().toISOString(),
        description: description || `Graph version ${version}`,
        checksum,
        path: graphPath,
        nodeCount: graph.nodes.length,
        edgeCount: graph.edges.length,
      });

      // Cleanup old versions if needed
      await this.cleanupOldVersions();

      return version;
    } catch (error) {
      throw new Error(`Failed to store graph: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Retrieve a graph version
   */
  async getGraph(version: string): Promise<UIGraph | null> {
    try {
      const graphPath = join(this.graphsDir, version, 'ui-graph.json');
      const content = await fs.readFile(graphPath, 'utf8');
      const graph = JSON.parse(content);

      const validation = validateUIGraph(graph);
      if (!validation.success) {
        throw new Error(`Invalid graph format: ${validation.error.message}`);
      }

      return validation.data as UIGraph;
    } catch (error) {
      console.warn(`Failed to load graph version ${version}:`, error);
      return null;
    }
  }

  /**
   * Get the latest graph version
   */
  async getLatestGraph(): Promise<UIGraph | null> {
    try {
      const index = await this.getIndex();
      if (index.graphs.length === 0) {
        return null;
      }

      // Sort by timestamp descending to get latest
      const sortedVersions = index.graphs
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      const latest = sortedVersions[0];
      return this.getGraph(latest.version);
    } catch (error) {
      console.warn('Failed to get latest graph:', error);
      return null;
    }
  }

  /**
   * Add or update a node in the graph
   */
  async addNode(node: ScreenNode, description?: string): Promise<string> {
    try {
      // Get current graph or create new one
      let currentGraph = await this.getLatestGraph();
      if (!currentGraph) {
        currentGraph = this.createEmptyGraph();
      }

      // Check if node already exists
      const existingNodeIndex = currentGraph.nodes.findIndex(n => n.id === node.id);
      if (existingNodeIndex >= 0) {
        // Update existing node
        currentGraph.nodes[existingNodeIndex] = node;
      } else {
        // Add new node
        currentGraph.nodes.push(node);
      }

      // Update metadata
      currentGraph.metadata.totalNodes = currentGraph.nodes.length;
      currentGraph.metadata.lastUpdated = new Date().toISOString();

      // Recalculate checksum
      const serialized = serializeUIGraph(currentGraph);
      currentGraph.metadata.checksum = this.calculateContentChecksum(serialized);

      // Store updated graph
      return await this.storeGraph(currentGraph, description || `Add/update node: ${node.name}`);
    } catch (error) {
      throw new Error(`Failed to add node: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Add or update an edge in the graph
   */
  async addEdge(edge: ActionEdge, description?: string): Promise<string> {
    try {
      // Get current graph or create new one
      let currentGraph = await this.getLatestGraph();
      if (!currentGraph) {
        currentGraph = this.createEmptyGraph();
      }

      // Check if edge already exists
      const existingEdgeIndex = currentGraph.edges.findIndex(e => e.id === edge.id);
      if (existingEdgeIndex >= 0) {
        // Update existing edge
        currentGraph.edges[existingEdgeIndex] = edge;
      } else {
        // Add new edge
        currentGraph.edges.push(edge);
      }

      // Update node edge references
      this.updateNodeEdgeReferences(currentGraph, edge);

      // Update metadata
      currentGraph.metadata.totalEdges = currentGraph.edges.length;
      currentGraph.metadata.lastUpdated = new Date().toISOString();

      // Recalculate checksum
      const serialized = serializeUIGraph(currentGraph);
      currentGraph.metadata.checksum = this.calculateContentChecksum(serialized);

      // Store updated graph
      return await this.storeGraph(currentGraph, description || `Add/update edge: ${edge.id}`);
    } catch (error) {
      throw new Error(`Failed to add edge: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get a specific node by ID
   */
  async getNode(nodeId: string): Promise<ScreenNode | null> {
    try {
      const graph = await this.getLatestGraph();
      if (!graph) {
        return null;
      }

      return graph.nodes.find(node => node.id === nodeId) || null;
    } catch (error) {
      console.warn(`Failed to get node ${nodeId}:`, error);
      return null;
    }
  }

  /**
   * Get a specific edge by ID
   */
  async getEdge(edgeId: string): Promise<ActionEdge | null> {
    try {
      const graph = await this.getLatestGraph();
      if (!graph) {
        return null;
      }

      return graph.edges.find(edge => edge.id === edgeId) || null;
    } catch (error) {
      console.warn(`Failed to get edge ${edgeId}:`, error);
      return null;
    }
  }

  /**
   * List all available graph versions
   */
  async listVersions(): Promise<GraphVersion[]> {
    try {
      const index = await this.getIndex();
      return index.graphs.map(entry => ({
        version: entry.version,
        timestamp: entry.timestamp,
        description: entry.description,
        checksum: entry.checksum,
      }));
    } catch (error) {
      console.warn('Failed to list graph versions:', error);
      return [];
    }
  }

  /**
   * Search nodes by criteria
   */
  async searchNodes(criteria: {
    activity?: string;
    hasText?: string;
    nameContains?: string;
    status?: 'active' | 'deprecated' | 'duplicate';
  }): Promise<ScreenNode[]> {
    try {
      const graph = await this.getLatestGraph();
      if (!graph) {
        return [];
      }

      return graph.nodes.filter(node => {
        if (criteria.activity && node.signature.activity !== criteria.activity) {
          return false;
        }

        if (criteria.hasText &&
            !node.signature.requiredTexts.some(text =>
              text.toLowerCase().includes(criteria.hasText!.toLowerCase()))) {
          return false;
        }

        if (criteria.nameContains &&
            !node.name.toLowerCase().includes(criteria.nameContains!.toLowerCase())) {
          return false;
        }

        if (criteria.status && node.status !== criteria.status) {
          return false;
        }

        return true;
      });
    } catch (error) {
      console.warn('Failed to search nodes:', error);
      return [];
    }
  }

  /**
   * Get graph index
   */
  async getIndex(): Promise<GraphIndex> {
    try {
      const content = await fs.readFile(this.indexPath, 'utf8');
      const index = JSON.parse(content);

      const validation = validateGraphIndex(index);
      if (!validation.success) {
        throw new Error(`Invalid index format: ${validation.error.message}`);
      }

      return validation.data;
    } catch (error) {
      console.warn('Failed to read graph index, creating new one:', error);
      return await this.createInitialIndex();
    }
  }

  /**
   * Private helper methods
   */
  private createEmptyGraph(): UIGraph {
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
    };
  }

  private generateVersion(): string {
    const timestamp = new Date().toISOString();
    return timestamp.replace(/[:.]/g, '-');
  }

  private calculateFileChecksum(filePath: string): string {
    const hash = createHash('sha256');
    // In a real implementation, this would read the file and calculate hash
    // For now, return a placeholder
    return hash.update(filePath).digest('hex');
  }

  private calculateContentChecksum(content: string): string {
    const hash = createHash('sha256');
    return hash.update(content).digest('hex');
  }

  private async createInitialIndex(): Promise<GraphIndex> {
    // Ensure directory exists before writing index
    await fs.mkdir(this.graphsDir, { recursive: true });

    const initialIndex: GraphIndex = {
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

    await fs.writeFile(this.indexPath, serializeGraphIndex(initialIndex), 'utf8');
    return initialIndex;
  }

  private async updateIndex(entry: {
    version: string;
    timestamp: string;
    description: string;
    checksum: string;
    path: string;
    nodeCount: number;
    edgeCount: number;
  }): Promise<void> {
    const index = await this.getIndex();

    // Add or update graph entry
    const existingIndex = index.graphs.findIndex(g => g.version === entry.version);
    const graphEntry = {
      version: entry.version,
      timestamp: entry.timestamp,
      path: entry.path,
      checksum: entry.checksum,
      description: entry.description,
    };

    if (existingIndex >= 0) {
      index.graphs[existingIndex] = graphEntry;
    } else {
      index.graphs.push(graphEntry);
    }

    // Update metadata
    index.metadata.lastUpdated = new Date().toISOString();
    index.metadata.totalNodes = entry.nodeCount;
    index.metadata.totalEdges = entry.edgeCount;
    index.metadata.checksum = entry.checksum;

    // Save updated index
    await fs.writeFile(this.indexPath, serializeGraphIndex(index), 'utf8');
  }

  private updateNodeEdgeReferences(graph: UIGraph, edge: ActionEdge): void {
    // Update from node outgoing edges
    const fromNode = graph.nodes.find(n => n.id === edge.fromNodeId);
    if (fromNode) {
      if (!fromNode.outgoingEdgeIds.includes(edge.id)) {
        fromNode.outgoingEdgeIds.push(edge.id);
      }
    }

    // Update to node incoming edges if toNodeId is set
    if (edge.toNodeId) {
      const toNode = graph.nodes.find(n => n.id === edge.toNodeId);
      if (toNode) {
        if (!toNode.incomingEdgeIds.includes(edge.id)) {
          toNode.incomingEdgeIds.push(edge.id);
        }
      }
    }
  }

  private async cleanupOldVersions(): Promise<void> {
    try {
      const versions = await this.listVersions();
      if (versions.length <= this.maxVersions) {
        return;
      }

      // Sort by timestamp (oldest first)
      const sortedVersions = versions.sort((a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );

      // Keep only the latest maxVersions
      const versionsToDelete = sortedVersions.slice(0, -this.maxVersions);

      for (const version of versionsToDelete) {
        const versionDir = join(this.graphsDir, version.version);
        try {
          await fs.rm(versionDir, { recursive: true, force: true });
        } catch (error) {
          console.warn(`Failed to delete old version ${version.version}:`, error);
        }
      }

      // Rebuild index to remove deleted versions
      await this.rebuildIndex();
    } catch (error) {
      console.warn('Failed to cleanup old versions:', error);
    }
  }

  private async rebuildIndex(): Promise<void> {
    try {
      const entries = await fs.readdir(this.graphsDir, { withFileTypes: true });
      const versionDirs = entries
        .filter(entry => entry.isDirectory())
        .map(entry => entry.name);

      const index = await this.getIndex();
      index.graphs = index.graphs.filter(graph =>
        versionDirs.includes(graph.version)
      );

      // Save updated index
      await fs.writeFile(this.indexPath, serializeGraphIndex(index), 'utf8');
    } catch (error) {
      console.warn('Failed to rebuild index:', error);
    }
  }

  /**
   * Load the latest graph version
   */
  async loadLatestGraph(): Promise<UIGraph> {
    try {
      const index = await this.getIndex();

      if (index.graphs.length === 0) {
        // Return empty graph if no graphs exist
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
        };
      }

      // Sort by timestamp and get the latest
      const sortedGraphs = index.graphs.sort((a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );

      const latestVersion = sortedGraphs[0].version;
      const graph = await this.getGraph(latestVersion);

      if (!graph) {
        throw new Error(`Failed to load latest graph version: ${latestVersion}`);
      }

      return graph;
    } catch (error) {
      console.error('Failed to load latest graph:', error);
      // Return empty graph on error
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
      };
    }
  }
}

export const graphStore = new GraphStore();