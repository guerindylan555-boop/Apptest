/**
 * Artifact Storage Service
 *
 * Manages filesystem-based storage for UI graph artifacts including:
 * - Screen captures (screenshots, XML dumps, metadata)
 * - Graph versions and indexes
 * - Flow definitions
 *
 * Follows the single-volume mandate (Constitution §7) using the var/ directory.
 */

import { promises as fs } from 'fs';
import { join, dirname } from 'path';
import { createHash } from 'crypto';
import type { ScreenNode, ActionEdge, UIGraph, GraphIndex, FlowDefinition } from '../../types/uiGraph';
import { validateUIGraph, validateGraphIndex, serializeUIGraph, serializeGraphIndex } from '../../utils/validation/uiGraphSchema';

export class ArtifactStore {
  private readonly baseDir: string;
  private readonly capturesDir: string;
  private readonly graphsDir: string;
  private readonly flowsDir: string;

  constructor(baseDir: string = 'var') {
    this.baseDir = baseDir;
    this.capturesDir = join(baseDir, 'captures');
    this.graphsDir = join(baseDir, 'graphs');
    this.flowsDir = join(baseDir, 'flows');
  }

  /**
   * Initialize the artifact storage directory structure
   */
  async initialize(): Promise<void> {
    await this.ensureDir(this.baseDir);
    await this.ensureDir(this.capturesDir);
    await this.ensureDir(this.graphsDir);
    await this.ensureDir(this.flowsDir);

    // Initialize graph index if it doesn't exist
    const indexPath = join(this.graphsDir, 'index.json');
    try {
      await fs.access(indexPath);
    } catch {
      await this.createInitialIndex();
    }
  }

  /**
   * Store a screen capture with all associated artifacts
   */
  async storeScreenCapture(nodeId: string, artifacts: {
    screenshot: Buffer;
    xml: string;
    metadata?: any;
  }): Promise<void> {
    const nodeDir = join(this.capturesDir, nodeId);
    await this.ensureDir(nodeDir);

    // Store screenshot
    const screenshotPath = join(nodeDir, 'screenshot.png');
    await fs.writeFile(screenshotPath, artifacts.screenshot);

    // Store XML dump
    const xmlPath = join(nodeDir, 'ui.xml');
    await fs.writeFile(xmlPath, artifacts.xml, 'utf8');

    // Store metadata if provided
    if (artifacts.metadata) {
      const metadataPath = join(nodeDir, 'metadata.json');
      await fs.writeFile(metadataPath, JSON.stringify(artifacts.metadata, null, 2), 'utf8');
    }

    // Calculate and store checksums
    const checksums = await this.calculateArtifactChecksums({
      screenshotPath,
      xmlPath,
      metadataPath: artifacts.metadata ? join(nodeDir, 'metadata.json') : undefined,
    });

    await this.storeArtifactChecksums(nodeDir, checksums);
  }

  /**
   * Retrieve screen capture artifacts
   */
  async getScreenCapture(nodeId: string): Promise<{
    screenshot?: Buffer;
    xml?: string;
    metadata?: any;
    paths: {
      screenshot: string;
      xml: string;
      metadata?: string;
    };
  }> {
    const nodeDir = join(this.capturesDir, nodeId);
    const screenshotPath = join(nodeDir, 'screenshot.png');
    const xmlPath = join(nodeDir, 'ui.xml');
    const metadataPath = join(nodeDir, 'metadata.json');

    const result: any = {
      paths: {
        screenshot: screenshotPath,
        xml: xmlPath,
      },
    };

    try {
      result.screenshot = await fs.readFile(screenshotPath);
    } catch {
      // Screenshot might not exist
    }

    try {
      result.xml = await fs.readFile(xmlPath, 'utf8');
    } catch {
      // XML might not exist
    }

    try {
      const metadataContent = await fs.readFile(metadataPath, 'utf8');
      result.metadata = JSON.parse(metadataContent);
      result.paths.metadata = metadataPath;
    } catch {
      // Metadata might not exist
    }

    return result;
  }

  /**
   * Store a UI graph version
   */
  async storeGraph(graph: UIGraph, version?: string): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const graphVersion = version || timestamp;
    const graphDir = join(this.graphsDir, graphVersion);

    await this.ensureDir(graphDir);

    const graphPath = join(graphDir, 'ui-graph.json');
    await fs.writeFile(graphPath, serializeUIGraph(graph), 'utf8');

    // Update the index
    await this.updateGraphIndex(graphVersion, graphPath, graph);

    return graphVersion;
  }

  /**
   * Retrieve a UI graph version
   */
  async getGraph(version: string): Promise<UIGraph | null> {
    const graphPath = join(this.graphsDir, version, 'ui-graph.json');

    try {
      const content = await fs.readFile(graphPath, 'utf8');
      const graph = JSON.parse(content);
      const validation = validateUIGraph(graph);

      if (!validation.success) {
        throw new Error(`Invalid graph format: ${validation.error.message}`);
      }

      return validation.data as UIGraph;
    } catch {
      return null;
    }
  }

  /**
   * Get the latest UI graph version
   */
  async getLatestGraph(): Promise<UIGraph | null> {
    const index = await this.getGraphIndex();

    if (index.graphs.length === 0) {
      return null;
    }

    // Sort by timestamp descending and get the latest
    const sortedGraphs = index.graphs.sort((a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    return this.getGraph(sortedGraphs[0].version);
  }

  /**
   * Store a flow definition
   */
  async storeFlow(flow: FlowDefinition): Promise<void> {
    const flowPath = join(this.flowsDir, `${flow.name}.yaml`);
    const yamlContent = this.convertFlowToYaml(flow);
    await fs.writeFile(flowPath, yamlContent, 'utf8');
  }

  /**
   * Retrieve a flow definition
   */
  async getFlow(name: string): Promise<FlowDefinition | null> {
    const flowPath = join(this.flowsDir, `${name}.yaml`);

    try {
      const yamlContent = await fs.readFile(flowPath, 'utf8');
      return this.parseFlowFromYaml(yamlContent);
    } catch {
      return null;
    }
  }

  /**
   * List all available flows
   */
  async listFlows(): Promise<string[]> {
    try {
      const files = await fs.readdir(this.flowsDir);
      return files
        .filter(file => file.endsWith('.yaml'))
        .map(file => file.replace('.yaml', ''));
    } catch {
      return [];
    }
  }

  /**
   * List all available graph versions
   */
  async listGraphVersions(): Promise<string[]> {
    try {
      const entries = await fs.readdir(this.graphsDir, { withFileTypes: true });
      return entries
        .filter(entry => entry.isDirectory() && entry.name !== 'templates')
        .map(entry => entry.name)
        .sort()
        .reverse(); // Latest first
    } catch {
      return [];
    }
  }

  /**
   * Calculate checksums for artifact files
   */
  async calculateArtifactChecksums(paths: {
    screenshotPath: string;
    xmlPath: string;
    metadataPath?: string;
  }): Promise<{
    screenshot: string;
    xml: string;
    metadata?: string;
  }> {
    const checksums: any = {};

    checksums.screenshot = await this.calculateFileChecksum(paths.screenshotPath);
    checksums.xml = await this.calculateFileChecksum(paths.xmlPath);

    if (paths.metadataPath) {
      checksums.metadata = await this.calculateFileChecksum(paths.metadataPath);
    }

    return checksums;
  }

  /**
   * Get the graph index
   */
  async getGraphIndex(): Promise<GraphIndex> {
    const indexPath = join(this.graphsDir, 'index.json');

    try {
      const content = await fs.readFile(indexPath, 'utf8');
      const index = JSON.parse(content);
      const validation = validateGraphIndex(index);

      if (!validation.success) {
        throw new Error(`Invalid index format: ${validation.error.message}`);
      }

      return validation.data;
    } catch {
      return await this.createInitialIndex();
    }
  }

  /**
   * Clean up old graph versions (keep latest N)
   */
  async cleanupOldGraphVersions(keepCount: number = 10): Promise<void> {
    const versions = await this.listGraphVersions();

    if (versions.length <= keepCount) {
      return;
    }

    const versionsToDelete = versions.slice(keepCount);

    for (const version of versionsToDelete) {
      const versionDir = join(this.graphsDir, version);
      try {
        await fs.rm(versionDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }

    // Update index to remove deleted versions
    await this.rebuildGraphIndex();
  }

  /**
   * Private helper methods
   */
  private async ensureDir(dir: string): Promise<void> {
    await fs.mkdir(dir, { recursive: true });
  }

  private async calculateFileChecksum(filePath: string): Promise<string> {
    try {
      const content = await fs.readFile(filePath);
      return createHash('sha256').digest('hex');
    } catch {
      return '';
    }
  }

  private async storeArtifactChecksums(nodeDir: string, checksums: any): Promise<void> {
    const checksumPath = join(nodeDir, 'checksums.json');
    await fs.writeFile(checksumPath, JSON.stringify(checksums, null, 2), 'utf8');
  }

  private async createInitialIndex(): Promise<GraphIndex> {
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

    const indexPath = join(this.graphsDir, 'index.json');
    await fs.writeFile(indexPath, serializeGraphIndex(initialIndex), 'utf8');

    return initialIndex;
  }

  private async updateGraphIndex(version: string, graphPath: string, graph: UIGraph): Promise<void> {
    const index = await this.getGraphIndex();

    // Calculate checksum for the graph file
    const checksum = await this.calculateFileChecksum(graphPath);

    // Add or update the graph entry
    const existingIndex = index.graphs.findIndex(g => g.version === version);
    const graphEntry = {
      version,
      timestamp: new Date().toISOString(),
      path: graphPath,
      checksum,
      description: `Graph version ${version}`,
    };

    if (existingIndex >= 0) {
      index.graphs[existingIndex] = graphEntry;
    } else {
      index.graphs.push(graphEntry);
    }

    // Update metadata
    index.metadata.lastUpdated = new Date().toISOString();
    index.metadata.totalNodes = graph.nodes.length;
    index.metadata.totalEdges = graph.edges.length;
    index.metadata.checksum = checksum;

    // Save updated index
    const indexPath = join(this.graphsDir, 'index.json');
    await fs.writeFile(indexPath, serializeGraphIndex(index), 'utf8');
  }

  private async rebuildGraphIndex(): Promise<void> {
    const versions = await this.listGraphVersions();
    const index: GraphIndex = {
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

    for (const version of versions) {
      const graphPath = join(this.graphsDir, version, 'ui-graph.json');
      try {
        const checksum = await this.calculateFileChecksum(graphPath);
        index.graphs.push({
          version,
          timestamp: new Date().toISOString(),
          path: graphPath,
          checksum,
          description: `Graph version ${version}`,
        });
      } catch {
        // Skip invalid graph versions
      }
    }

    const indexPath = join(this.graphsDir, 'index.json');
    await fs.writeFile(indexPath, serializeGraphIndex(index), 'utf8');
  }

  private convertFlowToYaml(flow: FlowDefinition): string {
    // Basic YAML conversion - in a real implementation, you'd use a YAML library
    const yaml = `
name: ${flow.name}
description: "${flow.description}"
version: "${flow.version}"

variables:
${flow.variables.map(v => `  - name: ${v.name}
    description: "${v.description}"
    type: ${v.type}
    required: ${v.required}
    prompt: "${v.prompt}"`).join('\n')}

precondition:
${flow.precondition.nodeId ? `  nodeId: ${flow.precondition.nodeId}` :
  flow.precondition.query ? `  query:
    ${flow.precondition.query.activity ? `activity: ${flow.precondition.query.activity}` : ''}
    ${flow.precondition.query.requiredTexts ? `requiredTexts: [${flow.precondition.query.requiredTexts.map(t => `"${t}"`).join(', ')}]` : ''}` : ''}

steps:
${flow.steps.map(step => {
  if (step.kind === 'edgeRef') {
    return `  - kind: edgeRef
    edgeId: ${step.edgeId}
    ${step.expectNodeId ? `expectNodeId: ${step.expectNodeId}` : ''}
    ${step.guard ? `guard:
      ${step.guard.mustMatchSignatureHash ? `mustMatchSignatureHash: ${step.guard.mustMatchSignatureHash}` : ''}
      ${step.guard.requiredTexts ? `requiredTexts: [${step.guard.requiredTexts.map(t => `"${t}"`).join(', ')}]` : ''}` : ''}`;
  } else {
    return `  - kind: inline
    inlineAction:
      action: ${step.inlineAction?.action}
      ${step.inlineAction?.selectorId ? `selectorId: ${step.inlineAction.selectorId}` : ''}
      ${step.inlineAction?.text ? `text: "${step.inlineAction.text}"` : ''}
      ${step.inlineAction?.keycode ? `keycode: ${step.inlineAction.keycode}` : ''}
      ${step.inlineAction?.waitMs ? `waitMs: ${step.inlineAction.waitMs}` : ''}`;
  }
}).join('\n')}

postcondition:
${flow.postcondition.nodeId ? `  nodeId: ${flow.postcondition.nodeId}` :
  flow.postcondition.query ? `  query:
    ${flow.postcondition.query.activity ? `activity: ${flow.postcondition.query.activity}` : ''}
    ${flow.postcondition.query.requiredTexts ? `requiredTexts: [${flow.postcondition.query.requiredTexts.map(t => `"${t}"`).join(', ')}]` : ''}` : ''}

recovery:
${flow.recovery.map(rule => `  - trigger: ${rule.trigger}
    allowedActions: [${rule.allowedActions.join(', ')}]`).join('\n')}

metadata:
  owner: ${flow.metadata.owner || 'unknown'}
  lastUpdatedAt: ${flow.metadata.lastUpdatedAt}
  validationStatus: ${flow.metadata.validationStatus}
  ${flow.metadata.notes ? `notes: "${flow.metadata.notes}"` : ''}
`;

    return yaml.trim();
  }

  private parseFlowFromYaml(yamlContent: string): FlowDefinition {
    // Basic YAML parsing - in a real implementation, you'd use a YAML library
    // This is a simplified version for demonstration
    throw new Error('YAML parsing not implemented - use a YAML library like js-yaml');
  }
}

export const artifactStore = new ArtifactStore();