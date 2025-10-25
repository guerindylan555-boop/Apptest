/**
 * State Detector Service
 *
 * Orchestrates the state detection process, runs scoring, applies thresholds,
 * and logs telemetry for continuous improvement.
 */

import fs from 'fs/promises';
import path from 'path';
import { XMLParser } from 'fast-xml-parser';
import { ScoringEngine, XMLDump, CandidateScore } from './scoring';
import { ScreenNode, StateDetectionResult } from '../../types/uiGraph';
import { GraphStore } from '../ui-graph/graphStore';
import { logger } from '../../utils/logger';

export interface StateDetectorConfig {
  confidenceMin: number; // Minimum confidence for automatic match
  confidenceAmbiguous: number; // Range for ambiguous matches
  maxCandidates: number; // Maximum candidates to return
  enableTelemetry: boolean; // Whether to log detection results
}

export interface TelemetryEntry {
  timestamp: string;
  dumpPath: string;
  status: 'matched' | 'ambiguous' | 'unknown';
  topScore: number;
  candidatesCount: number;
  processingTime: number;
  selectedNodeId?: string;
  operatorAction?: 'accept' | 'map_new' | 'merge' | 'retry';
}

export class StateDetectorService {
  private scoringEngine: ScoringEngine;
  private graphStore: GraphStore;
  private config: StateDetectorConfig;
  private telemetryPath: string;

  constructor(
    graphStore: GraphStore,
    config: Partial<StateDetectorConfig> = {}
  ) {
    this.graphStore = graphStore;
    this.config = {
      confidenceMin: 75,
      confidenceAmbiguous: 50,
      maxCandidates: 5,
      enableTelemetry: true,
      ...config,
    };

    this.scoringEngine = new ScoringEngine({
      confidenceThreshold: this.config.confidenceMin,
      minCandidates: this.config.maxCandidates,
    });

    this.telemetryPath = path.join(process.cwd(), 'var', 'telemetry', 'state-detection.json');
  }

  /**
   * Detect the current state from an XML dump
   */
  async detectState(dumpPath: string): Promise<StateDetectionResult> {
    const startTime = Date.now();
    logger.info(`Starting state detection for dump: ${dumpPath}`);

    try {
      // Parse and extract features from XML dump
      const xmlDump = await this.parseXMLDump(dumpPath);

      // Load all active nodes from graph store
      const nodes = await this.loadActiveNodes();

      if (nodes.length === 0) {
        logger.warn('No active nodes found in graph store');
        return this.createUnknownResult(dumpPath, 'No nodes available');
      }

      // Score against all nodes
      const candidates = await this.scoringEngine.scoreDump(xmlDump, nodes);
      const processingTime = Date.now() - startTime;

      // Create detection result
      const result = this.scoringEngine.createDetectionResult(candidates, dumpPath);

      // Log telemetry if enabled
      if (this.config.enableTelemetry) {
        await this.logTelemetry({
          timestamp: new Date().toISOString(),
          dumpPath,
          status: result.status,
          topScore: candidates.length > 0 ? candidates[0].score : 0,
          candidatesCount: candidates.length,
          processingTime,
          selectedNodeId: result.selectedNodeId,
        });
      }

      logger.info(`State detection completed: ${result.status}, top score: ${candidates[0]?.score || 0}`);
      return result;
    } catch (error) {
      const processingTime = Date.now() - startTime;
      logger.error(`State detection failed: ${error instanceof Error ? error.message : String(error)}`);

      return this.createUnknownResult(dumpPath, `Detection error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Parse XML dump and extract relevant features
   */
  private async parseXMLDump(dumpPath: string): Promise<XMLDump> {
    const xmlContent = await fs.readFile(dumpPath, 'utf-8');

    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      textNodeName: '#text',
    });

    const uiHierarchy = parser.parse(xmlContent);
    const rootElement = uiHierarchy.hierarchy || uiHierarchy;

    // Extract basic information
    const activity = this.extractActivity(rootElement);
    const resourceIds = this.extractResourceIds(rootElement);
    const visibleTexts = this.extractVisibleTexts(rootElement);
    const layoutFingerprint = this.generateLayoutFingerprint(rootElement);

    return {
      xmlContent,
      activity,
      resourceIds,
      visibleTexts,
      layoutFingerprint,
    };
  }

  /**
   * Extract current activity name from XML dump
   */
  private extractActivity(rootElement: any): string {
    // Try different possible locations for activity name
    if (rootElement['@_activity']) {
      return rootElement['@_activity'];
    }

    if (rootElement['@_package'] && rootElement['@_class']) {
      return `${rootElement['@_package']}.${rootElement['@_class']}`;
    }

    // Search through nodes for activity information
    const findActivity = (node: any): string | null => {
      if (node['@_activity']) {
        return node['@_activity'];
      }

      if (node['@_focused'] === 'true' && node['@_class']) {
        return node['@_class'];
      }

      if (node.node) {
        const nodes = Array.isArray(node.node) ? node.node : [node.node];
        for (const child of nodes) {
          const activity = findActivity(child);
          if (activity) return activity;
        }
      }

      return null;
    };

    return findActivity(rootElement) || 'unknown.activity';
  }

  /**
   * Extract all resource IDs from the hierarchy
   */
  private extractResourceIds(rootElement: any): string[] {
    const resourceIds = new Set<string>();

    const traverse = (node: any) => {
      if (node['@_resource-id'] && node['@_resource-id'] !== '') {
        resourceIds.add(node['@_resource-id']);
      }

      if (node.node) {
        const nodes = Array.isArray(node.node) ? node.node : [node.node];
        for (const child of nodes) {
          traverse(child);
        }
      }
    };

    traverse(rootElement);
    return Array.from(resourceIds);
  }

  /**
   * Extract all visible text content
   */
  private extractVisibleTexts(rootElement: any): string[] {
    const texts = new Set<string>();

    const traverse = (node: any) => {
      // Extract text from various attributes
      const textSources = [
        node['@_text'],
        node['@_content-desc'],
        node['#text'],
        node['@_hint'],
        node['@_label'],
      ];

      for (const text of textSources) {
        if (text && typeof text === 'string' && text.trim().length > 0) {
          texts.add(text.trim());
        }
      }

      // Continue traversal
      if (node.node) {
        const nodes = Array.isArray(node.node) ? node.node : [node.node];
        for (const child of nodes) {
          traverse(child);
        }
      }
    };

    traverse(rootElement);
    return Array.from(texts);
  }

  /**
   * Generate layout fingerprint from node hierarchy
   */
  private generateLayoutFingerprint(rootElement: any): string {
    const extractStructure = (node: any, depth = 0): string => {
      if (!node || typeof node !== 'object') return '';

      const attributes = [
        node['@_class'] || 'unknown',
        node['@_package'] || '',
        node['@_clickable'] === 'true' ? 'clickable' : '',
        node['@_checkable'] === 'true' ? 'checkable' : '',
        node['@_focusable'] === 'true' ? 'focusable' : '',
      ].filter(Boolean).join(':');

      let structure = `${'  '.repeat(depth)}${attributes}`;

      if (node.node) {
        const nodes = Array.isArray(node.node) ? node.node : [node.node];
        const children = nodes.map((child: any) => extractStructure(child, depth + 1)).filter(Boolean);
        if (children.length > 0) {
          structure += '\n' + children.join('\n');
        }
      }

      return structure;
    };

    const structure = extractStructure(rootElement);
    const crypto = require('crypto');
    return crypto.createHash('md5').update(structure).digest('hex').substring(0, 16);
  }

  /**
   * Load all active nodes from graph store
   */
  private async loadActiveNodes(): Promise<ScreenNode[]> {
    try {
      const graph = await this.graphStore.loadLatestGraph();
      return graph.nodes.filter(node => node.status === 'active');
    } catch (error) {
      logger.error(`Failed to load nodes from graph store: ${error instanceof Error ? error.message : String(error)}`);
      return [];
    }
  }

  /**
   * Create an unknown result when detection fails
   */
  private createUnknownResult(dumpPath: string, reason: string): StateDetectionResult {
    return {
      timestamp: new Date().toISOString(),
      dumpSource: dumpPath,
      topCandidates: [],
      status: 'unknown',
    };
  }

  /**
   * Log telemetry data for continuous improvement
   */
  private async logTelemetry(entry: TelemetryEntry): Promise<void> {
    try {
      // Ensure telemetry directory exists
      await fs.mkdir(path.dirname(this.telemetryPath), { recursive: true });

      // Read existing telemetry or create new array
      let telemetry: TelemetryEntry[] = [];
      try {
        const existing = await fs.readFile(this.telemetryPath, 'utf-8');
        telemetry = JSON.parse(existing);
      } catch {
        // File doesn't exist or is invalid, start fresh
      }

      // Add new entry (keep last 1000 entries to avoid unbounded growth)
      telemetry.push(entry);
      if (telemetry.length > 1000) {
        telemetry = telemetry.slice(-1000);
      }

      // Write back to file
      await fs.writeFile(this.telemetryPath, JSON.stringify(telemetry, null, 2));
    } catch (error) {
      logger.error(`Failed to log telemetry: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get telemetry statistics for monitoring
   */
  async getTelemetryStats(): Promise<{
    totalDetections: number;
    successRate: number;
    averageProcessingTime: number;
    topScoreDistribution: Record<string, number>;
  }> {
    try {
      const data = await fs.readFile(this.telemetryPath, 'utf-8');
      const telemetry: TelemetryEntry[] = JSON.parse(data);

      const totalDetections = telemetry.length;
      const successfulDetections = telemetry.filter(t => t.status === 'matched').length;
      const successRate = totalDetections > 0 ? (successfulDetections / totalDetections) * 100 : 0;

      const averageProcessingTime = totalDetections > 0
        ? telemetry.reduce((sum, t) => sum + t.processingTime, 0) / totalDetections
        : 0;

      // Score distribution
      const scoreRanges = {
        '90-100': 0,
        '75-89': 0,
        '50-74': 0,
        '25-49': 0,
        '0-24': 0,
      };

      telemetry.forEach(t => {
        const score = t.topScore;
        if (score >= 90) scoreRanges['90-100']++;
        else if (score >= 75) scoreRanges['75-89']++;
        else if (score >= 50) scoreRanges['50-74']++;
        else if (score >= 25) scoreRanges['25-49']++;
        else scoreRanges['0-24']++;
      });

      return {
        totalDetections,
        successRate: Math.round(successRate * 100) / 100,
        averageProcessingTime: Math.round(averageProcessingTime * 100) / 100,
        topScoreDistribution: scoreRanges,
      };
    } catch (error) {
      logger.error(`Failed to get telemetry stats: ${error instanceof Error ? error.message : String(error)}`);
      return {
        totalDetections: 0,
        successRate: 0,
        averageProcessingTime: 0,
        topScoreDistribution: {},
      };
    }
  }

  /**
   * Update detection result with operator feedback
   */
  async updateWithOperatorFeedback(
    dumpPath: string,
    action: 'accept' | 'map_new' | 'merge' | 'retry',
    selectedNodeId?: string
  ): Promise<void> {
    try {
      const data = await fs.readFile(this.telemetryPath, 'utf-8');
      const telemetry: TelemetryEntry[] = JSON.parse(data);

      // Find the most recent detection for this dump
      const detectionIndex = telemetry.findIndex(
        t => t.dumpPath === dumpPath && !t.operatorAction
      );

      if (detectionIndex >= 0) {
        telemetry[detectionIndex].operatorAction = action;
        if (selectedNodeId) {
          telemetry[detectionIndex].selectedNodeId = selectedNodeId;
        }

        await fs.writeFile(this.telemetryPath, JSON.stringify(telemetry, null, 2));
        logger.info(`Updated detection for ${dumpPath} with operator action: ${action}`);
      }
    } catch (error) {
      logger.error(`Failed to update operator feedback: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}