/**
 * Telemetry Logger for State Detection and Flow Execution
 *
 * Aggregates detection and flow telemetry data, provides summaries,
 * and updates the graph index with performance metrics.
 */

import fs from 'fs/promises';
import path from 'path';
import { StateDetectionResult } from '../../types/uiGraph';
import { logger } from '../../utils/logger';

export interface DetectionTelemetry {
  timestamp: string;
  dumpPath: string;
  status: 'matched' | 'ambiguous' | 'unknown';
  topScore: number;
  candidatesCount: number;
  processingTime: number;
  selectedNodeId?: string;
  operatorAction?: 'accept' | 'map_new' | 'merge' | 'retry';
}

export interface FlowTelemetry {
  timestamp: string;
  flowName: string;
  executionId: string;
  startNodeId?: string;
  endNodeId?: string;
  success: boolean;
  finalState: 'completed' | 'failed' | 'recovered' | 'timeout';
  stepsExecuted: number;
  totalSteps: number;
  executionTime: number;
  recoveryTriggered?: string;
  error?: string;
}

export interface TelemetrySummary {
  period: {
    start: string;
    end: string;
    totalHours: number;
  };
  detection: {
    totalDetections: number;
    successRate: number;
    averageConfidence: number;
    averageProcessingTime: number;
    topScoreDistribution: Record<string, number>;
    statusDistribution: Record<string, number>;
  };
  flows: {
    totalExecutions: number;
    successRate: number;
    averageExecutionTime: number;
    mostUsedFlows: Array<{
      flowName: string;
      executions: number;
      successRate: number;
    }>;
    failureReasons: Record<string, number>;
  };
  graph: {
    totalNodes: number;
    totalEdges: number;
    newNodesThisPeriod: number;
    newEdgesThisPeriod: number;
    mostConnectedNodes: Array<{
      nodeId: string;
      nodeName: string;
      connections: number;
    }>;
  };
}

export class TelemetryLogger {
  private detectionTelemetryPath: string;
  private flowTelemetryPath: string;
  private summaryPath: string;
  private graphIndexPath: string;

  constructor() {
    const telemetryDir = path.join(process.cwd(), 'var', 'telemetry');
    this.detectionTelemetryPath = path.join(telemetryDir, 'detection.json');
    this.flowTelemetryPath = path.join(telemetryPath, 'flows.json');
    this.summaryPath = path.join(telemetryDir, 'summary.json');
    this.graphIndexPath = path.join(process.cwd(), 'var', 'graphs', 'index.json');
  }

  /**
   * Log a detection event
   */
  async logDetection(result: StateDetectionResult, processingTime: number): Promise<void> {
    try {
      const telemetry: DetectionTelemetry = {
        timestamp: result.timestamp,
        dumpPath: result.dumpSource,
        status: result.status,
        topScore: result.topCandidates[0]?.score || 0,
        candidatesCount: result.topCandidates.length,
        processingTime,
        selectedNodeId: result.selectedNodeId,
        operatorAction: result.operatorAction,
      };

      await this.appendToTelemetryFile(this.detectionTelemetryPath, telemetry);
    } catch (error) {
      logger.error(`Failed to log detection telemetry: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Log a flow execution event
   */
  async logFlowExecution(result: any): Promise<void> {
    try {
      const telemetry: FlowTelemetry = {
        timestamp: result.endTime.toISOString(),
        flowName: result.flowName,
        executionId: `${result.flowName}-${result.startTime.getTime()}`,
        startNodeId: result.startNodeId,
        endNodeId: result.endNodeId,
        success: result.success,
        finalState: result.finalState,
        stepsExecuted: result.stepsExecuted,
        totalSteps: result.totalSteps,
        executionTime: result.endTime.getTime() - result.startTime.getTime(),
        recoveryTriggered: result.recoveryTriggered,
        error: result.error,
      };

      await this.appendToTelemetryFile(this.flowTelemetryPath, telemetry);
    } catch (error) {
      logger.error(`Failed to log flow telemetry: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Generate telemetry summary for the last N hours
   */
  async generateSummary(hours: number = 24): Promise<TelemetrySummary> {
    try {
      const now = new Date();
      const periodStart = new Date(now.getTime() - hours * 60 * 60 * 1000);

      const detectionTelemetry = await this.loadTelemetry<DetectionTelemetry>(this.detectionTelemetryPath);
      const flowTelemetry = await this.loadTelemetry<FlowTelemetry>(this.flowTelemetryPath);

      // Filter telemetry by time period
      const recentDetections = detectionTelemetry.filter(
        t => new Date(t.timestamp) >= periodStart
      );
      const recentFlows = flowTelemetry.filter(
        t => new Date(t.timestamp) >= periodStart
      );

      // Calculate detection metrics
      const detectionStats = this.calculateDetectionStats(recentDetections);

      // Calculate flow metrics
      const flowStats = this.calculateFlowStats(recentFlows);

      // Get graph statistics
      const graphStats = await this.getGraphStats(periodStart);

      const summary: TelemetrySummary = {
        period: {
          start: periodStart.toISOString(),
          end: now.toISOString(),
          totalHours: hours,
        },
        detection: detectionStats,
        flows: flowStats,
        graph: graphStats,
      };

      // Save summary
      await this.saveSummary(summary);

      // Update graph index with telemetry
      await this.updateGraphIndex(summary);

      return summary;
    } catch (error) {
      logger.error(`Failed to generate telemetry summary: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  /**
   * Get telemetry statistics for monitoring dashboards
   */
  async getMonitoringStats(): Promise<any> {
    try {
      const summary = await this.loadSummary();
      if (!summary) {
        return await this.generateSummary();
      }

      // Add real-time metrics
      const lastHourDetections = await this.getRecentDetectionCount(1);
      const lastHourFlows = await this.getRecentFlowCount(1);

      return {
        ...summary,
        realTime: {
          lastHourDetections,
          lastHourFlows,
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      logger.error(`Failed to get monitoring stats: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  /**
   * Append entry to telemetry file
   */
  private async appendToTelemetryFile(filePath: string, entry: any): Promise<void> {
    await fs.mkdir(path.dirname(filePath), { recursive: true });

    let telemetry: any[] = [];
    try {
      const data = await fs.readFile(filePath, 'utf-8');
      telemetry = JSON.parse(data);
    } catch {
      // File doesn't exist or is invalid
    }

    telemetry.push(entry);

    // Keep only last 10,000 entries to prevent unbounded growth
    if (telemetry.length > 10000) {
      telemetry = telemetry.slice(-10000);
    }

    await fs.writeFile(filePath, JSON.stringify(telemetry, null, 2));
  }

  /**
   * Load telemetry from file
   */
  private async loadTelemetry<T>(filePath: string): Promise<T[]> {
    try {
      const data = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(data);
    } catch {
      return [];
    }
  }

  /**
   * Calculate detection statistics
   */
  private calculateDetectionStats(telemetry: DetectionTelemetry[]): any {
    if (telemetry.length === 0) {
      return {
        totalDetections: 0,
        successRate: 0,
        averageConfidence: 0,
        averageProcessingTime: 0,
        topScoreDistribution: {},
        statusDistribution: {},
      };
    }

    const totalDetections = telemetry.length;
    const successfulDetections = telemetry.filter(t => t.status === 'matched').length;
    const successRate = (successfulDetections / totalDetections) * 100;

    const averageConfidence = telemetry.reduce((sum, t) => sum + t.topScore, 0) / totalDetections;
    const averageProcessingTime = telemetry.reduce((sum, t) => sum + t.processingTime, 0) / totalDetections;

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

    // Status distribution
    const statusDistribution = telemetry.reduce((acc, t) => {
      acc[t.status] = (acc[t.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalDetections,
      successRate: Math.round(successRate * 100) / 100,
      averageConfidence: Math.round(averageConfidence * 100) / 100,
      averageProcessingTime: Math.round(averageProcessingTime * 100) / 100,
      topScoreDistribution: scoreRanges,
      statusDistribution,
    };
  }

  /**
   * Calculate flow statistics
   */
  private calculateFlowStats(telemetry: FlowTelemetry[]): any {
    if (telemetry.length === 0) {
      return {
        totalExecutions: 0,
        successRate: 0,
        averageExecutionTime: 0,
        mostUsedFlows: [],
        failureReasons: {},
      };
    }

    const totalExecutions = telemetry.length;
    const successfulExecutions = telemetry.filter(t => t.success).length;
    const successRate = (successfulExecutions / totalExecutions) * 100;

    const averageExecutionTime = telemetry.reduce((sum, t) => sum + t.executionTime, 0) / totalExecutions;

    // Most used flows
    const flowUsage = telemetry.reduce((acc, t) => {
      if (!acc[t.flowName]) {
        acc[t.flowName] = { executions: 0, successes: 0 };
      }
      acc[t.flowName].executions++;
      if (t.success) acc[t.flowName].successes++;
      return acc;
    }, {} as Record<string, { executions: number; successes: number }>);

    const mostUsedFlows = Object.entries(flowUsage)
      .map(([flowName, stats]) => ({
        flowName,
        executions: stats.executions,
        successRate: (stats.successes / stats.executions) * 100,
      }))
      .sort((a, b) => b.executions - a.executions)
      .slice(0, 10);

    // Failure reasons
    const failureReasons = telemetry
      .filter(t => !t.success)
      .reduce((acc, t) => {
        const reason = t.error || t.finalState || 'unknown';
        acc[reason] = (acc[reason] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

    return {
      totalExecutions,
      successRate: Math.round(successRate * 100) / 100,
      averageExecutionTime: Math.round(averageExecutionTime * 100) / 100,
      mostUsedFlows,
      failureReasons,
    };
  }

  /**
   * Get graph statistics
   */
  private async getGraphStats(periodStart: Date): Promise<any> {
    try {
      const graphIndexPath = this.graphIndexPath;
      const indexData = await fs.readFile(graphIndexPath, 'utf-8');
      const index = JSON.parse(indexData);

      // Get recent graph changes
      const recentGraphs = index.graphs?.filter((g: any) =>
        new Date(g.timestamp) >= periodStart
      ) || [];

      return {
        totalNodes: index.totalNodes || 0,
        totalEdges: index.totalEdges || 0,
        newNodesThisPeriod: recentGraphs.length,
        newEdgesThisPeriod: recentGraphs.length, // Simplified
        mostConnectedNodes: [], // Would need detailed graph analysis
      };
    } catch (error) {
      logger.warn(`Failed to get graph stats: ${error instanceof Error ? error.message : String(error)}`);
      return {
        totalNodes: 0,
        totalEdges: 0,
        newNodesThisPeriod: 0,
        newEdgesThisPeriod: 0,
        mostConnectedNodes: [],
      };
    }
  }

  /**
   * Save telemetry summary
   */
  private async saveSummary(summary: TelemetrySummary): Promise<void> {
    await fs.mkdir(path.dirname(this.summaryPath), { recursive: true });
    await fs.writeFile(this.summaryPath, JSON.stringify(summary, null, 2));
  }

  /**
   * Load existing summary
   */
  private async loadSummary(): Promise<TelemetrySummary | null> {
    try {
      const data = await fs.readFile(this.summaryPath, 'utf-8');
      return JSON.parse(data);
    } catch {
      return null;
    }
  }

  /**
   * Update graph index with telemetry summary
   */
  private async updateGraphIndex(summary: TelemetrySummary): Promise<void> {
    try {
      const indexData = await fs.readFile(this.graphIndexPath, 'utf-8');
      const index = JSON.parse(indexData);

      // Add telemetry summary to index
      index.telemetry = {
        lastUpdated: new Date().toISOString(),
        summary,
      };

      await fs.writeFile(this.graphIndexPath, JSON.stringify(index, null, 2));
      logger.info('Updated graph index with telemetry summary');
    } catch (error) {
      logger.error(`Failed to update graph index: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get recent detection count
   */
  private async getRecentDetectionCount(hours: number): Promise<number> {
    const telemetry = await this.loadTelemetry<DetectionTelemetry>(this.detectionTelemetryPath);
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);

    return telemetry.filter(t => new Date(t.timestamp) >= cutoff).length;
  }

  /**
   * Get recent flow count
   */
  private async getRecentFlowCount(hours: number): Promise<number> {
    const telemetry = await this.loadTelemetry<FlowTelemetry>(this.flowTelemetryPath);
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);

    return telemetry.filter(t => new Date(t.timestamp) >= cutoff).length;
  }
}