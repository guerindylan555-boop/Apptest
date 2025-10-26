/**
 * StateDetectionResult Entity
 *
 * Manages telemetry and results from state detection attempts
 * for analysis, improvement, and operator feedback.
 */

import { StateDetectionResult } from '../types/uiGraph';

export interface DetectionCandidate {
  nodeId: string;
  score: number; // 0-100
  reasons: string[]; // Why this candidate matched
  breakdown: {
    signatureScore: number;
    selectorScore: number;
    structuralScore: number;
  };
}

export interface StateDetectionResultOptions {
  timestamp?: string;
  dumpSource: string;
  topCandidates: Array<{ nodeId: string; score: number }>;
  selectedNodeId?: string;
  status: 'matched' | 'ambiguous' | 'unknown';
  operatorAction?: 'accept' | 'map_new' | 'merge' | 'retry';
  metadata?: {
    detectionTimeMs: number;
    totalCandidates: number;
    thresholds: {
      matched: number;
      ambiguous: number;
    };
    configHash?: string;
    platformInfo?: {
      emulatorBuild?: string;
      appVersion?: string;
      screenSize?: string;
    };
  };
}

export class StateDetectionResultEntity implements StateDetectionResult {
  timestamp: string;
  dumpSource: string;
  topCandidates: Array<{ nodeId: string; score: number }>;
  selectedNodeId?: string;
  status: 'matched' | 'ambiguous' | 'unknown';
  operatorAction?: 'accept' | 'map_new' | 'merge' | 'retry';

  // Extended fields for detailed analysis
  detailedCandidates: DetectionCandidate[];
  metadata: {
    detectionTimeMs: number;
    totalCandidates: number;
    thresholds: {
      matched: number;
      ambiguous: number;
    };
    configHash?: string;
    detectorVersion: string;
    platformInfo?: {
      emulatorBuild?: string;
      appVersion?: string;
      screenSize?: string;
    };
    operatorNotes?: string;
    performanceMetrics?: {
      xmlParsingTimeMs?: number;
      scoringTimeMs?: number;
      sortingTimeMs?: number;
      memoryUsageMB?: number;
    };
  };

  constructor(options: StateDetectionResultOptions) {
    this.timestamp = options.timestamp || new Date().toISOString();
    this.dumpSource = options.dumpSource;
    this.topCandidates = options.topCandidates.slice(0, 10); // Limit to top 10
    this.selectedNodeId = options.selectedNodeId;
    this.status = options.status;
    this.operatorAction = options.operatorAction;

    // Initialize detailed candidates (placeholder for now)
    this.detailedCandidates = this.topCandidates.map(candidate => ({
      nodeId: candidate.nodeId,
      score: candidate.score,
      reasons: ['Base match'],
      breakdown: {
        signatureScore: candidate.score * 0.4, // Approximate breakdown
        selectorScore: candidate.score * 0.4,
        structuralScore: candidate.score * 0.2
      }
    }));

    // Initialize metadata with defaults
    this.metadata = {
      detectionTimeMs: options.metadata?.detectionTimeMs || 0,
      totalCandidates: options.metadata?.totalCandidates || this.topCandidates.length,
      thresholds: options.metadata?.thresholds || { matched: 70, ambiguous: 50 },
      configHash: options.metadata?.configHash,
      detectorVersion: '1.0.0',
      platformInfo: options.metadata?.platformInfo || {}
    };
  }

  /**
   * Create result from detection process
   */
  static fromDetection(
    dumpSource: string,
    candidates: DetectionCandidate[],
    thresholds: { matched: number; ambiguous: number },
    detectionTimeMs: number,
    configHash?: string
  ): StateDetectionResultEntity {
    // Sort candidates by score (highest first)
    const sortedCandidates = candidates
      .sort((a, b) => b.score - a.score)
      .slice(0, 10); // Keep top 10

    const topCandidates = sortedCandidates.map(candidate => ({
      nodeId: candidate.nodeId,
      score: candidate.score
    }));

    // Determine status and selection
    let status: 'matched' | 'ambiguous' | 'unknown';
    let selectedNodeId: string | undefined;

    if (sortedCandidates.length === 0) {
      status = 'unknown';
    } else if (sortedCandidates[0].score >= thresholds.matched) {
      status = 'matched';
      selectedNodeId = sortedCandidates[0].nodeId;
    } else if (sortedCandidates[0].score >= thresholds.ambiguous) {
      status = 'ambiguous';
    } else {
      status = 'unknown';
    }

    const result = new StateDetectionResultEntity({
      timestamp: new Date().toISOString(),
      dumpSource,
      topCandidates,
      selectedNodeId,
      status,
      metadata: {
        detectionTimeMs,
        totalCandidates: candidates.length,
        thresholds,
        configHash
      }
    });

    result.detailedCandidates = sortedCandidates;
    return result;
  }

  /**
   * Record operator action on this detection result
   */
  recordOperatorAction(action: 'accept' | 'map_new' | 'merge' | 'retry', notes?: string): void {
    this.operatorAction = action;

    // Add notes to metadata if provided
    if (notes) {
      this.metadata.operatorNotes = notes;
    }
  }

  /**
   * Check if detection was successful (matched or accepted by operator)
   */
  isSuccessful(): boolean {
    return this.status === 'matched' || this.operatorAction === 'accept';
  }

  /**
   * Check if detection requires operator intervention
   */
  requiresOperatorIntervention(): boolean {
    return this.status === 'ambiguous' || this.status === 'unknown';
  }

  /**
   * Get the confidence score of the top candidate
   */
  getTopCandidateScore(): number {
    return this.topCandidates.length > 0 ? this.topCandidates[0].score : 0;
  }

  /**
   * Get the gap between top and second candidate (if exists)
   */
  getCandidateScoreGap(): number {
    if (this.topCandidates.length < 2) return 100;
    return this.topCandidates[0].score - this.topCandidates[1].score;
  }

  /**
   * Check if the top candidate is significantly better than others
   */
  hasClearWinner(): boolean {
    if (this.topCandidates.length === 0) return false;
    if (this.topCandidates.length === 1) return true;

    const topScore = this.topCandidates[0].score;
    const secondScore = this.topCandidates[1].score;

    // Top candidate is clear winner if it's at least 15 points higher
    return (topScore - secondScore) >= 15;
  }

  /**
   * Get detailed breakdown of why candidates scored as they did
   */
  getDetailedBreakdown(): DetectionCandidate[] {
    return this.detailedCandidates;
  }

  /**
   * Add performance metrics
   */
  addPerformanceMetrics(metrics: {
    xmlParsingTimeMs?: number;
    scoringTimeMs?: number;
    sortingTimeMs?: number;
    memoryUsageMB?: number;
  }): void {
    this.metadata.performanceMetrics = {
      ...this.metadata.performanceMetrics,
      ...metrics
    };
  }

  /**
   * Add platform information
   */
  setPlatformInfo(platformInfo: {
    emulatorBuild?: string;
    appVersion?: string;
    screenSize?: string;
  }): void {
    this.metadata.platformInfo = {
      ...this.metadata.platformInfo,
      ...platformInfo
    };
  }

  /**
   * Check if detection meets performance criteria
   */
  meetsPerformanceCriteria(maxTimeMs: number = 2000): boolean {
    return this.metadata.detectionTimeMs <= maxTimeMs;
  }

  /**
   * Get analysis summary for operator review
   */
  getAnalysisSummary(): {
    status: string;
    confidence: string;
    recommendation: string;
    reasons: string[];
  } {
    const topScore = this.getTopCandidateScore();
    const hasClearWinner = this.hasClearWinner();
    const scoreGap = this.getCandidateScoreGap();

    let status: string;
    let confidence: string;
    let recommendation: string;
    const reasons: string[] = [];

    switch (this.status) {
      case 'matched':
        status = 'Match';
        confidence = topScore >= 85 ? 'High' : topScore >= 75 ? 'Medium' : 'Low';
        recommendation = hasClearWinner ? 'Accept match' : 'Review similar candidates';
        reasons.push(`Top score: ${topScore}%`);
        if (scoreGap < 15) {
          reasons.push(`Close scores: gap only ${scoreGap}%`);
        }
        break;

      case 'ambiguous':
        status = 'Ambiguous';
        confidence = 'Low';
        recommendation = 'Manual review required';
        reasons.push(`Score ${topScore}% below threshold`);
        reasons.push(`Multiple possible matches`);
        break;

      case 'unknown':
        status = 'Unknown';
        confidence = 'Very Low';
        recommendation = 'Create new node or review capture';
        reasons.push(`No suitable matches found`);
        if (this.topCandidates.length > 0) {
          reasons.push(`Best score: ${topScore}%`);
        }
        break;

      default:
        status = 'Error';
        confidence = 'Unknown';
        recommendation = 'System error occurred';
        reasons.push('Invalid detection status');
    }

    return {
      status,
      confidence,
      recommendation,
      reasons
    };
  }

  /**
   * Export result for telemetry analysis
   */
  exportForTelemetry(): {
    timestamp: string;
    status: string;
    success: boolean;
    score: number;
    candidatesCount: number;
    detectionTimeMs: number;
    operatorAction?: string;
    clearWinner: boolean;
  } {
    return {
      timestamp: this.timestamp,
      status: this.status,
      success: this.isSuccessful(),
      score: this.getTopCandidateScore(),
      candidatesCount: this.topCandidates.length,
      detectionTimeMs: this.metadata.detectionTimeMs,
      operatorAction: this.operatorAction,
      clearWinner: this.hasClearWinner()
    };
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): StateDetectionResult {
    return {
      timestamp: this.timestamp,
      dumpSource: this.dumpSource,
      topCandidates: [...this.topCandidates],
      selectedNodeId: this.selectedNodeId,
      status: this.status,
      operatorAction: this.operatorAction
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: StateDetectionResult): StateDetectionResultEntity {
    const entity = Object.create(StateDetectionResultEntity.prototype);
    Object.assign(entity, data);

    // Initialize detailed candidates and metadata with defaults
    entity.detailedCandidates = entity.topCandidates.map((candidate: { nodeId: string; score: number }) => ({
      nodeId: candidate.nodeId,
      score: candidate.score,
      reasons: ['Restored from storage'],
      breakdown: {
        signatureScore: candidate.score * 0.4,
        selectorScore: candidate.score * 0.4,
        structuralScore: candidate.score * 0.2
      }
    }));

    if (!entity.metadata) {
      entity.metadata = {
        detectionTimeMs: 0,
        totalCandidates: entity.topCandidates.length,
        thresholds: { matched: 70, ambiguous: 50 },
        detectorVersion: '1.0.0',
        platformInfo: {}
      };
    }

    return entity;
  }

  /**
   * Filter results by time range
   */
  static filterByTimeRange(
    results: StateDetectionResultEntity[],
    startTime: Date,
    endTime: Date
  ): StateDetectionResultEntity[] {
    return results.filter(result => {
      const resultTime = new Date(result.timestamp);
      return resultTime >= startTime && resultTime <= endTime;
    });
  }

  /**
   * Get success rate statistics from results
   */
  static getSuccessStatistics(results: StateDetectionResultEntity[]): {
    totalDetections: number;
    successfulDetections: number;
    successRate: number;
    averageScore: number;
    averageDetectionTime: number;
    operatorInterventionRate: number;
  } {
    const totalDetections = results.length;
    const successfulDetections = results.filter(r => r.isSuccessful()).length;
    const averageScore = results.reduce((sum, r) => sum + r.getTopCandidateScore(), 0) / totalDetections;
    const averageDetectionTime = results.reduce((sum, r) => sum + r.metadata.detectionTimeMs, 0) / totalDetections;
    const operatorInterventions = results.filter(r => r.requiresOperatorIntervention()).length;

    return {
      totalDetections,
      successfulDetections,
      successRate: totalDetections > 0 ? (successfulDetections / totalDetections) * 100 : 0,
      averageScore: Math.round(averageScore),
      averageDetectionTime: Math.round(averageDetectionTime),
      operatorInterventionRate: totalDetections > 0 ? (operatorInterventions / totalDetections) * 100 : 0
    };
  }
}