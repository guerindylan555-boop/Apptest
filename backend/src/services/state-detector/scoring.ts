/**
 * Weighted Scoring Engine for UI State Detection
 *
 * Implements the scoring algorithm that compares XML dumps against stored signatures
 * using hash matches, selector weights, and layout similarity.
 */

import crypto from 'crypto';
import { ScreenNode, ScreenSignature, StateDetectionResult } from '../../types/uiGraph';

export interface ScoringConfig {
  hashMatchWeight: number; // Weight for exact signature hash matches
  selectorWeight: number; // Weight for selector similarity
  layoutWeight: number; // Weight for layout similarity
  confidenceThreshold: number; // Minimum score to consider a match
  minCandidates: number; // Minimum candidates to return
}

export interface XMLDump {
  xmlContent: string;
  activity: string;
  resourceIds: string[];
  visibleTexts: string[];
  layoutFingerprint: string;
}

export interface CandidateScore {
  nodeId: string;
  score: number;
  breakdown: {
    hashMatch: number;
    selectorMatch: number;
    layoutSimilarity: number;
  };
}

export class ScoringEngine {
  private config: ScoringConfig;

  constructor(config: Partial<ScoringConfig> = {}) {
    this.config = {
      hashMatchWeight: 0.5,
      selectorWeight: 0.3,
      layoutWeight: 0.2,
      confidenceThreshold: 75,
      minCandidates: 3,
      ...config,
    };
  }

  /**
   * Score a dump against all known nodes and return top candidates
   */
  async scoreDump(dump: XMLDump, nodes: ScreenNode[]): Promise<CandidateScore[]> {
    const candidates: CandidateScore[] = [];

    for (const node of nodes) {
      if (node.status !== 'active') continue;

      const score = await this.scoreNode(dump, node);
      if (score.score > 0) {
        candidates.push(score);
      }
    }

    // Sort by score descending and return top candidates
    return candidates
      .sort((a, b) => b.score - a.score)
      .slice(0, this.config.minCandidates);
  }

  /**
   * Score a single node against the dump
   */
  private async scoreNode(dump: XMLDump, node: ScreenNode): Promise<CandidateScore> {
    const hashScore = this.scoreHashMatch(dump, node.signature);
    const selectorScore = this.scoreSelectorMatch(dump, node);
    const layoutScore = this.scoreLayoutSimilarity(dump, node.signature);

    const totalScore =
      hashScore * this.config.hashMatchWeight +
      selectorScore * this.config.selectorWeight +
      layoutScore * this.config.layoutWeight;

    return {
      nodeId: node.id,
      score: Math.round(totalScore * 100) / 100, // Round to 2 decimal places
      breakdown: {
        hashMatch: Math.round(hashScore * 100) / 100,
        selectorMatch: Math.round(selectorScore * 100) / 100,
        layoutSimilarity: Math.round(layoutScore * 100) / 100,
      },
    };
  }

  /**
   * Score hash match between dump and stored signature
   */
  private scoreHashMatch(dump: XMLDump, signature: ScreenSignature): number {
    // Generate hash from dump components
    const dumpHash = this.generateSignatureHash(dump);

    if (dumpHash === signature.hash) {
      return 100; // Perfect match
    }

    // Partial match based on component similarity
    const activityMatch = dump.activity === signature.activity ? 50 : 0;
    const resourceIdOverlap = this.calculateArrayOverlap(
      dump.resourceIds.sort(),
      signature.resourceIds.sort()
    );

    return Math.max(activityMatch, resourceIdOverlap * 25);
  }

  /**
   * Score selector match based on resource IDs and texts present in dump
   */
  private scoreSelectorMatch(dump: XMLDump, node: ScreenNode): number {
    let totalScore = 0;
    let consideredSelectors = 0;

    for (const selector of node.selectors) {
      let selectorScore = 0;

      switch (selector.type) {
        case 'resource-id':
          if (dump.resourceIds.includes(selector.value)) {
            selectorScore = selector.confidence * 100;
          }
          break;

        case 'text':
          if (dump.visibleTexts.some(text =>
            text.toLowerCase().includes(selector.value.toLowerCase())
          )) {
            selectorScore = selector.confidence * 90; // Slightly lower for text matching
          }
          break;

        case 'content-desc':
        case 'accessibility':
          // These would need additional parsing from XML
          selectorScore = selector.confidence * 70; // Estimated
          break;
      }

      if (selectorScore > 0) {
        totalScore += selectorScore;
        consideredSelectors++;
      }
    }

    return consideredSelectors > 0 ? totalScore / consideredSelectors : 0;
  }

  /**
   * Score layout similarity between dump and stored signature
   */
  private scoreLayoutSimilarity(dump: XMLDump, signature: ScreenSignature): number {
    if (dump.layoutFingerprint === signature.layoutFingerprint) {
      return 100;
    }

    // Simple similarity based on fingerprint characteristics
    const dumpLength = dump.layoutFingerprint.length;
    const signatureLength = signature.layoutFingerprint.length;

    if (dumpLength === 0 || signatureLength === 0) {
      return 0;
    }

    // Calculate Levenshtein distance for similarity
    const distance = this.levenshteinDistance(
      dump.layoutFingerprint,
      signature.layoutFingerprint
    );

    const maxLength = Math.max(dumpLength, signatureLength);
    const similarity = ((maxLength - distance) / maxLength) * 100;

    return Math.max(0, similarity);
  }

  /**
   * Generate deterministic signature hash from dump components
   */
  private generateSignatureHash(dump: XMLDump): string {
    const normalized = {
      activity: dump.activity.toLowerCase().trim(),
      resourceIds: [...new Set(dump.resourceIds.map(id => id.toLowerCase().trim()))].sort(),
      requiredTexts: [...new Set(dump.visibleTexts.map(text => text.toLowerCase().trim()))]
        .filter(text => text.length > 2) // Skip very short texts
        .sort(),
      layoutFingerprint: dump.layoutFingerprint,
    };

    const hashInput = JSON.stringify(normalized);
    return crypto.createHash('sha256').update(hashInput).digest('hex').substring(0, 16);
  }

  /**
   * Calculate overlap percentage between two sorted arrays
   */
  private calculateArrayOverlap(arr1: string[], arr2: string[]): number {
    if (arr1.length === 0 || arr2.length === 0) {
      return 0;
    }

    let i = 0, j = 0, matches = 0;

    while (i < arr1.length && j < arr2.length) {
      if (arr1[i] === arr2[j]) {
        matches++;
        i++;
        j++;
      } else if (arr1[i] < arr2[j]) {
        i++;
      } else {
        j++;
      }
    }

    const totalUnique = new Set([...arr1, ...arr2]).size;
    return totalUnique > 0 ? matches / totalUnique : 0;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix = Array(str2.length + 1).fill(null).map(() =>
      Array(str1.length + 1).fill(null)
    );

    for (let i = 0; i <= str1.length; i++) {
      matrix[0][i] = i;
    }

    for (let j = 0; j <= str2.length; j++) {
      matrix[j][0] = j;
    }

    for (let j = 1; j <= str2.length; j++) {
      for (let i = 1; i <= str1.length; i++) {
        const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[j][i] = Math.min(
          matrix[j][i - 1] + 1, // deletion
          matrix[j - 1][i] + 1, // insertion
          matrix[j - 1][i - 1] + indicator, // substitution
        );
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Convert scoring results to StateDetectionResult format
   */
  createDetectionResult(
    candidates: CandidateScore[],
    dumpPath: string,
  ): StateDetectionResult {
    const topScore = candidates.length > 0 ? candidates[0].score : 0;

    let status: 'matched' | 'ambiguous' | 'unknown';
    let selectedNodeId: string | undefined;

    if (topScore >= this.config.confidenceThreshold) {
      status = 'matched';
      selectedNodeId = candidates[0].nodeId;
    } else if (topScore >= this.config.confidenceThreshold * 0.6) {
      status = 'ambiguous';
    } else {
      status = 'unknown';
    }

    return {
      timestamp: new Date().toISOString(),
      dumpSource: dumpPath,
      topCandidates: candidates.map(c => ({
        nodeId: c.nodeId,
        score: c.score,
      })),
      selectedNodeId,
      status,
    };
  }
}