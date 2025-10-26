/**
 * Node Capture Service
 *
 * Orchestrates screen capture, UI dump analysis, and node creation.
 * Manages selector ranking and artifact persistence for UI graph discovery.
 */

import { promises as fs } from 'fs';
import { join } from 'path';
import { v4 as uuidv4 } from 'uuid';
import type { ScreenNode, SelectorCandidate, ArtifactBundle } from '../../types/uiGraph';
import { signatureBuilder } from './signatureBuilder';
import { artifactStore } from '../storage/artifactStore';

interface CaptureInput {
  name: string;
  hints?: string[];
  operatorId: string;
  metadata?: {
    activity?: string;
    package?: string;
    emulatorBuild?: string;
  };
}

interface UIDumpResult {
  xmlContent: string;
  screenshot: Buffer;
  activity?: string;
  package?: string;
  extractedSelectors: SelectorCandidate[];
}

interface CaptureOptions {
  includeScreenshot?: boolean;
  selectorConfidenceThreshold?: number;
  maxSelectors?: number;
}

export class NodeCaptureService {
  private readonly defaultOptions: Required<CaptureOptions> = {
    includeScreenshot: true,
    selectorConfidenceThreshold: 0.3,
    maxSelectors: 20,
  };

  /**
   * Capture a screen node from current emulator state
   */
  async captureNode(input: CaptureInput, options: CaptureOptions = {}): Promise<ScreenNode> {
    const opts = { ...this.defaultOptions, ...options };

    try {
      // Step 1: Capture UI dump and screenshot from emulator
      const uiDump = await this.captureUIDump(opts);

      // Step 2: Extract and rank selectors from UI dump
      const rankedSelectors = this.rankSelectors(uiDump.extractedSelectors, opts);

      // Step 3: Build signature using research-driven approach
      const signature = await signatureBuilder.buildSignature({
        activity: uiDump.activity,
        package: uiDump.package,
        resourceIds: rankedSelectors
          .filter(s => s.type === 'resource-id')
          .map(s => s.value),
        requiredTexts: rankedSelectors
          .filter(s => s.type === 'text')
          .map(s => s.value),
        xmlContent: uiDump.xmlContent,
      });

      // Step 4: Create node with deterministic ID from signature hash
      const nodeId = signature.hash;
      const now = new Date().toISOString();

      const node: ScreenNode = {
        id: nodeId,
        name: input.name,
        signature,
        selectors: rankedSelectors,
        hints: input.hints || [],
        samples: await this.storeArtifacts(nodeId, uiDump, opts),
        metadata: {
          activity: uiDump.activity,
          package: uiDump.package,
          emulatorBuild: input.metadata?.emulatorBuild,
          captureTimestamp: now,
          operatorId: input.operatorId,
        },
        outgoingEdgeIds: [],
        incomingEdgeIds: [],
        status: 'active',
      };

      // Step 5: Persist node and artifacts
      await this.persistNode(node);

      return node;
    } catch (error) {
      throw new Error(`Node capture failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Capture UI dump and screenshot from emulator
   */
  private async captureUIDump(options: Required<CaptureOptions>): Promise<UIDumpResult> {
    try {
      // In a real implementation, this would interface with ADB/emulator
      // For now, we'll simulate the capture process

      const xmlContent = await this.getUIXMLDump();
      const screenshot = options.includeScreenshot ? await this.takeScreenshot() : Buffer.alloc(0);

      // Parse XML to extract activity, package, and selectors
      const parsed = await this.parseUIDump(xmlContent);

      return {
        xmlContent,
        screenshot,
        activity: parsed.activity,
        package: parsed.package,
        extractedSelectors: parsed.selectors,
      };
    } catch (error) {
      throw new Error(`UI dump capture failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get UI XML dump from emulator
   */
  private async getUIXMLDump(): Promise<string> {
    try {
      const { execSync } = await import('child_process');

      // Dump UI hierarchy to device
      execSync('adb shell uiautomator dump /sdcard/window_dump.xml', { encoding: 'utf-8' });

      // Read the XML content directly from device
      const xmlContent = execSync('adb shell cat /sdcard/window_dump.xml', { encoding: 'utf-8' });

      return xmlContent;
    } catch (error) {
      throw new Error(`Failed to get UI XML dump: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Take screenshot from emulator
   */
  private async takeScreenshot(): Promise<Buffer> {
    try {
      const { execSync } = await import('child_process');

      // Take screenshot on device
      execSync('adb shell screencap -p /sdcard/screenshot.png', { encoding: 'utf-8' });

      // Pull screenshot as binary data
      const screenshot = execSync('adb shell cat /sdcard/screenshot.png', {
        encoding: 'buffer',
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large screenshots
      });

      return screenshot;
    } catch (error) {
      throw new Error(`Failed to take screenshot: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Parse UI XML dump to extract activity, package, and selectors
   */
  private async parseUIDump(xmlContent: string): Promise<{
    activity?: string;
    package?: string;
    selectors: SelectorCandidate[];
  }> {
    const selectors: SelectorCandidate[] = [];
    let activity: string | undefined;
    let packageName: string | undefined;

    try {
      // Extract package from hierarchy node
      const packageMatch = xmlContent.match(/package=['"]([^'"]+)['"]/);
      if (packageMatch) {
        packageName = packageMatch[1];
      }

      // Extract activity (this might need to be determined differently)
      // In Android, activity is often not directly in the UI dump
      // This might require additional ADB commands or heuristics

      // Extract selectors from node elements
      const nodeRegex = /<node[^>]*>/g;
      const nodes = xmlContent.match(nodeRegex) || [];

      nodes.forEach((nodeString, index) => {
        const resourceIdMatch = nodeString.match(/resource-id=['"]([^'"]+)['"]/);
        const textMatch = nodeString.match(/text=['"]([^'"]*)['"]/);
        const contentDescMatch = nodeString.match(/content-desc=['"]([^'"]*)['"]/);
        const classMatch = nodeString.match(/class=['"]([^'"]+)['"]/);
        const clickableMatch = nodeString.match(/clickable=['"](true|false)['"]/);
        const boundsMatch = nodeString.match(/bounds=['"]\[(\d+),(\d+)\]\[(\d+),(\d+)\]['"]/);

        const isClickable = clickableMatch?.[1] === 'true';
        const hasText = textMatch?.[1] && textMatch[1].length > 0;
        const hasResourceId = resourceIdMatch?.[1] && resourceIdMatch[1].trim().length > 0;
        const hasContentDesc = contentDescMatch?.[1] && contentDescMatch[1].trim().length > 0;

        // Only create selectors for interactive elements
        if (isClickable && (hasText || hasResourceId || hasContentDesc)) {
          const selectorId = `selector_${index}`;
          const confidence = this.calculateSelectorConfidence({
            hasText: !!hasText,
            hasResourceId: !!hasResourceId,
            hasContentDesc: !!hasContentDesc,
            isClickable,
            hasBounds: !!boundsMatch,
          });

          if (confidence >= 0.3) { // Filter very low-confidence selectors
            // Add resource-id selector if available
            if (hasResourceId) {
              selectors.push({
                id: `${selectorId}_resource_id`,
                type: 'resource-id',
                value: resourceIdMatch![1],
                confidence: Math.min(confidence * 1.2, 1.0), // Boost resource-id confidence but cap at 1.0
                lastValidatedAt: new Date().toISOString(),
              });
            }

            // Add text selector if available
            if (hasText) {
              selectors.push({
                id: `${selectorId}_text`,
                type: 'text',
                value: textMatch![1],
                confidence: Math.min(confidence * 0.8, 1.0), // Text selectors are slightly less reliable
                lastValidatedAt: new Date().toISOString(),
              });
            }

            // Add content-desc selector if available
            if (hasContentDesc) {
              selectors.push({
                id: `${selectorId}_content_desc`,
                type: 'content-desc',
                value: contentDescMatch![1],
                confidence: Math.min(confidence * 0.9, 1.0), // Content-desc is fairly reliable
                lastValidatedAt: new Date().toISOString(),
              });
            }

            // Add coordinate fallback if bounds available
            if (boundsMatch) {
              const [x1, y1, x2, y2] = boundsMatch.slice(1).map(Number);
              const centerX = Math.floor((x1 + x2) / 2);
              const centerY = Math.floor((y1 + y2) / 2);

              selectors.push({
                id: `${selectorId}_coords`,
                type: 'coords',
                value: `${centerX},${centerY}`,
                confidence: Math.min(confidence * 0.4, 1.0), // Coordinate selectors are least reliable
                lastValidatedAt: new Date().toISOString(),
              });
            }
          }
        }
      });

      return {
        activity,
        package: packageName,
        selectors,
      };
    } catch (error) {
      throw new Error(`Failed to parse UI dump: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Calculate selector confidence based on available attributes
   */
  private calculateSelectorConfidence(traits: {
    hasText: boolean;
    hasResourceId: boolean;
    hasContentDesc: boolean;
    isClickable: boolean;
    hasBounds: boolean;
  }): number {
    let confidence = 0.0;

    // Base confidence for clickable elements
    if (traits.isClickable) confidence += 0.3;

    // Boosts for reliable attributes
    if (traits.hasResourceId) confidence += 0.5;
    if (traits.hasText) confidence += 0.3;
    if (traits.hasContentDesc) confidence += 0.2;
    if (traits.hasBounds) confidence += 0.1;

    // Cap at 1.0
    return Math.min(confidence, 1.0);
  }

  /**
   * Rank selectors by confidence and deduplicate similar ones
   */
  private rankSelectors(selectors: SelectorCandidate[], options: Required<CaptureOptions>): SelectorCandidate[] {
    // Filter by confidence threshold
    const filtered = selectors.filter(s => s.confidence >= options.selectorConfidenceThreshold);

    // Group by type and value to remove exact duplicates
    const uniqueSelectors = new Map<string, SelectorCandidate>();

    filtered.forEach(selector => {
      const key = `${selector.type}:${selector.value}`;
      const existing = uniqueSelectors.get(key);

      // Keep the one with higher confidence
      if (!existing || selector.confidence > existing.confidence) {
        uniqueSelectors.set(key, selector);
      }
    });

    // Sort by confidence (highest first) and by type priority
    const sorted = Array.from(uniqueSelectors.values()).sort((a, b) => {
      // Type priority: resource-id > content-desc > text > accessibility > xpath > coords
      const typePriority = {
        'resource-id': 5,
        'content-desc': 4,
        'text': 3,
        'accessibility': 2,
        'xpath': 1,
        'coords': 0,
      };

      const priorityDiff = typePriority[b.type] - typePriority[a.type];
      if (priorityDiff !== 0) {
        return priorityDiff; // Higher type priority first
      }

      return b.confidence - a.confidence; // Higher confidence first
    });

    // Limit to maximum number of selectors
    return sorted.slice(0, options.maxSelectors);
  }

  /**
   * Store artifacts in the artifact store
   */
  private async storeArtifacts(nodeId: string, uiDump: UIDumpResult, options: Required<CaptureOptions>): Promise<ArtifactBundle> {
    const artifacts = {
      screenshot: uiDump.screenshot,
      xml: uiDump.xmlContent,
      metadata: {
        activity: uiDump.activity,
        package: uiDump.package,
        captureOptions: options,
      },
    };

    await artifactStore.storeScreenCapture(nodeId, artifacts);

    return {
      screenshotPath: `var/captures/${nodeId}/screenshot.png`,
      xmlPath: `var/captures/${nodeId}/ui.xml`,
      metadataPath: `var/captures/${nodeId}/metadata.json`,
      checksum: await this.calculateArtifactChecksum(artifacts),
    };
  }

  /**
   * Calculate checksum for artifact bundle
   */
  private async calculateArtifactChecksum(artifacts: {
    screenshot: Buffer;
    xml: string;
    metadata?: any;
  }): Promise<string> {
    const { createHash } = await import('crypto');

    const hash = createHash('sha256');
    hash.update(artifacts.screenshot);
    hash.update(artifacts.xml);

    if (artifacts.metadata) {
      hash.update(JSON.stringify(artifacts.metadata));
    }

    return hash.digest('hex');
  }

  /**
   * Persist node to storage and update graph
   */
  private async persistNode(node: ScreenNode): Promise<void> {
    // This would integrate with the GraphStore service
    // For now, we'll just store the artifacts
    // The graph update would happen in the GraphStore service

    console.log(`Node captured: ${node.id} - ${node.name}`);
    console.log(`Selectors: ${node.selectors.length}`);
    console.log(`Signature hash: ${node.signature.hash}`);
  }
}

export const nodeCaptureService = new NodeCaptureService();