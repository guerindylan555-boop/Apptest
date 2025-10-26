/**
 * ScreenNode Entity
 *
 * Represents a captured screen state with signature, selectors,
 * artifacts, and metadata for the UI graph system.
 */

import { v4 as uuidv4 } from 'uuid';
import { ExtendedScreenNode, StartStateTag } from '../types/graph';
import { ScreenSignatureEntity } from './ScreenSignature';
import { SelectorCandidateEntity } from './SelectorCandidate';
import { ArtifactBundleEntity } from './ArtifactBundle';

export interface ScreenNodeOptions {
  name: string;
  signature: ScreenSignatureEntity;
  selectors: SelectorCandidateEntity[];
  hints?: string[];
  samples: ArtifactBundleEntity;
  metadata: {
    activity?: string;
    class?: string;
    package?: string;
    emulatorBuild?: string;
    captureTimestamp: string;
    operatorId: string;
  };
  startStateTag?: StartStateTag;
  status?: 'active' | 'deprecated' | 'duplicate';
}

export class ScreenNodeEntity implements ExtendedScreenNode {
  id: string;
  name: string;
  signature: ScreenSignatureEntity;
  selectors: SelectorCandidateEntity[];
  hints: string[];
  samples: ArtifactBundleEntity;
  metadata: {
    activity?: string;
    class?: string;
    package?: string;
    emulatorBuild?: string;
    captureTimestamp: string;
    operatorId: string;
  };
  startStateTag?: StartStateTag;
  outgoingEdgeIds: string[];
  incomingEdgeIds: string[];
  status: 'active' | 'deprecated' | 'duplicate';

  constructor(options: ScreenNodeOptions) {
    this.id = options.signature.hash; // Use signature hash as primary key
    this.name = options.name;
    this.signature = options.signature;
    this.selectors = [...options.selectors];
    this.hints = options.hints || [];
    this.samples = options.samples;
    this.metadata = { ...options.metadata };
    this.startStateTag = options.startStateTag;
    this.outgoingEdgeIds = [];
    this.incomingEdgeIds = [];
    this.status = options.status || 'active';

    this.validate();
  }

  /**
   * Create screen node from capture data
   */
  static async fromCapture(
    name: string,
    screenshotPath: string,
    xmlPath: string,
    xmlData: any,
    operatorId: string,
    hints: string[] = [],
    startStateTag?: StartStateTag,
    metadataPath?: string,
    baseDir: string = 'var/captures'
  ): Promise<ScreenNodeEntity> {
    // Extract signature from XML data
    const signature = ScreenSignatureEntity.fromXmlDump(xmlData);

    // Extract selectors from XML data
    const allSelectors = this.extractSelectorsFromXml(xmlData);

    // Create artifact bundle
    const samples = await ArtifactBundleEntity.fromFiles(
      screenshotPath,
      xmlPath,
      metadataPath,
      baseDir
    );

    return new ScreenNodeEntity({
      name,
      signature,
      selectors: allSelectors,
      hints,
      samples,
      metadata: {
        activity: xmlData?.['@_activity'],
        class: xmlData?.['@_class'],
        package: xmlData?.['@_package'],
        emulatorBuild: process.env.EMULATOR_BUILD || 'unknown',
        captureTimestamp: new Date().toISOString(),
        operatorId
      },
      startStateTag
    });
  }

  /**
   * Extract all selectors from XML dump
   */
  private static extractSelectorsFromXml(xmlData: any): SelectorCandidateEntity[] {
    const allSelectors: SelectorCandidateEntity[] = [];

    const extractFromElement = (element: any, index: number = 0) => {
      if (!element) return;

      // Extract selectors from current element
      const elementSelectors = SelectorCandidateEntity.extractFromElement(element, index);
      allSelectors.push(...elementSelectors);

      // Recursively extract from child elements
      if (element?.node) {
        const children = Array.isArray(element.node) ? element.node : [element.node];
        children.forEach((child: any, childIndex: number) => extractFromElement(child, childIndex));
      }
    };

    extractFromElement(xmlData);

    // Deduplicate by type and value, keeping highest confidence
    const deduplicatedSelectors = this.deduplicateSelectors(allSelectors);

    // Sort by confidence and limit to top 10 selectors
    return deduplicatedSelectors
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 10);
  }

  /**
   * Deduplicate selectors by type and value
   */
  private static deduplicateSelectors(selectors: SelectorCandidateEntity[]): SelectorCandidateEntity[] {
    const uniqueSelectors = new Map<string, SelectorCandidateEntity>();

    for (const selector of selectors) {
      const key = `${selector.type}:${selector.value}`;
      const existing = uniqueSelectors.get(key);

      if (!existing || selector.confidence > existing.confidence) {
        uniqueSelectors.set(key, selector);
      }
    }

    return Array.from(uniqueSelectors.values());
  }

  /**
   * Validate node configuration
   */
  private validate(): void {
    const errors: string[] = [];

    if (!this.name || this.name.trim().length < 3 || this.name.trim().length > 80) {
      errors.push('Node name must be between 3-80 characters');
    }

    if (!this.signature) {
      errors.push('Screen signature is required');
    }

    if (!this.selectors || this.selectors.length === 0) {
      errors.push('At least one selector is required');
    }

    // Check for high-confidence selectors
    const hasReliableSelector = this.selectors.some(s => s.confidence >= 0.6);
    if (!hasReliableSelector) {
      errors.push('At least one selector with confidence >= 0.6 is required');
    }

    if (!this.samples) {
      errors.push('Artifact bundle is required');
    }

    if (!this.metadata.operatorId) {
      errors.push('Operator ID is required in metadata');
    }

    if (!this.metadata.captureTimestamp) {
      errors.push('Capture timestamp is required in metadata');
    }

    if (errors.length > 0) {
      throw new Error(`Invalid screen node: ${errors.join(', ')}`);
    }
  }

  /**
   * Add outgoing edge
   */
  addOutgoingEdge(edgeId: string): void {
    if (!this.outgoingEdgeIds.includes(edgeId)) {
      this.outgoingEdgeIds.push(edgeId);
    }
  }

  /**
   * Remove outgoing edge
   */
  removeOutgoingEdge(edgeId: string): void {
    const index = this.outgoingEdgeIds.indexOf(edgeId);
    if (index > -1) {
      this.outgoingEdgeIds.splice(index, 1);
    }
  }

  /**
   * Add incoming edge
   */
  addIncomingEdge(edgeId: string): void {
    if (!this.incomingEdgeIds.includes(edgeId)) {
      this.incomingEdgeIds.push(edgeId);
    }
  }

  /**
   * Remove incoming edge
   */
  removeIncomingEdge(edgeId: string): void {
    const index = this.incomingEdgeIds.indexOf(edgeId);
    if (index > -1) {
      this.incomingEdgeIds.splice(index, 1);
    }
  }

  /**
   * Update selector validation results
   */
  updateSelectorValidation(selectorId: string, success: boolean): void {
    const selector = this.selectors.find(s => s.id === selectorId);
    if (selector) {
      selector.updateValidationResult(success);
    }
  }

  /**
   * Get best selector for automation
   */
  getBestSelector(): SelectorCandidateEntity | null {
    if (this.selectors.length === 0) return null;

    // Sort by confidence and return highest
    return this.selectors
      .sort((a, b) => b.confidence - a.confidence)[0];
  }

  /**
   * Get selectors by type
   */
  getSelectorsByType(type: string): SelectorCandidateEntity[] {
    return this.selectors.filter(s => s.type === type);
  }

  /**
   * Check if node has reliable selectors
   */
  hasReliableSelectors(): boolean {
    return this.selectors.some(s => s.confidence >= 0.6);
  }

  /**
   * Check if node is considered risky for automation
   */
  isRisky(): boolean {
    return !this.hasReliableSelectors() || this.status === 'deprecated';
  }

  /**
   * Mark node as deprecated
   */
  markDeprecated(reason?: string): void {
    this.status = 'deprecated';
    if (reason) {
      this.hints.push(`Deprecated: ${reason}`);
    }
  }

  /**
   * Mark node as duplicate
   */
  markDuplicate(originalNodeId: string): void {
    this.status = 'duplicate';
    this.hints.push(`Duplicate of: ${originalNodeId}`);
  }

  /**
   * Mark node as active
   */
  markActive(): void {
    this.status = 'active';
    // Remove deprecated/duplicate hints
    this.hints = this.hints.filter(hint =>
      !hint.startsWith('Deprecated:') && !hint.startsWith('Duplicate of:')
    );
  }

  /**
   * Update start state tag
   */
  updateStartStateTag(tag: StartStateTag): void {
    this.startStateTag = tag;
  }

  /**
   * Check if node matches given characteristics
   */
  matchesCharacteristics(characteristics: {
    signatureHash?: string;
    activity?: string;
    texts?: string[];
    startStateTag?: StartStateTag;
  }): boolean {
    if (characteristics.signatureHash && this.signature.hash !== characteristics.signatureHash) {
      return false;
    }

    if (characteristics.activity && this.metadata.activity !== characteristics.activity) {
      return false;
    }

    if (characteristics.startStateTag && this.startStateTag !== characteristics.startStateTag) {
      return false;
    }

    if (characteristics.texts && characteristics.texts.length > 0) {
      const nodeTexts = [
        ...this.signature.requiredTexts,
        ...this.hints
      ].join(' ').toLowerCase();

      const hasRequiredText = characteristics.texts.some(text =>
        nodeTexts.includes(text.toLowerCase())
      );

      if (!hasRequiredText) {
        return false;
      }
    }

    return true;
  }

  /**
   * Get node summary information
   */
  getSummary(): {
    id: string;
    name: string;
    activity?: string;
    status: string;
    selectorCount: number;
    hasReliableSelectors: boolean;
    startStateTag?: string;
    captureDate: string;
  } {
    return {
      id: this.id,
      name: this.name,
      activity: this.metadata.activity,
      status: this.status,
      selectorCount: this.selectors.length,
      hasReliableSelectors: this.hasReliableSelectors(),
      startStateTag: this.startStateTag,
      captureDate: this.metadata.captureTimestamp
    };
  }

  /**
   * Validate artifact integrity
   */
  async validateArtifacts(): Promise<boolean> {
    try {
      return await this.samples.validate();
    } catch (error) {
      console.error(`Failed to validate artifacts for node ${this.id}: ${error}`);
      return false;
    }
  }

  /**
   * Check if artifacts exceed size limit
   */
  async artifactsExceedLimit(limitBytes: number = 1024 * 1024): Promise<boolean> {
    try {
      return await this.samples.exceedsSizeLimit(limitBytes);
    } catch (error) {
      console.error(`Failed to check artifact size for node ${this.id}: ${error}`);
      return false;
    }
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): ExtendedScreenNode {
    return {
      id: this.id,
      name: this.name,
      signature: this.signature.toJSON(),
      selectors: this.selectors.map(s => s.toJSON()),
      hints: [...this.hints],
      samples: this.samples.toJSON(),
      metadata: { ...this.metadata },
      startStateTag: this.startStateTag,
      outgoingEdgeIds: [...this.outgoingEdgeIds],
      incomingEdgeIds: [...this.incomingEdgeIds],
      status: this.status
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: ExtendedScreenNode): ScreenNodeEntity {
    const entity = Object.create(ScreenNodeEntity.prototype);

    entity.id = data.id;
    entity.name = data.name;
    entity.signature = ScreenSignatureEntity.fromJSON(data.signature);
    entity.selectors = data.selectors.map(s => SelectorCandidateEntity.fromJSON(s));
    entity.hints = [...data.hints];
    entity.samples = ArtifactBundleEntity.fromJSON(data.samples);
    entity.metadata = { ...data.metadata };
    entity.startStateTag = data.startStateTag;
    entity.outgoingEdgeIds = [...data.outgoingEdgeIds];
    entity.incomingEdgeIds = [...data.incomingEdgeIds];
    entity.status = data.status;

    return entity;
  }

  /**
   * Find nodes matching criteria
   */
  static findMatchingNodes(
    nodes: ScreenNodeEntity[],
    criteria: {
      signatureHash?: string;
      activity?: string;
      startStateTag?: StartStateTag;
      status?: string;
    }
  ): ScreenNodeEntity[] {
    return nodes.filter(node => node.matchesCharacteristics(criteria));
  }

  /**
   * Get nodes by status
   */
  static getByStatus(nodes: ScreenNodeEntity[], status: string): ScreenNodeEntity[] {
    return nodes.filter(node => node.status === status);
  }

  /**
   * Get active nodes with reliable selectors
   */
  static getActiveReliableNodes(nodes: ScreenNodeEntity[]): ScreenNodeEntity[] {
    return nodes.filter(node =>
      node.status === 'active' && node.hasReliableSelectors()
    );
  }
}