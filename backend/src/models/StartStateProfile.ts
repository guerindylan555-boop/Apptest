/**
 * StartStateProfile Entity
 *
 * Manages start state profiles for categorizing screen nodes
 * and providing context-aware routing for flow execution.
 */

import { StartStateProfile, StartStateTag } from '../types/graph';

export interface StartStateProfileOptions {
  id: string;
  description: string;
  nodeIds?: string[];
  preferredEntryEdgeIds?: string[];
  unlockPolicy?: 'any_available' | 'existing_rental_only' | 'n/a';
  detectorHints?: Record<string, any>;
}

export class StartStateProfileEntity implements StartStateProfile {
  id: string;
  description: string;
  nodeIds: string[];
  preferredEntryEdgeIds: string[];
  unlockPolicy: 'any_available' | 'existing_rental_only' | 'n/a';
  detectorHints: Record<string, any>;

  constructor(options: StartStateProfileOptions) {
    this.id = options.id;
    this.description = options.description;
    this.nodeIds = options.nodeIds || [];
    this.preferredEntryEdgeIds = options.preferredEntryEdgeIds || [];
    this.unlockPolicy = options.unlockPolicy || 'n/a';
    this.detectorHints = options.detectorHints || {};
  }

  /**
   * Create predefined start state profiles for MaynDrive
   */
  static createMaynDriveProfiles(): StartStateProfileEntity[] {
    return [
      new StartStateProfileEntity({
        id: 'clean',
        description: 'Clean boot state - app launched fresh, no user session',
        unlockPolicy: 'n/a',
        detectorHints: {
          activityPatterns: ['.*SplashActivity.*', '.*MainActivity.*'],
          requiredTexts: ['Get Started', 'Login', 'Sign In'],
          absenceTexts: ['Home', 'Profile', 'My Rentals'],
          minimumNodes: 1
        }
      }),

      new StartStateProfileEntity({
        id: 'logged_out_home',
        description: 'Logged out home state - user can see app but not authenticated',
        unlockPolicy: 'n/a',
        detectorHints: {
          activityPatterns: ['.*HomeActivity.*', '.*MainActivity.*'],
          requiredTexts: ['Login', 'Sign In', 'Get Started'],
          absenceTexts: ['Profile', 'My Account', 'Rentals'],
          minimumNodes: 1
        }
      }),

      new StartStateProfileEntity({
        id: 'logged_in_no_rental',
        description: 'Logged in state with no active rental - user can rent scooters',
        unlockPolicy: 'any_available',
        detectorHints: {
          activityPatterns: ['.*HomeActivity.*', '.*MapActivity.*'],
          requiredTexts: ['Map', 'Scan', 'Find Scooter', 'Rent'],
          absenceTexts: ['End Ride', 'Lock', 'Current Rental'],
          minimumNodes: 1
        }
      }),

      new StartStateProfileEntity({
        id: 'logged_in_with_rental',
        description: 'Logged in state with active rental - user is currently renting',
        unlockPolicy: 'existing_rental_only',
        detectorHints: {
          activityPatterns: ['.*RideActivity.*', '.*MapActivity.*'],
          requiredTexts: ['End Ride', 'Lock', 'Current Rental', 'Timer'],
          absenceTexts: ['Scan QR', 'Rent', 'Find Scooter'],
          minimumNodes: 1
        }
      }),

      new StartStateProfileEntity({
        id: 'other',
        description: 'Other states - settings, profile, help, etc.',
        unlockPolicy: 'n/a',
        detectorHints: {
          activityPatterns: ['.*SettingsActivity.*', '.*ProfileActivity.*', '.*HelpActivity.*'],
          requiredTexts: ['Settings', 'Profile', 'Help', 'Support'],
          minimumNodes: 0
        }
      })
    ];
  }

  /**
   * Check if a node belongs to this profile based on its characteristics
   */
  matchesNode(nodeCharacteristics: {
    activity?: string;
    texts?: string[];
    tag?: StartStateTag;
  }): boolean {
    const { activity, texts = [], tag } = nodeCharacteristics;

    // Direct tag match (highest priority)
    if (tag && this.tagMatchesProfile(tag)) {
      return true;
    }

    // Activity pattern matching
    if (activity && this.detectorHints.activityPatterns) {
      const activityPatterns = this.detectorHints.activityPatterns as string[];
      const matchesActivity = activityPatterns.some(pattern =>
        new RegExp(pattern).test(activity)
      );
      if (!matchesActivity) {
        return false;
      }
    }

    // Required text matching
    if (this.detectorHints.requiredTexts) {
      const requiredTexts = this.detectorHints.requiredTexts as string[];
      const hasRequiredTexts = requiredTexts.some(requiredText =>
        texts.some(text => text.toLowerCase().includes(requiredText.toLowerCase()))
      );
      if (!hasRequiredTexts) {
        return false;
      }
    }

    // Absence text matching (should NOT contain these texts)
    if (this.detectorHints.absenceTexts) {
      const absenceTexts = this.detectorHints.absenceTexts as string[];
      const hasAbsenceTexts = absenceTexts.some(absenceText =>
        texts.some(text => text.toLowerCase().includes(absenceText.toLowerCase()))
      );
      if (hasAbsenceTexts) {
        return false;
      }
    }

    return true;
  }

  /**
   * Check if a start state tag matches this profile
   */
  private tagMatchesProfile(tag: StartStateTag): boolean {
    const tagToProfileMap: Record<StartStateTag, string[]> = {
      'clean': ['clean'],
      'logged_out_home': ['logged_out_home'],
      'logged_in_no_rental': ['logged_in_no_rental'],
      'logged_in_with_rental': ['logged_in_with_rental'],
      'other': ['other']
    };

    return tagToProfileMap[tag]?.includes(this.id) || false;
  }

  /**
   * Add a node to this profile
   */
  addNode(nodeId: string): void {
    if (!this.nodeIds.includes(nodeId)) {
      this.nodeIds.push(nodeId);
    }
  }

  /**
   * Remove a node from this profile
   */
  removeNode(nodeId: string): void {
    const index = this.nodeIds.indexOf(nodeId);
    if (index > -1) {
      this.nodeIds.splice(index, 1);
    }
  }

  /**
   * Add a preferred entry edge
   */
  addPreferredEntryEdge(edgeId: string): void {
    if (!this.preferredEntryEdgeIds.includes(edgeId)) {
      this.preferredEntryEdgeIds.push(edgeId);
    }
  }

  /**
   * Remove a preferred entry edge
   */
  removePreferredEntryEdge(edgeId: string): void {
    const index = this.preferredEntryEdgeIds.indexOf(edgeId);
    if (index > -1) {
      this.preferredEntryEdgeIds.splice(index, 1);
    }
  }

  /**
   * Check if this profile has any nodes
   */
  hasNodes(): boolean {
    return this.nodeIds.length > 0;
  }

  /**
   * Check if this profile can support unlock policies
   */
  supportsUnlockPolicies(): boolean {
    return this.unlockPolicy !== 'n/a';
  }

  /**
   * Get the appropriate unlock policy for scooter selection
   */
  getUnlockPolicy(): 'any_available' | 'existing_rental_only' | null {
    return this.unlockPolicy === 'n/a' ? null : this.unlockPolicy;
  }

  /**
   * Update detector hints
   */
  updateDetectorHints(hints: Record<string, any>): void {
    this.detectorHints = { ...this.detectorHints, ...hints };
  }

  /**
   * Get profile summary information
   */
  getSummary(): {
    id: string;
    description: string;
    nodeCount: number;
    hasPreferredEdges: boolean;
    supportsUnlock: boolean;
    unlockPolicy: string;
  } {
    return {
      id: this.id,
      description: this.description,
      nodeCount: this.nodeIds.length,
      hasPreferredEdges: this.preferredEntryEdgeIds.length > 0,
      supportsUnlock: this.supportsUnlockPolicies(),
      unlockPolicy: this.unlockPolicy
    };
  }

  /**
   * Validate profile configuration
   */
  validate(): string[] {
    const errors: string[] = [];

    if (!this.id || this.id.trim().length === 0) {
      errors.push('Profile ID is required');
    }

    if (!this.description || this.description.trim().length === 0) {
      errors.push('Profile description is required');
    }

    if (this.nodeIds.length === 0) {
      errors.push('Profile must have at least one node');
    }

    // Validate unlock policy consistency
    if (this.id.includes('rental') && this.unlockPolicy === 'n/a') {
      errors.push('Rental profiles should specify unlock policy');
    }

    if (this.id === 'clean' && this.unlockPolicy !== 'n/a') {
      errors.push('Clean boot profile should not have unlock policy');
    }

    // Validate detector hints
    if (this.detectorHints.minimumNodes && this.nodeIds.length < this.detectorHints.minimumNodes) {
      errors.push(`Profile requires at least ${this.detectorHints.minimumNodes} nodes`);
    }

    return errors;
  }

  /**
   * Convert to plain object for storage
   */
  toJSON(): StartStateProfile {
    return {
      id: this.id,
      description: this.description,
      nodeIds: [...this.nodeIds],
      preferredEntryEdgeIds: [...this.preferredEntryEdgeIds],
      unlockPolicy: this.unlockPolicy,
      detectorHints: { ...this.detectorHints }
    };
  }

  /**
   * Create from plain object (from storage)
   */
  static fromJSON(data: StartStateProfile): StartStateProfileEntity {
    const entity = Object.create(StartStateProfileEntity.prototype);
    Object.assign(entity, data);
    return entity;
  }

  /**
   * Find profile by ID from a list of profiles
   */
  static findById(profiles: StartStateProfileEntity[], id: string): StartStateProfileEntity | null {
    return profiles.find(profile => profile.id === id) || null;
  }

  /**
   * Get profiles that support unlock policies
   */
  static getUnlockableProfiles(profiles: StartStateProfileEntity[]): StartStateProfileEntity[] {
    return profiles.filter(profile => profile.supportsUnlockPolicies());
  }

  /**
   * Get profiles that match node characteristics
   */
  static getMatchingProfiles(
    profiles: StartStateProfileEntity[],
    nodeCharacteristics: {
      activity?: string;
      texts?: string[];
      tag?: StartStateTag;
    }
  ): StartStateProfileEntity[] {
    return profiles.filter(profile => profile.matchesNode(nodeCharacteristics));
  }
}