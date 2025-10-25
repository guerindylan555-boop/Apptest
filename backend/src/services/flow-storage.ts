/**
 * Flow Storage Service (T045)
 *
 * Comprehensive persistent storage service for flow definitions with optimistic locking,
 * conflict resolution, versioning, search capabilities, template management, and analytics.
 *
 * Features:
 * - CRUD operations with validation and optimistic locking
 * - Flow versioning with change history and conflict resolution
 * - Full-text search and advanced filtering
 * - Template management with inheritance
 * - Backup/restore with point-in-time recovery
 * - Batch operations and bulk updates
 * - Performance optimization with caching
 * - Usage analytics and dependency tracking
 */

import { promises as fs } from 'fs';
import { join, resolve, dirname, basename } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { createHash, randomUUID } from 'crypto';
import {
  FlowDefinition,
  FlowTemplate,
  FlowValidationResult,
  CreateFlowRequest,
  UpdateFlowRequest,
  ListFlowsRequest,
  FlowExecutionResult
} from '../types/flow';
import {
  JsonStorageService,
  StorageResult,
  VersionMetadata,
  ConflictError,
  ValidationError,
  StorageError
} from './json-storage';
import { logger } from './logger';

// ============================================================================
// Core Service Types
// ============================================================================

export interface FlowStorageConfig {
  /** Root directory for flow storage */
  flowsRoot: string;

  /** Backup directory */
  backupRoot: string;

  /** Template directory */
  templatesRoot: string;

  /** Enable automatic backups */
  backupEnabled: boolean;

  /** Maximum backups to retain */
  maxBackups: number;

  /** Cache TTL in milliseconds */
  cacheTTL: number;

  /** Maximum cache size */
  maxCacheSize: number;

  /** Enable validation */
  validationEnabled: boolean;

  /** Analytics retention period (days) */
  analyticsRetentionDays: number;
}

export interface FlowMetadata extends VersionMetadata {
  /** Flow category */
  category?: string;

  /** Flow tags */
  tags: string[];

  /** Flow dependencies */
  dependencies: string[];

  /** Flow usage count */
  usageCount: number;

  /** Success rate */
  successRate: number;

  /** Average execution time */
  avgExecutionTime: number;

  /** Last execution timestamp */
  lastExecuted?: string;

  /** Flow size (bytes) */
  size: number;

  /** Checksum for integrity verification */
  checksum: string;
}

export interface FlowSearchResult {
  /** Matching flows */
  flows: Array<{
    flow: FlowDefinition;
    metadata: FlowMetadata;
    relevanceScore: number;
    matchedFields: string[];
  }>;

  /** Search metadata */
  total: number;
  took: number;
  facets: {
    categories: Record<string, number>;
    tags: Record<string, number>;
    authors: Record<string, number>;
  };
}

export interface FlowVersion {
  /** Version identifier */
  version: string;

  /** Flow definition at this version */
  flow: FlowDefinition;

  /** Version metadata */
  metadata: FlowMetadata;

  /** Changes from previous version */
  changes?: FlowChange[];

  /** Parent version */
  parentVersion?: string;

  /** Branch information */
  branch?: string;
}

export interface FlowChange {
  /** Change type */
  type: 'create' | 'update' | 'delete' | 'move';

  /** Changed field */
  field: string;

  /** Old value */
  oldValue?: any;

  /** New value */
  newValue?: any;

  /** Change timestamp */
  timestamp: string;

  /** Author of change */
  author: string;

  /** Change description */
  description?: string;
}

export interface FlowConflict {
  /** Conflict type */
  type: 'version' | 'content' | 'dependency' | 'metadata';

  /** Conflict description */
  description: string;

  /** Current version */
  current: {
    version: string;
    flow: FlowDefinition;
    metadata: FlowMetadata;
  };

  /** Incoming version */
  incoming: {
    version: string;
    flow: FlowDefinition;
    metadata: FlowMetadata;
  };

  /** Merge strategies available */
  strategies: Array<{
    name: string;
    description: string;
    risk: 'low' | 'medium' | 'high';
  }>;
}

export interface FlowBackup {
  /** Backup ID */
  id: string;

  /** Backup timestamp */
  timestamp: string;

  /** Backup type */
  type: 'manual' | 'auto' | 'migration';

  /** Flows included in backup */
  flows: Array<{
    flowId: string;
    version: string;
    name: string;
    metadata: FlowMetadata;
  }>;

  /** Backup size */
  size: number;

  /** Backup location */
  location: string;

  /** Backup checksum */
  checksum: string;

  /** Backup metadata */
  metadata: {
    createdBy: string;
    description?: string;
    tags?: string[];
  };
}

export interface FlowAnalytics {
  /** Analytics period */
  period: {
    start: string;
    end: string;
  };

  /** Flow usage statistics */
  usage: {
    totalExecutions: number;
    uniqueFlows: number;
    avgExecutionsPerFlow: number;
    mostUsedFlows: Array<{
      flowId: string;
      name: string;
      executions: number;
      successRate: number;
    }>;
  };

  /** Performance metrics */
  performance: {
    avgExecutionTime: number;
    fastestFlow: string;
    slowestFlow: string;
    reliabilityScores: Record<string, number>;
  };

  /** User behavior */
  behavior: {
    mostActiveAuthors: Array<{
      author: string;
      flowCount: number;
      executions: number;
    }>;
    popularCategories: Record<string, number>;
    popularTags: Record<string, number>;
  };

  /** System health */
  health: {
    totalFlows: number;
    totalTemplates: number;
    storageSize: number;
    backupSize: number;
    errors: number;
  };
}

export interface BatchOperation {
  /** Operation ID */
  id: string;

  /** Operation type */
  type: 'create' | 'update' | 'delete' | 'restore';

  /** Target flow IDs */
  flowIds: string[];

  /** Operation data */
  data?: any;

  /** Operation status */
  status: 'pending' | 'running' | 'completed' | 'failed' | 'partial';

  /** Progress tracking */
  progress: {
    total: number;
    completed: number;
    failed: number;
  };

  /** Operation results */
  results: Array<{
    flowId: string;
    success: boolean;
    error?: string;
    metadata?: FlowMetadata;
  }>;

  /** Operation metadata */
  metadata: {
    createdAt: string;
    startedAt?: string;
    completedAt?: string;
    createdBy: string;
    description?: string;
  };
}

// ============================================================================
// Flow Storage Service Implementation
// ============================================================================

export class FlowStorageService {
  private jsonStorage: JsonStorageService;
  private config: FlowStorageConfig;
  private cache = new Map<string, { data: any; timestamp: number; ttl: number }>();
  private searchIndex = new Map<string, Set<string>>();
  private analytics: Map<string, FlowExecutionResult[]> = new Map();

  constructor(config?: Partial<FlowStorageConfig>) {
    this.config = {
      flowsRoot: process.env.FLOW_ROOT || resolve(process.cwd(), 'var/autoapp/flows'),
      backupRoot: process.env.FLOW_BACKUP_ROOT || resolve(process.cwd(), 'var/autoapp/backups/flows'),
      templatesRoot: process.env.FLOW_TEMPLATES_ROOT || resolve(process.cwd(), 'var/autoapp/templates'),
      backupEnabled: process.env.FLOW_BACKUP_ENABLED !== 'false',
      maxBackups: parseInt(process.env.FLOW_MAX_BACKUPS || '20'),
      cacheTTL: parseInt(process.env.FLOW_CACHE_TTL || '300000'), // 5 minutes
      maxCacheSize: parseInt(process.env.FLOW_MAX_CACHE_SIZE || '1000'),
      validationEnabled: process.env.FLOW_VALIDATION_ENABLED !== 'false',
      analyticsRetentionDays: parseInt(process.env.FLOW_ANALYTICS_RETENTION_DAYS || '90'),
      ...config
    };

    this.jsonStorage = new JsonStorageService();
    this.ensureDirectories();
    this.initializeSearchIndex();
    this.startMaintenanceTasks();
  }

  // ============================================================================
  // Initialization and Directory Management
  // ============================================================================

  private ensureDirectories(): void {
    const dirs = [
      this.config.flowsRoot,
      this.config.backupRoot,
      this.config.templatesRoot,
      join(this.config.flowsRoot, 'versions'),
      join(this.config.flowsRoot, 'metadata'),
      join(this.config.flowsRoot, 'analytics'),
      join(this.config.backupRoot, 'manual'),
      join(this.config.backupRoot, 'auto'),
      join(this.config.backupRoot, 'migration')
    ];

    dirs.forEach(dir => {
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
        logger.info('Created flow storage directory', { directory: dir, service: 'flow-storage' });
      }
    });
  }

  private async initializeSearchIndex(): Promise<void> {
    try {
      const flows = await this.listAllFlows();

      // Clear existing index
      this.searchIndex.clear();

      // Build search index
      for (const flow of flows) {
        const indexableText = this.extractIndexableText(flow.flow);
        const tokens = this.tokenizeText(indexableText);

        for (const token of tokens) {
          if (!this.searchIndex.has(token)) {
            this.searchIndex.set(token, new Set());
          }
          this.searchIndex.get(token)!.add(flow.flow.id);
        }
      }

      logger.info('Search index initialized', {
        totalFlows: flows.length,
        totalTokens: this.searchIndex.size,
        service: 'flow-storage'
      });
    } catch (error) {
      logger.error('Failed to initialize search index', { error, service: 'flow-storage' });
    }
  }

  private startMaintenanceTasks(): void {
    // Cleanup expired cache entries
    setInterval(() => {
      this.cleanupCache();
    }, this.config.cacheTTL);

    // Cleanup old analytics data
    setInterval(() => {
      this.cleanupAnalytics();
    }, 24 * 60 * 60 * 1000); // Daily

    // Optimize search index
    setInterval(() => {
      this.optimizeSearchIndex();
    }, 60 * 60 * 1000); // Hourly
  }

  // ============================================================================
  // Core CRUD Operations
  // ============================================================================

  async createFlow(request: CreateFlowRequest, userId: string = 'system'): Promise<{
    flow: FlowDefinition;
    metadata: FlowMetadata;
    validation?: FlowValidationResult;
  }> {
    const startTime = Date.now();

    try {
      logger.info('Creating flow', {
        name: request.flow.name,
        packageName: request.flow.packageName,
        userId,
        service: 'flow-storage'
      });

      // Validate flow definition
      if (this.config.validationEnabled && request.validate !== false) {
        const validation = await this.validateFlow(request.flow as FlowDefinition);
        if (!validation.isValid) {
          throw new ValidationError(`Flow validation failed: ${validation.errors.map(e => e.message).join(', ')}`);
        }
      }

      // Generate flow ID if not provided
      const flowId = request.flow.id || this.generateFlowId();
      const flow: FlowDefinition = {
        ...request.flow,
        id: flowId,
        metadata: {
          ...request.flow.metadata,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          author: request.flow.metadata?.author || userId
        }
      };

      // Calculate flow metadata
      const metadata = await this.calculateFlowMetadata(flow, userId);

      // Store flow
      const filePath = `${flow.packageName}/${flowId}.json`;
      const storageResult = await this.jsonStorage.create(filePath, flow, {
        includeMetadata: true,
        createdBy: userId,
        comment: 'Initial flow creation'
      });

      // Store extended metadata
      await this.storeFlowMetadata(flowId, metadata);

      // Update search index
      await this.updateSearchIndex(flow, 'create');

      // Cache the flow
      this.cacheFlow(flowId, flow);

      // Track analytics
      this.trackFlowEvent(flowId, 'created', { userId });

      const duration = Date.now() - startTime;
      logger.info('Flow created successfully', {
        flowId,
        name: flow.name,
        packageName: flow.packageName,
        version: metadata.version,
        duration,
        service: 'flow-storage'
      });

      return {
        flow,
        metadata
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Failed to create flow', {
        error: error instanceof Error ? error.message : error,
        duration,
        service: 'flow-storage'
      });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to create flow: ${error}`,
        'CREATE_ERROR'
      );
    }
  }

  async getFlow(flowId: string, packageName?: string): Promise<{
    flow: FlowDefinition;
    metadata: FlowMetadata;
  }> {
    const startTime = Date.now();

    try {
      // Check cache first
      const cached = this.getCachedFlow(flowId);
      if (cached) {
        const metadata = await this.getFlowMetadata(flowId);
        return { flow: cached, metadata: metadata! };
      }

      // Determine file path
      let filePath: string;
      if (packageName) {
        filePath = `${packageName}/${flowId}.json`;
      } else {
        // Search for flow in all packages
        filePath = await this.findFlowPath(flowId);
      }

      if (!filePath) {
        throw new StorageError(`Flow not found: ${flowId}`, 'NOT_FOUND');
      }

      // Read from storage
      const storageResult = await this.jsonStorage.read<FlowDefinition>(filePath);
      const metadata = await this.getFlowMetadata(flowId);

      if (!metadata) {
        // Generate metadata if missing
        const calculatedMetadata = await this.calculateFlowMetadata(storageResult.data);
        await this.storeFlowMetadata(flowId, calculatedMetadata);
      }

      // Cache the flow
      this.cacheFlow(flowId, storageResult.data);

      const duration = Date.now() - startTime;
      logger.debug('Flow retrieved', {
        flowId,
        filePath,
        version: metadata?.version,
        duration,
        service: 'flow-storage'
      });

      return {
        flow: storageResult.data,
        metadata: metadata || await this.calculateFlowMetadata(storageResult.data)
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Failed to get flow', {
        flowId,
        error: error instanceof Error ? error.message : error,
        duration,
        service: 'flow-storage'
      });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to get flow: ${error}`,
        'READ_ERROR'
      );
    }
  }

  async updateFlow(request: UpdateFlowRequest, userId: string = 'system'): Promise<{
    flow: FlowDefinition;
    metadata: FlowMetadata;
    changes: FlowChange[];
    conflicts?: FlowConflict[];
  }> {
    const startTime = Date.now();

    try {
      logger.info('Updating flow', {
        flowId: request.flowId,
        userId,
        strategy: request.mergeStrategy,
        service: 'flow-storage'
      });

      // Get current flow
      const current = await this.getFlow(request.flowId);

      // Detect conflicts
      const conflicts = await this.detectConflicts(current, request);
      if (conflicts.length > 0 && request.mergeStrategy !== 'force') {
        logger.warn('Flow update conflicts detected', {
          flowId: request.flowId,
          conflictCount: conflicts.length,
          service: 'flow-storage'
        });
        return {
          flow: current.flow,
          metadata: current.metadata,
          changes: [],
          conflicts
        };
      }

      // Apply changes based on merge strategy
      const { updatedFlow, changes } = await this.applyMergeStrategy(
        current.flow,
        request.flow,
        request.mergeStrategy || 'merge',
        userId
      );

      // Update timestamps
      updatedFlow.metadata = {
        ...updatedFlow.metadata,
        updatedAt: new Date().toISOString()
      };

      // Calculate new metadata
      const updatedMetadata = await this.calculateFlowMetadata(updatedFlow, userId);

      // Store updated flow
      const filePath = await this.findFlowPath(request.flowId);
      if (!filePath) {
        throw new StorageError(`Flow not found: ${request.flowId}`, 'NOT_FOUND');
      }

      await this.jsonStorage.update(filePath, updatedFlow, {
        expectedVersion: current.metadata.version,
        updatedBy: userId,
        comment: `Flow update via ${request.mergeStrategy} strategy`
      });

      // Store updated metadata
      await this.storeFlowMetadata(request.flowId, updatedMetadata);

      // Update search index
      await this.updateSearchIndex(updatedFlow, 'update');

      // Update cache
      this.cacheFlow(request.flowId, updatedFlow);

      // Store version history
      await this.storeFlowVersion(request.flowId, updatedFlow, updatedMetadata, changes);

      // Track analytics
      this.trackFlowEvent(request.flowId, 'updated', { userId, changes: changes.length });

      const duration = Date.now() - startTime;
      logger.info('Flow updated successfully', {
        flowId: request.flowId,
        version: updatedMetadata.version,
        changesCount: changes.length,
        duration,
        service: 'flow-storage'
      });

      return {
        flow: updatedFlow,
        metadata: updatedMetadata,
        changes
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Failed to update flow', {
        flowId: request.flowId,
        error: error instanceof Error ? error.message : error,
        duration,
        service: 'flow-storage'
      });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to update flow: ${error}`,
        'UPDATE_ERROR'
      );
    }
  }

  async deleteFlow(flowId: string, expectedVersion?: string, userId: string = 'system'): Promise<{
    success: boolean;
    metadata: FlowMetadata;
  }> {
    const startTime = Date.now();

    try {
      logger.info('Deleting flow', {
        flowId,
        expectedVersion,
        userId,
        service: 'flow-storage'
      });

      // Get current flow
      const current = await this.getFlow(flowId);

      // Create backup before deletion
      if (this.config.backupEnabled) {
        await this.createFlowBackup(flowId, 'manual', `Flow deletion: ${flowId}`, userId);
      }

      // Delete from storage
      const filePath = await this.findFlowPath(flowId);
      if (!filePath) {
        throw new StorageError(`Flow not found: ${flowId}`, 'NOT_FOUND');
      }

      await this.jsonStorage.delete(filePath, {
        expectedVersion: expectedVersion || current.metadata.version,
        deletedBy: userId,
        reason: 'Flow deletion'
      });

      // Delete metadata
      await this.deleteFlowMetadata(flowId);

      // Remove from cache
      this.cache.delete(flowId);

      // Update search index
      await this.updateSearchIndex(current.flow, 'delete');

      // Track analytics
      this.trackFlowEvent(flowId, 'deleted', { userId });

      const duration = Date.now() - startTime;
      logger.info('Flow deleted successfully', {
        flowId,
        version: current.metadata.version,
        duration,
        service: 'flow-storage'
      });

      return {
        success: true,
        metadata: current.metadata
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Failed to delete flow', {
        flowId,
        error: error instanceof Error ? error.message : error,
        duration,
        service: 'flow-storage'
      });
      throw error instanceof StorageError ? error : new StorageError(
        `Failed to delete flow: ${error}`,
        'DELETE_ERROR'
      );
    }
  }

  // ============================================================================
  // Flow Search and Discovery
  // ============================================================================

  async searchFlows(query: string, options: {
    limit?: number;
    offset?: number;
    filters?: {
      packageName?: string;
      category?: string;
      tags?: string[];
      author?: string;
      dateRange?: {
        start: string;
        end: string;
      };
    };
    sort?: {
      field: 'name' | 'createdAt' | 'updatedAt' | 'usageCount' | 'successRate';
      order: 'asc' | 'desc';
    };
  } = {}): Promise<FlowSearchResult> {
    const startTime = Date.now();

    try {
      const {
        limit = 50,
        offset = 0,
        filters = {},
        sort = { field: 'updatedAt', order: 'desc' }
      } = options;

      logger.debug('Searching flows', {
        query,
        limit,
        offset,
        filters,
        sort,
        service: 'flow-storage'
      });

      // Tokenize search query
      const queryTokens = this.tokenizeText(query);

      // Find matching flow IDs
      const matchingFlowIds = new Set<string>();
      const tokenMatches = new Map<string, Set<string>>();

      for (const token of queryTokens) {
        const matches = this.searchIndex.get(token);
        if (matches) {
          matchingFlowIds.add(...matches);
          tokenMatches.set(token, matches);
        }
      }

      // Get flow details and calculate relevance scores
      const matchedFlows: Array<{
        flow: FlowDefinition;
        metadata: FlowMetadata;
        relevanceScore: number;
        matchedFields: string[];
      }> = [];

      for (const flowId of matchingFlowIds) {
        try {
          const { flow, metadata } = await this.getFlow(flowId);

          // Apply filters
          if (filters.packageName && flow.packageName !== filters.packageName) continue;
          if (filters.category && metadata.category !== filters.category) continue;
          if (filters.author && flow.metadata.author !== filters.author) continue;
          if (filters.tags && !filters.tags.some(tag => metadata.tags.includes(tag))) continue;
          if (filters.dateRange) {
            const updatedAt = new Date(flow.metadata.updatedAt);
            const start = new Date(filters.dateRange.start);
            const end = new Date(filters.dateRange.end);
            if (updatedAt < start || updatedAt > end) continue;
          }

          // Calculate relevance score
          const { score, matchedFields } = this.calculateRelevanceScore(
            flow,
            metadata,
            queryTokens,
            tokenMatches
          );

          matchedFlows.push({
            flow,
            metadata,
            relevanceScore: score,
            matchedFields
          });

        } catch (error) {
          logger.warn('Failed to load flow for search', {
            flowId,
            error: error instanceof Error ? error.message : error,
            service: 'flow-storage'
          });
        }
      }

      // Sort results
      matchedFlows.sort((a, b) => {
        // Primary sort by relevance score
        if (b.relevanceScore !== a.relevanceScore) {
          return b.relevanceScore - a.relevanceScore;
        }

        // Secondary sort by specified field
        const aValue = this.getSortValue(a.flow, a.metadata, sort.field);
        const bValue = this.getSortValue(b.flow, b.metadata, sort.field);

        if (aValue !== bValue) {
          return sort.order === 'asc' ? aValue - bValue : bValue - aValue;
        }

        return 0;
      });

      // Apply pagination
      const startIndex = offset;
      const endIndex = startIndex + limit;
      const paginatedResults = matchedFlows.slice(startIndex, endIndex);

      // Calculate facets
      const facets = await this.calculateFacets(matchedFlows);

      const duration = Date.now() - startTime;
      logger.debug('Flow search completed', {
        query,
        totalMatches: matchedFlows.length,
        returned: paginatedResults.length,
        duration,
        service: 'flow-storage'
      });

      return {
        flows: paginatedResults,
        total: matchedFlows.length,
        took: duration,
        facets
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Flow search failed', {
        query,
        error: error instanceof Error ? error.message : error,
        duration,
        service: 'flow-storage'
      });
      throw new StorageError(`Flow search failed: ${error}`, 'SEARCH_ERROR');
    }
  }

  async listFlows(request: ListFlowsRequest): Promise<{
    flows: FlowDefinition[];
    total: number;
    facets: {
      packages: Record<string, number>;
      categories: Record<string, number>;
      tags: Record<string, number>;
      authors: Record<string, number>;
    };
  }> {
    const startTime = Date.now();

    try {
      logger.debug('Listing flows', {
        filter: request.filter,
        sort: request.sort,
        pagination: request.pagination,
        service: 'flow-storage'
      });

      // Get all flows
      const allFlows = await this.listAllFlows();

      // Apply filters
      let filteredFlows = allFlows;

      if (request.filter) {
        filteredFlows = allFlows.filter(item => {
          const { flow, metadata } = item;

          if (request.filter!.package && flow.packageName !== request.filter!.package) {
            return false;
          }

          if (request.filter!.tags && !request.filter!.tags.some(tag => metadata.tags.includes(tag))) {
            return false;
          }

          if (request.filter!.author && flow.metadata.author !== request.filter!.author) {
            return false;
          }

          if (request.filter!.complexity) {
            const complexity = metadata.complexity || 0;
            if (request.filter!.complexity.min !== undefined && complexity < request.filter!.complexity.min) {
              return false;
            }
            if (request.filter!.complexity.max !== undefined && complexity > request.filter!.complexity.max) {
              return false;
            }
          }

          if (request.filter!.search) {
            const searchText = `${flow.name} ${flow.description || ''} ${metadata.tags.join(' ')}`.toLowerCase();
            if (!searchText.includes(request.filter!.search!.toLowerCase())) {
              return false;
            }
          }

          return true;
        });
      }

      // Sort flows
      const sortField = request.sort?.field || 'updatedAt';
      const sortOrder = request.sort?.order || 'desc';

      filteredFlows.sort((a, b) => {
        const aValue = this.getSortValue(a.flow, a.metadata, sortField);
        const bValue = this.getSortValue(b.flow, b.metadata, sortField);
        return sortOrder === 'asc' ? aValue - bValue : bValue - aValue;
      });

      // Apply pagination
      const page = request.pagination?.page || 1;
      const limit = request.pagination?.limit || 50;
      const startIndex = (page - 1) * limit;
      const endIndex = startIndex + limit;
      const paginatedFlows = filteredFlows.slice(startIndex, endIndex);

      // Calculate facets
      const facets = await this.calculateFacets(filteredFlows);

      const duration = Date.now() - startTime;
      logger.debug('Flow listing completed', {
        total: filteredFlows.length,
        returned: paginatedFlows.length,
        page,
        limit,
        duration,
        service: 'flow-storage'
      });

      return {
        flows: paginatedFlows.map(item => item.flow),
        total: filteredFlows.length,
        facets: {
          packages: facets.packages || {},
          categories: facets.categories || {},
          tags: facets.tags || {},
          authors: facets.authors || {}
        }
      };

    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error('Flow listing failed', {
        error: error instanceof Error ? error.message : error,
        duration,
        service: 'flow-storage'
      });
      throw new StorageError(`Flow listing failed: ${error}`, 'LIST_ERROR');
    }
  }

  // ============================================================================
  // Flow Versioning and History
  // ============================================================================

  async getFlowVersions(flowId: string): Promise<FlowVersion[]> {
    try {
      const versionsDir = join(this.config.flowsRoot, 'versions', flowId);

      if (!existsSync(versionsDir)) {
        return [];
      }

      const versionFiles = await fs.readdir(versionsDir);
      const versions: FlowVersion[] = [];

      for (const file of versionFiles.sort()) {
        if (file.endsWith('.json')) {
          try {
            const versionPath = join(versionsDir, file);
            const content = await fs.readFile(versionPath, 'utf-8');
            const versionData = JSON.parse(content);
            versions.push(versionData);
          } catch (error) {
            logger.warn('Failed to load flow version', {
              flowId,
              file,
              error: error instanceof Error ? error.message : error,
              service: 'flow-storage'
            });
          }
        }
      }

      return versions.sort((a, b) =>
        new Date(b.metadata.lastModified).getTime() - new Date(a.metadata.lastModified).getTime()
      );

    } catch (error) {
      logger.error('Failed to get flow versions', {
        flowId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      throw new StorageError(`Failed to get flow versions: ${error}`, 'VERSION_ERROR');
    }
  }

  async restoreFlowVersion(flowId: string, version: string, userId: string = 'system'): Promise<{
    flow: FlowDefinition;
    metadata: FlowMetadata;
  }> {
    try {
      logger.info('Restoring flow version', {
        flowId,
        version,
        userId,
        service: 'flow-storage'
      });

      // Get version data
      const versionData = await this.getFlowVersion(flowId, version);
      if (!versionData) {
        throw new StorageError(`Version not found: ${version}`, 'NOT_FOUND');
      }

      // Get current flow for backup
      try {
        const current = await this.getFlow(flowId);
        await this.createFlowBackup(flowId, 'auto', `Pre-restore backup: ${version}`, userId);
      } catch (error) {
        // Flow might not exist, continue with restore
      }

      // Restore flow
      const restoredFlow = {
        ...versionData.flow,
        metadata: {
          ...versionData.flow.metadata,
          updatedAt: new Date().toISOString(),
          restoredFrom: version,
          restoredBy: userId
        }
      };

      const metadata = await this.calculateFlowMetadata(restoredFlow, userId);

      // Store restored flow
      const filePath = await this.findFlowPath(flowId) || `${restoredFlow.packageName}/${flowId}.json`;

      try {
        await this.jsonStorage.update(filePath, restoredFlow, {
          expectedVersion: version,
          updatedBy: userId,
          comment: `Restored from version ${version}`
        });
      } catch (error) {
        // Flow might not exist, create it
        await this.jsonStorage.create(filePath, restoredFlow, {
          createdBy: userId,
          comment: `Restored from version ${version}`
        });
      }

      await this.storeFlowMetadata(flowId, metadata);
      await this.updateSearchIndex(restoredFlow, 'update');
      this.cacheFlow(flowId, restoredFlow);

      // Track analytics
      this.trackFlowEvent(flowId, 'restored', { userId, fromVersion: version });

      logger.info('Flow version restored successfully', {
        flowId,
        fromVersion: version,
        newVersion: metadata.version,
        service: 'flow-storage'
      });

      return {
        flow: restoredFlow,
        metadata
      };

    } catch (error) {
      logger.error('Failed to restore flow version', {
        flowId,
        version,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      throw new StorageError(`Failed to restore flow version: ${error}`, 'RESTORE_ERROR');
    }
  }

  // ============================================================================
  // Flow Template Management
  // ============================================================================

  async createTemplate(template: FlowTemplate, userId: string = 'system'): Promise<{
    template: FlowTemplate;
  }> {
    try {
      logger.info('Creating flow template', {
        templateId: template.id,
        name: template.name,
        category: template.category,
        userId,
        service: 'flow-storage'
      });

      // Validate template
      await this.validateTemplate(template);

      // Store template
      const templatePath = join(this.config.templatesRoot, `${template.id}.json`);
      await fs.writeFile(templatePath, JSON.stringify(template, null, 2));

      logger.info('Flow template created successfully', {
        templateId: template.id,
        service: 'flow-storage'
      });

      return { template };

    } catch (error) {
      logger.error('Failed to create flow template', {
        templateId: template.id,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      throw new StorageError(`Failed to create flow template: ${error}`, 'TEMPLATE_ERROR');
    }
  }

  async getTemplate(templateId: string): Promise<FlowTemplate | null> {
    try {
      const templatePath = join(this.config.templatesRoot, `${templateId}.json`);

      if (!existsSync(templatePath)) {
        return null;
      }

      const content = await fs.readFile(templatePath, 'utf-8');
      const template = JSON.parse(content) as FlowTemplate;

      return template;

    } catch (error) {
      logger.error('Failed to get flow template', {
        templateId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      return null;
    }
  }

  async listTemplates(category?: string): Promise<FlowTemplate[]> {
    try {
      const templateFiles = await fs.readdir(this.config.templatesRoot);
      const templates: FlowTemplate[] = [];

      for (const file of templateFiles) {
        if (file.endsWith('.json')) {
          try {
            const templatePath = join(this.config.templatesRoot, file);
            const content = await fs.readFile(templatePath, 'utf-8');
            const template = JSON.parse(content) as FlowTemplate;

            if (!category || template.category === category) {
              templates.push(template);
            }
          } catch (error) {
            logger.warn('Failed to load template', {
              file,
              error: error instanceof Error ? error.message : error,
              service: 'flow-storage'
            });
          }
        }
      }

      return templates.sort((a, b) => a.name.localeCompare(b.name));

    } catch (error) {
      logger.error('Failed to list flow templates', {
        category,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      return [];
    }
  }

  async createFlowFromTemplate(
    templateId: string,
    parameters: Record<string, any>,
    flowData: {
      name: string;
      description?: string;
      packageName: string;
    },
    userId: string = 'system'
  ): Promise<{
    flow: FlowDefinition;
    metadata: FlowMetadata;
  }> {
    try {
      logger.info('Creating flow from template', {
        templateId,
        flowName: flowData.name,
        packageName: flowData.packageName,
        userId,
        service: 'flow-storage'
      });

      // Get template
      const template = await this.getTemplate(templateId);
      if (!template) {
        throw new StorageError(`Template not found: ${templateId}`, 'NOT_FOUND');
      }

      // Validate parameters
      await this.validateTemplateParameters(template, parameters);

      // Apply template parameters
      const flow = await this.applyTemplateParameters(template, parameters, flowData, userId);

      // Create flow
      const result = await this.createFlow({ flow }, userId);

      // Update template usage
      template.metadata.usage = (template.metadata.usage || 0) + 1;
      await this.createTemplate(template, userId);

      logger.info('Flow created from template successfully', {
        flowId: result.flow.id,
        templateId,
        service: 'flow-storage'
      });

      return result;

    } catch (error) {
      logger.error('Failed to create flow from template', {
        templateId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      throw new StorageError(`Failed to create flow from template: ${error}`, 'TEMPLATE_ERROR');
    }
  }

  // ============================================================================
  // Backup and Restore Operations
  // ============================================================================

  async createBackup(
    backupType: 'manual' | 'auto' = 'manual',
    description?: string,
    userId: string = 'system'
  ): Promise<FlowBackup> {
    try {
      logger.info('Creating flow backup', {
        backupType,
        description,
        userId,
        service: 'flow-storage'
      });

      const backupId = this.generateBackupId();
      const timestamp = new Date().toISOString();

      // Get all flows
      const allFlows = await this.listAllFlows();

      // Create backup data
      const backupData = {
        id: backupId,
        timestamp,
        type: backupType,
        flows: allFlows.map(item => ({
          flowId: item.flow.id,
          version: item.metadata.version,
          name: item.flow.name,
          metadata: item.metadata,
          data: item.flow
        })),
        metadata: {
          createdBy: userId,
          description,
          totalFlows: allFlows.length
        }
      };

      // Calculate backup size and checksum
      const backupJson = JSON.stringify(backupData, null, 2);
      const size = Buffer.byteLength(backupJson, 'utf8');
      const checksum = createHash('sha256').update(backupJson).digest('hex');

      // Determine backup location
      const backupDir = join(this.config.backupRoot, backupType);
      const backupPath = join(backupDir, `${backupId}.json`);

      // Write backup file
      await fs.writeFile(backupPath, backupJson);

      // Create backup metadata
      const backup: FlowBackup = {
        id: backupId,
        timestamp,
        type: backupType,
        flows: backupData.flows.map(f => ({
          flowId: f.flowId,
          version: f.version,
          name: f.name,
          metadata: f.metadata
        })),
        size,
        location: backupPath,
        checksum,
        metadata: {
          createdBy: userId,
          description,
          tags: [backupType]
        }
      };

      // Store backup metadata
      const metadataPath = join(backupDir, `${backupId}.meta.json`);
      await fs.writeFile(metadataPath, JSON.stringify(backup, null, 2));

      // Cleanup old backups
      await this.cleanupOldBackups(backupType);

      logger.info('Flow backup created successfully', {
        backupId,
        backupType,
        totalFlows: backupData.flows.length,
        size,
        service: 'flow-storage'
      });

      return backup;

    } catch (error) {
      logger.error('Failed to create flow backup', {
        backupType,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      throw new StorageError(`Failed to create flow backup: ${error}`, 'BACKUP_ERROR');
    }
  }

  async restoreBackup(backupId: string, options: {
    overwriteExisting?: boolean;
    includeFlows?: string[];
    excludeFlows?: string[];
  } = {}, userId: string = 'system'): Promise<{
    restoredFlows: string[];
    skippedFlows: string[];
    errors: string[];
  }> {
    try {
      logger.info('Restoring flow backup', {
        backupId,
        options,
        userId,
        service: 'flow-storage'
      });

      // Load backup
      const backupPath = join(this.config.backupRoot, 'manual', `${backupId}.json`);
      if (!existsSync(backupPath)) {
        // Try other backup types
        for (const type of ['auto', 'migration']) {
          const altPath = join(this.config.backupRoot, type, `${backupId}.json`);
          if (existsSync(altPath)) {
            backupPath.replace('manual', type);
            break;
          }
        }
      }

      if (!existsSync(backupPath)) {
        throw new StorageError(`Backup not found: ${backupId}`, 'NOT_FOUND');
      }

      const backupData = JSON.parse(await fs.readFile(backupPath, 'utf-8'));

      // Filter flows based on options
      let flowsToRestore = backupData.flows;

      if (options.includeFlows) {
        flowsToRestore = flowsToRestore.filter(f => options.includeFlows!.includes(f.flowId));
      }

      if (options.excludeFlows) {
        flowsToRestore = flowsToRestore.filter(f => !options.excludeFlows!.includes(f.flowId));
      }

      const restoredFlows: string[] = [];
      const skippedFlows: string[] = [];
      const errors: string[] = [];

      // Restore flows
      for (const flowData of flowsToRestore) {
        try {
          // Check if flow already exists
          const existingPath = `${flowData.data.packageName}/${flowData.flowId}.json`;

          if (!options.overwriteExisting) {
            try {
              await this.jsonStorage.read(existingPath);
              skippedFlows.push(flowData.flowId);
              continue;
            } catch (error) {
              // Flow doesn't exist, can restore
            }
          }

          // Restore flow
          await this.jsonStorage.create(existingPath, flowData.data, {
            overwrite: true,
            createdBy: userId,
            comment: `Restored from backup ${backupId}`
          });

          // Restore metadata
          await this.storeFlowMetadata(flowData.flowId, flowData.metadata);

          // Update search index
          await this.updateSearchIndex(flowData.data, 'create');

          restoredFlows.push(flowData.flowId);

        } catch (error) {
          const errorMsg = `Failed to restore flow ${flowData.flowId}: ${error}`;
          logger.error(errorMsg, { service: 'flow-storage' });
          errors.push(errorMsg);
        }
      }

      logger.info('Flow backup restore completed', {
        backupId,
        restored: restoredFlows.length,
        skipped: skippedFlows.length,
        errors: errors.length,
        service: 'flow-storage'
      });

      return {
        restoredFlows,
        skippedFlows,
        errors
      };

    } catch (error) {
      logger.error('Failed to restore flow backup', {
        backupId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      throw new StorageError(`Failed to restore flow backup: ${error}`, 'RESTORE_ERROR');
    }
  }

  async listBackups(backupType?: 'manual' | 'auto' | 'migration'): Promise<FlowBackup[]> {
    try {
      const backups: FlowBackup[] = [];
      const types = backupType ? [backupType] : ['manual', 'auto', 'migration'];

      for (const type of types) {
        const backupDir = join(this.config.backupRoot, type);

        if (!existsSync(backupDir)) {
          continue;
        }

        const metadataFiles = await fs.readdir(backupDir);

        for (const file of metadataFiles) {
          if (file.endsWith('.meta.json')) {
            try {
              const metadataPath = join(backupDir, file);
              const content = await fs.readFile(metadataPath, 'utf-8');
              const backup = JSON.parse(content) as FlowBackup;
              backups.push(backup);
            } catch (error) {
              logger.warn('Failed to load backup metadata', {
                file,
                error: error instanceof Error ? error.message : error,
                service: 'flow-storage'
              });
            }
          }
        }
      }

      return backups.sort((a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );

    } catch (error) {
      logger.error('Failed to list flow backups', {
        backupType,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      return [];
    }
  }

  // ============================================================================
  // Batch Operations
  // ============================================================================

  async createBatchOperation(
    operation: Omit<BatchOperation, 'id' | 'status' | 'progress' | 'results' | 'metadata'>,
    userId: string = 'system'
  ): Promise<BatchOperation> {
    const batchOperation: BatchOperation = {
      ...operation,
      id: this.generateBatchId(),
      status: 'pending',
      progress: {
        total: operation.flowIds.length,
        completed: 0,
        failed: 0
      },
      results: [],
      metadata: {
        createdAt: new Date().toISOString(),
        createdBy: userId,
        description: operation.data?.description
      }
    };

    // Start batch operation in background
    this.executeBatchOperation(batchOperation).catch(error => {
      logger.error('Batch operation failed', {
        operationId: batchOperation.id,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
    });

    return batchOperation;
  }

  async getBatchOperation(operationId: string): Promise<BatchOperation | null> {
    try {
      const operationPath = join(this.config.flowsRoot, 'batch', `${operationId}.json`);

      if (!existsSync(operationPath)) {
        return null;
      }

      const content = await fs.readFile(operationPath, 'utf-8');
      return JSON.parse(content) as BatchOperation;

    } catch (error) {
      logger.error('Failed to get batch operation', {
        operationId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      return null;
    }
  }

  // ============================================================================
  // Analytics and Statistics
  // ============================================================================

  async getFlowAnalytics(period?: {
    start: string;
    end: string;
  }): Promise<FlowAnalytics> {
    try {
      const defaultPeriod = {
        start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days ago
        end: new Date().toISOString()
      };

      const analyticsPeriod = period || defaultPeriod;

      // Get all flows
      const allFlows = await this.listAllFlows();

      // Calculate usage statistics
      const usage = {
        totalExecutions: 0,
        uniqueFlows: allFlows.length,
        avgExecutionsPerFlow: 0,
        mostUsedFlows: this.calculateMostUsedFlows(allFlows)
      };

      usage.totalExecutions = usage.mostUsedFlows.reduce((sum, flow) => sum + flow.executions, 0);
      usage.avgExecutionsPerFlow = usage.uniqueFlows > 0 ? usage.totalExecutions / usage.uniqueFlows : 0;

      // Calculate performance metrics
      const performance = {
        avgExecutionTime: this.calculateAvgExecutionTime(allFlows),
        fastestFlow: '',
        slowestFlow: '',
        reliabilityScores: this.calculateReliabilityScores(allFlows)
      };

      // Calculate user behavior
      const behavior = {
        mostActiveAuthors: this.calculateMostActiveAuthors(allFlows),
        popularCategories: this.calculatePopularCategories(allFlows),
        popularTags: this.calculatePopularTags(allFlows)
      };

      // Calculate system health
      const health = await this.calculateSystemHealth();

      return {
        period: analyticsPeriod,
        usage,
        performance,
        behavior,
        health
      };

    } catch (error) {
      logger.error('Failed to get flow analytics', {
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      throw new StorageError(`Failed to get flow analytics: ${error}`, 'ANALYTICS_ERROR');
    }
  }

  async trackFlowExecution(flowId: string, executionResult: FlowExecutionResult): Promise<void> {
    try {
      // Store execution result
      if (!this.analytics.has(flowId)) {
        this.analytics.set(flowId, []);
      }

      const executions = this.analytics.get(flowId)!;
      executions.push(executionResult);

      // Keep only recent executions
      const retentionLimit = this.config.analyticsRetentionDays * 24 * 60 * 60 * 1000;
      const cutoffTime = Date.now() - retentionLimit;

      const filteredExecutions = executions.filter(
        exec => new Date(exec.completedAt).getTime() > cutoffTime
      );

      this.analytics.set(flowId, filteredExecutions);

      // Update flow metadata with execution stats
      const { metadata } = await this.getFlow(flowId);

      const successCount = filteredExecutions.filter(exec => exec.status === 'completed').length;
      const newSuccessRate = filteredExecutions.length > 0 ? successCount / filteredExecutions.length : 0;
      const avgDuration = filteredExecutions.length > 0
        ? filteredExecutions.reduce((sum, exec) => sum + exec.duration, 0) / filteredExecutions.length
        : 0;

      // Update metadata
      const updatedMetadata = {
        ...metadata,
        usageCount: metadata.usageCount + 1,
        successRate: newSuccessRate,
        avgExecutionTime: avgDuration,
        lastExecuted: new Date().toISOString()
      };

      await this.storeFlowMetadata(flowId, updatedMetadata);

    } catch (error) {
      logger.error('Failed to track flow execution', {
        flowId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
    }
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private async listAllFlows(): Promise<Array<{ flow: FlowDefinition; metadata: FlowMetadata }>> {
    const flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }> = [];

    // Recursively scan flow directories
    const scanDirectory = async (dir: string): Promise<void> => {
      if (!existsSync(dir)) {
        return;
      }

      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          await scanDirectory(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.json') && !entry.name.includes('version')) {
          try {
            const content = await fs.readFile(fullPath, 'utf-8');
            const data = JSON.parse(content);

            if (data.id && data.steps && data.packageName) {
              // This is a flow definition
              const flow = data as FlowDefinition;
              const metadata = await this.getFlowMetadata(flow.id) ||
                              await this.calculateFlowMetadata(flow);

              flows.push({ flow, metadata });
            }
          } catch (error) {
            logger.warn('Failed to load flow file', {
              file: fullPath,
              error: error instanceof Error ? error.message : error,
              service: 'flow-storage'
            });
          }
        }
      }
    };

    await scanDirectory(this.config.flowsRoot);
    return flows;
  }

  private async findFlowPath(flowId: string): Promise<string | null> {
    // Search for flow file in all packages
    const searchInDirectory = async (dir: string): Promise<string | null> => {
      if (!existsSync(dir)) {
        return null;
      }

      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          const result = await searchInDirectory(fullPath);
          if (result) {
            return result;
          }
        } else if (entry.isFile() && entry.name === `${flowId}.json`) {
          return fullPath.replace(this.config.flowsRoot + '/', '');
        }
      }

      return null;
    };

    return await searchInDirectory(this.config.flowsRoot);
  }

  private generateFlowId(): string {
    return `flow_${randomUUID().replace(/-/g, '_')}`;
  }

  private generateBackupId(): string {
    return `backup_${new Date().toISOString().replace(/[:.]/g, '-')}_${randomUUID().substring(0, 8)}`;
  }

  private generateBatchId(): string {
    return `batch_${randomUUID().replace(/-/g, '_')}`;
  }

  private async calculateFlowMetadata(flow: FlowDefinition, userId?: string): Promise<FlowMetadata> {
    const flowJson = JSON.stringify(flow);
    const hash = createHash('sha256').update(flowJson).digest('hex');
    const checksum = createHash('md5').update(flowJson).digest('hex');
    const size = Buffer.byteLength(flowJson, 'utf8');

    // Calculate complexity based on steps and conditions
    const complexity = this.calculateFlowComplexity(flow);

    // Determine category based on flow characteristics
    const category = this.determineFlowCategory(flow);

    return {
      version: this.generateVersion(hash),
      hash,
      lastModified: new Date().toISOString(),
      createdBy: userId,
      category,
      tags: flow.metadata.tags || [],
      dependencies: this.extractFlowDependencies(flow),
      usageCount: 0,
      successRate: 0,
      avgExecutionTime: 0,
      size,
      checksum,
      complexity
    };
  }

  private generateVersion(hash: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    return `${timestamp}-${hash.substring(0, 8)}`;
  }

  private calculateFlowComplexity(flow: FlowDefinition): number {
    let complexity = 0;

    // Base complexity for each step
    complexity += flow.steps.length * 10;

    // Additional complexity for conditions
    for (const step of flow.steps) {
      complexity += step.preconditions.length * 5;
      if (step.expectedState) {
        complexity += 5;
      }
    }

    // Complexity for entry/exit points
    if (flow.entryPoint) {
      complexity += this.calculateStateComplexity(flow.entryPoint);
    }
    if (flow.exitPoint) {
      complexity += this.calculateStateComplexity(flow.exitPoint);
    }

    return complexity;
  }

  private calculateStateComplexity(state: any): number {
    let complexity = 1;

    if (state.stateId) complexity += 1;
    if (state.activity) complexity += 1;
    if (state.containsText) complexity += state.containsText.length;
    if (state.matches) {
      if (state.matches.activity) complexity += 1;
      if (state.matches.text) complexity += 1;
      if (state.matches.selectors) complexity += 1;
    }
    if (state.hasSelectors) complexity += state.hasSelectors.length;

    return complexity;
  }

  private determineFlowCategory(flow: FlowDefinition): string {
    const name = flow.name.toLowerCase();
    const description = (flow.description || '').toLowerCase();
    const text = `${name} ${description}`;

    // Check for common flow categories
    if (text.includes('login') || text.includes('auth') || text.includes('signin')) {
      return 'authentication';
    }
    if (text.includes('search') || text.includes('find')) {
      return 'search';
    }
    if (text.includes('form') || text.includes('input') || text.includes('submit')) {
      return 'form';
    }
    if (text.includes('navigation') || text.includes('menu') || text.includes('browse')) {
      return 'navigation';
    }
    if (text.includes('purchase') || text.includes('buy') || text.includes('checkout')) {
      return 'ecommerce';
    }
    if (text.includes('test') || text.includes('verify') || text.includes('validate')) {
      return 'testing';
    }

    return 'general';
  }

  private extractFlowDependencies(flow: FlowDefinition): string[] {
    const dependencies = new Set<string>();

    // Extract package dependencies from actions
    for (const step of flow.steps) {
      if (step.action.targetActivity?.package) {
        dependencies.add(step.action.targetActivity.package);
      }
    }

    // Extract from entry/exit points
    if (flow.entryPoint.activity) {
      const match = flow.entryPoint.activity.match(/package:([^)]+)/);
      if (match) {
        dependencies.add(match[1]);
      }
    }

    return Array.from(dependencies).filter(dep => dep !== flow.packageName);
  }

  private extractIndexableText(flow: FlowDefinition): string {
    const parts = [
      flow.name,
      flow.description || '',
      flow.packageName,
      ...(flow.metadata.tags || []),
      flow.metadata.author || '',
      ...flow.steps.map(step => step.name),
      ...flow.steps.map(step => step.description || '')
    ];

    return parts.join(' ').toLowerCase();
  }

  private tokenizeText(text: string): string[] {
    // Simple tokenization - split on whitespace and punctuation
    return text.toLowerCase()
      .split(/[\s\W_]+/)
      .filter(token => token.length > 2)
      .filter(token => !this.isStopWord(token));
  }

  private isStopWord(word: string): boolean {
    const stopWords = new Set([
      'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with',
      'by', 'from', 'up', 'about', 'into', 'through', 'during', 'before',
      'after', 'above', 'below', 'between', 'among', 'is', 'are', 'was',
      'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does',
      'did', 'will', 'would', 'should', 'could', 'may', 'might', 'must',
      'can', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she',
      'it', 'we', 'they', 'what', 'which', 'who', 'when', 'where', 'why',
      'how', 'all', 'each', 'every', 'both', 'few', 'more', 'most', 'other',
      'some', 'such', 'only', 'own', 'same', 'so', 'than', 'too', 'very'
    ]);

    return stopWords.has(word);
  }

  private calculateRelevanceScore(
    flow: FlowDefinition,
    metadata: FlowMetadata,
    queryTokens: string[],
    tokenMatches: Map<string, Set<string>>
  ): { score: number; matchedFields: string[] } {
    let score = 0;
    const matchedFields: string[] = [];

    const indexableText = this.extractIndexableText(flow);
    const flowTokens = this.tokenizeText(indexableText);

    // Calculate term frequency
    for (const token of queryTokens) {
      if (tokenMatches.has(token) && tokenMatches.get(token)!.has(flow.id)) {
        const tokenCount = flowTokens.filter(t => t === token).length;
        score += tokenCount * 10;

        // Bonus for exact matches in name
        if (flow.name.toLowerCase().includes(token)) {
          score += 50;
          matchedFields.push('name');
        }

        // Bonus for matches in description
        if (flow.description?.toLowerCase().includes(token)) {
          score += 20;
          matchedFields.push('description');
        }

        // Bonus for matches in tags
        if (metadata.tags.some(tag => tag.toLowerCase().includes(token))) {
          score += 30;
          matchedFields.push('tags');
        }
      }
    }

    // Boost based on usage and success rate
    score += metadata.usageCount * 0.1;
    score += metadata.successRate * 10;

    return { score, matchedFields };
  }

  private getSortValue(flow: FlowDefinition, metadata: FlowMetadata, field: string): number {
    switch (field) {
      case 'name':
        return flow.name.toLowerCase().charCodeAt(0);
      case 'createdAt':
        return new Date(flow.metadata.createdAt).getTime();
      case 'updatedAt':
        return new Date(flow.metadata.updatedAt).getTime();
      case 'usageCount':
        return metadata.usageCount;
      case 'successRate':
        return metadata.successRate;
      default:
        return 0;
    }
  }

  private async calculateFacets(flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }>): Promise<{
    packages: Record<string, number>;
    categories: Record<string, number>;
    tags: Record<string, number>;
    authors: Record<string, number>;
  }> {
    const facets = {
      packages: {} as Record<string, number>,
      categories: {} as Record<string, number>,
      tags: {} as Record<string, number>,
      authors: {} as Record<string, number>
    };

    for (const { flow, metadata } of flows) {
      // Package facet
      facets.packages[flow.packageName] = (facets.packages[flow.packageName] || 0) + 1;

      // Category facet
      if (metadata.category) {
        facets.categories[metadata.category] = (facets.categories[metadata.category] || 0) + 1;
      }

      // Tags facet
      for (const tag of metadata.tags) {
        facets.tags[tag] = (facets.tags[tag] || 0) + 1;
      }

      // Author facet
      if (flow.metadata.author) {
        facets.authors[flow.metadata.author] = (facets.authors[flow.metadata.author] || 0) + 1;
      }
    }

    return facets;
  }

  private async validateFlow(flow: FlowDefinition): Promise<FlowValidationResult> {
    // Basic validation - in a real implementation, this would use the flow validation service
    const errors: any[] = [];
    const warnings: any[] = [];

    if (!flow.id) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Flow ID is required',
        code: 'MISSING_ID'
      });
    }

    if (!flow.name) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Flow name is required',
        code: 'MISSING_NAME'
      });
    }

    if (!flow.packageName) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Package name is required',
        code: 'MISSING_PACKAGE'
      });
    }

    if (!flow.steps || flow.steps.length === 0) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Flow must have at least one step',
        code: 'NO_STEPS'
      });
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      summary: {
        totalSteps: flow.steps?.length || 0,
        validSteps: flow.steps?.length || 0,
        invalidSteps: 0,
        unreachableStates: 0,
        circularDependencies: 0
      }
    };
  }

  private async detectConflicts(
    current: { flow: FlowDefinition; metadata: FlowMetadata },
    request: UpdateFlowRequest
  ): Promise<FlowConflict[]> {
    const conflicts: FlowConflict[] = [];

    // Check for version conflicts
    // This is a simplified implementation - in practice, you'd check for specific field conflicts

    return conflicts;
  }

  private async applyMergeStrategy(
    currentFlow: FlowDefinition,
    updates: Partial<FlowDefinition>,
    strategy: 'replace' | 'merge' | 'patch',
    userId: string
  ): Promise<{ updatedFlow: FlowDefinition; changes: FlowChange[] }> {
    const changes: FlowChange[] = [];
    let updatedFlow: FlowDefinition;

    switch (strategy) {
      case 'replace':
        updatedFlow = { ...currentFlow, ...updates };
        break;
      case 'merge':
        updatedFlow = this.deepMerge(currentFlow, updates);
        break;
      case 'patch':
        updatedFlow = this.patchMerge(currentFlow, updates, changes);
        break;
      default:
        updatedFlow = { ...currentFlow, ...updates };
    }

    return { updatedFlow, changes };
  }

  private deepMerge(target: any, source: any): any {
    const result = { ...target };

    for (const key in source) {
      if (source[key] !== undefined) {
        if (typeof source[key] === 'object' && !Array.isArray(source[key]) && source[key] !== null) {
          result[key] = this.deepMerge(result[key] || {}, source[key]);
        } else {
          result[key] = source[key];
        }
      }
    }

    return result;
  }

  private patchMerge(
    target: FlowDefinition,
    updates: Partial<FlowDefinition>,
    changes: FlowChange[]
  ): FlowDefinition {
    const result = { ...target };

    for (const [key, newValue] of Object.entries(updates)) {
      if (newValue !== undefined) {
        const oldValue = (target as any)[key];
        (result as any)[key] = newValue;

        changes.push({
          type: 'update',
          field: key,
          oldValue,
          newValue,
          timestamp: new Date().toISOString(),
          author: 'system'
        });
      }
    }

    return result;
  }

  private async storeFlowMetadata(flowId: string, metadata: FlowMetadata): Promise<void> {
    const metadataPath = join(this.config.flowsRoot, 'metadata', `${flowId}.json`);
    await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2));
  }

  private async getFlowMetadata(flowId: string): Promise<FlowMetadata | null> {
    try {
      const metadataPath = join(this.config.flowsRoot, 'metadata', `${flowId}.json`);

      if (!existsSync(metadataPath)) {
        return null;
      }

      const content = await fs.readFile(metadataPath, 'utf-8');
      return JSON.parse(content) as FlowMetadata;

    } catch (error) {
      logger.warn('Failed to get flow metadata', {
        flowId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      return null;
    }
  }

  private async deleteFlowMetadata(flowId: string): Promise<void> {
    try {
      const metadataPath = join(this.config.flowsRoot, 'metadata', `${flowId}.json`);

      if (existsSync(metadataPath)) {
        await fs.unlink(metadataPath);
      }
    } catch (error) {
      logger.warn('Failed to delete flow metadata', {
        flowId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
    }
  }

  private async storeFlowVersion(
    flowId: string,
    flow: FlowDefinition,
    metadata: FlowMetadata,
    changes: FlowChange[]
  ): Promise<void> {
    const versionsDir = join(this.config.flowsRoot, 'versions', flowId);

    if (!existsSync(versionsDir)) {
      await fs.mkdir(versionsDir, { recursive: true });
    }

    const version: FlowVersion = {
      version: metadata.version,
      flow,
      metadata,
      changes,
      parentVersion: metadata.version
    };

    const versionPath = join(versionsDir, `${metadata.version}.json`);
    await fs.writeFile(versionPath, JSON.stringify(version, null, 2));

    // Cleanup old versions
    await this.cleanupOldVersions(flowId);
  }

  private async getFlowVersion(flowId: string, version: string): Promise<FlowVersion | null> {
    try {
      const versionPath = join(this.config.flowsRoot, 'versions', flowId, `${version}.json`);

      if (!existsSync(versionPath)) {
        return null;
      }

      const content = await fs.readFile(versionPath, 'utf-8');
      return JSON.parse(content) as FlowVersion;

    } catch (error) {
      logger.warn('Failed to get flow version', {
        flowId,
        version,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
      return null;
    }
  }

  private async cleanupOldVersions(flowId: string): Promise<void> {
    try {
      const versionsDir = join(this.config.flowsRoot, 'versions', flowId);

      if (!existsSync(versionsDir)) {
        return;
      }

      const versionFiles = await fs.readdir(versionsDir);
      const versions: Array<{ name: string; time: Date }> = [];

      for (const file of versionFiles) {
        if (file.endsWith('.json')) {
          const stat = await fs.stat(join(versionsDir, file));
          versions.push({ name: file, time: stat.mtime });
        }
      }

      // Sort by time and keep only recent versions
      versions.sort((a, b) => b.time.getTime() - a.time.getTime());
      const versionsToDelete = versions.slice(10); // Keep last 10 versions

      for (const version of versionsToDelete) {
        await fs.unlink(join(versionsDir, version.name));
      }

    } catch (error) {
      logger.warn('Failed to cleanup old versions', {
        flowId,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
    }
  }

  private async updateSearchIndex(flow: FlowDefinition, operation: 'create' | 'update' | 'delete'): Promise<void> {
    try {
      const indexableText = this.extractIndexableText(flow);
      const tokens = this.tokenizeText(indexableText);

      if (operation === 'delete') {
        // Remove flow from index
        for (const [token, flowIds] of this.searchIndex.entries()) {
          flowIds.delete(flow.id);
          if (flowIds.size === 0) {
            this.searchIndex.delete(token);
          }
        }
      } else {
        // Add or update flow in index
        for (const token of tokens) {
          if (!this.searchIndex.has(token)) {
            this.searchIndex.set(token, new Set());
          }
          this.searchIndex.get(token)!.add(flow.id);
        }
      }

    } catch (error) {
      logger.warn('Failed to update search index', {
        flowId: flow.id,
        operation,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
    }
  }

  private cacheFlow(flowId: string, flow: FlowDefinition): void {
    if (this.cache.size >= this.config.maxCacheSize) {
      // Remove oldest entry
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }

    this.cache.set(flowId, {
      data: flow,
      timestamp: Date.now(),
      ttl: this.config.cacheTTL
    });
  }

  private getCachedFlow(flowId: string): FlowDefinition | null {
    const cached = this.cache.get(flowId);

    if (!cached) {
      return null;
    }

    // Check if cache entry is expired
    if (Date.now() - cached.timestamp > cached.ttl) {
      this.cache.delete(flowId);
      return null;
    }

    return cached.data;
  }

  private cleanupCache(): void {
    const now = Date.now();

    for (const [key, cached] of this.cache.entries()) {
      if (now - cached.timestamp > cached.ttl) {
        this.cache.delete(key);
      }
    }
  }

  private cleanupAnalytics(): void {
    const cutoffTime = Date.now() - (this.config.analyticsRetentionDays * 24 * 60 * 60 * 1000);

    for (const [flowId, executions] of this.analytics.entries()) {
      const filteredExecutions = executions.filter(
        exec => new Date(exec.completedAt).getTime() > cutoffTime
      );

      if (filteredExecutions.length === 0) {
        this.analytics.delete(flowId);
      } else {
        this.analytics.set(flowId, filteredExecutions);
      }
    }
  }

  private optimizeSearchIndex(): void {
    // Remove tokens that match too many flows (not selective enough)
    const threshold = this.cache.size * 0.8; // If a token matches 80% of flows, it's not useful

    for (const [token, flowIds] of this.searchIndex.entries()) {
      if (flowIds.size > threshold) {
        this.searchIndex.delete(token);
      }
    }
  }

  private async createFlowBackup(
    flowId: string,
    backupType: 'manual' | 'auto' | 'migration',
    description: string,
    userId: string
  ): Promise<void> {
    if (!this.config.backupEnabled) {
      return;
    }

    try {
      const { flow, metadata } = await this.getFlow(flowId);

      const backupData = {
        flowId,
        flow,
        metadata,
        timestamp: new Date().toISOString(),
        backupType,
        description,
        createdBy: userId
      };

      const backupDir = join(this.config.backupRoot, backupType, 'flows');
      if (!existsSync(backupDir)) {
        await fs.mkdir(backupDir, { recursive: true });
      }

      const backupPath = join(backupDir, `${flowId}_${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
      await fs.writeFile(backupPath, JSON.stringify(backupData, null, 2));

    } catch (error) {
      logger.warn('Failed to create flow backup', {
        flowId,
        backupType,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
    }
  }

  private async cleanupOldBackups(backupType: string): Promise<void> {
    try {
      const backupDir = join(this.config.backupRoot, backupType);

      if (!existsSync(backupDir)) {
        return;
      }

      const backupFiles = await fs.readdir(backupDir);
      const backups: Array<{ name: string; time: Date }> = [];

      for (const file of backupFiles) {
        if (file.endsWith('.json') || file.endsWith('.meta.json')) {
          const stat = await fs.stat(join(backupDir, file));
          backups.push({ name: file, time: stat.mtime });
        }
      }

      // Sort by time and keep only recent backups
      backups.sort((a, b) => b.time.getTime() - a.time.getTime());
      const backupsToDelete = backups.slice(this.config.maxBackups);

      for (const backup of backupsToDelete) {
        await fs.unlink(join(backupDir, backup.name));
      }

    } catch (error) {
      logger.warn('Failed to cleanup old backups', {
        backupType,
        error: error instanceof Error ? error.message : error,
        service: 'flow-storage'
      });
    }
  }

  private async validateTemplate(template: FlowTemplate): Promise<void> {
    if (!template.id) {
      throw new ValidationError('Template ID is required');
    }

    if (!template.name) {
      throw new ValidationError('Template name is required');
    }

    if (!template.category) {
      throw new ValidationError('Template category is required');
    }

    if (!template.parameters || template.parameters.length === 0) {
      throw new ValidationError('Template must have at least one parameter');
    }
  }

  private async validateTemplateParameters(
    template: FlowTemplate,
    parameters: Record<string, any>
  ): Promise<void> {
    for (const param of template.parameters) {
      if (param.required && !(param.name in parameters)) {
        throw new ValidationError(`Required parameter missing: ${param.name}`);
      }

      if (param.name in parameters) {
        const value = parameters[param.name];

        // Type validation
        switch (param.type) {
          case 'string':
            if (typeof value !== 'string') {
              throw new ValidationError(`Parameter ${param.name} must be a string`);
            }
            break;
          case 'number':
            if (typeof value !== 'number') {
              throw new ValidationError(`Parameter ${param.name} must be a number`);
            }
            break;
          case 'boolean':
            if (typeof value !== 'boolean') {
              throw new ValidationError(`Parameter ${param.name} must be a boolean`);
            }
            break;
        }
      }
    }
  }

  private async applyTemplateParameters(
    template: FlowTemplate,
    parameters: Record<string, any>,
    flowData: { name: string; description?: string; packageName: string },
    userId: string
  ): Promise<FlowDefinition> {
    // Create flow definition by applying parameters to template
    const flow: FlowDefinition = {
      id: this.generateFlowId(),
      name: flowData.name,
      description: flowData.description,
      version: '1.0.0',
      packageName: flowData.packageName,
      steps: [],
      entryPoint: template.template.entryPoint,
      exitPoint: template.template.exitPoint,
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        author: userId,
        tags: ['template-generated'],
        templateId: template.id
      },
      config: template.template.config
    };

    // Apply parameters to template steps
    for (const stepTemplate of template.template.steps) {
      const step: any = {
        ...stepTemplate,
        id: this.generateFlowId(), // Generate unique step ID
        action: this.applyParametersToAction(stepTemplate.action, parameters)
      };

      flow.steps.push(step);
    }

    return flow;
  }

  private applyParametersToAction(action: any, parameters: Record<string, any>): any {
    // Simple parameter substitution - in practice, this would be more sophisticated
    const actionJson = JSON.stringify(action);
    let substitutedJson = actionJson;

    for (const [key, value] of Object.entries(parameters)) {
      const placeholder = `\${${key}}`;
      substitutedJson = substitutedJson.replace(new RegExp(placeholder, 'g'), String(value));
    }

    return JSON.parse(substitutedJson);
  }

  private async executeBatchOperation(operation: BatchOperation): Promise<void> {
    operation.status = 'running';
    operation.metadata.startedAt = new Date().toISOString();

    for (const flowId of operation.flowIds) {
      try {
        switch (operation.type) {
          case 'delete':
            await this.deleteFlow(flowId, undefined, operation.metadata.createdBy);
            operation.results.push({
              flowId,
              success: true
            });
            operation.progress.completed++;
            break;

          // Add other operation types as needed
          default:
            throw new Error(`Unsupported batch operation type: ${operation.type}`);
        }
      } catch (error) {
        operation.results.push({
          flowId,
          success: false,
          error: error instanceof Error ? error.message : String(error)
        });
        operation.progress.failed++;
      }
    }

    operation.status = operation.progress.failed === 0 ? 'completed' : 'partial';
    operation.metadata.completedAt = new Date().toISOString();

    // Store batch operation result
    const batchDir = join(this.config.flowsRoot, 'batch');
    if (!existsSync(batchDir)) {
      await fs.mkdir(batchDir, { recursive: true });
    }

    const batchPath = join(batchDir, `${operation.id}.json`);
    await fs.writeFile(batchPath, JSON.stringify(operation, null, 2));
  }

  private trackFlowEvent(flowId: string, event: string, data: any): void {
    logger.debug('Flow event tracked', {
      flowId,
      event,
      data,
      service: 'flow-storage'
    });
  }

  private calculateMostUsedFlows(flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }>): Array<{
    flowId: string;
    name: string;
    executions: number;
    successRate: number;
  }> {
    return flows
      .map(item => ({
        flowId: item.flow.id,
        name: item.flow.name,
        executions: item.metadata.usageCount,
        successRate: item.metadata.successRate
      }))
      .sort((a, b) => b.executions - a.executions)
      .slice(0, 10);
  }

  private calculateAvgExecutionTime(flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }>): number {
    if (flows.length === 0) return 0;

    const totalTime = flows.reduce((sum, item) => sum + item.metadata.avgExecutionTime, 0);
    return totalTime / flows.length;
  }

  private calculateReliabilityScores(flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }>): Record<string, number> {
    const scores: Record<string, number> = {};

    for (const item of flows) {
      scores[item.flow.id] = item.metadata.successRate;
    }

    return scores;
  }

  private calculateMostActiveAuthors(flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }>): Array<{
    author: string;
    flowCount: number;
    executions: number;
  }> {
    const authorStats = new Map<string, { flowCount: number; executions: number }>();

    for (const item of flows) {
      const author = item.flow.metadata.author || 'unknown';
      const stats = authorStats.get(author) || { flowCount: 0, executions: 0 };

      stats.flowCount++;
      stats.executions += item.metadata.usageCount;

      authorStats.set(author, stats);
    }

    return Array.from(authorStats.entries())
      .map(([author, stats]) => ({ author, ...stats }))
      .sort((a, b) => b.flowCount - a.flowCount)
      .slice(0, 10);
  }

  private calculatePopularCategories(flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }>): Record<string, number> {
    const categories: Record<string, number> = {};

    for (const item of flows) {
      const category = item.metadata.category || 'general';
      categories[category] = (categories[category] || 0) + 1;
    }

    return categories;
  }

  private calculatePopularTags(flows: Array<{ flow: FlowDefinition; metadata: FlowMetadata }>): Record<string, number> {
    const tags: Record<string, number> = {};

    for (const item of flows) {
      for (const tag of item.metadata.tags) {
        tags[tag] = (tags[tag] || 0) + 1;
      }
    }

    return tags;
  }

  private async calculateSystemHealth(): Promise<{
    totalFlows: number;
    totalTemplates: number;
    storageSize: number;
    backupSize: number;
    errors: number;
  }> {
    let storageSize = 0;
    let backupSize = 0;

    // Calculate storage size
    const calculateDirectorySize = async (dir: string): Promise<number> => {
      if (!existsSync(dir)) return 0;

      let size = 0;
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          size += await calculateDirectorySize(fullPath);
        } else if (entry.isFile()) {
          const stat = await fs.stat(fullPath);
          size += stat.size;
        }
      }

      return size;
    };

    storageSize = await calculateDirectorySize(this.config.flowsRoot);
    backupSize = await calculateDirectorySize(this.config.backupRoot);

    // Get template count
    const templates = await this.listTemplates();

    return {
      totalFlows: (await this.listAllFlows()).length,
      totalTemplates: templates.length,
      storageSize,
      backupSize,
      errors: 0 // Would be calculated from error logs
    };
  }
}

// Export singleton instance
export const flowStorage = new FlowStorageService();

// Export types
export {
  FlowStorageConfig,
  FlowMetadata,
  FlowSearchResult,
  FlowVersion,
  FlowChange,
  FlowConflict,
  FlowBackup,
  FlowAnalytics,
  BatchOperation
};