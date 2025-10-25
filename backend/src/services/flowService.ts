/**
 * Flow Management Service
 *
 * Flow definition, validation, execution, and management.
 * Handles flow storage, validation, and execution lifecycle.
 */

import { promises as fs } from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import {
  FlowDefinition,
  FlowValidationResult,
  FlowExecutionContext,
  FlowExecutionResult,
  FlowLibrary,
  FlowTemplate,
  CreateFlowRequest,
  UpdateFlowRequest,
  ExecuteFlowRequest,
  ValidateFlowRequest,
  ListFlowsRequest,
  FlowValidationError,
  FlowValidationWarning,
  StatePredicate,
  FlowStep,
  UserAction,
  FlowExecutionLog
} from '../types/flow';
import { StateRecord, UIGraph } from '../types/graph';
import { GraphService } from './graphService';
import { FLOW_CONFIG, FLOW_TARGETS } from '../config/discovery';

export class FlowService {
  private graphService: GraphService;
  private activeExecutions: Map<string, FlowExecutionContext> = new Map();
  private flowCache: Map<string, FlowDefinition> = new Map();
  private executionLogs: Map<string, FlowExecutionLog[]> = new Map();

  constructor(graphService: GraphService) {
    this.graphService = graphService;
    this.initializeDirectories();
  }

  /**
   * Initialize flow directories
   */
  private async initializeDirectories(): Promise<void> {
    const dirs = [
      FLOW_CONFIG.flowsDir,
      FLOW_CONFIG.flowLogsDir
    ];

    for (const dir of dirs) {
      try {
        await fs.mkdir(dir, { recursive: true });
      } catch (error) {
        console.error(`Failed to create directory ${dir}:`, error);
      }
    }
  }

  /**
   * Create a new flow
   */
  async createFlow(request: CreateFlowRequest): Promise<FlowDefinition> {
    const startTime = Date.now();

    // Generate flow ID
    const flowId = this.generateFlowId(request.flow);

    // Create flow definition
    const flow: FlowDefinition = {
      id: flowId,
      name: request.flow.name,
      description: request.flow.description,
      version: '1.0.0',
      packageName: request.flow.packageName,
      steps: request.flow.steps,
      entryPoint: request.flow.entryPoint,
      exitPoint: request.flow.exitPoint,
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        author: (request.flow as any).author,
        tags: (request.flow as any).tags || [],
        estimatedDuration: (request.flow as any).estimatedDuration,
        complexity: 0, // Will be calculated during validation
        executionCount: 0
      },
      config: {
        defaultTimeout: FLOW_CONFIG.defaultFlowTimeout,
        retryAttempts: FLOW_CONFIG.flowRetryAttempts,
        allowParallel: false,
        priority: 'medium',
        ...request.flow.config
      }
    };

    // Validate flow if requested
    let validation: FlowValidationResult | undefined;
    if (request.validate !== false) {
      validation = await this.validateFlow({ flow });
      if (!validation.isValid && FLOW_CONFIG.flowValidationStrict) {
        throw new Error(`Flow validation failed: ${validation.errors.map(e => e.message).join(', ')}`);
      }
    }

    // Calculate flow complexity
    flow.metadata.complexity = this.calculateFlowComplexity(flow);

    // Save flow
    await this.saveFlow(flow);

    // Cache flow
    if (FLOW_CONFIG.enableFlowCaching) {
      this.flowCache.set(flowId, flow);
    }

    const duration = Date.now() - startTime;
    console.log(`Created flow ${flowId} in ${duration}ms`);

    return flow;
  }

  /**
   * Update an existing flow
   */
  async updateFlow(request: UpdateFlowRequest): Promise<FlowDefinition> {
    const startTime = Date.now();

    // Load existing flow
    const existingFlow = await this.loadFlow(request.flowId);
    if (!existingFlow) {
      throw new Error(`Flow not found: ${request.flowId}`);
    }

    // Apply updates based on merge strategy
    let updatedFlow: FlowDefinition;
    switch (request.mergeStrategy) {
      case 'replace':
        updatedFlow = { ...existingFlow, ...request.flow };
        break;
      case 'merge':
        updatedFlow = this.mergeFlowDefinitions(existingFlow, request.flow);
        break;
      case 'patch':
        updatedFlow = this.patchFlowDefinition(existingFlow, request.flow);
        break;
      default:
        updatedFlow = { ...existingFlow, ...request.flow };
    }

    // Update metadata
    updatedFlow.metadata.updatedAt = new Date().toISOString();
    updatedFlow.version = this.incrementVersion(existingFlow.version);

    // Recalculate complexity
    updatedFlow.metadata.complexity = this.calculateFlowComplexity(updatedFlow);

    // Validate updated flow
    const validation = await this.validateFlow({ flow: updatedFlow });
    if (!validation.isValid && FLOW_CONFIG.flowValidationStrict) {
      throw new Error(`Updated flow validation failed: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    // Save updated flow
    await this.saveFlow(updatedFlow);

    // Update cache
    if (FLOW_CONFIG.enableFlowCaching) {
      this.flowCache.set(request.flowId, updatedFlow);
    }

    const duration = Date.now() - startTime;
    console.log(`Updated flow ${request.flowId} in ${duration}ms`);

    return updatedFlow;
  }

  /**
   * Execute a flow
   */
  async executeFlow(request: ExecuteFlowRequest): Promise<string> {
    const startTime = Date.now();

    // Load flow
    const flow = await this.loadFlow(request.flowId);
    if (!flow) {
      throw new Error(`Flow not found: ${request.flowId}`);
    }

    // Check if we can start another execution
    if (this.activeExecutions.size >= FLOW_CONFIG.maxParallelExecutions) {
      throw new Error('Maximum parallel executions reached');
    }

    // Create execution context
    const executionId = uuidv4();
    const context: FlowExecutionContext = {
      executionId,
      flow,
      currentStep: 0,
      startedAt: new Date().toISOString(),
      status: 'pending',
      stepHistory: [],
      variables: request.config?.variables || {},
      config: {
        timeout: request.config?.timeout || flow.config.defaultTimeout,
        dryRun: request.config?.dryRun || false,
        debugMode: request.config?.debugMode || false
      }
    };

    // Store execution context
    this.activeExecutions.set(executionId, context);
    this.executionLogs.set(executionId, []);

    // Start execution in background
    this.startFlowExecution(context, request.config?.startFromStep, request.config?.stopAtStep)
      .catch(error => {
        console.error(`Flow execution ${executionId} failed:`, error);
        context.status = 'failed';
        this.logExecutionEvent(executionId, 'error', `Execution failed: ${error.message}`);
      });

    const duration = Date.now() - startTime;
    console.log(`Started flow execution ${executionId} in ${duration}ms`);

    return executionId;
  }

  /**
   * Get flow execution status
   */
  getExecutionStatus(executionId: string): FlowExecutionContext | null {
    return this.activeExecutions.get(executionId) || null;
  }

  /**
   * Get flow execution result
   */
  async getExecutionResult(executionId: string): Promise<FlowExecutionResult | null> {
    const context = this.activeExecutions.get(executionId);
    if (!context) {
      // Try to load from storage
      return await this.loadExecutionResult(executionId);
    }

    // If still running, return current status
    if (context.status === 'running' || context.status === 'pending') {
      throw new Error(`Execution ${executionId} is still running`);
    }

    // Create result from completed context
    const result: FlowExecutionResult = {
      executionId: context.executionId,
      flowId: context.flow.id,
      status: context.status as 'completed' | 'failed' | 'partial' | 'cancelled',
      startedAt: context.startedAt,
      completedAt: new Date().toISOString(),
      duration: Date.now() - new Date(context.startedAt).getTime(),
      stepsCompleted: context.stepHistory.filter(s => s.status === 'completed').length,
      stepsFailed: context.stepHistory.filter(s => s.status === 'failed').length,
      finalState: context.currentState,
      summary: {
        totalSteps: context.flow.steps.length,
        successfulSteps: context.stepHistory.filter(s => s.status === 'completed').length,
        failedSteps: context.stepHistory.filter(s => s.status === 'failed').length,
        skippedSteps: context.stepHistory.filter(s => s.status === 'skipped').length,
        averageStepDuration: this.calculateAverageStepDuration(context.stepHistory)
      },
      logs: this.executionLogs.get(executionId) || []
    };

    // Move from active to completed
    this.activeExecutions.delete(executionId);
    await this.saveExecutionResult(result);

    return result;
  }

  /**
   * Validate a flow definition
   */
  async validateFlow(request: ValidateFlowRequest): Promise<FlowValidationResult> {
    const startTime = Date.now();
    const { flow } = request;

    const errors: FlowValidationError[] = [];
    const warnings: FlowValidationError[] = [];

    // Basic structure validation
    this.validateFlowStructure(flow, errors);

    // Steps validation
    this.validateFlowSteps(flow, errors, warnings);

    // State predicates validation (if requested)
    if (request.options?.checkStates !== false) {
      await this.validateStatePredicates(flow, errors, warnings);
    }

    // Actions validation (if requested)
    if (request.options?.checkActions !== false) {
      this.validateActions(flow, errors, warnings);
    }

    // Logic validation (if requested)
    if (request.options?.checkLogic !== false) {
      this.validateFlowLogic(flow, errors, warnings);
    }

    // Performance analysis (if requested)
    let analysis;
    if (request.options?.analyzePerformance) {
      analysis = await this.analyzeFlowPerformance(flow);
    }

    const isValid = errors.length === 0;
    const duration = Date.now() - startTime;

    console.log(`Validated flow ${flow.id} in ${duration}ms - ${errors.length} errors, ${warnings.length} warnings`);

    return {
      isValid,
      errors,
      warnings,
      summary: {
        totalSteps: flow.steps.length,
        validSteps: flow.steps.length - errors.filter(e => e.stepId).length,
        invalidSteps: errors.filter(e => e.stepId).length,
        unreachableStates: 0, // Will be calculated during state validation
        circularDependencies: 0 // Will be calculated during logic validation
      }
    };
  }

  /**
   * List flows with filtering and pagination
   */
  async listFlows(request: ListFlowsRequest = {}): Promise<{ flows: FlowDefinition[], total: number }> {
    const startTime = Date.now();

    // Load all flows
    const allFlows = await this.loadAllFlows();

    // Apply filters
    let filteredFlows = allFlows.filter(flow => {
      if (request.filter?.package && flow.packageName !== request.filter.package) {
        return false;
      }

      if (request.filter?.tags?.length) {
        const hasAllTags = request.filter.tags.every(tag =>
          flow.metadata.tags?.includes(tag)
        );
        if (!hasAllTags) return false;
      }

      if (request.filter?.author && flow.metadata.author !== request.filter.author) {
        return false;
      }

      if (request.filter?.search) {
        const search = request.filter.search.toLowerCase();
        const inName = flow.name.toLowerCase().includes(search);
        const inDescription = flow.description?.toLowerCase().includes(search);
        const inTags = flow.metadata.tags?.some(tag =>
          tag.toLowerCase().includes(search)
        );
        if (!inName && !inDescription && !inTags) return false;
      }

      return true;
    });

    // Apply sorting
    if (request.sort) {
      filteredFlows.sort((a, b) => {
        let aValue: any, bValue: any;

        switch (request.sort!.field) {
          case 'name':
            aValue = a.name.toLowerCase();
            bValue = b.name.toLowerCase();
            break;
          case 'createdAt':
            aValue = new Date(a.metadata.createdAt);
            bValue = new Date(b.metadata.createdAt);
            break;
          case 'updatedAt':
            aValue = new Date(a.metadata.updatedAt);
            bValue = new Date(b.metadata.updatedAt);
            break;
          case 'successRate':
            aValue = a.metadata.successRate || 0;
            bValue = b.metadata.successRate || 0;
            break;
          case 'executionCount':
            aValue = a.metadata.executionCount || 0;
            bValue = b.metadata.executionCount || 0;
            break;
          default:
            return 0;
        }

        if (aValue < bValue) return request.sort!.order === 'asc' ? -1 : 1;
        if (aValue > bValue) return request.sort!.order === 'asc' ? 1 : -1;
        return 0;
      });
    }

    // Apply pagination
    const total = filteredFlows.length;
    const page = request.pagination?.page || 1;
    const limit = request.pagination?.limit || 50;
    const startIndex = (page - 1) * limit;
    const flows = filteredFlows.slice(startIndex, startIndex + limit);

    const duration = Date.now() - startTime;
    console.log(`Listed ${flows.length} flows (total: ${total}) in ${duration}ms`);

    return { flows, total };
  }

  /**
   * Load a specific flow
   */
  async loadFlow(flowId: string): Promise<FlowDefinition | null> {
    // Check cache first
    if (FLOW_CONFIG.enableFlowCaching && this.flowCache.has(flowId)) {
      return this.flowCache.get(flowId)!;
    }

    try {
      const filePath = path.join(FLOW_CONFIG.flowsDir, `${flowId}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      const flow = JSON.parse(content) as FlowDefinition;

      // Cache the loaded flow
      if (FLOW_CONFIG.enableFlowCaching) {
        this.flowCache.set(flowId, flow);
      }

      return flow;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }

  // ============================================================================
  // Private Helper Methods
  // ============================================================================

  private generateFlowId(flow: Partial<FlowDefinition>): string {
    const input = `${flow.packageName}:${flow.name}:${flow.version || '1.0.0'}:${Date.now()}`;
    return crypto.createHash('sha256').update(input).digest('hex').substring(0, 16);
  }

  private calculateFlowComplexity(flow: FlowDefinition): number {
    let complexity = 0;

    // Base complexity per step
    complexity += flow.steps.length * 10;

    // Complexity for conditional logic
    for (const step of flow.steps) {
      if (step.preconditions.length > 1) {
        complexity += step.preconditions.length * 5;
      }

      if (step.expectedState) {
        complexity += 5;
      }
    }

    // Complexity for state matching
    for (const step of flow.steps) {
      for (const precondition of step.preconditions) {
        if (precondition.type === 'fuzzy') {
          complexity += 3;
        } else if (precondition.type === 'matches') {
          complexity += 5;
        }
      }
    }

    return Math.min(complexity, FLOW_CONFIG.maxFlowComplexity);
  }

  private async saveFlow(flow: FlowDefinition): Promise<void> {
    const filePath = path.join(FLOW_CONFIG.flowsDir, `${flow.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(flow, null, 2), 'utf-8');
  }

  private mergeFlowDefinitions(existing: FlowDefinition, updates: Partial<FlowDefinition>): FlowDefinition {
    return {
      ...existing,
      ...updates,
      metadata: {
        ...existing.metadata,
        ...updates.metadata
      },
      config: {
        ...existing.config,
        ...updates.config
      }
    };
  }

  private patchFlowDefinition(existing: FlowDefinition, updates: Partial<FlowDefinition>): FlowDefinition {
    const patched = { ...existing };

    // Only apply defined updates
    Object.keys(updates).forEach(key => {
      if (updates[key as keyof FlowDefinition] !== undefined) {
        (patched as any)[key] = updates[key as keyof FlowDefinition];
      }
    });

    return patched;
  }

  private incrementVersion(version: string): string {
    const parts = version.split('.');
    const patch = parseInt(parts[2] || '0') + 1;
    return `${parts[0]}.${parts[1]}.${patch}`;
  }

  private validateFlowStructure(flow: FlowDefinition, errors: FlowValidationError[]): void {
    if (!flow.id) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Flow ID is required',
        code: 'MISSING_FLOW_ID'
      });
    }

    if (!flow.name) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Flow name is required',
        code: 'MISSING_FLOW_NAME'
      });
    }

    if (!flow.packageName) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Package name is required',
        code: 'MISSING_PACKAGE_NAME'
      });
    }

    if (!flow.steps || flow.steps.length === 0) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Flow must have at least one step',
        code: 'MISSING_STEPS'
      });
    }

    if (!flow.entryPoint) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: 'Flow entry point is required',
        code: 'MISSING_ENTRY_POINT'
      });
    }

    if (flow.steps && flow.steps.length > FLOW_CONFIG.maxFlowSteps) {
      errors.push({
        type: 'syntax',
        severity: 'error',
        message: `Flow exceeds maximum step limit (${FLOW_CONFIG.maxFlowSteps})`,
        code: 'TOO_MANY_STEPS'
      });
    }
  }

  private validateFlowSteps(flow: FlowDefinition, errors: FlowValidationError[], warnings: FlowValidationWarning[]): void {
    if (!flow.steps) return;

    flow.steps.forEach((step, index) => {
      if (!step.id) {
        errors.push({
          type: 'syntax',
          severity: 'error',
          message: `Step ${index + 1} missing ID`,
          stepId: step.id,
          code: 'MISSING_STEP_ID'
        });
      }

      if (!step.name) {
        errors.push({
          type: 'syntax',
          severity: 'error',
          message: `Step ${index + 1} missing name`,
          stepId: step.id,
          code: 'MISSING_STEP_NAME'
        });
      }

      if (!step.action) {
        errors.push({
          type: 'syntax',
          severity: 'error',
          message: `Step ${index + 1} missing action`,
          stepId: step.id,
          code: 'MISSING_STEP_ACTION'
        });
      }

      if (!step.preconditions || step.preconditions.length === 0) {
        warnings.push({
          type: 'reliability',
          severity: 'warning' as const,
          message: `Step ${index + 1} has no preconditions`,
          stepId: step.id,
          code: 'NO_PRECONDITIONS',
          suggestion: 'Add preconditions to ensure step executes in correct context'
        });
      }

      if (step.timeout && step.timeout > FLOW_CONFIG.maxFlowTimeout) {
        warnings.push({
          type: 'performance',
          severity: 'warning' as const,
          message: `Step ${index + 1} timeout exceeds maximum (${FLOW_CONFIG.maxFlowTimeout}ms)`,
          stepId: step.id,
          code: 'TIMEOUT_EXCEEDS_MAXIMUM',
          suggestion: 'Consider breaking down into smaller steps'
        });
      }
    });
  }

  private async validateStatePredicates(flow: FlowDefinition, errors: FlowValidationError[], warnings: FlowValidationError[]): Promise<void> {
    const graph = await this.graphService.loadGraph();

    // Validate entry point
    const entryPointErrors = await this.validateStatePredicate(flow.entryPoint, graph);
    errors.push(...entryPointErrors.map(error => ({
      ...error,
      message: `Entry point: ${error.message}`,
      code: `ENTRY_POINT_${error.code}`
    })));

    // Validate exit point if present
    if (flow.exitPoint) {
      const exitPointErrors = await this.validateStatePredicate(flow.exitPoint, graph);
      errors.push(...exitPointErrors.map(error => ({
        ...error,
        message: `Exit point: ${error.message}`,
        code: `EXIT_POINT_${error.code}`
      })));
    }

    // Validate step preconditions and expected states
    for (const step of flow.steps) {
      for (const precondition of step.preconditions) {
        const preconditionErrors = await this.validateStatePredicate(precondition, graph);
        errors.push(...preconditionErrors.map(error => ({
          ...error,
          stepId: step.id,
          message: `Step precondition: ${error.message}`,
          code: `STEP_PRECONDITION_${error.code}`
        })));
      }

      if (step.expectedState) {
        const expectedStateErrors = await this.validateStatePredicate(step.expectedState, graph);
        errors.push(...expectedStateErrors.map(error => ({
          ...error,
          stepId: step.id,
          message: `Step expected state: ${error.message}`,
          code: `STEP_EXPECTED_STATE_${error.code}`
        })));
      }
    }
  }

  private async validateStatePredicate(predicate: StatePredicate, graph: UIGraph): Promise<FlowValidationError[]> {
    const errors: FlowValidationError[] = [];

    // Validate exact state predicates
    if (predicate.type === 'exact') {
      if (!predicate.stateId) {
        errors.push({
          type: 'reference',
          severity: 'error',
          message: 'Exact state predicate requires stateId',
          code: 'MISSING_STATE_ID'
        });
      } else {
        const stateExists = graph.states.some(s => s.id === predicate.stateId);
        if (!stateExists) {
          errors.push({
            type: 'reference',
            severity: 'error',
            message: `State not found: ${predicate.stateId}`,
            code: 'STATE_NOT_FOUND',
            details: {
              availableStates: graph.states.map(s => ({ id: s.id, activity: s.activity })).slice(0, 10)
            }
          });
        }
      }
    }

    // Validate contains predicates
    if (predicate.type === 'contains') {
      if (!predicate.containsText || predicate.containsText.length === 0) {
        errors.push({
          type: 'semantic',
          severity: 'error',
          message: 'Contains predicate requires at least one text pattern',
          code: 'MISSING_CONTAINS_TEXT'
        });
      } else {
        // Check if any states match the contains criteria
        const matchingStates = graph.states.filter(state =>
          predicate.containsText!.some(text =>
            state.visibleText.some(visibleText =>
              visibleText.toLowerCase().includes(text.toLowerCase())
            )
          )
        );

        if (matchingStates.length === 0) {
          errors.push({
            type: 'reference',
            severity: 'warning',
            message: `No states contain text: ${predicate.containsText.join(', ')}`,
            code: 'NO_MATCHING_STATES',
            details: {
              searchText: predicate.containsText,
              availableText: graph.states.flatMap(s => s.visibleText).slice(0, 20)
            }
          });
        }
      }
    }

    // Validate matches predicates
    if (predicate.type === 'matches') {
      if (!predicate.matches) {
        errors.push({
          type: 'semantic',
          severity: 'error',
          message: 'Matches predicate requires match criteria',
          code: 'MISSING_MATCHES_CRITERIA'
        });
      } else {
        // Validate activity regex
        if (predicate.matches.activity) {
          try {
            new RegExp(predicate.matches.activity);

            // Check if any states match the activity pattern
            const matchingStates = graph.states.filter(state =>
              new RegExp(predicate.matches!.activity!).test(state.activity)
            );

            if (matchingStates.length === 0) {
              errors.push({
                type: 'reference',
                severity: 'warning',
                message: `No states match activity pattern: ${predicate.matches.activity}`,
                code: 'NO_MATCHING_ACTIVITIES',
                details: {
                  pattern: predicate.matches.activity,
                  availableActivities: [...new Set(graph.states.map(s => s.activity))].slice(0, 10)
                }
              });
            }
          } catch (error) {
            errors.push({
              type: 'syntax',
              severity: 'error',
              message: `Invalid activity regex: ${predicate.matches.activity}`,
              code: 'INVALID_REGEX'
            });
          }
        }

        // Validate text regex
        if (predicate.matches.text) {
          try {
            new RegExp(predicate.matches.text);
          } catch (error) {
            errors.push({
              type: 'syntax',
              severity: 'error',
              message: `Invalid text regex: ${predicate.matches.text}`,
              code: 'INVALID_REGEX'
            });
          }
        }

        // Validate selectors regex
        if (predicate.matches.selectors) {
          try {
            new RegExp(predicate.matches.selectors);
          } catch (error) {
            errors.push({
              type: 'syntax',
              severity: 'error',
              message: `Invalid selectors regex: ${predicate.matches.selectors}`,
              code: 'INVALID_REGEX'
            });
          }
        }
      }
    }

    // Validate fuzzy predicates
    if (predicate.type === 'fuzzy') {
      if (!predicate.fuzzyThreshold) {
        errors.push({
          type: 'semantic',
          severity: 'warning',
          message: 'Fuzzy predicate should specify a threshold (using default 0.8)',
          code: 'MISSING_FUZZY_THRESHOLD'
        });
      }

      if (predicate.fuzzyThreshold && (predicate.fuzzyThreshold < 0 || predicate.fuzzyThreshold > 1)) {
        errors.push({
          type: 'semantic',
          severity: 'error',
          message: 'Fuzzy threshold must be between 0 and 1',
          code: 'INVALID_FUZZY_THRESHOLD'
        });
      }
    }

    // Validate hasSelectors criteria
    if (predicate.hasSelectors) {
      for (const selector of predicate.hasSelectors) {
        if (!selector.rid && !selector.text && !selector.desc) {
          errors.push({
            type: 'semantic',
            severity: 'warning',
            message: 'Selector criterion should specify at least one of rid, text, or desc',
            code: 'VAGUE_SELECTOR_CRITERION'
          });
        }
      }

      // Check if states have matching selectors
      const matchingStates = graph.states.filter(state =>
        predicate.hasSelectors!.some(requiredSelector =>
          state.selectors.some(stateSelector => {
            if (requiredSelector.rid && stateSelector.rid) {
              return stateSelector.rid === requiredSelector.rid;
            }
            if (requiredSelector.text && stateSelector.text) {
              return stateSelector.text.toLowerCase().includes(requiredSelector.text.toLowerCase());
            }
            if (requiredSelector.desc && stateSelector.desc) {
              return stateSelector.desc.toLowerCase().includes(requiredSelector.desc.toLowerCase());
            }
            return false;
          })
        )
      );

      if (matchingStates.length === 0) {
        errors.push({
          type: 'reference',
          severity: 'warning',
          message: `No states contain required selectors`,
          code: 'NO_MATCHING_SELECTORS',
          details: {
            requiredSelectors: predicate.hasSelectors,
            availableSelectors: graph.states.flatMap(s => s.selectors.map(sel => ({
              rid: sel.rid,
              text: sel.text,
              desc: sel.desc
            }))).slice(0, 20)
          }
        });
      }
    }

    // Validate activity-based predicates
    if (predicate.activity) {
      const matchingStates = graph.states.filter(state => state.activity === predicate.activity);

      if (matchingStates.length === 0) {
        errors.push({
          type: 'reference',
          severity: 'error',
          message: `No states found for activity: ${predicate.activity}`,
          code: 'ACTIVITY_NOT_FOUND',
          details: {
            requestedActivity: predicate.activity,
            availableActivities: [...new Set(graph.states.map(s => s.activity))].slice(0, 10)
          }
        });
      }
    }

    return errors;
  }

  private validateActions(flow: FlowDefinition, errors: FlowValidationError[], warnings: FlowValidationWarning[]): void {
    for (const step of flow.steps) {
      if (!step.action) continue;

      const action = step.action;

      if (action.type === 'type' && !action.text) {
        errors.push({
          type: 'semantic',
          severity: 'error',
          message: 'Type action requires text',
          stepId: step.id,
          code: 'MISSING_TYPE_TEXT'
        });
      }

      if (action.type === 'swipe' && !action.swipe) {
        errors.push({
          type: 'semantic',
          severity: 'error',
          message: 'Swipe action requires swipe configuration',
          stepId: step.id,
          code: 'MISSING_SWIPE_CONFIG'
        });
      }

      if (action.type === 'intent' && !action.intent) {
        errors.push({
          type: 'semantic',
          severity: 'error',
          message: 'Intent action requires intent configuration',
          stepId: step.id,
          code: 'MISSING_INTENT_CONFIG'
        });
      }

      if (['tap', 'type', 'long_press'].includes(action.type) && !action.target) {
        warnings.push({
          type: 'reliability',
          severity: 'warning' as const,
          message: `${action.type} action without target selector may be unreliable`,
          stepId: step.id,
          code: 'NO_TARGET_SELECTOR',
          suggestion: 'Add target selector for better reliability'
        });
      }
    }
  }

  private validateFlowLogic(flow: FlowDefinition, errors: FlowValidationError[], warnings: FlowValidationWarning[]): void {
    // Check for unreachable steps
    const reachableSteps = new Set<string>();
    const visitedSteps = new Set<string>();

    // BFS from entry point
    const queue = ['entry'];
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visitedSteps.has(current)) continue;
      visitedSteps.add(current);

      if (current === 'entry') {
        // Find steps that match entry point
        flow.steps.forEach(step => {
          if (this.matchesEntryPoint(step, flow.entryPoint)) {
            reachableSteps.add(step.id);
            queue.push(step.id);
          }
        });
      } else {
        // Find next steps
        const currentStep = flow.steps.find(s => s.id === current);
        if (currentStep) {
          flow.steps.forEach(nextStep => {
            if (this.canTransitionBetween(currentStep, nextStep)) {
              if (!reachableSteps.has(nextStep.id)) {
                reachableSteps.add(nextStep.id);
                queue.push(nextStep.id);
              }
            }
          });
        }
      }
    }

    // Check for unreachable steps
    flow.steps.forEach(step => {
      if (!reachableSteps.has(step.id)) {
        warnings.push({
          type: 'logic',
          severity: 'warning' as const,
          message: `Step "${step.name}" may be unreachable from entry point`,
          stepId: step.id,
          code: 'UNREACHABLE_STEP',
          suggestion: 'Check preconditions and flow structure'
        });
      }
    });

    // Check for potential infinite loops
    const stepDependencies = new Map<string, string[]>();
    flow.steps.forEach(step => {
      const dependencies = flow.steps
        .filter(otherStep => this.canTransitionBetween(otherStep, step))
        .map(otherStep => otherStep.id);
      stepDependencies.set(step.id, dependencies);
    });

    // Simple cycle detection
    const visiting = new Set<string>();
    const visited = new Set<string>();

    function hasCycle(stepId: string): boolean {
      if (visiting.has(stepId)) return true; // Cycle detected
      if (visited.has(stepId)) return false;

      visiting.add(stepId);
      const dependencies = stepDependencies.get(stepId) || [];

      for (const dep of dependencies) {
        if (hasCycle(dep)) return true;
      }

      visiting.delete(stepId);
      visited.add(stepId);
      return false;
    }

    for (const stepId of stepDependencies.keys()) {
      if (hasCycle(stepId)) {
        warnings.push({
          type: 'logic',
          severity: 'warning' as const,
          message: `Potential infinite loop detected involving step "${stepId}"`,
          stepId: stepId,
          code: 'POTENTIAL_INFINITE_LOOP',
          suggestion: 'Review flow logic to prevent cycles'
        });
      }
    }
  }

  private matchesEntryPoint(step: FlowStep, entryPoint: StatePredicate): boolean {
    // Simplified matching - in real implementation would be more sophisticated
    return step.preconditions.some(precondition =>
      precondition.type === entryPoint.type &&
      precondition.activity === entryPoint.activity
    );
  }

  private canTransitionBetween(fromStep: FlowStep, toStep: FlowStep): boolean {
    // Simplified transition logic - in real implementation would be more sophisticated
    return fromStep.expectedState && toStep.preconditions.some(precondition =>
      precondition.type === 'exact' && precondition.stateId === fromStep.expectedState?.stateId
    );
  }

  private async analyzeFlowPerformance(flow: FlowDefinition): Promise<any> {
    const estimatedDuration = this.estimateFlowDuration(flow);
    const reliabilityScore = this.calculateReliabilityScore(flow);
    const complexityScore = flow.metadata.complexity || this.calculateFlowComplexity(flow);

    let performanceImpact: 'low' | 'medium' | 'high' = 'low';
    if (complexityScore > 70) performanceImpact = 'high';
    else if (complexityScore > 40) performanceImpact = 'medium';

    const suggestions = [];
    if (complexityScore > 50) {
      suggestions.push('Consider breaking flow into smaller, simpler flows');
    }
    if (reliabilityScore < 0.8) {
      suggestions.push('Add more specific preconditions to improve reliability');
    }
    if (estimatedDuration > 60000) {
      suggestions.push('Flow may take too long to execute, consider optimization');
    }

    return {
      estimatedDuration,
      reliabilityScore,
      complexityScore,
      performanceImpact,
      suggestions
    };
  }

  private estimateFlowDuration(flow: FlowDefinition): number {
    // Simple estimation based on step count and complexity
    const baseTimePerStep = 2000; // 2 seconds base per step
    const complexityMultiplier = 1 + (flow.metadata.complexity || 0) / 100;

    return flow.steps.length * baseTimePerStep * complexityMultiplier;
  }

  private calculateReliabilityScore(flow: FlowDefinition): number {
    let score = 1.0;

    // Deduct for missing preconditions
    flow.steps.forEach(step => {
      if (!step.preconditions || step.preconditions.length === 0) {
        score -= 0.1;
      }

      if (!step.expectedState) {
        score -= 0.05;
      }

      if (!step.action.target) {
        score -= 0.05;
      }
    });

    return Math.max(0, score);
  }

  private async loadAllFlows(): Promise<FlowDefinition[]> {
    try {
      const files = await fs.readdir(FLOW_CONFIG.flowsDir);
      const jsonFiles = files.filter(file => file.endsWith('.json'));

      const flows: FlowDefinition[] = [];
      for (const file of jsonFiles) {
        try {
          const filePath = path.join(FLOW_CONFIG.flowsDir, file);
          const content = await fs.readFile(filePath, 'utf-8');
          const flow = JSON.parse(content) as FlowDefinition;
          flows.push(flow);
        } catch (error) {
          console.error(`Failed to load flow from ${file}:`, error);
        }
      }

      return flows;
    } catch (error) {
      console.error('Failed to load flows directory:', error);
      return [];
    }
  }

  private async startFlowExecution(
    context: FlowExecutionContext,
    startFromStep?: number,
    stopAtStep?: number
  ): Promise<void> {
    context.status = 'running';
    this.logExecutionEvent(context.executionId, 'info', `Starting flow execution: ${context.flow.name}`);

    const startIndex = startFromStep || 0;
    const endIndex = stopAtStep !== undefined ? stopAtStep + 1 : context.flow.steps.length;

    try {
      for (let i = startIndex; i < endIndex && i < context.flow.steps.length; i++) {
        context.currentStep = i;
        const step = context.flow.steps[i];

        this.logExecutionEvent(context.executionId, 'info', `Executing step ${i + 1}: ${step.name}`);

        const stepResult = await this.executeStep(context, step);
        context.stepHistory.push(stepResult);

        if (stepResult.status === 'failed' && step.critical !== false) {
          context.status = 'failed';
          this.logExecutionEvent(context.executionId, 'error', `Critical step failed: ${step.name}`);
          return;
        }
      }

      context.status = 'completed';
      this.logExecutionEvent(context.executionId, 'info', 'Flow execution completed successfully');
    } catch (error) {
      context.status = 'failed';
      this.logExecutionEvent(context.executionId, 'error', `Flow execution failed: ${error.message}`);
    }
  }

  private async executeStep(context: FlowExecutionContext, step: FlowStep): Promise<any> {
    const startTime = Date.now();

    const stepExecution: any = {
      stepId: step.id,
      status: 'running' as const,
      startedAt: new Date().toISOString(),
      beforeState: context.currentState
    };

    try {
      // Check preconditions
      const preconditionsMet = await this.checkPreconditions(step.preconditions, context);
      if (!preconditionsMet) {
        stepExecution.status = 'failed';
        stepExecution.result = {
          success: false,
          error: 'Preconditions not met',
          duration: Date.now() - startTime,
          retryCount: 0
        };
        return stepExecution;
      }

      // Execute action (in dry run mode, just simulate)
      if (!context.config?.dryRun) {
        // TODO: Implement actual action execution
        await this.executeAction(step.action, context);
      }

      // Check expected state
      if (step.expectedState) {
        // TODO: Implement state verification
        // const expectedStateMet = await this.checkExpectedState(step.expectedState, context);
      }

      stepExecution.status = 'completed';
      stepExecution.completedAt = new Date().toISOString();
      stepExecution.result = {
        success: true,
        duration: Date.now() - startTime,
        retryCount: 0
      };

      this.logExecutionEvent(context.executionId, 'info', `Step completed: ${step.name}`);

    } catch (error) {
      stepExecution.status = 'failed';
      stepExecution.completedAt = new Date().toISOString();
      stepExecution.result = {
        success: false,
        error: error.message,
        duration: Date.now() - startTime,
        retryCount: 0
      };

      this.logExecutionEvent(context.executionId, 'error', `Step failed: ${step.name} - ${error.message}`);
    }

    return stepExecution;
  }

  private async checkPreconditions(preconditions: StatePredicate[], context: FlowExecutionContext): Promise<boolean> {
    // TODO: Implement precondition checking
    return true;
  }

  private async executeAction(action: UserAction, context: FlowExecutionContext): Promise<void> {
    // TODO: Implement actual action execution via ADB
    this.logExecutionEvent(context.executionId, 'info', `Executing action: ${action.type}`);
  }

  private logExecutionEvent(executionId: string, level: string, message: string, data?: any): void {
    const log: FlowExecutionLog = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      level: level as any,
      message,
      data
    };

    const logs = this.executionLogs.get(executionId) || [];
    logs.push(log);
    this.executionLogs.set(executionId, logs);

    console.log(`[${executionId}] ${level.toUpperCase()}: ${message}`);
  }

  private calculateAverageStepDuration(stepHistory: any[]): number {
    if (stepHistory.length === 0) return 0;

    const completedSteps = stepHistory.filter(s => s.status === 'completed' && s.result?.duration);
    if (completedSteps.length === 0) return 0;

    const totalDuration = completedSteps.reduce((sum, step) => sum + step.result.duration, 0);
    return totalDuration / completedSteps.length;
  }

  private async saveExecutionResult(result: FlowExecutionResult): Promise<void> {
    const filePath = path.join(FLOW_CONFIG.flowLogsDir, `${result.executionId}.json`);
    await fs.writeFile(filePath, JSON.stringify(result, null, 2), 'utf-8');
  }

  private async loadExecutionResult(executionId: string): Promise<FlowExecutionResult | null> {
    try {
      const filePath = path.join(FLOW_CONFIG.flowLogsDir, `${executionId}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content) as FlowExecutionResult;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        return null;
      }
      throw error;
    }
  }
}