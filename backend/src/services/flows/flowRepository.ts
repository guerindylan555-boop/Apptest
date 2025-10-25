/**
 * Flow Repository Service
 *
 * Manages YAML flow definitions, loading, saving, and validation
 * for the flow execution system.
 */

import fs from 'fs/promises';
import path from 'path';
import yaml from 'js-yaml';
import { FlowDefinition } from '../../types/uiGraph';
import { logger } from '../../utils/logger';

export interface FlowRepositoryConfig {
  flowsDirectory: string;
  templateDirectory: string;
  maxFlowsPerFile: number;
}

export interface FlowMetadata {
  name: string;
  description: string;
  version: string;
  owner?: string;
  lastUpdatedAt: string;
  validationStatus: 'draft' | 'validated' | 'deprecated';
  filePath: string;
}

export interface FlowValidationError {
  path: string;
  message: string;
  severity: 'error' | 'warning';
}

export class FlowRepository {
  private config: FlowRepositoryConfig;
  private flowCache: Map<string, FlowDefinition> = new Map();

  constructor(config: Partial<FlowRepositoryConfig> = {}) {
    this.config = {
      flowsDirectory: path.join(process.cwd(), 'var', 'flows'),
      templateDirectory: path.join(process.cwd(), 'var', 'flows', 'templates'),
      maxFlowsPerFile: 100,
      ...config,
    };
  }

  /**
   * Initialize the flow repository structure
   */
  async initialize(): Promise<void> {
    try {
      await fs.mkdir(this.config.flowsDirectory, { recursive: true });
      await fs.mkdir(this.config.templateDirectory, { recursive: true });

      // Create README if it doesn't exist
      const readmePath = path.join(this.config.flowsDirectory, 'README.md');
      try {
        await fs.access(readmePath);
      } catch {
        await this.createReadme();
      }

      logger.info('Flow repository initialized');
    } catch (error) {
      logger.error(`Failed to initialize flow repository: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  /**
   * Load a flow by name
   */
  async loadFlow(name: string): Promise<FlowDefinition | null> {
    try {
      // Check cache first
      const cached = this.flowCache.get(name);
      if (cached) {
        return cached;
      }

      const filePath = this.getFlowFilePath(name);
      const content = await fs.readFile(filePath, 'utf-8');
      const flow = yaml.load(content) as FlowDefinition;

      // Validate basic structure
      this.validateFlowStructure(flow, filePath);

      // Cache the flow
      this.flowCache.set(name, flow);

      return flow;
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        return null;
      }

      logger.error(`Failed to load flow ${name}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  /**
   * Save a flow definition
   */
  async saveFlow(flow: FlowDefinition): Promise<void> {
    try {
      const filePath = this.getFlowFilePath(flow.name);
      const yamlContent = yaml.dump(flow, {
        indent: 2,
        lineWidth: 120,
        noRefs: true,
        sortKeys: false,
      });

      // Validate before saving
      const validation = this.validateFlow(flow);
      if (validation.errors.length > 0) {
        throw new Error(`Flow validation failed: ${validation.errors.map(e => e.message).join(', ')}`);
      }

      await fs.writeFile(filePath, yamlContent, 'utf-8');

      // Update cache
      this.flowCache.set(flow.name, flow);

      logger.info(`Flow saved: ${flow.name} (${filePath})`);
    } catch (error) {
      logger.error(`Failed to save flow ${flow.name}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  /**
   * List all available flows
   */
  async listFlows(): Promise<FlowMetadata[]> {
    try {
      const files = await fs.readdir(this.config.flowsDirectory);
      const flowFiles = files.filter(file =>
        file.endsWith('.yaml') || file.endsWith('.yml')
      );

      const flows: FlowMetadata[] = [];

      for (const file of flowFiles) {
        if (file === 'README.md') continue;

        const filePath = path.join(this.config.flowsDirectory, file);
        try {
          const content = await fs.readFile(filePath, 'utf-8');
          const flow = yaml.load(content) as FlowDefinition;

          const stat = await fs.stat(filePath);

          flows.push({
            name: flow.name,
            description: flow.description,
            version: flow.version,
            owner: flow.metadata.owner,
            lastUpdatedAt: flow.metadata.lastUpdatedAt || stat.mtime.toISOString(),
            validationStatus: flow.metadata.validationStatus || 'draft',
            filePath,
          });
        } catch (error) {
          logger.warn(`Failed to parse flow file ${file}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      return flows.sort((a, b) => a.name.localeCompare(b.name));
    } catch (error) {
      logger.error(`Failed to list flows: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  /**
   * Delete a flow
   */
  async deleteFlow(name: string): Promise<void> {
    try {
      const filePath = this.getFlowFilePath(name);
      await fs.unlink(filePath);

      // Remove from cache
      this.flowCache.delete(name);

      logger.info(`Flow deleted: ${name}`);
    } catch (error) {
      if ((error as any).code === 'ENOENT') {
        throw new Error(`Flow not found: ${name}`);
      }

      logger.error(`Failed to delete flow ${name}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  /**
   * Validate a flow definition
   */
  validateFlow(flow: FlowDefinition): { errors: FlowValidationError[]; warnings: FlowValidationError[] } {
    const errors: FlowValidationError[] = [];
    const warnings: FlowValidationError[] = [];

    // Basic structure validation
    if (!flow.name || typeof flow.name !== 'string') {
      errors.push({
        path: 'name',
        message: 'Flow name is required and must be a string',
        severity: 'error',
      });
    }

    if (!flow.description || typeof flow.description !== 'string') {
      errors.push({
        path: 'description',
        message: 'Flow description is required and must be a string',
        severity: 'error',
      });
    }

    if (!flow.version || !this.isValidSemver(flow.version)) {
      errors.push({
        path: 'version',
        message: 'Flow version is required and must be a valid semantic version',
        severity: 'error',
      });
    }

    // Validate precondition
    if (!flow.precondition) {
      errors.push({
        path: 'precondition',
        message: 'Precondition is required',
        severity: 'error',
      });
    } else if (!flow.precondition.nodeId && !flow.precondition.query) {
      errors.push({
        path: 'precondition',
        message: 'Precondition must specify either nodeId or query',
        severity: 'error',
      });
    }

    // Validate postcondition
    if (!flow.postcondition) {
      errors.push({
        path: 'postcondition',
        message: 'Postcondition is required',
        severity: 'error',
      });
    } else if (!flow.postcondition.nodeId && !flow.postcondition.query) {
      errors.push({
        path: 'postcondition',
        message: 'Postcondition must specify either nodeId or query',
        severity: 'error',
      });
    }

    // Validate steps
    if (!flow.steps || !Array.isArray(flow.steps)) {
      errors.push({
        path: 'steps',
        message: 'Steps array is required',
        severity: 'error',
      });
    } else if (flow.steps.length === 0) {
      warnings.push({
        path: 'steps',
        message: 'Flow has no steps defined',
        severity: 'warning',
      });
    } else {
      flow.steps.forEach((step, index) => {
        const stepPath = `steps[${index}]`;

        if (step.kind === 'edgeRef' && !step.edgeId) {
          errors.push({
            path: `${stepPath}.edgeId`,
            message: 'Edge reference step must specify edgeId',
            severity: 'error',
          });
        }

        if (step.kind === 'inline' && !step.inlineAction) {
          errors.push({
            path: `${stepPath}.inlineAction`,
            message: 'Inline step must specify inlineAction',
            severity: 'error',
          });
        }

        if (step.retryPolicy && (step.retryPolicy.maxAttempts < 1 || step.retryPolicy.delayMs < 0)) {
          errors.push({
            path: `${stepPath}.retryPolicy`,
            message: 'Retry policy must have maxAttempts >= 1 and delayMs >= 0',
            severity: 'error',
          });
        }
      });
    }

    // Validate recovery rules
    if (!flow.recovery || !Array.isArray(flow.recovery)) {
      errors.push({
        path: 'recovery',
        message: 'Recovery rules array is required',
        severity: 'error',
      });
    } else {
      const requiredTriggers = ['unexpected_node', 'system_dialog', 'timeout'];
      const existingTriggers = flow.recovery.map(rule => rule.trigger);

      requiredTriggers.forEach(trigger => {
        if (!existingTriggers.includes(trigger as any)) {
          warnings.push({
            path: 'recovery',
            message: `Missing recovery rule for trigger: ${trigger}`,
            severity: 'warning',
          });
        }
      });

      flow.recovery.forEach((rule, index) => {
        if (!rule.trigger || !rule.allowedActions || rule.allowedActions.length === 0) {
          errors.push({
            path: `recovery[${index}]`,
            message: 'Recovery rule must specify trigger and allowedActions',
            severity: 'error',
          });
        }
      });
    }

    return { errors, warnings };
  }

  /**
   * Clear the flow cache
   */
  clearCache(): void {
    this.flowCache.clear();
  }

  /**
   * Get the file path for a flow
   */
  private getFlowFilePath(name: string): string {
    const safeName = name.replace(/[^a-zA-Z0-9-_]/g, '_');
    return path.join(this.config.flowsDirectory, `${safeName}.yaml`);
  }

  /**
   * Validate basic flow structure
   */
  private validateFlowStructure(flow: any, filePath: string): void {
    if (!flow || typeof flow !== 'object') {
      throw new Error(`Invalid flow structure in ${filePath}: must be an object`);
    }

    const requiredFields = ['name', 'description', 'version', 'precondition', 'steps', 'postcondition', 'recovery'];
    for (const field of requiredFields) {
      if (!(field in flow)) {
        throw new Error(`Missing required field '${field}' in flow from ${filePath}`);
      }
    }
  }

  /**
   * Check if a string is valid semantic version
   */
  private isValidSemver(version: string): boolean {
    const semverRegex = /^\d+\.\d+\.\d+(-[a-zA-Z0-9\-\.]+)?(\+[a-zA-Z0-9\-\.]+)?$/;
    return semverRegex.test(version);
  }

  /**
   * Create the README file for the flows directory
   */
  private async createReadme(): Promise<void> {
    const readmeContent = `# MaynDrive Flows

This directory contains YAML flow definitions for automating MaynDrive interactions.

## Structure

Each flow is defined in a separate YAML file with the following structure:

\`\`\`yaml
name: example-flow
description: "Example flow for demonstrating the format"
version: "1.0.0"

variables:
  - name: phone
    description: "User phone number"
    type: string
    required: true
    prompt: "Enter phone number"

precondition:
  nodeId: "login-screen"  # or query with activity/texts

steps:
  - kind: edgeRef
    edgeId: "login-screen-enter-phone"
  - kind: inline
    inlineAction:
      action: type
      text: "{{phone}}"

postcondition:
  nodeId: "home-screen"

recovery:
  - trigger: unexpected_node
    allowedActions: [back, reopen]
  - trigger: system_dialog
    allowedActions: [dismiss]
  - trigger: timeout
    allowedActions: [retry, back]

metadata:
  owner: "operator-name"
  lastUpdatedAt: "2025-10-25T10:00:00Z"
  validationStatus: "validated"
\`\`\`

## Naming Conventions

- Flow names should use kebab-case (e.g., \`login-home\`)
- File names should match the flow name with .yaml extension
- Use descriptive names that indicate the start and end states

## Validation

Flows are automatically validated when loaded. Use the CLI tool to validate flows:

\`\`\`bash
scripts/flows/lint-flow.ts <flow-name>
\`\`\`

## Best Practices

1. Keep flows focused on a single user journey
2. Use meaningful variable names and descriptions
3. Include recovery rules for common failure scenarios
4. Test flows in a safe environment before production use
5. Update validation status when flows are ready for production
`;

    const readmePath = path.join(this.config.flowsDirectory, 'README.md');
    await fs.writeFile(readmePath, readmeContent, 'utf-8');
  }
}