#!/usr/bin/env ts-node

/**
 * Flow Lint CLI Tool
 *
 * Validates flow definitions for references, recovery coverage,
 * and YAML schema compliance.
 */

import fs from 'fs/promises';
import path from 'path';
import { program } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import { FlowRepository } from '../../backend/src/services/flows/flowRepository';
import { GraphStore } from '../../backend/src/services/ui-graph/graphStore';

interface LintOptions {
  verbose: boolean;
  fix: boolean;
  checkReferences: boolean;
  checkRecovery: boolean;
  output: string;
}

interface LintResult {
  flowName: string;
  valid: boolean;
  errors: Array<{
    type: 'structure' | 'reference' | 'recovery' | 'schema';
    message: string;
    path?: string;
    severity: 'error' | 'warning';
  }>;
  warnings: Array<{
    type: 'structure' | 'reference' | 'recovery' | 'schema';
    message: string;
    path?: string;
    severity: 'warning';
  }>;
  fixedIssues: string[];
}

class FlowLinter {
  private flowRepository: FlowRepository;
  private graphStore: GraphStore;

  constructor() {
    this.flowRepository = new FlowRepository();
    this.graphStore = new GraphStore();
  }

  /**
   * Lint a single flow
   */
  async lintFlow(flowName: string, options: LintOptions): Promise<LintResult> {
    console.log(chalk.blue(`🔍 Linting flow: ${flowName}`));

    const result: LintResult = {
      flowName,
      valid: true,
      errors: [],
      warnings: [],
      fixedIssues: [],
    };

    try {
      // Load flow
      const flow = await this.flowRepository.loadFlow(flowName);
      if (!flow) {
        result.errors.push({
          type: 'structure',
          message: 'Flow not found',
          severity: 'error',
        });
        result.valid = false;
        return result;
      }

      if (options.verbose) {
        console.log(chalk.gray(`Loaded flow: ${flow.name} v${flow.version}`));
      }

      // Basic validation
      const validation = this.flowRepository.validateFlow(flow);
      result.errors.push(...validation.errors.map(e => ({ ...e, type: 'structure' as const })));
      result.warnings.push(...validation.warnings.map(w => ({ ...w, type: 'structure' as const })));

      if (validation.errors.length > 0) {
        result.valid = false;
      }

      // Check edge references
      if (options.checkReferences) {
        const referenceErrors = await this.checkEdgeReferences(flow);
        result.errors.push(...referenceErrors);
        if (referenceErrors.length > 0) {
          result.valid = false;
        }
      }

      // Check recovery coverage
      if (options.checkRecovery) {
        const recoveryWarnings = this.checkRecoveryCoverage(flow);
        result.warnings.push(...recoveryWarnings);
      }

      // Check YAML schema compliance
      const schemaIssues = await this.checkYamlSchema(flow);
      result.errors.push(...schemaIssues.filter(e => e.severity === 'error'));
      result.warnings.push(...schemaIssues.filter(e => e.severity === 'warning'));
      if (schemaIssues.some(e => e.severity === 'error')) {
        result.valid = false;
      }

      // Attempt to fix issues if requested
      if (options.fix) {
        const fixedIssues = await this.fixIssues(flow, result.errors);
        result.fixedIssues.push(...fixedIssues);

        // Re-validate after fixes
        const revalidation = this.flowRepository.validateFlow(flow);
        result.errors = revalidation.errors.map(e => ({ ...e, type: 'structure' as const }));
        result.warnings = revalidation.warnings.map(w => ({ ...w, type: 'structure' as const }));
        result.valid = result.errors.length === 0;

        if (fixedIssues.length > 0) {
          await this.flowRepository.saveFlow(flow);
          console.log(chalk.green(`✓ Fixed ${fixedIssues.length} issues in ${flowName}`));
        }
      }

    } catch (error) {
      result.errors.push({
        type: 'structure',
        message: `Linting failed: ${error instanceof Error ? error.message : String(error)}`,
        severity: 'error',
      });
      result.valid = false;
    }

    return result;
  }

  /**
   * Check if all edge references exist in the graph
   */
  private async checkEdgeReferences(flow: any): Promise<Array<{
    type: 'reference';
    message: string;
    path: string;
    severity: 'error';
  }>> {
    const errors = [];

    try {
      const graph = await this.graphStore.loadLatestGraph();
      const edgeIds = new Set(graph.edges.map(e => e.id));

      for (let i = 0; i < flow.steps.length; i++) {
        const step = flow.steps[i];
        if (step.kind === 'edgeRef' && step.edgeId) {
          if (!edgeIds.has(step.edgeId)) {
            errors.push({
              type: 'reference' as const,
              message: `Edge not found in graph: ${step.edgeId}`,
              path: `steps[${i}].edgeId`,
              severity: 'error' as const,
            });
          }
        }
      }
    } catch (error) {
      errors.push({
        type: 'reference' as const,
        message: `Failed to load graph for reference checking: ${error instanceof Error ? error.message : String(error)}`,
        path: 'graph',
        severity: 'error' as const,
      });
    }

    return errors;
  }

  /**
   * Check recovery rule coverage
   */
  private checkRecoveryCoverage(flow: any): Array<{
    type: 'recovery';
    message: string;
    path: string;
    severity: 'warning';
  }> {
    const warnings = [];

    if (!flow.recovery || !Array.isArray(flow.recovery)) {
      warnings.push({
        type: 'recovery' as const,
        message: 'No recovery rules defined',
        path: 'recovery',
        severity: 'warning' as const,
      });
      return warnings;
    }

    const requiredTriggers = ['unexpected_node', 'system_dialog', 'timeout'];
    const existingTriggers = flow.recovery.map((rule: any) => rule.trigger);

    for (const trigger of requiredTriggers) {
      if (!existingTriggers.includes(trigger)) {
        warnings.push({
          type: 'recovery' as const,
          message: `Missing recovery rule for trigger: ${trigger}`,
          path: 'recovery',
          severity: 'warning' as const,
        });
      }
    }

    // Check if recovery rules have meaningful actions
    for (let i = 0; i < flow.recovery.length; i++) {
      const rule = flow.recovery[i];
      if (!rule.allowedActions || rule.allowedActions.length === 0) {
        warnings.push({
          type: 'recovery' as const,
          message: `Recovery rule has no allowed actions: ${rule.trigger}`,
          path: `recovery[${i}]`,
          severity: 'warning' as const,
        });
      }
    }

    return warnings;
  }

  /**
   * Check YAML schema compliance
   */
  private async checkYamlSchema(flow: any): Promise<Array<{
    type: 'schema';
    message: string;
    path?: string;
    severity: 'error' | 'warning';
  }>> {
    const issues = [];

    // Check required fields
    const requiredFields = ['name', 'description', 'version', 'precondition', 'steps', 'postcondition', 'recovery'];
    for (const field of requiredFields) {
      if (!(field in flow)) {
        issues.push({
          type: 'schema' as const,
          message: `Missing required field: ${field}`,
          path: field,
          severity: 'error' as const,
        });
      }
    }

    // Check field types
    if (flow.name && typeof flow.name !== 'string') {
      issues.push({
        type: 'schema' as const,
        message: 'Flow name must be a string',
        path: 'name',
        severity: 'error' as const,
      });
    }

    if (flow.version && typeof flow.version !== 'string') {
      issues.push({
        type: 'schema' as const,
        message: 'Flow version must be a string',
        path: 'version',
        severity: 'error' as const,
      });
    }

    if (flow.steps && !Array.isArray(flow.steps)) {
      issues.push({
        type: 'schema' as const,
        message: 'Flow steps must be an array',
        path: 'steps',
        severity: 'error' as const,
      });
    }

    if (flow.recovery && !Array.isArray(flow.recovery)) {
      issues.push({
        type: 'schema' as const,
        message: 'Flow recovery rules must be an array',
        path: 'recovery',
        severity: 'error' as const,
      });
    }

    // Check step structure
    if (Array.isArray(flow.steps)) {
      for (let i = 0; i < flow.steps.length; i++) {
        const step = flow.steps[i];
        const stepPath = `steps[${i}]`;

        if (!step.kind) {
          issues.push({
            type: 'schema' as const,
            message: 'Step missing kind field',
            path: stepPath,
            severity: 'error' as const,
          });
        }

        if (step.kind === 'edgeRef' && !step.edgeId) {
          issues.push({
            type: 'schema' as const,
            message: 'Edge reference step missing edgeId',
            path: `${stepPath}.edgeId`,
            severity: 'error' as const,
          });
        }

        if (step.kind === 'inline' && !step.inlineAction) {
          issues.push({
            type: 'schema' as const,
            message: 'Inline step missing inlineAction',
            path: `${stepPath}.inlineAction`,
            severity: 'error' as const,
          });
        }
      }
    }

    return issues;
  }

  /**
   * Attempt to fix common issues
   */
  private async fixIssues(flow: any, errors: any[]): Promise<string[]> {
    const fixedIssues = [];

    for (const error of errors) {
      if (error.type === 'structure' && error.path === 'metadata.lastUpdatedAt') {
        flow.metadata = {
          ...flow.metadata,
          lastUpdatedAt: new Date().toISOString(),
        };
        fixedIssues.push('Added missing lastUpdatedAt timestamp');
      }

      if (error.type === 'structure' && error.path === 'metadata.validationStatus') {
        flow.metadata = {
          ...flow.metadata,
          validationStatus: 'draft',
        };
        fixedIssues.push('Added missing validationStatus');
      }
    }

    return fixedIssues;
  }
}

const main = async () => {
  program
    .name('lint-flow')
    .description('Lint and validate MaynDrive flow definitions')
    .version('1.0.0');

  program
    .argument('[flow-names...]', 'Names of flows to lint (omits to lint all flows)')
    .option('-v, --verbose', 'Enable verbose output', false)
    .option('-f, --fix', 'Attempt to automatically fix issues', false)
    .option('--no-references', 'Skip edge reference checking', false)
    .option('--no-recovery', 'Skip recovery coverage checking', false)
    .option('-o, --output <file>', 'Save results to JSON file')
    .action(async (flowNames: string[], options: any) => {
      try {
        const lintOptions: LintOptions = {
          verbose: options.verbose,
          fix: options.fix,
          checkReferences: options.references,
          checkRecovery: options.recovery,
          output: options.output,
        };

        console.log(chalk.blue('🔧 MaynDrive Flow Linter'));
        console.log();

        const linter = new FlowLinter();

        // If no flow names provided, lint all flows
        if (flowNames.length === 0) {
          const allFlows = await linter.flowRepository.listFlows();
          flowNames = allFlows.map(f => f.name);
        }

        if (flowNames.length === 0) {
          console.log(chalk.yellow('No flows found to lint.'));
          return;
        }

        console.log(chalk.gray(`Linting ${flowNames.length} flow(s)...`));
        console.log();

        const results: LintResult[] = [];

        // Lint each flow
        for (const flowName of flowNames) {
          const result = await linter.lintFlow(flowName, lintOptions);
          results.push(result);

          // Display results
          const status = result.valid ? chalk.green('✓ PASS') : chalk.red('✗ FAIL');
          const errorCount = result.errors.length;
          const warningCount = result.warnings.length;

          console.log(`${status} ${flowName}`);
          if (errorCount > 0 || warningCount > 0) {
            console.log(chalk.gray(`  ${errorCount} errors, ${warningCount} warnings`));
          }

          if (options.verbose && (result.errors.length > 0 || result.warnings.length > 0)) {
            displayDetailedResults(result);
          }

          console.log();
        }

        // Summary
        const totalFlows = results.length;
        const validFlows = results.filter(r => r.valid).length;
        const totalErrors = results.reduce((sum, r) => sum + r.errors.length, 0);
        const totalWarnings = results.reduce((sum, r) => sum + r.warnings.length, 0);
        const totalFixed = results.reduce((sum, r) => sum + r.fixedIssues.length, 0);

        console.log(chalk.blue('📊 Summary:'));
        const summaryTable = new Table({
          head: ['Metric', 'Count'],
          colWidths: [20, 10],
        });

        summaryTable.push(
          ['Total Flows', totalFlows.toString()],
          ['Valid Flows', `${validFlows}/${totalFlows}`],
          ['Total Errors', totalErrors.toString()],
          ['Total Warnings', totalWarnings.toString()],
          ['Issues Fixed', totalFixed.toString()]
        );

        console.log(summaryTable.toString());

        // Save results if requested
        if (options.output) {
          await fs.writeFile(options.output, JSON.stringify(results, null, 2));
          console.log(chalk.green(`💾 Results saved to: ${options.output}`));
        }

        // Exit with error code if any flows failed
        if (validFlows < totalFlows) {
          process.exit(1);
        }

      } catch (error) {
        console.error(chalk.red('❌ Linting failed:'), error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  // Add command to initialize flow repository
  program
    .command('init')
    .description('Initialize the flow repository structure')
    .action(async () => {
      try {
        const repository = new FlowRepository();
        await repository.initialize();
        console.log(chalk.green('✓ Flow repository initialized successfully'));
      } catch (error) {
        console.error(chalk.red('❌ Failed to initialize repository:'), error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  await program.parseAsync();
};

function displayDetailedResults(result: LintResult) {
  if (result.errors.length > 0) {
    console.log(chalk.red('  Errors:'));
    result.errors.forEach(error => {
      console.log(chalk.red(`    ✗ ${error.message}`));
      if (error.path) {
        console.log(chalk.red(`      at: ${error.path}`));
      }
    });
  }

  if (result.warnings.length > 0) {
    console.log(chalk.yellow('  Warnings:'));
    result.warnings.forEach(warning => {
      console.log(chalk.yellow(`    ⚠ ${warning.message}`));
      if (warning.path) {
        console.log(chalk.yellow(`      at: ${warning.path}`));
      }
    });
  }

  if (result.fixedIssues.length > 0) {
    console.log(chalk.green('  Fixed:'));
    result.fixedIssues.forEach(issue => {
      console.log(chalk.green(`    ✓ ${issue}`));
    });
  }
}

if (require.main === module) {
  main().catch(error => {
    console.error(chalk.red('Unhandled error:'), error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}