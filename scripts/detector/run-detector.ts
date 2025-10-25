#!/usr/bin/env ts-node

/**
 * CLI Helper for State Detection
 *
 * Analyzes UI XML dumps locally using the state detection engine.
 * Useful for debugging and testing detector performance.
 */

import fs from 'fs/promises';
import path from 'path';
import { program } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import { StateDetectorService } from '../../backend/src/services/state-detector/stateDetectorService';
import { GraphStore } from '../../backend/src/services/ui-graph/graphStore';
import { logger } from '../../backend/src/utils/logger';

interface CLIOptions {
  verbose: boolean;
  output: string;
  top: number;
  threshold: number;
}

const main = async () => {
  program
    .name('run-detector')
    .description('Analyze UI XML dumps using the state detection engine')
    .version('1.0.0');

  program
    .argument('<xml-path>', 'Path to UI XML dump file or directory containing dumps')
    .option('-v, --verbose', 'Enable verbose logging', false)
    .option('-o, --output <file>', 'Save results to JSON file')
    .option('-t, --top <number>', 'Number of top candidates to show', '5')
    .option('--threshold <number>', 'Minimum confidence threshold for matches', '75')
    .action(async (xmlPath: string, options: CLIOptions) => {
      try {
        // Configure logging based on verbose flag
        if (options.verbose) {
          logger.level = 'debug';
        }

        console.log(chalk.blue('🔍 MaynDrive State Detection CLI'));
        console.log(chalk.gray(`Analyzing: ${xmlPath}`));
        console.log();

        // Initialize services
        const graphStore = new GraphStore();
        const detector = new StateDetectorService(graphStore, {
          confidenceMin: parseFloat(options.threshold),
          maxCandidates: parseInt(options.top),
        });

        // Determine if xmlPath is a file or directory
        const stat = await fs.stat(xmlPath);
        const xmlFiles: string[] = [];

        if (stat.isFile()) {
          xmlFiles.push(xmlPath);
        } else if (stat.isDirectory()) {
          const files = await fs.readdir(xmlPath);
          xmlFiles.push(
            ...files
              .filter(file => file.endsWith('.xml'))
              .map(file => path.join(xmlPath, file))
          );
        } else {
          throw new Error('Invalid path: must be a file or directory');
        }

        if (xmlFiles.length === 0) {
          console.log(chalk.yellow('No XML files found.'));
          return;
        }

        console.log(chalk.gray(`Found ${xmlFiles.length} XML file(s) to analyze`));
        console.log();

        const results = [];

        // Process each XML file
        for (const xmlFile of xmlFiles) {
          console.log(chalk.cyan(`📄 Processing: ${path.basename(xmlFile)}`));

          try {
            const result = await detector.detectState(xmlFile);

            // Display results
            displayResults(result, options);

            results.push({
              file: xmlFile,
              result,
            });

            if (options.verbose) {
              console.log(chalk.gray(`   Status: ${result.status}`));
              console.log(chalk.gray(`   Dump: ${result.dumpSource}`));
            }

          } catch (error) {
            console.error(chalk.red(`   ✗ Failed: ${error instanceof Error ? error.message : String(error)}`));

            results.push({
              file: xmlFile,
              error: error instanceof Error ? error.message : String(error),
            });
          }

          console.log();
        }

        // Save results to file if requested
        if (options.output) {
          await fs.writeFile(options.output, JSON.stringify(results, null, 2));
          console.log(chalk.green(`💾 Results saved to: ${options.output}`));
        }

        // Show telemetry stats
        try {
          const stats = await detector.getTelemetryStats();
          console.log(chalk.blue('📊 Telemetry Statistics:'));
          console.log(chalk.gray(`   Total Detections: ${stats.totalDetections}`));
          console.log(chalk.gray(`   Success Rate: ${stats.successRate}%`));
          console.log(chalk.gray(`   Avg Processing Time: ${stats.averageProcessingTime}ms`));
          console.log();
        } catch (error) {
          // Ignore telemetry errors in CLI
        }

      } catch (error) {
        console.error(chalk.red('❌ Error:'), error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  // Add a stats command to show telemetry
  program
    .command('stats')
    .description('Show detection telemetry statistics')
    .option('-v, --verbose', 'Show detailed score distribution', false)
    .action(async (options) => {
      try {
        const graphStore = new GraphStore();
        const detector = new StateDetectorService(graphStore);
        const stats = await detector.getTelemetryStats();

        console.log(chalk.blue('📊 State Detection Telemetry'));
        console.log();

        const statsTable = new Table({
          head: ['Metric', 'Value'],
          colWidths: [25, 20],
        });

        statsTable.push(
          ['Total Detections', stats.totalDetections.toString()],
          ['Success Rate', `${stats.successRate}%`],
          ['Avg Processing Time', `${stats.averageProcessingTime}ms`]
        );

        console.log(statsTable.toString());
        console.log();

        if (options.verbose && Object.keys(stats.topScoreDistribution).length > 0) {
          console.log(chalk.cyan('Score Distribution:'));
          const scoreTable = new Table({
            head: ['Score Range', 'Count'],
            colWidths: [15, 10],
          });

          Object.entries(stats.topScoreDistribution).forEach(([range, count]) => {
            scoreTable.push([range, count.toString()]);
          });

          console.log(scoreTable.toString());
        }

      } catch (error) {
        console.error(chalk.red('❌ Failed to get stats:'), error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  // Add a validate command to check XML dump format
  program
    .command('validate')
    .description('Validate XML dump format and structure')
    .argument('<xml-path>', 'Path to XML dump file')
    .action(async (xmlPath: string) => {
      try {
        console.log(chalk.blue('🔧 Validating XML dump format...'));
        console.log(chalk.gray(`File: ${xmlPath}`));
        console.log();

        const content = await fs.readFile(xmlPath, 'utf-8');

        // Basic XML validation
        if (!content.trim().startsWith('<')) {
          throw new Error('File does not appear to be valid XML');
        }

        // Try to parse with fast-xml-parser
        const { XMLParser } = await import('fast-xml-parser');
        const parser = new XMLParser();
        const parsed = parser.parse(content);

        console.log(chalk.green('✓ XML is well-formed'));

        // Check for hierarchy element
        if (parsed.hierarchy || parsed.node) {
          console.log(chalk.green('✓ Contains UI hierarchy data'));
        } else {
          console.log(chalk.yellow('⚠ May not contain complete UI hierarchy'));
        }

        // Extract basic stats
        const stats = extractXMLStats(parsed);
        console.log();
        console.log(chalk.cyan('XML Statistics:'));

        const statsTable = new Table({
          head: ['Metric', 'Value'],
          colWidths: [20, 15],
        });

        statsTable.push(
          ['Total Nodes', stats.nodeCount.toString()],
          ['Resource IDs', stats.resourceCount.toString()],
          ['Text Elements', stats.textCount.toString()],
          ['Max Depth', stats.maxDepth.toString()]
        );

        console.log(statsTable.toString());

      } catch (error) {
        console.error(chalk.red('❌ Validation failed:'), error instanceof Error ? error.message : String(error));
        process.exit(1);
      }
    });

  await program.parseAsync();
};

function displayResults(result: any, options: CLIOptions) {
  const table = new Table({
    head: ['Node ID', 'Score', 'Status', 'Details'],
    colWidths: [20, 10, 12, 30],
  });

  if (result.topCandidates.length === 0) {
    table.push(['N/A', '0', result.status.toUpperCase(), 'No matches found']);
  } else {
    result.topCandidates.slice(0, parseInt(options.top)).forEach((candidate: any, index: number) => {
      const isTopMatch = index === 0;
      const status = isTopMatch && result.selectedNodeId ? 'SELECTED' : 'CANDIDATE';
      const details = isTopMatch ? `Top match - ${result.status}` : 'Alternative candidate';

      table.push([
        candidate.nodeId.substring(0, 16) + '...',
        candidate.score.toString(),
        status,
        details,
      ]);
    });
  }

  console.log(table.toString());
}

function extractXMLStats(parsed: any) {
  let nodeCount = 0;
  let resourceCount = 0;
  let textCount = 0;
  let maxDepth = 0;

  const traverse = (node: any, depth = 0) => {
    if (!node || typeof node !== 'object') return;

    nodeCount++;
    maxDepth = Math.max(maxDepth, depth);

    if (node['@_resource-id'] && node['@_resource-id'] !== '') {
      resourceCount++;
    }

    const hasText = [
      node['@_text'],
      node['@_content-desc'],
      node['#text'],
      node['@_hint'],
      node['@_label'],
    ].some(text => text && typeof text === 'string' && text.trim().length > 0);

    if (hasText) {
      textCount++;
    }

    if (node.node) {
      const nodes = Array.isArray(node.node) ? node.node : [node.node];
      for (const child of nodes) {
        traverse(child, depth + 1);
      }
    }
  };

  traverse(parsed.hierarchy || parsed);

  return { nodeCount, resourceCount, textCount, maxDepth };
}

if (require.main === module) {
  main().catch(error => {
    console.error(chalk.red('Unhandled error:'), error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}