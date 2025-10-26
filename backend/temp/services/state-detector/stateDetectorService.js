"use strict";
/**
 * State Detector Service
 *
 * Orchestrates the state detection process, runs scoring, applies thresholds,
 * and logs telemetry for continuous improvement.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.StateDetectorService = void 0;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const fast_xml_parser_1 = require("fast-xml-parser");
const scoring_1 = require("./scoring");
const logger_1 = require("../../utils/logger");
class StateDetectorService {
    constructor(graphStore, config = {}) {
        this.graphStore = graphStore;
        this.config = {
            confidenceMin: 75,
            confidenceAmbiguous: 50,
            maxCandidates: 5,
            enableTelemetry: true,
            ...config,
        };
        this.scoringEngine = new scoring_1.ScoringEngine({
            confidenceThreshold: this.config.confidenceMin,
            minCandidates: this.config.maxCandidates,
        });
        this.telemetryPath = path_1.default.join(process.cwd(), 'var', 'telemetry', 'state-detection.json');
    }
    /**
     * Detect the current state from an XML dump
     */
    async detectState(dumpPath) {
        const startTime = Date.now();
        logger_1.logger.info(`Starting state detection for dump: ${dumpPath}`);
        try {
            // Parse and extract features from XML dump
            const xmlDump = await this.parseXMLDump(dumpPath);
            // Load all active nodes from graph store
            const nodes = await this.loadActiveNodes();
            if (nodes.length === 0) {
                logger_1.logger.warn('No active nodes found in graph store');
                return this.createUnknownResult(dumpPath, 'No nodes available');
            }
            // Score against all nodes
            const candidates = await this.scoringEngine.scoreDump(xmlDump, nodes);
            const processingTime = Date.now() - startTime;
            // Create detection result
            const result = this.scoringEngine.createDetectionResult(candidates, dumpPath);
            // Log telemetry if enabled
            if (this.config.enableTelemetry) {
                await this.logTelemetry({
                    timestamp: new Date().toISOString(),
                    dumpPath,
                    status: result.status,
                    topScore: candidates.length > 0 ? candidates[0].score : 0,
                    candidatesCount: candidates.length,
                    processingTime,
                    selectedNodeId: result.selectedNodeId,
                });
            }
            logger_1.logger.info(`State detection completed: ${result.status}, top score: ${candidates[0]?.score || 0}`);
            return result;
        }
        catch (error) {
            const processingTime = Date.now() - startTime;
            logger_1.logger.error(`State detection failed: ${error instanceof Error ? error.message : String(error)}`);
            return this.createUnknownResult(dumpPath, `Detection error: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    /**
     * Parse XML dump and extract relevant features
     */
    async parseXMLDump(dumpPath) {
        const xmlContent = await promises_1.default.readFile(dumpPath, 'utf-8');
        const parser = new fast_xml_parser_1.XMLParser({
            ignoreAttributes: false,
            attributeNamePrefix: '@_',
            textNodeName: '#text',
        });
        const uiHierarchy = parser.parse(xmlContent);
        const rootElement = uiHierarchy.hierarchy || uiHierarchy;
        // Extract basic information
        const activity = this.extractActivity(rootElement);
        const resourceIds = this.extractResourceIds(rootElement);
        const visibleTexts = this.extractVisibleTexts(rootElement);
        const layoutFingerprint = this.generateLayoutFingerprint(rootElement);
        return {
            xmlContent,
            activity,
            resourceIds,
            visibleTexts,
            layoutFingerprint,
        };
    }
    /**
     * Extract current activity name from XML dump
     */
    extractActivity(rootElement) {
        // Try different possible locations for activity name
        if (rootElement['@_activity']) {
            return rootElement['@_activity'];
        }
        if (rootElement['@_package'] && rootElement['@_class']) {
            return `${rootElement['@_package']}.${rootElement['@_class']}`;
        }
        // Search through nodes for activity information
        const findActivity = (node) => {
            if (node['@_activity']) {
                return node['@_activity'];
            }
            if (node['@_focused'] === 'true' && node['@_class']) {
                return node['@_class'];
            }
            if (node.node) {
                const nodes = Array.isArray(node.node) ? node.node : [node.node];
                for (const child of nodes) {
                    const activity = findActivity(child);
                    if (activity)
                        return activity;
                }
            }
            return null;
        };
        return findActivity(rootElement) || 'unknown.activity';
    }
    /**
     * Extract all resource IDs from the hierarchy
     */
    extractResourceIds(rootElement) {
        const resourceIds = new Set();
        const traverse = (node) => {
            if (node['@_resource-id'] && node['@_resource-id'] !== '') {
                resourceIds.add(node['@_resource-id']);
            }
            if (node.node) {
                const nodes = Array.isArray(node.node) ? node.node : [node.node];
                for (const child of nodes) {
                    traverse(child);
                }
            }
        };
        traverse(rootElement);
        return Array.from(resourceIds);
    }
    /**
     * Extract all visible text content
     */
    extractVisibleTexts(rootElement) {
        const texts = new Set();
        const traverse = (node) => {
            // Extract text from various attributes
            const textSources = [
                node['@_text'],
                node['@_content-desc'],
                node['#text'],
                node['@_hint'],
                node['@_label'],
            ];
            for (const text of textSources) {
                if (text && typeof text === 'string' && text.trim().length > 0) {
                    texts.add(text.trim());
                }
            }
            // Continue traversal
            if (node.node) {
                const nodes = Array.isArray(node.node) ? node.node : [node.node];
                for (const child of nodes) {
                    traverse(child);
                }
            }
        };
        traverse(rootElement);
        return Array.from(texts);
    }
    /**
     * Generate layout fingerprint from node hierarchy
     */
    generateLayoutFingerprint(rootElement) {
        const extractStructure = (node, depth = 0) => {
            if (!node || typeof node !== 'object')
                return '';
            const attributes = [
                node['@_class'] || 'unknown',
                node['@_package'] || '',
                node['@_clickable'] === 'true' ? 'clickable' : '',
                node['@_checkable'] === 'true' ? 'checkable' : '',
                node['@_focusable'] === 'true' ? 'focusable' : '',
            ].filter(Boolean).join(':');
            let structure = `${'  '.repeat(depth)}${attributes}`;
            if (node.node) {
                const nodes = Array.isArray(node.node) ? node.node : [node.node];
                const children = nodes.map((child) => extractStructure(child, depth + 1)).filter(Boolean);
                if (children.length > 0) {
                    structure += '\n' + children.join('\n');
                }
            }
            return structure;
        };
        const structure = extractStructure(rootElement);
        const crypto = require('crypto');
        return crypto.createHash('md5').update(structure).digest('hex').substring(0, 16);
    }
    /**
     * Load all active nodes from graph store
     */
    async loadActiveNodes() {
        try {
            const graph = await this.graphStore.loadLatestGraph();
            return graph.nodes.filter(node => node.status === 'active');
        }
        catch (error) {
            logger_1.logger.error(`Failed to load nodes from graph store: ${error instanceof Error ? error.message : String(error)}`);
            return [];
        }
    }
    /**
     * Create an unknown result when detection fails
     */
    createUnknownResult(dumpPath, reason) {
        return {
            timestamp: new Date().toISOString(),
            dumpSource: dumpPath,
            topCandidates: [],
            status: 'unknown',
        };
    }
    /**
     * Log telemetry data for continuous improvement
     */
    async logTelemetry(entry) {
        try {
            // Ensure telemetry directory exists
            await promises_1.default.mkdir(path_1.default.dirname(this.telemetryPath), { recursive: true });
            // Read existing telemetry or create new array
            let telemetry = [];
            try {
                const existing = await promises_1.default.readFile(this.telemetryPath, 'utf-8');
                telemetry = JSON.parse(existing);
            }
            catch {
                // File doesn't exist or is invalid, start fresh
            }
            // Add new entry (keep last 1000 entries to avoid unbounded growth)
            telemetry.push(entry);
            if (telemetry.length > 1000) {
                telemetry = telemetry.slice(-1000);
            }
            // Write back to file
            await promises_1.default.writeFile(this.telemetryPath, JSON.stringify(telemetry, null, 2));
        }
        catch (error) {
            logger_1.logger.error(`Failed to log telemetry: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    /**
     * Get telemetry statistics for monitoring
     */
    async getTelemetryStats() {
        try {
            const data = await promises_1.default.readFile(this.telemetryPath, 'utf-8');
            const telemetry = JSON.parse(data);
            const totalDetections = telemetry.length;
            const successfulDetections = telemetry.filter(t => t.status === 'matched').length;
            const successRate = totalDetections > 0 ? (successfulDetections / totalDetections) * 100 : 0;
            const averageProcessingTime = totalDetections > 0
                ? telemetry.reduce((sum, t) => sum + t.processingTime, 0) / totalDetections
                : 0;
            // Score distribution
            const scoreRanges = {
                '90-100': 0,
                '75-89': 0,
                '50-74': 0,
                '25-49': 0,
                '0-24': 0,
            };
            telemetry.forEach(t => {
                const score = t.topScore;
                if (score >= 90)
                    scoreRanges['90-100']++;
                else if (score >= 75)
                    scoreRanges['75-89']++;
                else if (score >= 50)
                    scoreRanges['50-74']++;
                else if (score >= 25)
                    scoreRanges['25-49']++;
                else
                    scoreRanges['0-24']++;
            });
            return {
                totalDetections,
                successRate: Math.round(successRate * 100) / 100,
                averageProcessingTime: Math.round(averageProcessingTime * 100) / 100,
                topScoreDistribution: scoreRanges,
            };
        }
        catch (error) {
            logger_1.logger.error(`Failed to get telemetry stats: ${error instanceof Error ? error.message : String(error)}`);
            return {
                totalDetections: 0,
                successRate: 0,
                averageProcessingTime: 0,
                topScoreDistribution: {},
            };
        }
    }
    /**
     * Update detection result with operator feedback
     */
    async updateWithOperatorFeedback(dumpPath, action, selectedNodeId) {
        try {
            const data = await promises_1.default.readFile(this.telemetryPath, 'utf-8');
            const telemetry = JSON.parse(data);
            // Find the most recent detection for this dump
            const detectionIndex = telemetry.findIndex(t => t.dumpPath === dumpPath && !t.operatorAction);
            if (detectionIndex >= 0) {
                telemetry[detectionIndex].operatorAction = action;
                if (selectedNodeId) {
                    telemetry[detectionIndex].selectedNodeId = selectedNodeId;
                }
                await promises_1.default.writeFile(this.telemetryPath, JSON.stringify(telemetry, null, 2));
                logger_1.logger.info(`Updated detection for ${dumpPath} with operator action: ${action}`);
            }
        }
        catch (error) {
            logger_1.logger.error(`Failed to update operator feedback: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
}
exports.StateDetectorService = StateDetectorService;
