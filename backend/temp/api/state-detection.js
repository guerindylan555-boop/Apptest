"use strict";
/**
 * State Detection API Routes
 *
 * Provides REST endpoints for UI state detection using XML dumps
 * from the Android emulator.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const multer_1 = __importDefault(require("multer"));
const path_1 = __importDefault(require("path"));
const promises_1 = __importDefault(require("fs/promises"));
const stateDetectorService_1 = require("../services/state-detector/stateDetectorService");
const graphStore_1 = require("../services/ui-graph/graphStore");
const logger_1 = require("../utils/logger");
const router = express_1.default.Router();
// Configure multer for file uploads
const upload = (0, multer_1.default)({
    dest: 'var/uploads/',
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB max
    },
    fileFilter: (req, file, cb) => {
        // Accept XML files
        if (file.mimetype === 'application/xml' || file.originalname.endsWith('.xml')) {
            cb(null, true);
        }
        else {
            cb(new Error('Only XML files are allowed'));
        }
    },
});
// Initialize services
const graphStore = new graphStore_1.GraphStore();
const stateDetector = new stateDetectorService_1.StateDetectorService(graphStore);
/**
 * POST /state-detection
 * Detect UI state from uploaded XML dump
 */
router.post('/state-detection', upload.single('xml'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                error: 'No XML file provided',
                message: 'Please upload an XML dump file',
            });
        }
        logger_1.logger.info(`Processing state detection request for file: ${req.file.originalname}`);
        // Move uploaded file to captures directory with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `ui-dump-${timestamp}.xml`;
        const dumpPath = path_1.default.join('var', 'captures', 'temp', filename);
        // Ensure directory exists
        await promises_1.default.mkdir(path_1.default.dirname(dumpPath), { recursive: true });
        await promises_1.default.rename(req.file.path, dumpPath);
        // Run state detection
        const result = await stateDetector.detectState(dumpPath);
        // Return detection result
        res.json({
            success: true,
            data: result,
            dumpPath: `/captures/temp/${filename}`, // Relative path for frontend
        });
        logger_1.logger.info(`State detection completed: ${result.status} (confidence: ${result.topCandidates[0]?.score || 0})`);
    }
    catch (error) {
        logger_1.logger.error(`State detection failed: ${error instanceof Error ? error.message : String(error)}`);
        res.status(500).json({
            error: 'State detection failed',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});
/**
 * POST /state-detection/feedback
 * Submit operator feedback for a detection result
 */
router.post('/state-detection/feedback', async (req, res) => {
    try {
        const { dumpPath, action, selectedNodeId } = req.body;
        if (!dumpPath || !action) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'dumpPath and action are required',
            });
        }
        if (!['accept', 'map_new', 'merge', 'retry'].includes(action)) {
            return res.status(400).json({
                error: 'Invalid action',
                message: 'Action must be one of: accept, map_new, merge, retry',
            });
        }
        // Convert relative path back to absolute
        const absoluteDumpPath = path_1.default.isAbsolute(dumpPath)
            ? dumpPath
            : path_1.default.join('var', 'captures', 'temp', path_1.default.basename(dumpPath));
        await stateDetector.updateWithOperatorFeedback(absoluteDumpPath, action, selectedNodeId);
        res.json({
            success: true,
            message: 'Feedback recorded successfully',
        });
        logger_1.logger.info(`Operator feedback recorded: ${action} for ${dumpPath}`);
    }
    catch (error) {
        logger_1.logger.error(`Failed to record feedback: ${error instanceof Error ? error.message : String(error)}`);
        res.status(500).json({
            error: 'Failed to record feedback',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});
/**
 * GET /state-detection/stats
 * Get detection telemetry statistics
 */
router.get('/state-detection/stats', async (req, res) => {
    try {
        const stats = await stateDetector.getTelemetryStats();
        res.json({
            success: true,
            data: stats,
        });
    }
    catch (error) {
        logger_1.logger.error(`Failed to get telemetry stats: ${error instanceof Error ? error.message : String(error)}`);
        res.status(500).json({
            error: 'Failed to get telemetry stats',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});
/**
 * POST /state-detection/batch
 * Process multiple XML dumps in batch
 */
router.post('/state-detection/batch', upload.array('xml', 10), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({
                error: 'No XML files provided',
                message: 'Please upload one or more XML dump files',
            });
        }
        logger_1.logger.info(`Processing batch state detection for ${req.files.length} files`);
        const results = [];
        const errors = [];
        for (const file of req.files) {
            try {
                // Move uploaded file to captures directory with timestamp
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const filename = `ui-dump-${timestamp}-${file.originalname}`;
                const dumpPath = path_1.default.join('var', 'captures', 'temp', filename);
                // Ensure directory exists
                await promises_1.default.mkdir(path_1.default.dirname(dumpPath), { recursive: true });
                await promises_1.default.rename(file.path, dumpPath);
                // Run state detection
                const result = await stateDetector.detectState(dumpPath);
                results.push({
                    filename: file.originalname,
                    dumpPath: `/captures/temp/${filename}`,
                    result,
                });
            }
            catch (error) {
                errors.push({
                    filename: file.originalname,
                    error: error instanceof Error ? error.message : 'Unknown error',
                });
                logger_1.logger.error(`Batch detection failed for ${file.originalname}: ${error instanceof Error ? error.message : String(error)}`);
            }
        }
        res.json({
            success: true,
            data: {
                processed: results.length,
                errorCount: errors.length,
                results,
                errors,
            },
        });
        logger_1.logger.info(`Batch state detection completed: ${results.length} successful, ${errors.length} failed`);
    }
    catch (error) {
        logger_1.logger.error(`Batch state detection failed: ${error instanceof Error ? error.message : String(error)}`);
        res.status(500).json({
            error: 'Batch state detection failed',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});
/**
 * DELETE /state-detection/cleanup/:dumpPath
 * Clean up temporary XML dump files
 */
router.delete('/state-detection/cleanup/:dumpPath', async (req, res) => {
    try {
        const dumpPath = path_1.default.join('var', 'captures', 'temp', req.params.dumpPath);
        // Ensure we're only deleting from temp directory
        if (!dumpPath.includes('temp')) {
            return res.status(400).json({
                error: 'Invalid path',
                message: 'Can only delete files from temp directory',
            });
        }
        await promises_1.default.unlink(dumpPath);
        res.json({
            success: true,
            message: 'File deleted successfully',
        });
        logger_1.logger.info(`Deleted temporary dump file: ${dumpPath}`);
    }
    catch (error) {
        if (error.code === 'ENOENT') {
            return res.status(404).json({
                error: 'File not found',
                message: 'The specified dump file does not exist',
            });
        }
        logger_1.logger.error(`Failed to delete dump file: ${error instanceof Error ? error.message : String(error)}`);
        res.status(500).json({
            error: 'Failed to delete file',
            message: error instanceof Error ? error.message : 'Unknown error',
        });
    }
});
exports.default = router;
