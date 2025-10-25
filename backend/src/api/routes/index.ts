import { Router } from 'express';
import { emulatorStartHandler } from './emulatorStart';
import { streamUrlHandler } from './streamUrl';
import { healthHandler } from './health';
import { emulatorStopHandler } from './emulatorStop';
import { appsRouter } from './apps';
import automationRouter from './automation';
import { emulatorRestartHandler } from './emulatorRestart';
import { logsRouter } from './logs';
import gpsRouter from './gps';
import uiGraphRouter from './ui-graph';

const routes = Router();

routes.post('/emulator/start', emulatorStartHandler);
routes.post('/emulator/stop', emulatorStopHandler);
routes.post('/emulator/restart', emulatorRestartHandler);
routes.get('/health', healthHandler);
routes.get('/stream/url', streamUrlHandler);
routes.use('/logs', logsRouter);

// GPS Location Control
routes.use('/gps', gpsRouter);

// Apps Library & Instrumentation Hub
routes.use('/apps', appsRouter);

// Automation & Logging
routes.use('/automation', automationRouter);

// UI Graph & Discovery
routes.use('/ui-graph', uiGraphRouter);

export const apiRouter = routes;
