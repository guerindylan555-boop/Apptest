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
import healthRouter from '../../routes/health';
import graphRouter from '../../routes/graph';
import corsRouter from './cors';

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

// UI Discovery & Graph Management
routes.use('/graph', graphRouter);
routes.use('/state', graphRouter);
routes.use('/sessions', graphRouter);
routes.use('/device', graphRouter);

// Health Check Endpoints (constitution compliance)
routes.use('/healthz', healthRouter);

// CORS Configuration and Health Check Endpoints
routes.use('/cors', corsRouter);

export const apiRouter = routes;
