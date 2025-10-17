import { Router } from 'express';
import { emulatorStartHandler } from './emulatorStart';
import { streamUrlHandler } from './streamUrl';
import { healthHandler } from './health';
import { emulatorStopHandler } from './emulatorStop';
import { appsRouter } from './apps';
import automationRouter from './automation';

const routes = Router();

routes.post('/emulator/start', emulatorStartHandler);
routes.post('/emulator/stop', emulatorStopHandler);
routes.get('/health', healthHandler);
routes.get('/stream/url', streamUrlHandler);

// Apps Library & Instrumentation Hub
routes.use('/apps', appsRouter);

// Automation & Logging
routes.use('/automation', automationRouter);

export const apiRouter = routes;
