import { Router } from 'express';
import { emulatorStartHandler } from './emulatorStart';
import { streamUrlHandler } from './streamUrl';
import { healthHandler } from './health';
import { emulatorStopHandler } from './emulatorStop';
import { appsRouter } from './apps';

const routes = Router();

routes.post('/emulator/start', emulatorStartHandler);
routes.post('/emulator/stop', emulatorStopHandler);
routes.get('/health', healthHandler);
routes.get('/stream/url', streamUrlHandler);

// Apps Library & Instrumentation Hub
routes.use('/apps', appsRouter);

export const apiRouter = routes;
