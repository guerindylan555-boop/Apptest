import { Router } from 'express';
import { emulatorStartHandler } from './emulatorStart';
import { streamUrlHandler } from './streamUrl';
import { healthHandler } from './health';
import { emulatorStopHandler } from './emulatorStop';

const routes = Router();

routes.post('/emulator/start', emulatorStartHandler);
routes.post('/emulator/stop', emulatorStopHandler);
routes.get('/health', healthHandler);
routes.get('/stream/url', streamUrlHandler);

export const apiRouter = routes;
