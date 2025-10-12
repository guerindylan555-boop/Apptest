import { Router } from 'express';
import { listHandler } from './list';
import { uploadHandler, uploadMiddleware } from './upload';
import { updateHandler } from './update';
import { deleteHandler } from './delete';
import { activityHandler } from './activity';
import { installLaunchHandler } from './installLaunch';
import {
  checkFridaEnabled,
  fridaServerHandler,
  fridaServerStatusHandler,
  fridaAttachHandler,
  fridaDetachHandler,
  fridaProcessesHandler
} from './frida';
import {
  startLogcatHandler,
  controlLogcatHandler,
  downloadLogcatHandler,
  listLogcatHandler
} from './logcat';
import {
  toggleProxyHandler,
  proxyStatusHandler
} from './proxy';

/**
 * Apps Library Routes
 *
 * Provides endpoints for APK management, installation, instrumentation, and logging.
 */

const appsRouter = Router();

// APK Library Management
appsRouter.get('/', listHandler);
appsRouter.post('/', uploadMiddleware, uploadHandler);
appsRouter.patch('/:id', updateHandler);
appsRouter.delete('/:id', deleteHandler);

// Activity Feed
appsRouter.get('/activity', activityHandler);

// Install & Launch
appsRouter.post('/:id/install-launch', installLaunchHandler);

// Frida Instrumentation (feature-flagged)
appsRouter.post('/frida/server', checkFridaEnabled, fridaServerHandler);
appsRouter.get('/frida/server', checkFridaEnabled, fridaServerStatusHandler);
appsRouter.post('/frida/attach', checkFridaEnabled, fridaAttachHandler);
appsRouter.post('/frida/detach', checkFridaEnabled, fridaDetachHandler);
appsRouter.get('/frida/processes', checkFridaEnabled, fridaProcessesHandler);

// Logcat Capture
appsRouter.post('/logcat/sessions', startLogcatHandler);
appsRouter.patch('/logcat/sessions/:id', controlLogcatHandler);
appsRouter.get('/logcat/sessions/:id', downloadLogcatHandler);
appsRouter.get('/logcat/sessions', listLogcatHandler);

// Proxy Toggle
appsRouter.post('/proxy/toggle', toggleProxyHandler);
appsRouter.get('/proxy/status', proxyStatusHandler);

export { appsRouter };
