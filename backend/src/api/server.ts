import express from 'express';
import type { Express } from 'express';
import cors from 'cors';
import { apiRouter } from './routes';
import { corsMiddleware, developmentCorsMiddleware, productionCorsMiddleware } from '../middleware/cors';

export const createServer = (): Express => {
  const app = express();

  app.disable('x-powered-by');

  // Select CORS middleware based on environment
  const environment = process.env.NODE_ENV || 'development';
  switch (environment) {
    case 'production':
      app.use(productionCorsMiddleware);
      break;
    case 'development':
      app.use(developmentCorsMiddleware);
      break;
    default:
      app.use(corsMiddleware);
      break;
  }

  app.use(express.json());

  app.use('/api', apiRouter);

  app.use((req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: `Route ${req.path} not found` } });
  });

  return app;
};

export const startServer = (port = 3001, host = '0.0.0.0') => {
  const app = createServer();
  return app.listen(port, host, () => {
    // eslint-disable-next-line no-console
    console.log(`Backend listening on http://${host}:${port}`);
  });
};
