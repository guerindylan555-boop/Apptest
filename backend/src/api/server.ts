import express from 'express';
import type { Express } from 'express';
import cors from 'cors';
import { apiRouter } from './routes';

export const createServer = (): Express => {
  const app = express();

  app.disable('x-powered-by');

  // Enable CORS for local development
  const allowedOrigins = [
    'http://127.0.0.1:8080',
    'http://localhost:8080',
    'http://127.0.0.1:8081',
    'http://localhost:8081'
  ];

  app.use(cors({
    origin: allowedOrigins,
    credentials: false
  }));

  app.use(express.json());

  app.use('/api', apiRouter);

  app.use((req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: `Route ${req.path} not found` } });
  });

  return app;
};

export const startServer = (port = 8080, host = '127.0.0.1') => {
  const app = createServer();
  return app.listen(port, host, () => {
    // eslint-disable-next-line no-console
    console.log(`Backend listening on http://${host}:${port}`);
  });
};
