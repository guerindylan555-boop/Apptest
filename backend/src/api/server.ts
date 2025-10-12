import express from 'express';
import type { Express } from 'express';
import cors from 'cors';
import { apiRouter } from './routes';

export const createServer = (): Express => {
  const app = express();

  app.disable('x-powered-by');

  const defaultAllowedOrigins = [
    'http://127.0.0.1:5173',
    'http://localhost:5173',
    'http://127.0.0.1:3001',
    'http://localhost:3001'
  ];

  const envOrigins = process.env.CORS_ALLOWED_ORIGINS?.split(',')
    .map((value) => value.trim())
    .filter((value) => value.length > 0);

  const corsOptions =
    process.env.CORS_ALLOWED_ORIGINS?.trim() === '*'
      ? { origin: '*', credentials: false }
      : {
          origin: envOrigins && envOrigins.length > 0 ? envOrigins : defaultAllowedOrigins,
          credentials: false
        };

  app.use(cors(corsOptions));

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
