import { startServer } from './api/server';
import { logger } from './services/logger';

const PORT = Number.parseInt(process.env.PORT ?? '3001', 10);
const HOST = process.env.HOST ?? '0.0.0.0';

const server = startServer(PORT, HOST);

logger.info('Backend booted', { port: PORT, host: HOST });

const shutdown = (signal: string) => {
  logger.warn('Shutting down backend', { signal });
  server.close(() => {
    process.exit(0);
  });
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', { error: error.message });
  process.exit(1);
});
