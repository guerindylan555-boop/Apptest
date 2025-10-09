import { startServer } from './api/server';
import { logger } from './services/logger';
import { initializeSession } from './services/sessionInitializer';

const PORT = Number.parseInt(process.env.PORT ?? '7070', 10);
const HOST = process.env.HOST ?? '127.0.0.1';

const server = startServer(PORT, HOST);

logger.info('Backend booted', { port: PORT, host: HOST });

// Check for already-running emulators and reconnect if found
void initializeSession();

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
