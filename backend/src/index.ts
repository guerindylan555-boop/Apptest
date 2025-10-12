import { startServer } from './api/server';
import { logger } from './services/logger';
import { initializeRepository } from './services/apps/appsRepository';
import { startScheduler, stopScheduler } from './services/apps/retentionScheduler';
import { initializeActivityLog } from './state/appsStore';

const PORT = Number.parseInt(process.env.PORT ?? '3001', 10);
const HOST = process.env.HOST ?? '0.0.0.0';

// Initialize apps library before starting server
async function bootstrap() {
  try {
    logger.info('Initializing apps library...');
    await initializeRepository();
    await initializeActivityLog();
    logger.info('Apps library initialized');

    // Start retention scheduler
    startScheduler();
    logger.info('Retention scheduler started');
  } catch (error) {
    logger.error('Failed to initialize apps library', { error });
    process.exit(1);
  }
}

bootstrap()
  .then(() => {
    const server = startServer(PORT, HOST);
    logger.info('Backend booted', { port: PORT, host: HOST });

    const shutdown = (signal: string) => {
      logger.warn('Shutting down backend', { signal });
      stopScheduler();
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
  })
  .catch((error) => {
    logger.error('Bootstrap failed', { error });
    process.exit(1);
  });
