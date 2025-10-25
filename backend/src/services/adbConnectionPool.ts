import { createClient, type Client } from '@dead50f7/adbkit';
import { logger } from './logger';
import { adb, type RunOptions } from './androidCli';

/**
 * ADB Connection Pool for High-Performance Operations
 *
 * Manages ADB connections with pooling, retry logic, and automatic recovery
 * to ensure sub-1s UI capture performance.
 */

export interface PoolConfig {
  /** Maximum concurrent connections per device */
  maxConnections: number;
  /** Connection timeout in milliseconds */
  connectionTimeout: number;
  /** Command timeout in milliseconds */
  commandTimeout: number;
  /** Maximum retry attempts for failed commands */
  maxRetries: number;
  /** Base delay between retries (exponential backoff) */
  retryBaseDelay: number;
  /** Health check interval in milliseconds */
  healthCheckInterval: number;
  /** Maximum connection age in milliseconds */
  maxConnectionAge: number;
}

export interface PooledConnection {
  /** Unique connection identifier */
  id: string;
  /** Device serial number */
  serial: string;
  /** ADB client instance */
  client: Client;
  /** Connection creation timestamp */
  createdAt: number;
  /** Last activity timestamp */
  lastUsed: number;
  /** Number of active operations */
  activeOperations: number;
  /** Whether connection is healthy */
  healthy: boolean;
}

export interface CommandResult<T = string> {
  success: boolean;
  data?: T;
  error?: string;
  executionTime: number;
  attempts: number;
}

const DEFAULT_CONFIG: PoolConfig = {
  maxConnections: 3,
  connectionTimeout: 10000,
  commandTimeout: 8000,
  maxRetries: 3,
  retryBaseDelay: 1000,
  healthCheckInterval: 30000,
  maxConnectionAge: 300000 // 5 minutes
};

/**
 * ADB Connection Pool Manager
 */
export class AdbConnectionPool {
  private config: PoolConfig;
  private connections: Map<string, PooledConnection[]> = new Map();
  private healthCheckTimer?: NodeJS.Timeout;
  private isShuttingDown = false;

  constructor(config: Partial<PoolConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.startHealthCheck();
  }

  /**
   * Execute ADB command with connection pooling and retry logic
   */
  async executeCommand<T = string>(
    serial: string,
    command: (client: Client) => Promise<T>,
    options: {
      timeout?: number;
      retries?: number;
      useDirectAdb?: boolean;
    } = {}
  ): Promise<CommandResult<T>> {
    const startTime = Date.now();
    const { timeout = this.config.commandTimeout, retries = this.config.maxRetries, useDirectAdb = false } = options;

    if (useDirectAdb) {
      return this.executeDirectAdbCommand<T>(serial, command, { timeout, retries });
    }

    for (let attempt = 1; attempt <= retries + 1; attempt++) {
      let connection: PooledConnection | undefined;

      try {
        // Get or create connection
        connection = await this.getConnection(serial);

        // Execute command with timeout
        const data = await this.executeWithTimeout(connection.client, command, timeout);

        // Update connection usage
        if (connection) {
          connection.lastUsed = Date.now();
          connection.activeOperations--;
        }

        const executionTime = Date.now() - startTime;

        return {
          success: true,
          data,
          executionTime,
          attempts: attempt
        };

      } catch (error) {
        const errorMessage = (error as Error).message;

        // Mark connection as unhealthy if it's the connection's fault
        if (connection && this.isConnectionError(errorMessage)) {
          connection.healthy = false;
          connection.activeOperations--;
          logger.warn('Connection marked as unhealthy', {
            connectionId: connection.id,
            serial,
            error: errorMessage
          });
        }

        if (attempt === retries + 1) {
          return {
            success: false,
            error: `Failed after ${retries + 1} attempts: ${errorMessage}`,
            executionTime: Date.now() - startTime,
            attempts: attempt
          };
        }

        // Exponential backoff with jitter
        const delay = Math.min(
          this.config.retryBaseDelay * Math.pow(2, attempt - 1) + Math.random() * 1000,
          10000
        );

        logger.debug(`Command execution attempt ${attempt} failed, retrying in ${delay}ms`, {
          serial,
          error: errorMessage,
          attempt
        });

        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    return {
      success: false,
      error: 'Unexpected error in retry loop',
      executionTime: Date.now() - startTime,
      attempts: 0
    };
  }

  /**
   * Execute command using direct ADB binary (fallback for complex operations)
   */
  private async executeDirectAdbCommand<T = string>(
    serial: string,
    command: (client: Client) => Promise<T>,
    options: { timeout: number; retries: number }
  ): Promise<CommandResult<T>> {
    // This would need to be implemented based on specific command types
    // For now, we'll use the existing androidCli service
    throw new Error('Direct ADB execution not implemented in this context');
  }

  /**
   * Get or create a connection for the specified device
   */
  private async getConnection(serial: string): Promise<PooledConnection> {
    const deviceConnections = this.connections.get(serial) || [];

    // Find existing healthy connection
    let connection = deviceConnections.find(conn =>
      conn.healthy && conn.activeOperations === 0
    );

    if (connection) {
      connection.activeOperations++;
      return connection;
    }

    // Check if we can create a new connection
    if (deviceConnections.length < this.config.maxConnections) {
      connection = await this.createConnection(serial);
      deviceConnections.push(connection);
      this.connections.set(serial, deviceConnections);
      connection.activeOperations++;
      return connection;
    }

    // Wait for an available connection
    return this.waitForAvailableConnection(serial);
  }

  /**
   * Create a new ADB connection
   */
  private async createConnection(serial: string): Promise<PooledConnection> {
    logger.info('Creating new ADB connection', { serial });

    try {
      const client = createClient();

      // Test connection with a simple command
      await this.executeWithTimeout(client, async (adbClient) => {
        const transport = await adbClient.transport(serial);
        await transport.command('echo', 'test');
      }, this.config.connectionTimeout);

      const connection: PooledConnection = {
        id: `${serial}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        serial,
        client,
        createdAt: Date.now(),
        lastUsed: Date.now(),
        activeOperations: 0,
        healthy: true
      };

      logger.info('ADB connection created successfully', { connectionId: connection.id, serial });
      return connection;

    } catch (error) {
      logger.error('Failed to create ADB connection', {
        serial,
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Wait for an available connection
   */
  private async waitForAvailableConnection(serial: string): Promise<PooledConnection> {
    const deviceConnections = this.connections.get(serial) || [];
    const startTime = Date.now();

    while (Date.now() - startTime < this.config.commandTimeout) {
      const connection = deviceConnections.find(conn =>
        conn.healthy && conn.activeOperations === 0
      );

      if (connection) {
        connection.activeOperations++;
        return connection;
      }

      await new Promise(resolve => setTimeout(resolve, 100));
    }

    throw new Error(`Timeout waiting for available connection for ${serial}`);
  }

  /**
   * Execute command with timeout
   */
  private async executeWithTimeout<T>(
    client: Client,
    command: (client: Client) => Promise<T>,
    timeoutMs: number
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Command execution timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      command(client)
        .then(result => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch(error => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  /**
   * Check if error is connection-related
   */
  private isConnectionError(errorMessage: string): boolean {
    const connectionErrorPatterns = [
      /connection refused/i,
      /connection reset/i,
      /broken pipe/i,
      /timeout/i,
      /device not found/i,
      /no device/i
    ];

    return connectionErrorPatterns.some(pattern => pattern.test(errorMessage));
  }

  /**
   * Start periodic health check
   */
  private startHealthCheck(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    this.healthCheckTimer = setInterval(() => {
      this.performHealthCheck();
    }, this.config.healthCheckInterval);
  }

  /**
   * Perform health check on all connections
   */
  private async performHealthCheck(): Promise<void> {
    if (this.isShuttingDown) return;

    logger.debug('Starting connection pool health check');

    for (const [serial, deviceConnections] of this.connections.entries()) {
      const unhealthyConnections: PooledConnection[] = [];

      for (const connection of deviceConnections) {
        try {
          // Check connection age
          const age = Date.now() - connection.createdAt;
          if (age > this.config.maxConnectionAge) {
            connection.healthy = false;
            unhealthyConnections.push(connection);
            continue;
          }

          // Perform health check
          if (connection.activeOperations === 0) {
            await this.executeWithTimeout(connection.client, async (client) => {
              const transport = await client.transport(serial);
              await transport.command('echo', 'health-check');
            }, 5000);

            connection.lastUsed = Date.now();
          }

        } catch (error) {
          logger.warn('Health check failed for connection', {
            connectionId: connection.id,
            serial,
            error: (error as Error).message
          });
          connection.healthy = false;
          unhealthyConnections.push(connection);
        }
      }

      // Remove unhealthy connections
      if (unhealthyConnections.length > 0) {
        await this.removeConnections(serial, unhealthyConnections);
      }
    }

    logger.debug('Health check completed');
  }

  /**
   * Remove connections from pool
   */
  private async removeConnections(serial: string, connectionsToRemove: PooledConnection[]): Promise<void> {
    const deviceConnections = this.connections.get(serial) || [];

    for (const connection of connectionsToRemove) {
      try {
        // Attempt graceful shutdown
        connection.client.end();
      } catch (error) {
        logger.warn('Error closing connection', {
          connectionId: connection.id,
          serial,
          error: (error as Error).message
        });
      }

      // Remove from pool
      const index = deviceConnections.indexOf(connection);
      if (index !== -1) {
        deviceConnections.splice(index, 1);
      }
    }

    // Update connections map
    if (deviceConnections.length === 0) {
      this.connections.delete(serial);
    } else {
      this.connections.set(serial, deviceConnections);
    }

    logger.info('Connections removed from pool', {
      serial,
      removedCount: connectionsToRemove.length,
      remainingCount: deviceConnections.length
    });
  }

  /**
   * Get pool statistics
   */
  getStats(): {
    totalConnections: number;
    connectionsByDevice: Record<string, { total: number; healthy: number; active: number }>;
    config: PoolConfig;
  } {
    const connectionsByDevice: Record<string, { total: number; healthy: number; active: number }> = {};
    let totalConnections = 0;

    for (const [serial, deviceConnections] of this.connections.entries()) {
      const healthy = deviceConnections.filter(conn => conn.healthy).length;
      const active = deviceConnections.reduce((sum, conn) => sum + conn.activeOperations, 0);

      connectionsByDevice[serial] = {
        total: deviceConnections.length,
        healthy,
        active
      };

      totalConnections += deviceConnections.length;
    }

    return {
      totalConnections,
      connectionsByDevice,
      config: this.config
    };
  }

  /**
   * Gracefully shutdown the connection pool
   */
  async shutdown(): Promise<void> {
    if (this.isShuttingDown) return;

    this.isShuttingDown = true;

    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = undefined;
    }

    logger.info('Shutting down ADB connection pool');

    const shutdownPromises: Promise<void>[] = [];

    for (const [serial, deviceConnections] of this.connections.entries()) {
      shutdownPromises.push(this.removeConnections(serial, deviceConnections));
    }

    await Promise.allSettled(shutdownPromises);

    this.connections.clear();

    logger.info('ADB connection pool shutdown completed');
  }
}

/**
 * Global connection pool instance
 */
export const globalAdbPool = new AdbConnectionPool();

/**
 * Cleanup on process exit
 */
process.on('SIGINT', async () => {
  await globalAdbPool.shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await globalAdbPool.shutdown();
  process.exit(0);
});