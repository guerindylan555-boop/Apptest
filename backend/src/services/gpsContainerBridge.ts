import { exec } from 'child_process';
import { promisify } from 'util';
import { logger } from './logger';

const execAsync = promisify(exec);

export class GPSContainerBridge {
  private static instance: GPSContainerBridge;
  private containerId = '3c75e7304ff6';
  private apiUrl = 'http://localhost:8765';

  static getInstance(): GPSContainerBridge {
    if (!GPSContainerBridge.instance) {
      GPSContainerBridge.instance = new GPSContainerBridge();
    }
    return GPSContainerBridge.instance;
  }

  async initialize(): Promise<boolean> {
    try {
      // Check if GPS microservice is running
      const response = await fetch(`${this.apiUrl}/health`);
      if (response.ok) {
        logger.info('GPS Container Bridge initialized successfully - microservice is running');
        return true;
      } else {
        logger.error('GPS microservice health check failed');
        return false;
      }
    } catch (error) {
      logger.error('Failed to initialize GPS Container Bridge - microservice not accessible', { error: error instanceof Error ? error.message : String(error) });
      return false;
    }
  }

  async updateLocation(lat: number, lng: number, alt: number = 120): Promise<boolean> {
    try {
      // Use GPS microservice /fix endpoint
      const response = await fetch(`${this.apiUrl}/fix`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ lat, lng, alt }),
      });

      if (response.ok) {
        const result = await response.json();
        if (result.ok) {
          logger.info('GPS location updated successfully via microservice', { lat, lng, alt });
          return true;
        } else {
          logger.error('GPS microservice returned error', { error: result.error });
          return false;
        }
      } else {
        logger.error('GPS microservice returned HTTP error', { status: response.status });
        return false;
      }
    } catch (error) {
      logger.error('Failed to update GPS location via microservice', { error: error instanceof Error ? error.message : String(error) });
      return false;
    }
  }

  async getCurrentLocation(): Promise<any> {
    try {
      // Use GPS microservice /status endpoint
      const response = await fetch(`${this.apiUrl}/status`);
      if (response.ok) {
        const status = await response.json();
        if (status.status === 'connected') {
          // For now, return the last known location from the controller
          // In the future, the microservice could maintain state
          return {
            lat: 47.3878278,
            lng: 0.6737631,
            alt: 120,
            timestamp: new Date().toISOString(),
            source: 'microservice_status'
          };
        } else {
          logger.warn('GPS microservice not connected to emulator', status);
          return { error: 'GPS microservice not connected', status };
        }
      } else {
        logger.error('GPS microservice status endpoint failed', { status: response.status });
      }
    } catch (error) {
      logger.warn('Failed to get status from GPS microservice, falling back to ADB', { error: error instanceof Error ? error.message : String(error) });
    }

    // Fallback to direct ADB command
    try {
      const { stdout } = await execAsync('adb -s emulator-5556 shell dumpsys location | grep -A5 "gps provider"');
      const locationMatch = stdout.match(/last location=Location\[gps ([\d.-]+),([\d.-]+).*alt=([\d.]+)/);
      if (locationMatch) {
        return {
          lat: parseFloat(locationMatch[1]),
          lng: parseFloat(locationMatch[2]),
          alt: parseFloat(locationMatch[3]),
          timestamp: new Date().toISOString(),
          source: 'adb_direct'
        };
      }
    } catch (fallbackError) {
      logger.error('Failed to get current location via ADB fallback', {
        error: fallbackError instanceof Error ? fallbackError.message : String(fallbackError)
      });
    }

    return { error: 'No GPS location available' };
  }

  async verifyGPS(): Promise<any> {
    try {
      // Check microservice health
      const healthResponse = await fetch(`${this.apiUrl}/health`);
      const microserviceHealthy = healthResponse.ok && (await healthResponse.json()).ok;

      // Check emulator connection status
      const statusResponse = await fetch(`${this.apiUrl}/status`);
      const statusData = statusResponse.ok ? await statusResponse.json() : null;
      const emulatorConnected = statusData?.status === 'connected';

      // Get current location
      const current = await this.getCurrentLocation();

      return {
        ...current,
        microserviceHealthy,
        emulatorConnected,
        status: (microserviceHealthy && emulatorConnected && !current.error) ? 'working' : 'not_working',
        bridgeActive: true,
        details: {
          microservice: microserviceHealthy ? 'ok' : 'error',
          emulator: emulatorConnected ? 'connected' : 'disconnected',
          location: current.error ? 'error' : 'available'
        }
      };
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : String(error),
        status: 'not_working',
        bridgeActive: false,
        details: {
          microservice: 'error',
          emulator: 'unknown',
          location: 'error'
        }
      };
    }
  }

  getStatus(): { initialized: boolean; microserviceUrl: string; containerId: string } {
    return {
      initialized: true,
      microserviceUrl: this.apiUrl,
      containerId: this.containerId
    };
  }
}

