import { exec } from 'child_process';
import { promisify } from 'util';
import { logger } from './logger';

const execAsync = promisify(exec);

export class GPSContainerBridge {
  private static instance: GPSContainerBridge;
  private containerId = 'apptest-emulator';
  private apiUrl = 'http://localhost:8765';

  static getInstance(): GPSContainerBridge {
    if (!GPSContainerBridge.instance) {
      GPSContainerBridge.instance = new GPSContainerBridge();
    }
    return GPSContainerBridge.instance;
  }

  async initialize(): Promise<boolean> {
    try {
      // Check if GPS service is running
      const response = await fetch(`${this.apiUrl}/health`);
      if (response.ok) {
        const result = await response.json();
        if (result.ok) {
          logger.info('GPS Container Bridge initialized successfully - service is running');
          return true;
        }
      }
      logger.warn('GPS service not ready yet');
      return false;
    } catch (error) {
      logger.warn('GPS service not yet available, will retry', { error: error instanceof Error ? error.message : String(error) });
      return false;
    }
  }

  async updateLocation(lat: number, lng: number, alt: number = 120): Promise<boolean> {
    try {
      // Use GPS service /fix endpoint
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
          logger.info('GPS location updated successfully via ADB emu', { lat, lng, alt });
          return true;
        } else {
          logger.error('GPS service returned error', { error: result });
          return false;
        }
      } else {
        logger.error('GPS service returned HTTP error', { status: response.status });
        return false;
      }
    } catch (error) {
      logger.error('Failed to update GPS location via service', { error: error instanceof Error ? error.message : String(error) });
      return false;
    }
  }

  async getCurrentLocation(): Promise<any> {
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
      // Check service health
      const healthResponse = await fetch(`${this.apiUrl}/health`);
      const serviceHealthy = healthResponse.ok && (await healthResponse.json()).ok;

      // Check emulator connection status
      const statusResponse = await fetch(`${this.apiUrl}/status`);
      const statusData = statusResponse.ok ? await statusResponse.json() : null;
      const emulatorConnected = statusData?.ok;

      // Get current location
      const current = await this.getCurrentLocation();

      return {
        ...current,
        serviceHealthy,
        emulatorConnected,
        status: (serviceHealthy && emulatorConnected && !current.error) ? 'working' : 'not_working',
        bridgeActive: true,
        details: {
          service: serviceHealthy ? 'ok' : 'error',
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
          service: 'error',
          emulator: 'unknown',
          location: 'error'
        }
      };
    }
  }

  getStatus(): { initialized: boolean; serviceUrl: string; containerId: string } {
    return {
      initialized: true,
      serviceUrl: this.apiUrl,
      containerId: this.containerId
    };
  }
}

