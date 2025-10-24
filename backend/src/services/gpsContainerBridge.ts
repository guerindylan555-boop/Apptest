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
      // Copy GPS script to container if needed
      await execAsync(`sudo docker cp /home/blhack/project/Apptest/scripts/auto_gps_setup.sh ${this.containerId}:/tmp/`);

      // Run GPS setup in container
      await execAsync(`sudo docker exec -i ${this.containerId} bash /tmp/auto_gps_setup.sh`);

      logger.info('GPS Container Bridge initialized successfully');
      return true;
    } catch (error) {
      logger.error('Failed to initialize GPS Container Bridge', { error: error instanceof Error ? error.message : String(error) });
      return false;
    }
  }

  async updateLocation(lat: number, lng: number, alt: number = 120): Promise<boolean> {
    try {
      // Try container API first, fallback to file-based approach
      const response = await fetch(`${this.apiUrl}/update`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ lat, lng, alt }),
      });

      if (response.ok) {
        return true;
      }
    } catch (error) {
      // Fallback to file-based communication
      try {
        const updateCommand = `lat=${lat}\nlng=${lng}\nalt=${alt}`;
        await execAsync(`echo "${updateCommand}" | sudo docker exec -i ${this.containerId} bash -c "cat > /tmp/gps_control/update_location.txt"`);
        return true;
      } catch (fallbackError) {
        logger.error('Failed to update GPS location', {
          primaryError: error instanceof Error ? error.message : String(error),
          fallbackError: fallbackError instanceof Error ? fallbackError.message : String(fallbackError)
        });
        return false;
      }
    }

    return false;
  }

  async getCurrentLocation(): Promise<any> {
    try {
      // Try container API first
      const response = await fetch(`${this.apiUrl}/location`);
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      // Fallback to direct command
      try {
        const { stdout } = await execAsync('adb -s emulator-5556 shell dumpsys location | grep -A5 "gps provider"');
        const locationMatch = stdout.match(/last location=Location\[gps ([\d.-]+),([\d.-]+).*alt=([\d.]+)/);
        if (locationMatch) {
          return {
            lat: parseFloat(locationMatch[1]),
            lng: parseFloat(locationMatch[2]),
            alt: parseFloat(locationMatch[3]),
            timestamp: new Date().toISOString()
          };
        }
      } catch (fallbackError) {
        logger.error('Failed to get current location', {
          primaryError: error instanceof Error ? error.message : String(error),
          fallbackError: fallbackError instanceof Error ? fallbackError.message : String(fallbackError)
        });
        return { error: 'Failed to get GPS location' };
      }
    }

    return { error: 'No GPS location available' };
  }

  async verifyGPS(): Promise<any> {
    const current = await this.getCurrentLocation();
    return {
      ...current,
      status: current.error ? 'not_working' : 'working',
      bridgeActive: true
    };
  }

  getStatus(): { initialized: boolean } {
    return { initialized: true };
  }
}

