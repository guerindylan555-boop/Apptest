import { Request, Response } from 'express';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

interface LocationUpdate {
  lat: number;
  lng: number;
  alt: number;
}

const CONTAINER_ID = "3c75e7304ff6";
const AUTH_TOKEN = "v0y2z0gSoz7JAyqD";
const GPS_CONTROL_DIR = "/tmp/gps_control";

class GPSController {
  private static instance: GPSController;
  private currentLocation: LocationUpdate = {
    lat: 47.3878278,
    lng: 0.6737631,
    alt: 120,
  };

  static getInstance(): GPSController {
    if (!GPSController.instance) {
      GPSController.instance = new GPSController();
    }
    return GPSController.instance;
  }

  async updateLocation(req: Request, res: Response) {
    try {
      const { lat, lng, alt } = req.body as LocationUpdate;

      // Validate coordinates
      if (typeof lat !== 'number' || typeof lng !== 'number' || typeof alt !== 'number') {
        return res.status(400).json({
          error: 'Invalid coordinates',
          message: 'lat, lng, and alt must be numbers',
        });
      }

      if (lat < -90 || lat > 90) {
        return res.status(400).json({
          error: 'Invalid latitude',
          message: 'Latitude must be between -90 and 90',
        });
      }

      if (lng < -180 || lng > 180) {
        return res.status(400).json({
          error: 'Invalid longitude',
          message: 'Longitude must be between -180 and 180',
        });
      }

      console.log(`[GPSController] Updating location to: ${lat}, ${lng}, ${alt}`);

      // Update GPS via emulator console
      const gpsCommand = `printf "auth ${AUTH_TOKEN}\\r\\ngeo fix ${lng} ${lat} ${alt}\\r\\nquit\\r\\n" | nc -w 2 localhost 5556`;

      const { stdout, stderr } = await execAsync(gpsCommand);

      if (stderr && stderr.includes('OK')) {
        // GPS command succeeded
        this.currentLocation = { lat, lng, alt };

        // Update control file for daemon
        await this.updateGPSControlFile({ lat, lng, alt });

        console.log(`[GPSController] GPS updated successfully: ${lat}, ${lng}, ${alt}`);

        return res.json({
          success: true,
          location: this.currentLocation,
          message: 'GPS location updated successfully',
          timestamp: new Date().toISOString(),
        });
      } else {
        console.error(`[GPSController] GPS update failed:`, stderr);
        return res.status(500).json({
          error: 'Failed to update GPS',
          message: 'Emulator console command failed',
          details: stderr,
        });
      }
    } catch (error) {
      console.error('[GPSController] Error updating GPS:', error);
      return res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to update GPS location',
      });
    }
  }

  async getCurrentLocation(req: Request, res: Response) {
    try {
      // Get current GPS status from emulator
      const { stdout } = await execAsync(
        "adb -s emulator-5556 shell dumpsys location | grep -A5 'gps provider' | head -6"
      );

      const gpsStatus = this.parseGPSStatus(stdout);

      return res.json({
        success: true,
        location: this.currentLocation,
        gpsStatus,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('[GPSController] Error getting current location:', error);
      return res.status(500).json({
        error: 'Failed to get current location',
        location: this.currentLocation,
      });
    }
  }

  async verifyGPS(req: Request, res: Response) {
    try {
      const { stdout } = await execAsync(
        "adb -s emulator-5556 shell dumpsys location | grep -A5 'gps provider'"
      );

      const isEnabled = stdout.includes('enabled=true');
      const hasLocation = stdout.includes('last location=Location[gps');

      const verification = {
        gpsEnabled: isEnabled,
        hasLocation: hasLocation,
        status: isEnabled && hasLocation ? 'working' : 'not_working',
        details: stdout,
      };

      return res.json({
        success: true,
        verification,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('[GPSController] Error verifying GPS:', error);
      return res.status(500).json({
        error: 'Failed to verify GPS status',
      });
    }
  }

  private async updateGPSControlFile(location: LocationUpdate) {
    try {
      // Ensure control directory exists
      await fs.mkdir(GPS_CONTROL_DIR, { recursive: true });

      // Create update file for daemon
      const updateFile = path.join(GPS_CONTROL_DIR, 'update_location.txt');
      const content = `lat=${location.lat}\nlng=${location.lng}\nalt=${location.alt}\n`;
      await fs.writeFile(updateFile, content);

      // Update current location file
      const currentFile = path.join(GPS_CONTROL_DIR, 'current_location.txt');
      await fs.writeFile(currentFile, content);

      console.log(`[GPSController] GPS control file updated: ${content.trim()}`);
    } catch (error) {
      console.error('[GPSController] Error updating GPS control file:', error);
    }
  }

  private parseGPSStatus(statusOutput: string) {
    const lines = statusOutput.split('\n');
    const result: any = {};

    lines.forEach(line => {
      if (line.includes('last location=Location[gps')) {
        const match = line.match(/last location=Location\[gps ([\d.-]+),([\d.-]+).*alt=([\d.]+)/);
        if (match) {
          result.lastLocation = {
            lat: parseFloat(match[1]),
            lng: parseFloat(match[2]),
            alt: parseFloat(match[3]),
          };
        }
      } else if (line.includes('enabled=true')) {
        result.enabled = true;
      } else if (line.includes('enabled=false')) {
        result.enabled = false;
      }
    });

    return result;
  }

  async setupAutoGPS() {
    try {
      console.log('[GPSController] Setting up automatic GPS...');

      // Run the auto GPS setup script
      const { stdout, stderr } = await execAsync(
        '/home/blhack/project/Apptest/scripts/auto_gps_setup.sh'
      );

      if (stderr) {
        console.error('[GPSController] Auto GPS setup stderr:', stderr);
      }

      console.log('[GPSController] Auto GPS setup completed');
      return { success: true, output: stdout };
    } catch (error) {
      console.error('[GPSController] Error in auto GPS setup:', error);
      return { success: false, error };
    }
  }
}

export default GPSController.getInstance();