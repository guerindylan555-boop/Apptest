import { exec } from 'child_process';
import { promisify } from 'util';
import { logger } from './logger';

const execAsync = promisify(exec);

export class GPSService {
  private static instance: GPSService;
  private isInitialized = false;

  static getInstance(): GPSService {
    if (!GPSService.instance) {
      GPSService.instance = new GPSService();
    }
    return GPSService.instance;
  }

  async initialize(): Promise<boolean> {
    if (this.isInitialized) {
      logger.info('GPS Service already initialized');
      return true;
    }

    try {
      logger.info('Initializing GPS Service...');

      // Wait for emulator to be ready
      const emulatorReady = await this.waitForEmulator();
      if (!emulatorReady) {
        logger.error('Emulator not ready, GPS initialization failed');
        return false;
      }

      // Run automatic GPS setup
      await this.setupAutoGPS();

      // Set initial location
      await this.setInitialLocation();

      // Verify GPS is working
      const verification = await this.verifyGPS();

      if (verification.gpsEnabled && verification.hasLocation) {
        this.isInitialized = true;
        logger.info('GPS Service initialized successfully', verification);
        return true;
      } else {
        logger.error('GPS verification failed', verification);
        return false;
      }
    } catch (error) {
      logger.error('Failed to initialize GPS Service', error);
      return false;
    }
  }

  private async waitForEmulator(): Promise<boolean> {
    logger.info('Waiting for emulator to be ready...');
    const maxAttempts = 60;

    for (let i = 0; i < maxAttempts; i++) {
      try {
        const { stdout } = await execAsync(
          "adb -s emulator-5556 shell getprop sys.boot_completed 2>/dev/null",
          { timeout: 5000 }
        );

        if (stdout.trim() === '1') {
          logger.info('Emulator is ready');
          return true;
        }
      } catch (error) {
        // Continue trying
      }

      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    return false;
  }

  private async setupAutoGPS(): Promise<void> {
    logger.info('Setting up automatic GPS...');

    const setupScript = '/home/blhack/project/Apptest/scripts/auto_gps_setup.sh';

    try {
      const { stdout, stderr } = await execAsync(`bash ${setupScript}`, {
        timeout: 60000
      });

      if (stderr) {
        logger.warn('GPS setup script stderr:', stderr);
      }

      logger.info('GPS setup completed');
    } catch (error) {
      logger.error('GPS setup failed:', error);
      throw error;
    }
  }

  private async setInitialLocation(): Promise<void> {
    logger.info('Setting initial GPS location...');

    const CONTAINER_ID = "3c75e7304ff6";
    const AUTH_TOKEN = "v0y2z0gSoz7JAyqD";
    const TARGET_LAT = "47.3878278";
    const TARGET_LNG = "0.6737631";
    const TARGET_ALT = "120";

    const gpsCommand = `docker exec -i ${CONTAINER_ID} bash -lc 'printf "auth %s\\r\\ngeo fix %s %s %s\\r\\nquit\\r\\n" "$(cat ~/.emulator_console_auth_token)" | nc -w 2 localhost 5556'`;

    try {
      const { stdout, stderr } = await execAsync(gpsCommand, { timeout: 10000 });

      if (stderr.includes('OK')) {
        logger.info(`Initial GPS location set: ${TARGET_LAT}, ${TARGET_LNG}, ${TARGET_ALT}`);
      } else {
        throw new Error(`GPS command failed: ${stderr}`);
      }
    } catch (error) {
      logger.error('Failed to set initial GPS location:', error);
      throw error;
    }
  }

  private async verifyGPS(): Promise<any> {
    logger.info('Verifying GPS status...');

    try {
      const { stdout } = await execAsync(
        "adb -s emulator-5556 shell dumpsys location | grep -A5 'gps provider'"
      );

      const isEnabled = stdout.includes('enabled=true');
      const hasLocation = stdout.includes('last location=Location[gps');

      // Parse location details
      let locationDetails = null;
      const locationMatch = stdout.match(/last location=Location\[gps ([\d.-]+),([\d.-]+).*alt=([\d.]+)/);
      if (locationMatch) {
        locationDetails = {
          lat: parseFloat(locationMatch[1]),
          lng: parseFloat(locationMatch[2]),
          alt: parseFloat(locationMatch[3])
        };
      }

      const verification = {
        gpsEnabled: isEnabled,
        hasLocation: hasLocation,
        status: isEnabled && hasLocation ? 'working' : 'not_working',
        location: locationDetails,
        details: stdout
      };

      logger.info('GPS verification completed', verification);
      return verification;
    } catch (error) {
      logger.error('GPS verification failed:', error);
      return {
        gpsEnabled: false,
        hasLocation: false,
        status: 'not_working',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  async updateLocation(lat: number, lng: number, alt: number): Promise<boolean> {
    if (!this.isInitialized) {
      logger.warn('GPS Service not initialized, cannot update location');
      return false;
    }

    try {
      logger.info(`Updating GPS location to: ${lat}, ${lng}, ${alt}`);

      const CONTAINER_ID = "3c75e7304ff6";
      const AUTH_TOKEN = "v0y2z0gSoz7JAyqD";

      const gpsCommand = `docker exec -i ${CONTAINER_ID} bash -lc 'printf "auth %s\\r\\ngeo fix %s %s %s\\r\\nquit\\r\\n" "$(cat ~/.emulator_console_auth_token)" | nc -w 2 localhost 5556'`;
      const fullCommand = gpsCommand.replace('%s', AUTH_TOKEN).replace('%s', lng.toString()).replace('%s', lat.toString()).replace('%s', alt.toString());

      const { stdout, stderr } = await execAsync(fullCommand, { timeout: 10000 });

      if (stderr.includes('OK')) {
        logger.info(`GPS location updated successfully: ${lat}, ${lng}, ${alt}`);
        return true;
      } else {
        logger.error(`GPS update failed: ${stderr}`);
        return false;
      }
    } catch (error) {
      logger.error('Error updating GPS location:', error);
      return false;
    }
  }

  async getLocation(): Promise<any> {
    if (!this.isInitialized) {
      return { error: 'GPS Service not initialized' };
    }

    try {
      const { stdout } = await execAsync(
        "adb -s emulator-5556 shell dumpsys location | grep -A5 'gps provider'"
      );

      const locationMatch = stdout.match(/last location=Location\[gps ([\d.-]+),([\d.-]+).*alt=([\d.]+)/);
      if (locationMatch) {
        return {
          lat: parseFloat(locationMatch[1]),
          lng: parseFloat(locationMatch[2]),
          alt: parseFloat(locationMatch[3]),
          timestamp: new Date().toISOString()
        };
      }

      return { error: 'No GPS location available' };
    } catch (error) {
      logger.error('Error getting GPS location:', error);
      return { error: 'Failed to get GPS location' };
    }
  }

  getStatus(): { initialized: boolean } {
    return { initialized: this.isInitialized };
  }
}

export default GPSService.getInstance();