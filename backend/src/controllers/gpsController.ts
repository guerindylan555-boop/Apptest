import { Request, Response } from 'express';
import { exec } from 'child_process';
import { promisify } from 'util';
import { GPSContainerBridge } from '../services/gpsContainerBridge';

const execAsync = promisify(exec);

interface LocationUpdate {
  lat: number;
  lng: number;
  alt: number;
}

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

      // Update GPS via container bridge
      const bridge = GPSContainerBridge.getInstance();
      const success = await bridge.updateLocation(lat, lng, alt);

      if (success) {
        this.currentLocation = { lat, lng, alt };

        console.log(`[GPSController] GPS updated successfully: ${lat}, ${lng}, ${alt}`);

        return res.json({
          success: true,
          location: this.currentLocation,
          message: 'GPS location updated successfully via container',
          timestamp: new Date().toISOString(),
        });
      } else {
        console.error(`[GPSController] GPS update failed via container bridge`);
        return res.status(500).json({
          error: 'Failed to update GPS',
          message: 'Container bridge failed',
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
      // Get current GPS status from container bridge
      const bridge = GPSContainerBridge.getInstance();
      const locationData = await bridge.getCurrentLocation();

      return res.json({
        success: true,
        location: this.currentLocation,
        containerLocation: locationData,
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
      // Use container bridge to verify GPS
      const bridge = GPSContainerBridge.getInstance();
      const verification = await bridge.verifyGPS();

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

  
  
  async setupAutoGPS() {
    try {
      console.log('[GPSController] Setting up automatic GPS via container bridge...');

      // Initialize container bridge
      const bridge = GPSContainerBridge.getInstance();
      const success = await bridge.initialize();

      if (success) {
        console.log('[GPSController] Container-based GPS system initialized successfully');
        return { success: true, message: 'GPS system initialized via container bridge' };
      } else {
        console.error('[GPSController] Failed to initialize container-based GPS system');
        return { success: false, error: 'Container bridge initialization failed' };
      }
    } catch (error) {
      console.error('[GPSController] Error in auto GPS setup:', error);
      return { success: false, error };
    }
  }
}

export default GPSController.getInstance();