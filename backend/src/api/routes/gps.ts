import { Router } from 'express';
import gpsController from '../controllers/gpsController';

const router = Router();

// POST /api/gps/update - Update GPS location
router.post('/update', gpsController.updateLocation.bind(gpsController));

// GET /api/gps/current - Get current GPS location
router.get('/current', gpsController.getCurrentLocation.bind(gpsController));

// GET /api/gps/verify - Verify GPS status
router.get('/verify', gpsController.verifyGPS.bind(gpsController));

// POST /api/gps/setup - Run automatic GPS setup
router.post('/setup', gpsController.setupAutoGPS.bind(gpsController));

export default router;