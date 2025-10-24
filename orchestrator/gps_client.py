#!/usr/bin/env python3
"""
GPS client for sidecar communication.
Handles communication with GPS sidecar container for mock location management.
"""

import requests
import time
import logging
import json
import subprocess
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

@dataclass
class GPSLocation:
    latitude: float
    longitude: float
    altitude: float = 120.0
    accuracy: float = 5.0
    timestamp: Optional[float] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).timestamp()

@dataclass
class GPSStatus:
    active: bool
    last_update: float
    current_location: Optional[GPSLocation] = None
    continuous_mode: bool = False
    update_interval: int = 30  # seconds

class GPSClient:
    """Client for GPS sidecar communication"""

    def __init__(self, sidecar_url: str = "http://localhost:8765", device_id: str = "emulator-5556"):
        self.sidecar_url = sidecar_url.rstrip('/')
        self.device_id = device_id
        self.session = requests.Session()
        self.session.timeout = 10
        self.default_location = GPSLocation(47.3878278, 0.6737631)  # Default coords
        self._current_location = None

    def _make_request(self, endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Tuple[bool, Dict[str, Any]]:
        """Make HTTP request to GPS sidecar"""
        try:
            url = f"{self.sidecar_url}{endpoint}"

            if method == "GET":
                response = self.session.get(url)
            elif method == "POST":
                response = self.session.post(url, json=data)
            elif method == "PUT":
                response = self.session.put(url, json=data)
            elif method == "DELETE":
                response = self.session.delete(url)
            else:
                return False, {"error": f"Unsupported HTTP method: {method}"}

            if response.status_code == 200:
                return True, response.json()
            else:
                logger.error(f"GPS sidecar request failed: {response.status_code} - {response.text}")
                return False, {"error": f"HTTP {response.status_code}", "message": response.text}

        except requests.exceptions.Timeout:
            logger.error("GPS sidecar request timed out")
            return False, {"error": "Request timeout"}
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to GPS sidecar")
            return False, {"error": "Connection error"}
        except Exception as e:
            logger.error(f"GPS sidecar request failed: {e}")
            return False, {"error": str(e)}

    def health_check(self) -> bool:
        """Check if GPS sidecar is healthy"""
        success, response = self._make_request("/health")
        if success:
            logger.info(f"GPS sidecar health: {response.get('status', 'unknown')}")
            return True
        else:
            logger.error("GPS sidecar health check failed")
            return False

    def get_current_location(self) -> Optional[GPSLocation]:
        """Get current GPS location from sidecar"""
        success, response = self._make_request("/fix")
        if success and "location" in response:
            loc_data = response["location"]
            location = GPSLocation(
                latitude=loc_data["latitude"],
                longitude=loc_data["longitude"],
                altitude=loc_data.get("altitude", 120.0),
                accuracy=loc_data.get("accuracy", 5.0),
                timestamp=loc_data.get("timestamp", time.time())
            )
            self._current_location = location
            return location
        else:
            logger.warning("Failed to get current location from GPS sidecar")
            return None

    def get_status(self) -> Optional[GPSStatus]:
        """Get GPS sidecar status"""
        success, response = self._make_request("/status")
        if success:
            status_data = response.get("status", {})

            current_location = None
            if "current_location" in status_data:
                loc_data = status_data["current_location"]
                current_location = GPSLocation(
                    latitude=loc_data["latitude"],
                    longitude=loc_data["longitude"],
                    altitude=loc_data.get("altitude", 120.0),
                    accuracy=loc_data.get("accuracy", 5.0),
                    timestamp=loc_data.get("timestamp", time.time())
                )

            return GPSStatus(
                active=status_data.get("active", False),
                last_update=status_data.get("last_update", 0),
                current_location=current_location,
                continuous_mode=status_data.get("continuous_mode", False),
                update_interval=status_data.get("update_interval", 30)
            )
        else:
            logger.error("Failed to get GPS status")
            return None

    def set_location(self, latitude: float, longitude: float, altitude: float = 120.0) -> bool:
        """
        Set GPS location via sidecar

        Args:
            latitude: Latitude in degrees
            longitude: Longitude in degrees
            altitude: Altitude in meters (default: 120)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Send to sidecar first
            location_data = {
                "latitude": latitude,
                "longitude": longitude,
                "altitude": altitude
            }

            success, response = self._make_request("/fix", "POST", location_data)
            if success:
                logger.info(f"GPS location set via sidecar: {latitude}, {longitude}")
                self._current_location = GPSLocation(latitude, longitude, altitude)
            else:
                logger.error(f"Failed to set GPS location via sidecar: {response}")
                return False

            # Also set via ADB emulator command (fallback)
            try:
                adb_command = [
                    "adb", "-s", self.device_id, "emu", "geo", "fix",
                    f"{latitude:.6f}", f"{longitude:.6f}", f"{altitude:.1f}"
                ]
                result = subprocess.run(adb_command, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    logger.info("GPS location set via ADB emu geo fix")
                else:
                    logger.warning(f"ADB geo fix failed: {result.stderr}")
            except Exception as e:
                logger.warning(f"ADB geo fix error: {e}")

            return True

        except Exception as e:
            logger.error(f"Failed to set GPS location: {e}")
            return False

    def start_continuous_updates(self, interval_seconds: int = 30) -> bool:
        """
        Start continuous GPS updates

        Args:
            interval_seconds: Update interval in seconds

        Returns:
            True if successful, False otherwise
        """
        try:
            data = {"interval": interval_seconds}
            success, response = self._make_request("/continuous/start", "POST", data)

            if success:
                logger.info(f"Started continuous GPS updates with {interval_seconds}s interval")
                return True
            else:
                logger.error(f"Failed to start continuous updates: {response}")
                return False

        except Exception as e:
            logger.error(f"Failed to start continuous GPS updates: {e}")
            return False

    def stop_continuous_updates(self) -> bool:
        """Stop continuous GPS updates"""
        try:
            success, response = self._make_request("/continuous/stop", "POST")

            if success:
                logger.info("Stopped continuous GPS updates")
                return True
            else:
                logger.error(f"Failed to stop continuous updates: {response}")
                return False

        except Exception as e:
            logger.error(f"Failed to stop continuous GPS updates: {e}")
            return False

    def enable_mock_location(self) -> bool:
        """Enable mock location on device"""
        try:
            # Enable mock location via settings
            commands = [
                ["adb", "-s", self.device_id, "shell", "settings", "put", "secure", "mock_location", "1"],
                ["adb", "-s", self.device_id, "shell", "appops", "set", "android", "android:mock_location", "allow"]
            ]

            for cmd in commands:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode != 0:
                    logger.warning(f"Mock location command failed: {' '.join(cmd)} - {result.stderr}")
                else:
                    logger.info(f"Mock location command succeeded: {' '.join(cmd)}")

            logger.info("Mock location settings applied")
            return True

        except Exception as e:
            logger.error(f"Failed to enable mock location: {e}")
            return False

    def verify_gps_active(self) -> bool:
        """Verify GPS is active and providing location"""
        try:
            # Check GPS status
            status = self.get_status()
            if not status or not status.active:
                logger.warning("GPS sidecar not active")
                return False

            # Check recent location update
            if status.current_location:
                time_since_update = time.time() - status.current_location.timestamp
                if time_since_update > 60:  # More than 1 minute old
                    logger.warning(f"GPS location stale: {time_since_update:.0f}s old")
                    return False

            # Check Android location services
            try:
                cmd = ["adb", "-s", self.device_id, "shell", "dumpsys", "location"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    output = result.stdout
                    # Look for recent GPS location
                    if "gps provider" in output:
                        lines = output.split('\n')
                        for i, line in enumerate(lines):
                            if "gps provider" in line and i + 8 < len(lines):
                                # Check next few lines for location data
                                for j in range(1, 9):
                                    if i + j < len(lines):
                                        next_line = lines[i + j]
                                        if "Location[gps" in next_line:
                                            logger.info("GPS location active in Android")
                                            return True
                    logger.warning("No active GPS location found in Android")
                    return False
                else:
                    logger.warning("Failed to check Android location services")
                    return False

            except Exception as e:
                logger.warning(f"Error checking Android location: {e}")
                return False

        except Exception as e:
            logger.error(f"Failed to verify GPS active: {e}")
            return False

    def initialize_gps_system(self, enable_continuous: bool = True) -> bool:
        """
        Initialize GPS system with default location and settings

        Args:
            enable_continuous: Whether to start continuous updates

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            logger.info("Initializing GPS system...")

            # Check sidecar health
            if not self.health_check():
                logger.error("GPS sidecar not healthy")
                return False

            # Enable mock location on device
            if not self.enable_mock_location():
                logger.warning("Failed to enable mock location, continuing anyway...")

            # Set default location
            if not self.set_location(
                self.default_location.latitude,
                self.default_location.longitude,
                self.default_location.altitude
            ):
                logger.error("Failed to set default GPS location")
                return False

            # Start continuous updates if requested
            if enable_continuous:
                if not self.start_continuous_updates(30):
                    logger.warning("Failed to start continuous GPS updates")

            # Verify system is working
            if not self.verify_gps_active():
                logger.error("GPS system verification failed")
                return False

            logger.info("✅ GPS system initialized successfully")
            return True

        except Exception as e:
            logger.error(f"GPS system initialization failed: {e}")
            return False

    def get_location_for_maps(self) -> Optional[Tuple[float, float]]:
        """
        Get current location suitable for maps applications
        Returns (latitude, longitude) or None if not available
        """
        location = self.get_current_location()
        if location:
            return (location.latitude, location.longitude)
        return None

    def ensure_maps_ready(self) -> bool:
        """Ensure GPS is ready for maps application"""
        try:
            # Check if we have a current location
            location = self.get_current_location()
            if not location:
                logger.warning("No current location, setting default")
                if not self.set_location(
                    self.default_location.latitude,
                    self.default_location.longitude,
                    self.default_location.altitude
                ):
                    return False

            # Verify GPS is active
            if not self.verify_gps_active():
                logger.warning("GPS not active, attempting to refresh")
                # Refresh current location
                current_loc = self.get_current_location()
                if current_loc:
                    if not self.set_location(current_loc.latitude, current_loc.longitude, current_loc.altitude):
                        return False

            logger.info("GPS ready for maps")
            return True

        except Exception as e:
            logger.error(f"Failed to ensure maps ready: {e}")
            return False

if __name__ == "__main__":
    # Test GPS client
    gps_client = GPSClient()

    print("Testing GPS client...")

    # Health check
    if gps_client.health_check():
        print("✅ GPS sidecar healthy")
    else:
        print("❌ GPS sidecar not healthy")

    # Initialize GPS system
    if gps_client.initialize_gps_system():
        print("✅ GPS system initialized")

        # Get current location
        location = gps_client.get_current_location()
        if location:
            print(f"✅ Current location: {location.latitude}, {location.longitude}")

        # Get status
        status = gps_client.get_status()
        if status:
            print(f"✅ GPS status: active={status.active}, continuous={status.continuous_mode}")

    else:
        print("❌ GPS system initialization failed")