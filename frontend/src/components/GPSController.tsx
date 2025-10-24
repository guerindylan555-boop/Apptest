import React, { useState, useEffect, useCallback } from 'react';

interface Location {
  lat: number;
  lng: number;
  alt: number;
}

interface GPSControllerProps {
  className?: string;
}

export const GPSController: React.FC<GPSControllerProps> = ({ className }) => {
  const [currentLocation, setCurrentLocation] = useState<Location>({
    lat: 47.3878278,
    lng: 0.6737631,
    alt: 120,
  });

  const [newLocation, setNewLocation] = useState<Location>({
    lat: 47.3878278,
    lng: 0.6737631,
    alt: 120,
  });

  const [isUpdating, setIsUpdating] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [status, setStatus] = useState<string>('Ready');

  // Fetch current GPS location from emulator
  const fetchCurrentLocation = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:3001/api/gps/current');
      if (response.ok) {
        const data = await response.json();
        if (data.location && data.location.lat && data.location.lng) {
          setCurrentLocation({
            lat: data.location.lat,
            lng: data.location.lng,
            alt: data.location.alt || 120,
          });
        }
      }
    } catch (error) {
      console.error('[GPSController] Error fetching current location:', error);
    }
  }, []);

  // Poll current location every 5 seconds
  useEffect(() => {
    fetchCurrentLocation();
    const interval = setInterval(fetchCurrentLocation, 5000);
    return () => clearInterval(interval);
  }, [fetchCurrentLocation]);

  const updateGPSLocation = useCallback(async (location: Location) => {
    setIsUpdating(true);
    setStatus('Updating GPS...');

    try {
      const response = await fetch('http://localhost:3001/api/gps/update', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(location),
      });

      if (response.ok) {
        const result = await response.json();
        setCurrentLocation(location);
        setLastUpdate(new Date());
        setStatus('✅ Location updated');
        console.log('[GPSController] Location updated:', result);
      } else {
        setStatus('❌ Update failed');
        console.error('[GPSController] Failed to update location');
      }
    } catch (error) {
      setStatus('❌ Network error');
      console.error('[GPSController] Error updating location:', error);
    } finally {
      setIsUpdating(false);
      setTimeout(() => setStatus('Ready'), 2000);
    }
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateGPSLocation(newLocation);
  };

  return (
    <div className={`bg-gradient-to-br from-gray-900 via-blue-900 to-indigo-900 rounded-lg shadow-xl p-4 text-white ${className || ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <div className="w-2 h-2 bg-green-400 rounded-full mr-2 animate-pulse"></div>
          <h2 className="text-sm font-bold text-blue-200">GPS Control</h2>
        </div>
        <div className="px-2 py-1 bg-white/10 backdrop-blur-sm rounded text-xs">
          LIVE
        </div>
      </div>

      {/* Current Location Display */}
      <div className="mb-4 p-3 bg-gradient-to-r from-blue-500/20 to-indigo-500/20 backdrop-blur-sm rounded-lg border border-white/10">
        <div className="text-xs font-semibold text-blue-300 mb-2">Current Location</div>
        <div className="grid grid-cols-3 gap-3 text-xs">
          <div>
            <div className="text-gray-400">Lat:</div>
            <div className="font-mono font-bold text-white">
              {currentLocation.lat.toFixed(7)}
            </div>
          </div>
          <div>
            <div className="text-gray-400">Lng:</div>
            <div className="font-mono font-bold text-white">
              {currentLocation.lng.toFixed(7)}
            </div>
          </div>
          <div>
            <div className="text-gray-400">Alt:</div>
            <div className="font-mono font-bold text-white">
              {currentLocation.alt}m
            </div>
          </div>
        </div>
        {lastUpdate && (
          <div className="mt-2 text-xs text-gray-400">
            Last: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* Status Display */}
      <div className="mb-4">
        <div className={`text-center py-2 px-3 rounded text-xs backdrop-blur-sm transition-all ${
          status.includes('✅') ? 'bg-green-500/20 text-green-300' :
          status.includes('❌') ? 'bg-red-500/20 text-red-300' :
          'bg-white/10 text-gray-300'
        }`}>
          {status}
        </div>
      </div>

      {/* Manual Location Input */}
      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="text-xs font-semibold text-indigo-300 mb-2">Manual Coordinates</div>

        <div className="grid grid-cols-3 gap-2">
          <div>
            <input
              type="number"
              step="0.0000001"
              min="-90"
              max="90"
              value={newLocation.lat}
              onChange={(e) => setNewLocation({ ...newLocation, lat: parseFloat(e.target.value) || 0 })}
              className="w-full px-2 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded text-xs text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all disabled:opacity-50"
              disabled={isUpdating}
              placeholder="47.3878278"
            />
          </div>

          <div>
            <input
              type="number"
              step="0.0000001"
              min="-180"
              max="180"
              value={newLocation.lng}
              onChange={(e) => setNewLocation({ ...newLocation, lng: parseFloat(e.target.value) || 0 })}
              className="w-full px-2 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded text-xs text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all disabled:opacity-50"
              disabled={isUpdating}
              placeholder="0.6737631"
            />
          </div>

          <div>
            <input
              type="number"
              step="1"
              value={newLocation.alt}
              onChange={(e) => setNewLocation({ ...newLocation, alt: parseFloat(e.target.value) || 0 })}
              className="w-full px-2 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded text-xs text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all disabled:opacity-50"
              disabled={isUpdating}
              placeholder="120"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={isUpdating}
          className="w-full py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white text-xs font-semibold rounded shadow-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          {isUpdating ? '🔄 Updating...' : '📍 Update GPS'}
        </button>
      </form>
    </div>
  );
};