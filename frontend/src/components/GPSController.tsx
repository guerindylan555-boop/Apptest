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
    <div className={`bg-gradient-to-br from-gray-900 via-blue-900 to-indigo-900 rounded-2xl shadow-2xl p-8 text-white ${className || ''}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center">
          <div className="relative mr-4">
            <div className="w-4 h-4 bg-green-400 rounded-full animate-pulse"></div>
            <div className="absolute inset-0 w-4 h-4 bg-green-400 rounded-full animate-ping opacity-75"></div>
          </div>
          <h2 className="text-2xl font-bold bg-gradient-to-r from-blue-300 to-indigo-300 bg-clip-text text-transparent">
            GPS Control Center
          </h2>
        </div>
        <div className="px-3 py-1 bg-white/10 backdrop-blur-sm rounded-full text-xs">
          LIVE
        </div>
      </div>

      {/* Current Location Display */}
      <div className="mb-8 p-6 bg-gradient-to-r from-blue-500/20 to-indigo-500/20 backdrop-blur-sm rounded-xl border border-white/10">
        <div className="flex items-center mb-4">
          <svg className="w-5 h-5 mr-2 text-blue-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          <h3 className="text-lg font-semibold text-blue-200">Current Location</h3>
        </div>
        <div className="grid grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-xs text-gray-400 mb-1 uppercase tracking-wider">Latitude</div>
            <div className="text-lg font-mono font-bold text-white">
              {currentLocation.lat.toFixed(7)}
            </div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-400 mb-1 uppercase tracking-wider">Longitude</div>
            <div className="text-lg font-mono font-bold text-white">
              {currentLocation.lng.toFixed(7)}
            </div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-400 mb-1 uppercase tracking-wider">Altitude</div>
            <div className="text-lg font-mono font-bold text-white">
              {currentLocation.alt}m
            </div>
          </div>
        </div>
        {lastUpdate && (
          <div className="mt-4 text-xs text-gray-400 text-center">
            Last updated: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* Status Display */}
      <div className="mb-8">
        <div className={`text-center py-3 px-6 rounded-full backdrop-blur-sm transition-all duration-300 ${
          status.includes('✅') ? 'bg-green-500/20 text-green-300 border border-green-500/30' :
          status.includes('❌') ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
          'bg-white/10 text-gray-300 border border-white/20'
        }`}>
          <span className="flex items-center justify-center">
            {status.includes('🔄') && <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>}
            {status}
          </span>
        </div>
      </div>

      {/* Manual Location Input */}
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="flex items-center mb-4">
          <svg className="w-5 h-5 mr-2 text-indigo-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V8a1 1 0 102 0V4a1 1 0 00-1-1h-4z" />
          </svg>
          <h3 className="text-lg font-semibold text-indigo-200">Manual Coordinates</h3>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-2 uppercase tracking-wider">
              Latitude
            </label>
            <div className="relative">
              <input
                type="number"
                step="0.0000001"
                min="-90"
                max="90"
                value={newLocation.lat}
                onChange={(e) => setNewLocation({ ...newLocation, lat: parseFloat(e.target.value) || 0 })}
                className="w-full px-4 py-3 bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 disabled:opacity-50"
                disabled={isUpdating}
                placeholder="47.3878278"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-2 uppercase tracking-wider">
              Longitude
            </label>
            <div className="relative">
              <input
                type="number"
                step="0.0000001"
                min="-180"
                max="180"
                value={newLocation.lng}
                onChange={(e) => setNewLocation({ ...newLocation, lng: parseFloat(e.target.value) || 0 })}
                className="w-full px-4 py-3 bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 disabled:opacity-50"
                disabled={isUpdating}
                placeholder="0.6737631"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-400 mb-2 uppercase tracking-wider">
              Altitude (m)
            </label>
            <div className="relative">
              <input
                type="number"
                step="1"
                value={newLocation.alt}
                onChange={(e) => setNewLocation({ ...newLocation, alt: parseFloat(e.target.value) || 0 })}
                className="w-full px-4 py-3 bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200 disabled:opacity-50"
                disabled={isUpdating}
                placeholder="120"
              />
            </div>
          </div>
        </div>

        <button
          type="submit"
          disabled={isUpdating}
          className="w-full py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-[1.02] disabled:hover:scale-100"
        >
          <span className="flex items-center justify-center">
            {isUpdating ? (
              <>
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Updating Location...
              </>
            ) : (
              <>
                <svg className="mr-2 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                Update GPS Location
              </>
            )}
          </span>
        </button>
      </form>
    </div>
  );
};