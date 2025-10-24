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

  const updateGPSLocation = useCallback(async (location: Location) => {
    setIsUpdating(true);
    setStatus('Updating GPS...');

    try {
      const response = await fetch('/api/gps/update', {
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

  const handleQuickLocation = (location: Location) => {
    setNewLocation(location);
    updateGPSLocation(location);
  };

  const presetLocations = [
    { name: 'Tours (Current)', lat: 47.3878278, lng: 0.6737631, alt: 120 },
    { name: 'Paris', lat: 48.8566, lng: 2.3522, alt: 100 },
    { name: 'Lyon', lat: 45.7640, lng: 4.8357, alt: 200 },
    { name: 'Marseille', lat: 43.2965, lng: 5.3698, alt: 10 },
    { name: 'Bordeaux', lat: 44.8378, lng: -0.5792, alt: 50 },
    { name: 'Toulouse', lat: 43.6047, lng: 1.4442, alt: 150 },
  ];

  return (
    <div className={`bg-white rounded-lg shadow-lg p-6 ${className || ''}`}>
      <div className="flex items-center mb-4">
        <div className="w-3 h-3 bg-green-500 rounded-full mr-3 animate-pulse"></div>
        <h2 className="text-xl font-bold text-gray-800">🗺️ GPS Controller</h2>
      </div>

      {/* Current Location Display */}
      <div className="mb-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
        <h3 className="text-sm font-semibold text-blue-800 mb-2">Current Location</h3>
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-gray-600">Lat:</span>
            <span className="ml-2 font-mono font-semibold text-blue-900">
              {currentLocation.lat.toFixed(7)}
            </span>
          </div>
          <div>
            <span className="text-gray-600">Lng:</span>
            <span className="ml-2 font-mono font-semibold text-blue-900">
              {currentLocation.lng.toFixed(7)}
            </span>
          </div>
          <div>
            <span className="text-gray-600">Alt:</span>
            <span className="ml-2 font-mono font-semibold text-blue-900">
              {currentLocation.alt}m
            </span>
          </div>
        </div>
        {lastUpdate && (
          <div className="text-xs text-blue-600 mt-2">
            Last updated: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* Status */}
      <div className="mb-4 text-center">
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${
          status.includes('✅') ? 'bg-green-100 text-green-800' :
          status.includes('❌') ? 'bg-red-100 text-red-800' :
          'bg-gray-100 text-gray-800'
        }`}>
          {status}
        </span>
      </div>

      {/* Quick Location Buttons */}
      <div className="mb-6">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Quick Locations</h3>
        <div className="grid grid-cols-2 gap-2">
          {presetLocations.map((preset) => (
            <button
              key={preset.name}
              onClick={() => handleQuickLocation({
                lat: preset.lat,
                lng: preset.lng,
                alt: preset.alt,
              })}
              className="px-3 py-2 text-xs bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              disabled={isUpdating}
            >
              {preset.name}
            </button>
          ))}
        </div>
      </div>

      {/* Manual Location Input */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <h3 className="text-sm font-semibold text-gray-700">Manual Coordinates</h3>

        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Latitude
            </label>
            <input
              type="number"
              step="0.0000001"
              min="-90"
              max="90"
              value={newLocation.lat}
              onChange={(e) => setNewLocation({ ...newLocation, lat: parseFloat(e.target.value) })}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={isUpdating}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Longitude
            </label>
            <input
              type="number"
              step="0.0000001"
              min="-180"
              max="180"
              value={newLocation.lng}
              onChange={(e) => setNewLocation({ ...newLocation, lng: parseFloat(e.target.value) })}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={isUpdating}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Altitude (m)
            </label>
            <input
              type="number"
              step="1"
              value={newLocation.alt}
              onChange={(e) => setNewLocation({ ...newLocation, alt: parseFloat(e.target.value) })}
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={isUpdating}
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={isUpdating}
          className="w-full px-4 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isUpdating ? '🔄 Updating...' : '📍 Update GPS Location'}
        </button>
      </form>

      {/* Instructions */}
      <div className="mt-4 p-3 bg-gray-50 rounded-md">
        <h4 className="text-xs font-semibold text-gray-700 mb-1">Instructions:</h4>
        <ul className="text-xs text-gray-600 space-y-1">
          <li>• Click preset locations for quick GPS changes</li>
          <li>• Enter custom coordinates and click "Update GPS Location"</li>
          <li>• Changes are applied in real-time to the emulator</li>
          <li>• Coordinates support 7 decimal places (~1cm precision)</li>
        </ul>
      </div>
    </div>
  );
};