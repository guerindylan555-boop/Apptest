/**
 * Health Endpoint Component
 *
 * Frontend health monitoring for constitution compliance.
 * Displays system status and connectivity information.
 */

import React, { useState, useEffect } from 'react';
import { CheckCircleIcon, ExclamationTriangleIcon, XCircleIcon } from '@heroicons/react/24/outline';

interface HealthStatus {
  status: 'ok' | 'degraded' | 'error';
  timestamp: string;
  services: {
    adb: ServiceHealth;
    graph: ServiceHealth;
    storage: ServiceHealth;
  };
  performance?: {
    memoryUsage?: number;
  };
}

interface ServiceHealth {
  status: 'ok' | 'degraded' | 'error';
  message?: string;
  details?: Record<string, any>;
}

interface HealthEndpointProps {
  className?: string;
  showDetails?: boolean;
  refreshInterval?: number;
}

export const HealthEndpoint: React.FC<HealthEndpointProps> = ({
  className = '',
  showDetails = false,
  refreshInterval = 30000 // 30 seconds
}) => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchHealth = async () => {
    try {
      setError(null);
      const response = await fetch('/api/healthz?include=performance');

      if (!response.ok) {
        throw new Error(`Health check failed: ${response.status} ${response.statusText}`);
      }

      const data: HealthStatus = await response.json();
      setHealth(data);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      console.error('Health check failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();

    if (refreshInterval > 0) {
      const interval = setInterval(fetchHealth, refreshInterval);
      return () => clearInterval(interval);
    }
  }, [refreshInterval]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'ok':
        return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'degraded':
        return <ExclamationTriangleIcon className="w-5 h-5 text-yellow-500" />;
      case 'error':
        return <XCircleIcon className="w-5 h-5 text-red-500" />;
      default:
        return <ExclamationTriangleIcon className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ok':
        return 'text-green-700 bg-green-100 border-green-200';
      case 'degraded':
        return 'text-yellow-700 bg-yellow-100 border-yellow-200';
      case 'error':
        return 'text-red-700 bg-red-100 border-red-200';
      default:
        return 'text-gray-700 bg-gray-100 border-gray-200';
    }
  };

  const formatMemoryUsage = (bytes?: number): string => {
    if (!bytes) return 'Unknown';
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(1)} MB`;
  };

  const formatUptime = (seconds: number): string => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${minutes}m`;
  };

  if (loading) {
    return (
      <div className={`p-4 border rounded-lg ${className}`}>
        <div className="flex items-center space-x-2">
          <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500"></div>
          <span className="text-sm text-gray-600">Checking system health...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`p-4 border border-red-200 rounded-lg bg-red-50 ${className}`}>
        <div className="flex items-center space-x-2">
          <XCircleIcon className="w-5 h-5 text-red-500" />
          <span className="text-sm text-red-700">Health check unavailable</span>
        </div>
        {showDetails && (
          <p className="mt-2 text-xs text-red-600">{error}</p>
        )}
      </div>
    );
  }

  if (!health) {
    return null;
  }

  return (
    <div className={`p-4 border rounded-lg ${className}`}>
      {/* Overall Status */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          {getStatusIcon(health.status)}
          <span className="font-medium text-gray-900">
            System {health.status === 'ok' ? 'Healthy' : health.status === 'degraded' ? 'Degraded' : 'Error'}
          </span>
        </div>

        <div className="flex items-center space-x-4 text-xs text-gray-500">
          {lastRefresh && (
            <span>Last check: {lastRefresh.toLocaleTimeString()}</span>
          )}
          <button
            onClick={fetchHealth}
            className="text-blue-600 hover:text-blue-800"
            title="Refresh health status"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Service Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        {Object.entries(health.services).map(([service, serviceHealth]) => (
          <div
            key={service}
            className={`p-3 border rounded ${getStatusColor(serviceHealth.status)}`}
          >
            <div className="flex items-center space-x-2 mb-1">
              {getStatusIcon(serviceHealth.status)}
              <span className="font-medium capitalize">{service}</span>
            </div>
            {serviceHealth.message && (
              <p className="text-xs mt-1 opacity-75">{serviceHealth.message}</p>
            )}
          </div>
        ))}
      </div>

      {/* Detailed Information */}
      {showDetails && (
        <div className="space-y-4 border-t pt-4">
          {/* Performance Metrics */}
          {health.performance && (
            <div>
              <h4 className="font-medium text-gray-900 mb-2">Performance</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Memory Usage:</span>
                  <span className="ml-2 font-mono">
                    {formatMemoryUsage(health.performance.memoryUsage)}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Service Details */}
          <div>
            <h4 className="font-medium text-gray-900 mb-2">Service Details</h4>
            <div className="space-y-3">
              {Object.entries(health.services).map(([service, serviceHealth]) => (
                <div key={service} className="text-sm">
                  <div className="font-medium capitalize mb-1">{service}</div>
                  {serviceHealth.details && (
                    <div className="ml-4 space-y-1 text-xs text-gray-600">
                      {Object.entries(serviceHealth.details).map(([key, value]) => (
                        <div key={key}>
                          <span className="font-medium">{key}:</span>{' '}
                          <span className="font-mono">
                            {typeof value === 'object'
                              ? JSON.stringify(value)
                              : String(value)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* System Information */}
          <div>
            <h4 className="font-medium text-gray-900 mb-2">System Information</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-600">Status:</span>
                <span className="ml-2 font-medium capitalize">{health.status}</span>
              </div>
              <div>
                <span className="text-gray-600">Timestamp:</span>
                <span className="ml-2 font-mono">
                  {new Date(health.timestamp).toLocaleString()}
                </span>
              </div>
              <div>
                <span className="text-gray-600">Uptime:</span>
                <span className="ml-2 font-mono">
                  {formatUptime(0)}
                </span>
              </div>
              <div>
                <span className="text-gray-600">Version:</span>
                <span className="ml-2 font-mono">{(health as any).version || '1.0.0'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default HealthEndpoint;