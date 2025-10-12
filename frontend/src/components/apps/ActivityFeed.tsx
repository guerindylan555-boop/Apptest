import { useEffect, useState } from 'react';
import type { ActivityLogEntry } from '../../types/apps';

/**
 * Activity Feed Component
 *
 * Displays recent activity log entries (uploads, installs, launches, etc.)
 */

const BACKEND_URL = window.__RUNTIME_CONFIG__?.BACKEND_URL || 'http://127.0.0.1:3001/api';

const ActivityFeed = () => {
  const [activity, setActivity] = useState<ActivityLogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadActivity() {
      try {
        setIsLoading(true);
        const response = await fetch(`${BACKEND_URL}/apps/activity?limit=20`);
        if (!response.ok) {
          throw new Error('Failed to load activity');
        }
        const data = await response.json();
        setActivity(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load activity');
      } finally {
        setIsLoading(false);
      }
    }

    loadActivity();
  }, []);

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return date.toLocaleDateString();
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'upload':
        return '📤';
      case 'install':
        return '📲';
      case 'launch':
        return '🚀';
      case 'frida':
        return '🔬';
      case 'logcat':
        return '📋';
      case 'proxy':
        return '🌐';
      case 'retention':
        return '🗑️';
      case 'error':
        return '❌';
      default:
        return '•';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'upload':
        return '#2196f3';
      case 'install':
        return '#4caf50';
      case 'launch':
        return '#ff9800';
      case 'error':
        return '#f44336';
      default:
        return '#666';
    }
  };

  if (isLoading) {
    return (
      <div style={{ padding: '1rem', textAlign: 'center', color: '#999' }}>
        Loading activity...
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '1rem', color: '#f44336', fontSize: '0.875rem' }}>
        {error}
      </div>
    );
  }

  if (activity.length === 0) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: '#999', fontSize: '0.875rem' }}>
        No activity yet
      </div>
    );
  }

  return (
    <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
      {activity.map((entry, idx) => (
        <div
          key={`${entry.timestamp}-${idx}`}
          style={{
            padding: '0.75rem',
            borderBottom: idx < activity.length - 1 ? '1px solid #e0e0e0' : 'none',
            fontSize: '0.875rem'
          }}
        >
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'start' }}>
            <span style={{ fontSize: '1rem', flexShrink: 0 }}>{getTypeIcon(entry.type)}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: '#333', wordBreak: 'break-word' }}>{entry.message}</div>
              <div style={{ color: '#999', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                {formatTime(entry.timestamp)}
                <span
                  style={{
                    marginLeft: '0.5rem',
                    padding: '0.125rem 0.375rem',
                    backgroundColor: getTypeColor(entry.type) + '20',
                    color: getTypeColor(entry.type),
                    borderRadius: '4px',
                    fontSize: '0.7rem',
                    fontWeight: 500,
                    textTransform: 'uppercase'
                  }}
                >
                  {entry.type}
                </span>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default ActivityFeed;
