import { useState, useEffect } from 'react';
import './LogcatPanel.css';

interface LogCapture {
  id: string;
  apkId: string | null;
  filters: {
    packages: string[];
    tags: string[];
  };
  status: 'active' | 'paused' | 'stopped';
  startedAt: string;
  endedAt: string | null;
  filePath: string | null;
  sizeBytes: number;
  downloaded: boolean;
}

const BACKEND_URL = window.__RUNTIME_CONFIG__?.BACKEND_URL || 'http://localhost:3001/api';

export function LogcatPanel() {
  const [captures, setCaptures] = useState<LogCapture[]>([]);
  const [packageFilter, setPackageFilter] = useState('');
  const [tagFilter, setTagFilter] = useState('');
  const [selectedCaptureId, setSelectedCaptureId] = useState<string | null>(null);
  const [logContent, setLogContent] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch all capture sessions
  const fetchCaptures = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions`);
      if (!response.ok) throw new Error('Failed to fetch captures');
      const data = await response.json();
      setCaptures(data);
    } catch (err) {
      console.error('Failed to fetch captures:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch captures');
    }
  };

  // Start new capture
  const handleStartCapture = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const body = {
        packageFilters: packageFilter ? packageFilter.split(',').map(p => p.trim()) : [],
        tagFilters: tagFilter ? tagFilter.split(',').map(t => t.trim()) : []
      };

      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      if (!response.ok) throw new Error('Failed to start capture');

      const newCapture = await response.json();
      setCaptures([...captures, newCapture]);
      setPackageFilter('');
      setTagFilter('');
    } catch (err) {
      console.error('Failed to start capture:', err);
      setError(err instanceof Error ? err.message : 'Failed to start capture');
    } finally {
      setIsLoading(false);
    }
  };

  // Control capture (pause/resume/stop)
  const handleControlCapture = async (captureId: string, action: 'pause' | 'resume' | 'stop') => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions/${captureId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
      });

      if (!response.ok) throw new Error(`Failed to ${action} capture`);

      await fetchCaptures();
    } catch (err) {
      console.error(`Failed to ${action} capture:`, err);
      setError(err instanceof Error ? err.message : `Failed to ${action} capture`);
    }
  };

  // Download capture logs
  const handleDownloadCapture = async (captureId: string) => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions/${captureId}`);
      if (!response.ok) throw new Error('Failed to download capture');

      const content = await response.text();
      setLogContent(content);
      setSelectedCaptureId(captureId);

      // Also trigger browser download
      const blob = new Blob([content], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `logcat-${captureId}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download capture:', err);
      setError(err instanceof Error ? err.message : 'Failed to download capture');
    }
  };

  // View capture logs inline
  const handleViewCapture = async (captureId: string) => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/logcat/sessions/${captureId}`);
      if (!response.ok) throw new Error('Failed to load capture');

      const content = await response.text();
      setLogContent(content);
      setSelectedCaptureId(captureId);
    } catch (err) {
      console.error('Failed to load capture:', err);
      setError(err instanceof Error ? err.message : 'Failed to load capture');
    }
  };

  // Auto-refresh captures every 2 seconds
  useEffect(() => {
    fetchCaptures();
    const interval = setInterval(fetchCaptures, 2000);
    return () => clearInterval(interval);
  }, []);

  // Format file size
  const formatSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${Math.round(bytes / Math.pow(k, i) * 100) / 100} ${sizes[i]}`;
  };

  // Format timestamp
  const formatTime = (iso: string): string => {
    return new Date(iso).toLocaleTimeString();
  };

  return (
    <div className="logcat-panel">
      <h2>📝 Logcat Capture</h2>

      {/* Start Capture Form */}
      <div className="logcat-start-form">
        <h3>Start New Capture</h3>
        <div className="form-row">
          <div className="form-field">
            <label htmlFor="packageFilter">Package Filter (comma-separated):</label>
            <input
              id="packageFilter"
              type="text"
              value={packageFilter}
              onChange={(e) => setPackageFilter(e.target.value)}
              placeholder="com.example.app1, com.example.app2"
              disabled={isLoading}
            />
          </div>
          <div className="form-field">
            <label htmlFor="tagFilter">Tag Filter (comma-separated):</label>
            <input
              id="tagFilter"
              type="text"
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              placeholder="ActivityManager, PackageManager"
              disabled={isLoading}
            />
          </div>
        </div>
        <button onClick={handleStartCapture} disabled={isLoading}>
          {isLoading ? '⏳ Starting...' : '▶️ Start Capture'}
        </button>
      </div>

      {/* Error Display */}
      {error && (
        <div className="logcat-error">
          ⚠️ {error}
        </div>
      )}

      {/* Capture Sessions List */}
      <div className="logcat-sessions">
        <h3>Capture Sessions ({captures.length})</h3>
        {captures.length === 0 ? (
          <p className="empty-state">No capture sessions yet. Start a new capture above.</p>
        ) : (
          <div className="sessions-list">
            {captures.map((capture) => (
              <div
                key={capture.id}
                className={`session-item ${capture.status} ${selectedCaptureId === capture.id ? 'selected' : ''}`}
              >
                <div className="session-header">
                  <span className={`status-badge ${capture.status}`}>
                    {capture.status === 'active' && '🟢'}
                    {capture.status === 'paused' && '🟡'}
                    {capture.status === 'stopped' && '🔴'}
                    {capture.status.toUpperCase()}
                  </span>
                  <span className="session-time">
                    {formatTime(capture.startedAt)}
                    {capture.endedAt && ` - ${formatTime(capture.endedAt)}`}
                  </span>
                  <span className="session-size">{formatSize(capture.sizeBytes)}</span>
                </div>

                {(capture.filters.packages.length > 0 || capture.filters.tags.length > 0) && (
                  <div className="session-filters">
                    {capture.filters.packages.length > 0 && (
                      <span>📦 {capture.filters.packages.join(', ')}</span>
                    )}
                    {capture.filters.tags.length > 0 && (
                      <span>🏷️ {capture.filters.tags.join(', ')}</span>
                    )}
                  </div>
                )}

                <div className="session-controls">
                  {capture.status === 'active' && (
                    <>
                      <button onClick={() => handleControlCapture(capture.id, 'pause')}>
                        ⏸️ Pause
                      </button>
                      <button onClick={() => handleControlCapture(capture.id, 'stop')}>
                        ⏹️ Stop
                      </button>
                    </>
                  )}
                  {capture.status === 'paused' && (
                    <>
                      <button onClick={() => handleControlCapture(capture.id, 'resume')}>
                        ▶️ Resume
                      </button>
                      <button onClick={() => handleControlCapture(capture.id, 'stop')}>
                        ⏹️ Stop
                      </button>
                    </>
                  )}
                  {capture.status === 'stopped' && (
                    <>
                      <button onClick={() => handleViewCapture(capture.id)}>
                        👁️ View
                      </button>
                      <button onClick={() => handleDownloadCapture(capture.id)}>
                        💾 Download
                      </button>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Log Viewer */}
      {selectedCaptureId && logContent && (
        <div className="log-viewer">
          <div className="log-viewer-header">
            <h3>Log Content</h3>
            <button onClick={() => { setSelectedCaptureId(null); setLogContent(''); }}>
              ✕ Close
            </button>
          </div>
          <pre className="log-content">{logContent}</pre>
        </div>
      )}
    </div>
  );
}
