import { useState, useEffect } from 'react';
import './ProxyToggle.css';

interface ProxyState {
  enabled: boolean;
  host: string;
  port: number;
}

const BACKEND_URL = window.__RUNTIME_CONFIG__?.BACKEND_URL || 'http://localhost:3001/api';

export function ProxyToggle() {
  const [proxyState, setProxyState] = useState<ProxyState>({
    enabled: false,
    host: '127.0.0.1',
    port: 8080
  });
  const [host, setHost] = useState('127.0.0.1');
  const [port, setPort] = useState(8080);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch current proxy status
  const fetchProxyStatus = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/apps/proxy/status`);
      if (!response.ok) throw new Error('Failed to fetch proxy status');
      const data: ProxyState = await response.json();
      setProxyState(data);
      setHost(data.host);
      setPort(data.port);
    } catch (err) {
      console.error('Failed to fetch proxy status:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch proxy status');
    }
  };

  // Toggle proxy on/off
  const handleToggleProxy = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const body = {
        enabled: !proxyState.enabled,
        host: !proxyState.enabled ? host : undefined,
        port: !proxyState.enabled ? port : undefined
      };

      const response = await fetch(`${BACKEND_URL}/apps/proxy/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to toggle proxy');
      }

      const data: ProxyState = await response.json();
      setProxyState(data);
    } catch (err) {
      console.error('Failed to toggle proxy:', err);
      setError(err instanceof Error ? err.message : 'Failed to toggle proxy');
    } finally {
      setIsLoading(false);
    }
  };

  // Auto-refresh status every 3 seconds
  useEffect(() => {
    fetchProxyStatus();
    const interval = setInterval(fetchProxyStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="proxy-toggle">
      <h2>🌐 HTTP Proxy</h2>

      <div className="proxy-status">
        <div className="status-indicator">
          <span className={`status-dot ${proxyState.enabled ? 'enabled' : 'disabled'}`}></span>
          <span className="status-text">
            {proxyState.enabled ? `Proxy Enabled (${proxyState.host}:${proxyState.port})` : 'Proxy Disabled'}
          </span>
        </div>
      </div>

      {!proxyState.enabled && (
        <div className="proxy-config">
          <h3>Proxy Configuration</h3>
          <div className="config-row">
            <div className="config-field">
              <label htmlFor="proxyHost">Host:</label>
              <input
                id="proxyHost"
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                disabled={isLoading}
                placeholder="127.0.0.1"
              />
            </div>
            <div className="config-field">
              <label htmlFor="proxyPort">Port:</label>
              <input
                id="proxyPort"
                type="number"
                value={port}
                onChange={(e) => setPort(parseInt(e.target.value) || 8080)}
                disabled={isLoading}
                placeholder="8080"
              />
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="proxy-error">
          ⚠️ {error}
        </div>
      )}

      <button
        className={`toggle-button ${proxyState.enabled ? 'enabled' : 'disabled'}`}
        onClick={handleToggleProxy}
        disabled={isLoading}
      >
        {isLoading ? '⏳ Processing...' : (proxyState.enabled ? '⏹️ Disable Proxy' : '▶️ Enable Proxy')}
      </button>

      <div className="proxy-guidance">
        <h3>🔒 SSL/TLS Interception Setup</h3>
        <p>
          To intercept HTTPS traffic, you need to install the proxy's CA certificate on the emulator:
        </p>
        <ol>
          <li>Start your proxy tool (e.g., <code>mitmproxy</code> or <code>mitmweb</code>)</li>
          <li>Enable the proxy above</li>
          <li>On the emulator, navigate to <code>mitm.it</code> in Chrome</li>
          <li>Download and install the Android certificate</li>
          <li>Go to Settings → Security → Encryption & credentials → Install from storage</li>
          <li>Select the downloaded certificate and confirm</li>
        </ol>
        <p className="note">
          📝 <strong>Note:</strong> Apps targeting API 24+ may require additional configuration to trust user certificates.
          You may need to modify the app's network security config.
        </p>
        <div className="guidance-links">
          <a
            href="https://docs.mitmproxy.org/stable/concepts-certificates/"
            target="_blank"
            rel="noopener noreferrer"
          >
            📚 mitmproxy Certificate Docs
          </a>
          <a
            href="https://developer.android.com/privacy-and-security/security-config"
            target="_blank"
            rel="noopener noreferrer"
          >
            📚 Android Network Security Config
          </a>
        </div>
      </div>

      <div className="proxy-tips">
        <h3>💡 Quick Tips</h3>
        <ul>
          <li><strong>mitmproxy CLI:</strong> <code>mitmproxy --listen-host 127.0.0.1 --listen-port 8080</code></li>
          <li><strong>mitmweb (Web UI):</strong> <code>mitmweb --listen-host 127.0.0.1 --listen-port 8080</code></li>
          <li><strong>Burp Suite:</strong> Configure proxy listener on 127.0.0.1:8080</li>
          <li><strong>Charles Proxy:</strong> Set proxy to 127.0.0.1:8080 in preferences</li>
        </ul>
      </div>
    </div>
  );
}
