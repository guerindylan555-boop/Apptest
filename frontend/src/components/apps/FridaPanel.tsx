import { useState, useEffect } from 'react';
import { useFridaControls } from '../../hooks/useFridaControls';

/**
 * Frida Control Panel
 *
 * Provides UI for Frida server control and process attachment.
 * Only visible when Frida feature flag is enabled.
 */

const FridaPanel = () => {
  const {
    session,
    isLoading,
    error,
    processes,
    fridaEnabled,
    startServer,
    stopServer,
    attachToProcess,
    listProcesses
  } = useFridaControls();

  const [selectedPackage, setSelectedPackage] = useState('');
  const [scriptPath, setScriptPath] = useState('');

  useEffect(() => {
    if (session?.active) {
      listProcesses();
    }
  }, [session?.active]);

  if (!fridaEnabled) {
    return (
      <div style={{ padding: '1rem', backgroundColor: '#fff3cd', border: '1px solid #856404', borderRadius: '4px', fontSize: '0.875rem', color: '#856404' }}>
        <strong>Frida Disabled:</strong> Set ENABLE_FRIDA=true to enable Frida instrumentation features.
      </div>
    );
  }

  const handleServerToggle = async () => {
    if (session?.active) {
      await stopServer();
    } else {
      await startServer();
    }
  };

  const handleAttach = async () => {
    if (!selectedPackage) return;
    const success = await attachToProcess(selectedPackage, scriptPath || undefined);
    if (success) {
      setScriptPath('');
    }
  };

  return (
    <div style={{ padding: '1.5rem', backgroundColor: '#fff', border: '1px solid #e0e0e0', borderRadius: '4px' }}>
      <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        🔬 Frida Instrumentation
        {session?.active && (
          <span style={{ fontSize: '0.75rem', padding: '0.125rem 0.5rem', backgroundColor: '#e8f5e9', color: '#2e7d32', borderRadius: '12px', fontWeight: 500 }}>
            Active
          </span>
        )}
      </h3>

      {/* Server Control */}
      <div style={{ marginBottom: '1.5rem' }}>
        <button
          onClick={handleServerToggle}
          disabled={isLoading}
          style={{
            padding: '0.75rem 1.5rem',
            backgroundColor: session?.active ? '#ffebee' : '#4caf50',
            color: session?.active ? '#c62828' : '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: isLoading ? 'not-allowed' : 'pointer',
            fontSize: '0.875rem',
            fontWeight: 500,
            width: '100%'
          }}
        >
          {isLoading ? 'Working...' : session?.active ? 'Stop Frida Server' : 'Start Frida Server'}
        </button>

        {session?.serverPid && (
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#666' }}>
            Server PID: {session.serverPid}
          </div>
        )}
      </div>

      {/* Attach Controls (only when server is active) */}
      {session?.active && (
        <div style={{ padding: '1rem', backgroundColor: '#f5f5f5', borderRadius: '4px' }}>
          <h4 style={{ margin: '0 0 0.75rem 0', fontSize: '0.875rem' }}>Attach to Process</h4>

          {/* Process Selection */}
          <div style={{ marginBottom: '0.75rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#666', marginBottom: '0.25rem' }}>
              Package Name
            </label>
            <select
              value={selectedPackage}
              onChange={(e) => setSelectedPackage(e.target.value)}
              style={{
                width: '100%',
                padding: '0.5rem',
                border: '1px solid #ccc',
                borderRadius: '4px',
                fontSize: '0.875rem'
              }}
            >
              <option value="">-- Select a package --</option>
              {processes.map((pkg) => (
                <option key={pkg} value={pkg}>
                  {pkg}
                </option>
              ))}
            </select>
            <button
              onClick={listProcesses}
              style={{
                marginTop: '0.5rem',
                padding: '0.25rem 0.5rem',
                backgroundColor: '#f5f5f5',
                border: '1px solid #ccc',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.75rem'
              }}
            >
              🔄 Refresh Processes
            </button>
          </div>

          {/* Script Path (optional) */}
          <div style={{ marginBottom: '0.75rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#666', marginBottom: '0.25rem' }}>
              Script Path (optional)
            </label>
            <input
              type="text"
              value={scriptPath}
              onChange={(e) => setScriptPath(e.target.value)}
              placeholder="/path/to/script.js"
              style={{
                width: '100%',
                padding: '0.5rem',
                border: '1px solid #ccc',
                borderRadius: '4px',
                fontSize: '0.875rem'
              }}
            />
          </div>

          {/* Attach Button */}
          <button
            onClick={handleAttach}
            disabled={!selectedPackage || isLoading}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: !selectedPackage ? '#ccc' : '#2196f3',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              cursor: !selectedPackage || isLoading ? 'not-allowed' : 'pointer',
              fontSize: '0.875rem',
              width: '100%'
            }}
          >
            Attach & Load Script
          </button>

          {/* Current Attachment */}
          {session.attachedPackage && (
            <div style={{ marginTop: '1rem', padding: '0.75rem', backgroundColor: '#e3f2fd', borderRadius: '4px', fontSize: '0.875rem' }}>
              <strong>Attached to:</strong> {session.attachedPackage}
              {session.scriptPath && (
                <div style={{ marginTop: '0.25rem', fontSize: '0.75rem', color: '#666' }}>
                  Script: {session.scriptPath}
                </div>
              )}
            </div>
          )}

          {/* Output Lines */}
          {session.lastOutputLines.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <strong style={{ fontSize: '0.75rem', color: '#666' }}>Console Output:</strong>
              <div style={{ marginTop: '0.5rem', padding: '0.5rem', backgroundColor: '#263238', color: '#aed581', fontFamily: 'monospace', fontSize: '0.75rem', borderRadius: '4px', maxHeight: '150px', overflowY: 'auto' }}>
                {session.lastOutputLines.map((line, idx) => (
                  <div key={idx}>{line}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Error Display */}
      {error && (
        <div style={{ marginTop: '1rem', padding: '0.75rem', backgroundColor: '#ffebee', border: '1px solid #ef5350', borderRadius: '4px', fontSize: '0.875rem', color: '#c62828' }}>
          <strong>Error:</strong> {error}
        </div>
      )}
    </div>
  );
};

export default FridaPanel;
