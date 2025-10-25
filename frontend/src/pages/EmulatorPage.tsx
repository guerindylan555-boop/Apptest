import { useCallback, useMemo, useEffect, useState } from 'react';
import { useAppStore } from '../state/useAppStore';
import StateBadge from '../components/StateBadge';
import StreamViewer from '../components/StreamViewer';
import { GPSController } from '../components/GPSController';
import DiscoveryPanel from '../components/apps/DiscoveryPanel';
import ErrorBanner from '../components/ErrorBanner';
import DiagnosticsDrawer from '../components/DiagnosticsDrawer';
import { fetchStreamUrl, fetchLogs, restartEmulator as restartEmulatorApi } from '../services/backendClient';
import { useHealthPoller } from '../hooks/useHealthPoller';
import { useDiscoveryPanel, useGpsPanel } from '../state/featureFlagsStore';

const EmulatorPage = () => {
  const emulatorState = useAppStore((state) => state.emulatorState);
  const streamTicket = useAppStore((state) => state.streamTicket);
  const setState = useAppStore((state) => state.setState);
  const lastError = useAppStore((state) => state.lastError);
  const pid = useAppStore((state) => state.pid);
  const bootElapsedMs = useAppStore((state) => state.bootElapsedMs);
  const ports = useAppStore((state) => state.ports);
  const streamerActive = useAppStore((state) => state.streamerActive);
  const isTransitioning = useAppStore((state) => state.isTransitioning);
  const setTransitioning = useAppStore((state) => state.setTransitioning);

  // Feature flags
  const discoveryEnabled = useDiscoveryPanel();
  const gpsEnabled = useGpsPanel();

  useHealthPoller();

  const [emulatorLogs, setEmulatorLogs] = useState<string[]>([]);
  const [streamerLogs, setStreamerLogs] = useState<string[]>([]);

  const handleRefreshStream = useCallback(async () => {
    try {
      const ticket = await fetchStreamUrl();
      setState({ streamTicket: ticket, lastError: undefined });
    } catch (error) {
      setState({
        lastError: {
          code: 'STREAM_TICKET_FAILED',
          message: error instanceof Error ? error.message : 'Unable to refresh stream ticket'
        }
      });
    }
  }, [setState]);

  const handleRestart = useCallback(async () => {
    if (isTransitioning) return;
    setTransitioning(true);
    try {
      await restartEmulatorApi();
      await handleRefreshStream();
    } catch (error) {
      setState({
        lastError: {
          code: 'RESTART_FAILED',
          message: error instanceof Error ? error.message : 'Failed to restart emulator',
          hint: 'Verify emulator tooling inside the container.'
        }
      });
    } finally {
      setTransitioning(false);
    }
  }, [handleRefreshStream, isTransitioning, setState, setTransitioning]);

  useEffect(() => {
    let cancelled = false;
    const pollLogs = async () => {
      try {
        const [emu, streamer] = await Promise.all([
          fetchLogs('emulator', 200),
          fetchLogs('streamer', 200)
        ]);
        if (cancelled) return;
        setEmulatorLogs(emu.lines);
        setStreamerLogs(streamer.lines);
      } catch (error) {
        if (!cancelled) {
          console.warn('[EmulatorPage] log poll failed', error);
        }
      }
    };

    void pollLogs();
    const interval = setInterval(pollLogs, 4000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const errorActions = useMemo(() => {
    if (!lastError) {
      return undefined;
    }
    if (['STREAM_RETRY', 'STREAM_TICKET_FAILED', 'STREAM_TICKET_UNAVAILABLE'].includes(lastError.code)) {
      return [
        {
          label: 'Refresh Stream',
          onClick: handleRefreshStream,
          primary: true
        }
      ];
    }
    return undefined;
  }, [handleRefreshStream, lastError]);

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: '#0f172a' }}>
      {/* Header */}
      <header style={{
        padding: '1rem 2rem',
        borderBottom: '1px solid #1e293b',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        backgroundColor: '#0f172a',
        color: '#f1f5f9'
      }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: '600', color: '#f1f5f9' }}>
            UI Discovery & Flow Automation
          </h1>
          <p style={{ margin: '4px 0 0 0', color: '#94a3b8', fontSize: '0.875rem' }}>
            Android UI state discovery and automated flow management
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <StateBadge state={emulatorState} />
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#64748b', fontSize: '0.875rem' }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              backgroundColor: streamerActive ? '#10b981' : '#ef4444'
            }} />
            <span>Streamer: {streamerActive ? 'active' : 'offline'}</span>
          </div>
        </div>
      </header>

      {/* Error Banner */}
      {lastError && (
        <div style={{ padding: '0 2rem' }}>
          <ErrorBanner
            message={lastError.message}
            hint={lastError.hint}
            logsPath="var/log/autoapp/backend.log"
            actions={errorActions}
          />
        </div>
      )}

      {/* Main Content */}
      <main style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        padding: '1.5rem 2rem',
        gap: '1.5rem',
        overflow: 'hidden'
      }}>
        {/* Top Section - Video Stream and Discovery Panel */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 480px',
          gap: '1.5rem',
          flex: 1,
          minHeight: 0
        }}>
          {/* Video Stream Section */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            backgroundColor: '#1e293b',
            borderRadius: '0.75rem',
            border: '1px solid #334155',
            overflow: 'hidden'
          }}>
            <div style={{
              padding: '1rem 1.25rem',
              borderBottom: '1px solid #334155',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <h2 style={{ margin: 0, fontSize: '1.125rem', fontWeight: '600', color: '#f1f5f9' }}>
                Device Stream
              </h2>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
                  {emulatorState}
                </span>
                <button
                  type="button"
                  onClick={handleRefreshStream}
                  style={{
                    padding: '0.5rem 1rem',
                    backgroundColor: '#3b82f6',
                    color: 'white',
                    border: 'none',
                    borderRadius: '0.375rem',
                    fontSize: '0.875rem',
                    fontWeight: '500',
                    cursor: 'pointer',
                    transition: 'background-color 0.2s'
                  }}
                  onMouseOver={(e) => {
                    const target = e.target as HTMLButtonElement;
                    target.style.backgroundColor = '#2563eb';
                  }}
                  onMouseOut={(e) => {
                    const target = e.target as HTMLButtonElement;
                    target.style.backgroundColor = '#3b82f6';
                  }}
                >
                  Refresh
                </button>
              </div>
            </div>
            <div style={{
              flex: 1,
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              padding: '1rem',
              minHeight: '400px',
              backgroundColor: '#000'
            }}>
              <StreamViewer state={emulatorState} streamTicket={streamTicket} />
            </div>
          </div>

          {/* Discovery Panel Section */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            height: '100%',
            minHeight: 0
          }}>
            {discoveryEnabled ? (
              <div style={{
                height: '100%',
                backgroundColor: '#1e293b',
                borderRadius: '0.75rem',
                border: '1px solid #334155',
                overflow: 'hidden'
              }}>
                <DiscoveryPanel />
              </div>
            ) : gpsEnabled ? (
              <div style={{
                height: '100%',
                backgroundColor: '#1e293b',
                borderRadius: '0.75rem',
                border: '1px solid #334155',
                padding: '1rem'
              }}>
                <GPSController />
              </div>
            ) : (
              <div style={{
                height: '100%',
                backgroundColor: '#1e293b',
                borderRadius: '0.75rem',
                border: '1px solid #334155',
                padding: '2rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                alignItems: 'center',
                textAlign: 'center'
              }}>
                <div style={{
                  width: '48px',
                  height: '48px',
                  backgroundColor: '#475569',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginBottom: '1rem'
                }}>
                  <span style={{ fontSize: '1.5rem', color: '#94a3b8' }}>⚙️</span>
                </div>
                <h3 style={{ margin: '0 0 0.5rem 0', color: '#cbd5f5' }}>
                  No Control Panel Active
                </h3>
                <p style={{ margin: 0, color: '#64748b', fontSize: '0.875rem' }}>
                  Enable the Discovery Panel or GPS Controller in settings
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Bottom Section - Controls and Diagnostics */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '1.5rem'
        }}>
          {/* Controls Section */}
          <div style={{
            backgroundColor: '#1e293b',
            borderRadius: '0.75rem',
            border: '1px solid #334155',
            padding: '1.25rem'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', color: '#f1f5f9', fontSize: '1rem', fontWeight: '600' }}>
              Device Controls
            </h3>
            <div style={{
              display: 'flex',
              gap: '1rem',
              alignItems: 'center',
              flexWrap: 'wrap'
            }}>
              <button
                type="button"
                onClick={handleRestart}
                disabled={isTransitioning}
                style={{
                  padding: '0.625rem 1.25rem',
                  backgroundColor: isTransitioning ? '#475569' : '#dc2626',
                  color: 'white',
                  border: 'none',
                  borderRadius: '0.375rem',
                  fontSize: '0.875rem',
                  fontWeight: '500',
                  cursor: isTransitioning ? 'not-allowed' : 'pointer',
                  transition: 'background-color 0.2s',
                  opacity: isTransitioning ? 0.6 : 1
                }}
              >
                {isTransitioning ? 'Restarting...' : 'Restart Device'}
              </button>
              <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
                Device runs continuously; restart if the stream stalls
              </span>
            </div>
          </div>

          {/* System Info Section */}
          <div style={{
            backgroundColor: '#1e293b',
            borderRadius: '0.75rem',
            border: '1px solid #334155',
            padding: '1.25rem'
          }}>
            <h3 style={{ margin: '0 0 1rem 0', color: '#f1f5f9', fontSize: '1rem', fontWeight: '600' }}>
              System Information
            </h3>
            <DiagnosticsDrawer
              pid={pid}
              bootElapsedMs={bootElapsedMs}
              ports={ports}
              lastError={lastError}
            />
          </div>
        </div>
      </main>
    </div>
  );
};

export default EmulatorPage;
