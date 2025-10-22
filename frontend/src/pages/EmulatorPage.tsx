import { useCallback, useMemo, useEffect, useState } from 'react';
import { useAppStore } from '../state/useAppStore';
import StateBadge from '../components/StateBadge';
import StreamViewer from '../components/StreamViewer';
import ErrorBanner from '../components/ErrorBanner';
import DiagnosticsDrawer from '../components/DiagnosticsDrawer';
import {
  fetchStreamUrl,
  fetchLogs,
  startEmulator as startEmulatorApi,
  stopEmulator as stopEmulatorApi,
  restartEmulator as restartEmulatorApi
} from '../services/backendClient';
import { useHealthPoller } from '../hooks/useHealthPoller';

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
  const forceStopRequired = useAppStore((state) => state.forceStopRequired);

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

  const handleStart = useCallback(async () => {
    if (isTransitioning) return;
    setTransitioning(true);
    try {
      await startEmulatorApi();
      await handleRefreshStream();
    } catch (error) {
      setState({
        lastError: {
          code: 'START_FAILED',
          message: error instanceof Error ? error.message : 'Failed to start emulator',
          hint: 'Review backend logs for emulator launch errors.'
        }
      });
    } finally {
      setTransitioning(false);
    }
  }, [handleRefreshStream, isTransitioning, setState, setTransitioning]);

  const handleStop = useCallback(async () => {
    if (isTransitioning) return;
    setTransitioning(true);
    try {
      await stopEmulatorApi(forceStopRequired);
    } catch (error) {
      setState({
        lastError: {
          code: 'STOP_FAILED',
          message: error instanceof Error ? error.message : 'Failed to stop emulator',
          hint: 'Try forcing a stop or inspect backend logs.'
        }
      });
    } finally {
      setTransitioning(false);
    }
  }, [forceStopRequired, isTransitioning, setState, setTransitioning]);

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
    <div style={{ padding: '2rem' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ margin: 0 }}>Emulator Control</h1>
          <p style={{ margin: 0, color: '#666' }}>Streaming an externally managed emulator</p>
        </div>
        <StateBadge state={emulatorState} />
      </header>

      <main
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '1.5rem'
        }}
      >
        {lastError && (
          <ErrorBanner
            message={lastError.message}
            hint={lastError.hint}
            logsPath="var/log/autoapp/backend.log"
            actions={errorActions}
          />
        )}
        <section style={{ width: '100%', display: 'flex', justifyContent: 'center' }}>
          <StreamViewer state={emulatorState} streamTicket={streamTicket} />
        </section>

        <div
          style={{
            display: 'flex',
            gap: '1rem',
            alignItems: 'center',
            flexWrap: 'wrap'
          }}
        >
          <button
            type="button"
            onClick={handleStart}
            disabled={isTransitioning || emulatorState === 'Running'}
            style={{ padding: '0.5rem 1rem' }}
          >
            Start
          </button>
          <button
            type="button"
            onClick={handleStop}
            disabled={isTransitioning || emulatorState === 'Stopped'}
            style={{ padding: '0.5rem 1rem' }}
          >
            Stop{forceStopRequired ? ' (force)' : ''}
          </button>
          <button
            type="button"
            onClick={handleRestart}
            disabled={isTransitioning}
            style={{ padding: '0.5rem 1rem' }}
          >
            Restart
          </button>
          <span style={{ color: '#93c5fd', fontSize: '0.85rem' }}>
            Streamer: {streamerActive ? 'active' : 'offline'}
          </span>
        </div>

        <div style={{ alignSelf: 'stretch' }}>
          <DiagnosticsDrawer
            pid={pid}
            bootElapsedMs={bootElapsedMs}
            ports={ports}
            lastError={lastError}
          />
        </div>

        <section style={{ width: '100%', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          <div
            style={{
              background: '#0f172a',
              color: '#cbd5f5',
              padding: '1rem',
              borderRadius: '0.75rem',
              minHeight: '220px'
            }}
          >
            <h2 style={{ marginTop: 0 }}>Emulator Logs</h2>
            <pre
              style={{
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                maxHeight: '240px',
                overflowY: 'auto',
                fontSize: '0.75rem'
              }}
            >
              {emulatorLogs.join('\n') || 'No emulator output yet.'}
            </pre>
          </div>
          <div
            style={{
              background: '#0f172a',
              color: '#cbd5f5',
              padding: '1rem',
              borderRadius: '0.75rem',
              minHeight: '220px'
            }}
          >
            <h2 style={{ marginTop: 0 }}>Streamer Logs</h2>
            <pre
              style={{
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                maxHeight: '240px',
                overflowY: 'auto',
                fontSize: '0.75rem'
              }}
            >
              {streamerLogs.join('\n') || 'No streamer output yet.'}
            </pre>
          </div>
        </section>
      </main>
    </div>
  );
};

export default EmulatorPage;
