import { useCallback, useMemo } from 'react';
import { useAppStore } from '../state/useAppStore';
import StateBadge from '../components/StateBadge';
import StreamViewer from '../components/StreamViewer';
import ErrorBanner from '../components/ErrorBanner';
import DiagnosticsDrawer from '../components/DiagnosticsDrawer';
import { fetchStreamUrl } from '../services/backendClient';
import { useHealthPoller } from '../hooks/useHealthPoller';

const EmulatorPage = () => {
  const emulatorState = useAppStore((state) => state.emulatorState);
  const streamTicket = useAppStore((state) => state.streamTicket);
  const setState = useAppStore((state) => state.setState);
  const lastError = useAppStore((state) => state.lastError);
  const pid = useAppStore((state) => state.pid);
  const bootElapsedMs = useAppStore((state) => state.bootElapsedMs);
  const ports = useAppStore((state) => state.ports);

  useHealthPoller();

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

        <div style={{ alignSelf: 'stretch' }}>
          <DiagnosticsDrawer
            pid={pid}
            bootElapsedMs={bootElapsedMs}
            ports={ports}
            lastError={lastError}
          />
        </div>
      </main>
    </div>
  );
};

export default EmulatorPage;
