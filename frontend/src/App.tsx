import { useCallback } from 'react';
import { useAppStore } from './state/useAppStore';
import StateBadge from './components/StateBadge';
import ControlButton from './components/ControlButton';
import StreamViewer from './components/StreamViewer';
import ErrorBanner from './components/ErrorBanner';
import DiagnosticsDrawer from './components/DiagnosticsDrawer';
import { startEmulator, stopEmulator } from './services/backendClient';
import { useHealthPoller } from './hooks/useHealthPoller';

const App = () => {
  const emulatorState = useAppStore((state) => state.emulatorState);
  const isTransitioning = useAppStore((state) => state.isTransitioning);
  const streamUrl = useAppStore((state) => state.streamUrl);
  const setState = useAppStore((state) => state.setState);
  const setTransitioning = useAppStore((state) => state.setTransitioning);
  const lastError = useAppStore((state) => state.lastError);
  const forceStopRequired = useAppStore((state) => state.forceStopRequired);
  const pid = useAppStore((state) => state.pid);
  const bootElapsedMs = useAppStore((state) => state.bootElapsedMs);
  const ports = useAppStore((state) => state.ports);

  useHealthPoller();

  const handleButtonClick = useCallback(async () => {
    setTransitioning(true);
    try {
      if (emulatorState === 'Running') {
        await stopEmulator();
      } else {
        await startEmulator();
      }
      setState({ lastError: undefined });
    } catch (error) {
      setState({
        emulatorState: 'Error',
        lastError: {
          code: emulatorState === 'Running' ? 'STOP_FAILED' : 'BOOT_FAILED',
          message: error instanceof Error ? error.message : 'Emulator lifecycle command failed'
        }
      });
    } finally {
      setTransitioning(false);
    }
  }, [emulatorState, setState, setTransitioning]);

  const isRunning = emulatorState === 'Running';
  const buttonLabel = isRunning ? 'Stop Emulator' : 'Start Emulator';
  const intent = isRunning ? 'stop' : 'start';
  const disableButton =
    isTransitioning || emulatorState === 'Stopping' || emulatorState === 'Booting';

  const handleForceStop = useCallback(async () => {
    setTransitioning(true);
    try {
      await stopEmulator(true);
      setState({ forceStopRequired: false, lastError: undefined });
    } catch (error) {
      setState({
        lastError: {
          code: 'FORCE_STOP_FAILED',
          message: error instanceof Error ? error.message : 'Force stop failed'
        }
      });
    } finally {
      setTransitioning(false);
    }
  }, [setState, setTransitioning]);

  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: '2rem' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <h1 style={{ margin: 0 }}>AutoApp Emulator Control</h1>
          <p style={{ margin: 0 }}>Local-only read-only stream + lifecycle controls</p>
        </div>
        <StateBadge state={emulatorState} />
      </header>

      <main style={{ display: 'grid', gap: '1.5rem' }}>
        {lastError && (
          <ErrorBanner
            message={lastError.message}
            hint={lastError.hint}
            logsPath="var/log/autoapp/backend.log"
            actionLabel={forceStopRequired ? 'Force Stop' : undefined}
            onAction={forceStopRequired ? handleForceStop : undefined}
          />
        )}
        <section style={{ display: 'grid', placeItems: 'center' }}>
          <StreamViewer state={emulatorState} src={streamUrl} />
        </section>

        <section>
          <ControlButton
            label={buttonLabel}
            intent={intent}
            onClick={handleButtonClick}
            loading={isTransitioning}
            disabled={disableButton}
          />
        </section>

        <DiagnosticsDrawer
          pid={pid}
          bootElapsedMs={bootElapsedMs}
          ports={ports}
          lastError={lastError}
        />
      </main>
    </div>
  );
};

export default App;
