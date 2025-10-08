import { useEffect } from 'react';
import { fetchHealth, fetchStreamUrl } from '../services/backendClient';
import { useAppStore } from '../state/useAppStore';

const POLL_INTERVAL_MS = 1000;

export const useHealthPoller = () => {
  const setState = useAppStore((state) => state.setState);
  const setTransitioning = useAppStore((state) => state.setTransitioning);
  const streamUrl = useAppStore((state) => state.streamUrl);
  const forceStopRequired = useAppStore((state) => state.forceStopRequired);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const payload = await fetchHealth();
        if (cancelled) return;
        setState({
          emulatorState: payload.state,
          lastError: payload.lastError
            ? {
                code: payload.lastError.code,
                message: payload.lastError.message,
                hint: payload.lastError.hint
              }
            : undefined,
          pid: payload.pid,
          bootElapsedMs: payload.bootElapsedMs,
          ports: payload.ports ?? undefined,
          forceStopRequired: payload.forceStopRequired ?? false
        });
        setTransitioning(payload.state === 'Booting' || payload.state === 'Stopping');

        if (payload.state === 'Running' && !streamUrl) {
          try {
            const ticket = await fetchStreamUrl();
            if (!cancelled) {
              setState({ streamUrl: ticket.url, lastError: undefined });
            }
          } catch (error) {
            console.warn('Stream attach failed; retrying', error);
            if (!cancelled) {
              setState({
                lastError: {
                  code: 'STREAM_RETRY',
                  message: 'Stream unavailable; retrying…',
                  hint: 'ws-scrcpy may still be initialising; ensure the streamer process is running.'
                }
              });
            }
          }
        }

        if (payload.state !== 'Running' && streamUrl) {
          setState({ streamUrl: undefined });
        }
      } catch (error) {
        console.error('Health poll failed', error);
        if (!cancelled) {
          setState({
            emulatorState: 'Error',
            lastError: {
              code: 'HEALTH_UNREACHABLE',
              message: 'Lost contact with backend health endpoint',
              hint: 'Confirm backend service is running on http://127.0.0.1:8080'
            },
            forceStopRequired: false
          });
          setTransitioning(false);
        }
      }
    };

    const interval = setInterval(poll, POLL_INTERVAL_MS);
    void poll();

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [forceStopRequired, setState, setTransitioning, streamUrl]);
};
