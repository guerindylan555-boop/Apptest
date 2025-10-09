import { useEffect } from 'react';
import { fetchHealth, fetchStreamUrl } from '../services/backendClient';
import { useAppStore } from '../state/useAppStore';

const POLL_INTERVAL_MS = 1000;

export const useHealthPoller = () => {
  const setState = useAppStore((state) => state.setState);
  const setTransitioning = useAppStore((state) => state.setTransitioning);
  const streamTicket = useAppStore((state) => state.streamTicket);
  const forceStopRequired = useAppStore((state) => state.forceStopRequired);

  // Check if ticket is expired
  const isTicketExpired = (ticket?: { expiresAt: string }): boolean => {
    if (!ticket) return true;
    return new Date(ticket.expiresAt) <= new Date();
  };

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const payload = await fetchHealth();
        if (cancelled) return;

        console.log('[Health Poll]', {
          state: payload.state,
          streamAttached: payload.streamAttached,
          hasTicket: !!streamTicket,
          ticketExpired: streamTicket ? isTicketExpired(streamTicket) : null
        });

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

        if (payload.state === 'Running' && (!streamTicket || isTicketExpired(streamTicket))) {
          console.log('[Health Poll] Fetching stream ticket...');
          try {
            const ticket = await fetchStreamUrl();
            console.log('[Health Poll] Got stream ticket:', ticket);
            if (!cancelled) {
              setState({ streamTicket: ticket, lastError: undefined });
            }
          } catch (error) {
            console.warn('Stream attach failed; retrying', error);
            if (!cancelled) {
              setState({
                streamTicket: undefined, // Clear expired/invalid ticket
                lastError: {
                  code: 'STREAM_RETRY',
                  message: 'Stream ticket unavailable; retrying…',
                  hint: 'ws-scrcpy bridge may still be initialising; ensure the bridge process is running.'
                }
              });
            }
          }
        }

        if (payload.state !== 'Running' && streamTicket) {
          setState({ streamTicket: undefined });
        }
      } catch (error) {
        console.error('Health poll failed', error);
        if (!cancelled) {
          setState({
            emulatorState: 'Error',
            lastError: {
              code: 'HEALTH_UNREACHABLE',
              message: 'Lost contact with backend health endpoint',
              hint: 'Confirm backend service is running on http://127.0.0.1:7070'
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
  }, [forceStopRequired, setState, setTransitioning, streamTicket]);
};
