import { useCallback, useEffect, useState, useRef } from 'react';
import { Emulator } from 'android-emulator-webrtc';
import StreamPlaceholder from './StreamPlaceholder';
import type { StreamTicket } from '../services/backendClient';
import { fetchStreamUrl } from '../services/backendClient';
import { useAppStore } from '../state/useAppStore';
import '../styles/stream.css';

interface StreamViewerProps {
  streamTicket?: StreamTicket;
  state: 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';
}

const StreamViewer = ({ streamTicket, state }: StreamViewerProps) => {
  const [localTicket, setLocalTicket] = useState<StreamTicket | undefined>(streamTicket);
  const [connectionState, setConnectionState] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [lastError, setLastError] = useState<string | undefined>();
  const [retryCounter, setRetryCounter] = useState(0);
  const [reconnectAttempts, setReconnectAttempts] = useState(0);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const lastDisconnectTimeRef = useRef<number>(0);
  const setGlobalState = useAppStore((state) => state.setState);
  const activeTicket = streamTicket ?? localTicket;

  const scheduleReconnect = useCallback(() => {
    if (state !== 'Running') {
      return;
    }

    // Debounce rapid disconnections (within 2 seconds)
    const now = Date.now();
    if (now - lastDisconnectTimeRef.current < 2000) {
      console.log('[StreamViewer] Ignoring rapid disconnection event');
      return;
    }
    lastDisconnectTimeRef.current = now;

    // Clear any pending reconnection
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }

    // Calculate exponential backoff (max 30 seconds)
    const backoffMs = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
    console.log(`[StreamViewer] Scheduling reconnection in ${backoffMs}ms (attempt ${reconnectAttempts + 1})`);

    setConnectionState('connecting');
    setReconnectAttempts((prev) => prev + 1);

    reconnectTimeoutRef.current = setTimeout(() => {
      setLocalTicket(undefined);
      setGlobalState({ streamTicket: undefined });
      setRetryCounter((value) => value + 1);
    }, backoffMs);
  }, [setGlobalState, state, reconnectAttempts]);

  useEffect(() => {
    if (state !== 'Running') {
      setLocalTicket(undefined);
      setConnectionState('idle');
      setLastError(undefined);
      return;
    }

    if (streamTicket) {
      setLocalTicket(streamTicket);
      setConnectionState('connecting');
      setLastError(undefined);
      return;
    }

    let cancelled = false;
    setConnectionState('connecting');
    setLastError(undefined);
    fetchStreamUrl()
      .then((ticket) => {
        if (!cancelled) {
          setLocalTicket(ticket);
          setGlobalState({ streamTicket: ticket });
        }
      })
      .catch((error) => {
        if (!cancelled) {
          console.error('[StreamViewer] Failed to fetch stream ticket', error);
          setLocalTicket(undefined);
          setConnectionState('error');
          setLastError(error instanceof Error ? error.message : String(error));
        }
      });

    return () => {
      cancelled = true;
    };
  }, [state, streamTicket, setGlobalState, retryCounter]);

  const handleStateChange = useCallback((value: 'connecting' | 'connected' | 'disconnected') => {
    if (value === 'connected') {
      setConnectionState('connected');
      setLastError(undefined);
      setReconnectAttempts(0); // Reset reconnection counter on successful connection
      return;
    }
    if (value === 'disconnected') {
      console.warn('[StreamViewer] WebRTC session disconnected; scheduling reconnection');
      scheduleReconnect();
      return;
    }
    setConnectionState('connecting');
  }, [scheduleReconnect]);

  const handleError = useCallback((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[StreamViewer] WebRTC error', message);
    setLastError(message);

    // Don't reconnect on every error - some errors are transient
    // Only reconnect if we're not already in a reconnection state
    if (connectionState === 'connected') {
      scheduleReconnect();
    }
  }, [scheduleReconnect, connectionState]);

  // Cleanup reconnection timeout on unmount
  useEffect(() => {
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, []);

  const resolvedEndpoint = activeTicket?.grpcUrl ?? activeTicket?.url;

  if (state !== 'Running' || !activeTicket || !resolvedEndpoint) {
    return <StreamPlaceholder />;
  }

  const connectionKey = `${resolvedEndpoint}::${activeTicket.token}`;

  if (connectionState === 'error') {
    return (
      <div className="stream-viewer-error">
        <p>WebRTC stream unavailable</p>
        {lastError && <p>{lastError}</p>}
        {reconnectAttempts > 0 && <p>Reconnection attempts: {reconnectAttempts}</p>}
      </div>
    );
  }

  return (
    <div className="stream-viewer">
      <Emulator
        key={connectionKey}
        uri={resolvedEndpoint}
        view="webrtc"
        muted
        poll={true}
        onStateChange={handleStateChange}
        onError={handleError}
      />
      {connectionState !== 'connected' && (
        <div className="stream-viewer-status">
          {connectionState === 'connecting' ?
            (reconnectAttempts > 0 ? `Reconnecting (attempt ${reconnectAttempts})…` : 'Connecting Stream…')
            : 'Initialising Stream…'}
        </div>
      )}
    </div>
  );
};

export default StreamViewer;
