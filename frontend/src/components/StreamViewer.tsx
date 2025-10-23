import { useCallback, useEffect, useState } from 'react';
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
  const setGlobalState = useAppStore((state) => state.setState);
  const activeTicket = streamTicket ?? localTicket;

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
  }, [state, streamTicket, setGlobalState]);

  const handleStateChange = useCallback((value: 'connecting' | 'connected' | 'disconnected') => {
    if (value === 'connected') {
      setConnectionState('connected');
      return;
    }
    if (value === 'disconnected') {
      setConnectionState('error');
      return;
    }
    setConnectionState('connecting');
  }, []);

  const handleError = useCallback((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error('[StreamViewer] WebRTC error', message);
    setLastError(message);
    setConnectionState('error');
  }, []);

  const resolvedEndpoint = activeTicket?.grpcUrl ?? activeTicket?.url;

  if (state !== 'Running' || !activeTicket || !resolvedEndpoint) {
    return <StreamPlaceholder />;
  }

  if (connectionState === 'error') {
    return (
      <div className="stream-viewer-error">
        <p>WebRTC stream unavailable</p>
        {lastError && <p>{lastError}</p>}
      </div>
    );
  }

  return (
    <div className="stream-viewer">
      <Emulator
        key={resolvedEndpoint}
        uri={resolvedEndpoint}
        view="webrtc"
        muted
        poll={false}
        onStateChange={handleStateChange}
        onError={handleError}
      />
      {connectionState !== 'connected' && (
        <div className="stream-viewer-status">
          {connectionState === 'connecting' ? 'Connecting Stream…' : 'Initialising Stream…'}
        </div>
      )}
    </div>
  );
};

export default StreamViewer;
