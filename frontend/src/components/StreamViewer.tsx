import { useEffect, useRef } from 'react';
import StreamPlaceholder from './StreamPlaceholder';
import type { StreamTicket } from '../services/backendClient';
import { StreamClient } from '../services/streamClient';
import '../styles/stream.css';

interface StreamViewerProps {
  streamTicket?: StreamTicket;
  state: 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';
}

const StreamViewer = ({ streamTicket, state }: StreamViewerProps) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const clientRef = useRef<StreamClient | null>(null);
  const token = streamTicket?.token;

  useEffect(() => {
    return () => {
      clientRef.current?.disconnect();
      clientRef.current = null;
    };
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    const ticket = streamTicket;

    if (!container) {
      clientRef.current?.disconnect();
      return;
    }

    if (state !== 'Running' || !ticket) {
      clientRef.current?.disconnect();
      container.innerHTML = '';
      return;
    }

    let cancelled = false;
    const client = clientRef.current ?? new StreamClient(container);
    clientRef.current = client;

    client
      .connect(ticket)
      .catch((error) => {
        if (!cancelled) {
          console.error('[StreamViewer] Failed to attach stream', error);
          container.innerHTML = '';
        }
      });

    return () => {
      cancelled = true;
    };
  }, [state, token, streamTicket?.url, streamTicket?.wsUrl]);

  if (!streamTicket || state !== 'Running') {
    return <StreamPlaceholder />;
  }

  return (
    <div className="stream-viewer">
      <div ref={containerRef} className="stream-canvas" />
    </div>
  );
};

export default StreamViewer;
