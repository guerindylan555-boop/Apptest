import { useEffect, useState } from 'react';
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
  const setGlobalState = useAppStore((state) => state.setState);
  const activeTicket = streamTicket ?? localTicket;

  console.log('[StreamViewer] Render:', { state, hasStreamTicket: !!streamTicket, hasLocalTicket: !!localTicket, hasActiveTicket: !!activeTicket });

  useEffect(() => {
    console.log('[StreamViewer] Effect running:', { state, hasStreamTicket: !!streamTicket });
    if (state !== 'Running') {
      setLocalTicket(undefined);
      return;
    }

    if (streamTicket) {
      setLocalTicket(streamTicket);
      return;
    }

    console.log('[StreamViewer] Fetching stream URL...');
    let cancelled = false;
    fetchStreamUrl()
      .then((ticket) => {
        console.log('[StreamViewer] Fetched stream ticket:', ticket);
        if (!cancelled) {
          setLocalTicket(ticket);
          setGlobalState({ streamTicket: ticket });
        }
      })
      .catch((error) => {
        if (!cancelled) {
          console.error('[StreamViewer] Failed to fetch stream ticket', error);
          setLocalTicket(undefined);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [state, streamTicket?.token, setGlobalState]);

  if (state !== 'Running' || !activeTicket) {
    return <StreamPlaceholder />;
  }

  return (
    <iframe
      title="Emulator Stream"
      src={activeTicket.url}
      className="stream-viewer"
      allow="autoplay; fullscreen"
    />
  );
};

export default StreamViewer;
