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

  useEffect(() => {
    if (state !== 'Running') {
      setLocalTicket(undefined);
      return;
    }

    if (streamTicket) {
      setLocalTicket(streamTicket);
      return;
    }

    let cancelled = false;
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
        }
      });

    return () => {
      cancelled = true;
    };
  }, [state, streamTicket, setGlobalState]);

  if (state !== 'Running' || !activeTicket) {
    return <StreamPlaceholder />;
  }

  return (
    <div
      style={{
        width: '100%',
        maxWidth: '420px',
        aspectRatio: '9 / 16',
        overflow: 'hidden',
        borderRadius: '16px',
        background: '#000',
        position: 'relative'
      }}
    >
      <iframe
        title="Emulator Stream"
        src={activeTicket.url}
        className="stream-viewer"
        style={{
          width: '208px',
          height: '480px',
          background: '#000',
          border: 'none',
          transform: 'scale(2.02)',
          transformOrigin: 'top left',
          position: 'absolute',
          top: 0,
          left: 0
        }}
        allow="autoplay; fullscreen"
      />
    </div>
  );
};

export default StreamViewer;
