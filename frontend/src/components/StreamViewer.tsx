import StreamPlaceholder from './StreamPlaceholder';
import type { StreamTicket } from '../services/streamClient';
import '../styles/stream.css';

interface StreamViewerProps {
  streamTicket?: StreamTicket;
  state: 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';
}

const StreamViewer = ({ streamTicket, state }: StreamViewerProps) => {
  console.log('[StreamViewer]', { state, hasTicket: !!streamTicket, ticket: streamTicket });

  if (!streamTicket || state !== 'Running') {
    return <StreamPlaceholder />;
  }

  return (
    <iframe
      title="Emulator Stream"
      src={streamTicket.url}
      className="stream-viewer"
      style={{
        width: '100%',
        maxWidth: '1280px',
        minHeight: '900px',
        background: '#000',
        border: 'none',
        borderRadius: '8px'
      }}
      allow="autoplay; fullscreen"
    />
  );
};

export default StreamViewer;
