import { useEffect, useRef } from 'react';
import StreamPlaceholder from './StreamPlaceholder';
import '../styles/stream.css';

interface StreamViewerProps {
  src?: string;
  state: 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';
}

const StreamViewer = ({ src, state }: StreamViewerProps) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) {
      return;
    }
    if (!src) {
      video.pause();
      video.removeAttribute('src');
      video.load();
      return;
    }
    video.src = src;
    void video.play().catch(() => {
      // playback errors are surfaced via UI banner elsewhere
    });
  }, [src]);

  if (!src || state !== 'Running') {
    return <StreamPlaceholder />;
  }

  return (
    <video
      ref={videoRef}
      className="stream-viewer"
      aria-label="Android emulator live stream"
      muted
      playsInline
      autoPlay
    />
  );
};

export default StreamViewer;
