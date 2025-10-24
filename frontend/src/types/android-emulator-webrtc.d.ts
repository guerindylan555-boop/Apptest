declare module 'android-emulator-webrtc' {
  import { ComponentType } from 'react';

  export interface EmulatorProps {
    uri: string;
    view?: 'webrtc' | 'png';
    auth?: unknown;
    muted?: boolean;
    volume?: number;
    poll?: boolean;
    width?: number;
    height?: number;
    onStateChange?: (state: 'connecting' | 'connected' | 'disconnected') => void;
    onAudioStateChange?: (enabled: boolean) => void;
    onError?: (error: unknown) => void;
  }

  export const Emulator: ComponentType<EmulatorProps>;
}
