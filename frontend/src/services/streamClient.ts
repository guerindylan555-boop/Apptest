// @ts-expect-error - Dependency has type issues but works at runtime
import Device from 'scrcpyws-client';
// @ts-expect-error - Dependency has type issues but works at runtime
import VideoSettings from 'scrcpyws-client/src/VideoSettings';
// @ts-expect-error - Dependency has type issues but works at runtime
import Size from 'scrcpyws-client/src/Size';
import type { StreamTicket } from './backendClient';

export class StreamClient {
  private device: typeof Device | null = null;
  private container: HTMLElement | null = null;
  private isActive = false;

  constructor(container: HTMLElement) {
    this.container = container;
  }

  private getWebSocketUrl(ticket: StreamTicket): string {
    if (ticket.wsUrl) {
      return ticket.wsUrl;
    }

    try {
      const url = new URL(ticket.url);
      const hash = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
      const params = new URLSearchParams(hash.replace(/^!/, ''));
      const wsParam = params.get('ws');
      if (wsParam) {
        return decodeURIComponent(wsParam);
      }
    } catch (error) {
      console.warn('[StreamClient] Failed to derive wsUrl from ticket', error);
    }

    throw new Error('Missing wsUrl in stream ticket');
  }

  async connect(ticket: StreamTicket): Promise<void> {
    if (!this.container) {
      throw new Error('Container element not provided');
    }

    try {
      const wsTarget = this.getWebSocketUrl(ticket);
      console.log('[StreamClient] Connecting to', wsTarget);

      if (this.device) {
        this.device.shutdown();
        this.device = null;
      }

      // Create video settings
      const settings = new VideoSettings({
        lockedVideoOrientation: -1,
        bitrate: 8000000,
        maxFps: 30,
        iFrameInterval: 10,
        bounds: new Size(1920, 1080),
        sendFrameMeta: false,
      });

      // Create device instance (serial can be any string for ws-scrcpy)
      const serialNumber = ticket.token; // Use token as serial identifier
      this.device = new Device(serialNumber, wsTarget, true, settings);

      // Start the stream
      this.device.clientRun(true, settings);

      // Get the device element and add it to our container
      const deviceElement = this.device.getDeviceElement();
      this.container.innerHTML = ''; // Clear container
      this.container.appendChild(deviceElement);

      this.isActive = true;
      console.log('[StreamClient] Connected successfully');

    } catch (error) {
      console.error('[StreamClient] Connection failed:', error);
      this.isActive = false;
      throw error;
    }
  }

  disconnect(): void {
    if (this.device) {
      this.device.shutdown();
      this.device = null;
    }
    if (this.container) {
      this.container.innerHTML = '';
    }
    this.isActive = false;
    console.log('[StreamClient] Disconnected');
  }

  isStreaming(): boolean {
    return this.isActive;
  }
}
