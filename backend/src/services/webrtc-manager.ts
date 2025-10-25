import { EventEmitter } from 'events';
import { logger } from './logger';
import { streamConfig } from '../config/stream';

// WebRTC connection states as per constitution
export type WebRTCConnectionState =
  | 'disconnected'  // No active connection
  | 'connecting'    // Attempting to establish connection
  | 'connected'     // Connection established and stable
  | 'reconnecting'  // Attempting to restore lost connection
  | 'failed'        // Connection failed after retries
  | 'closed';       // Connection intentionally closed

// Connection quality metrics
export interface ConnectionMetrics {
  connectionTime: number;        // Time to establish connection (ms)
  lastActivity: Date;           // Last activity timestamp
  reconnectAttempts: number;    // Number of reconnection attempts
  totalDowntime: number;        // Total time disconnected (ms)
  dataTransferred: number;      // Bytes transferred
  iceCandidates: number;        // ICE candidates processed
}

// WebRTC connection configuration
export interface WebRTCConnectionConfig {
  // Constitution-mandated timeouts (all in milliseconds)
  CONNECTION_TIMEOUT: number;           // 1.5s connection timeout as per constitution
  HEALTH_CHECK_INTERVAL: number;        // <500ms performance budget for health checks
  ICE_TIMEOUT: number;                  // ICE gathering timeout
  MAX_RECONNECTION_ATTEMPTS: number;    // Maximum retry attempts
  RECONNECTION_DELAY: number;           // Base delay for exponential backoff
  MAX_RECONNECTION_DELAY: number;       // Maximum delay for reconnection

  // WebRTC server configuration
  iceServers: RTCIceServer[];

  // Quality settings
  videoResolution?: string;
  frameRate?: number;
  bitrate?: number;
}

// Connection event data
export interface ConnectionEvent {
  timestamp: Date;
  state: WebRTCConnectionState;
  error?: Error;
  metrics?: Partial<ConnectionMetrics>;
  metadata?: Record<string, unknown>;
}

// Stream information for emulator display
export interface StreamInfo {
  streamId: string;
  emulatorId: string;
  isActive: boolean;
  quality: {
    resolution: string;
    frameRate: number;
    bitrate: number;
  };
  startTime: Date;
  lastFrame: Date;
}

/**
 * WebRTC Connection Manager
 *
 * Manages WebRTC peer connections with constitution-mandated 1.5s timeout
 * and provides connection state monitoring, health checks, and retry logic.
 */
export class WebRTCManager extends EventEmitter {
  private config: WebRTCConnectionConfig;
  private peerConnection: RTCPeerConnection | null = null;
  private dataChannel: RTCDataChannel | null = null;
  private connectionState: WebRTCConnectionState = 'disconnected';
  private metrics: ConnectionMetrics;
  private healthCheckTimer: NodeJS.Timeout | null = null;
  private connectionTimer: NodeJS.Timeout | null = null;
  private iceGatherTimer: NodeJS.Timeout | null = null;
  private reconnectionAttempts = 0;
  private currentStream: StreamInfo | null = null;
  private isDestroyed = false;

  constructor(config?: Partial<WebRTCConnectionConfig>) {
    super();

    // Load configuration from environment variables with constitution defaults
    this.config = {
      // Constitution-mandated timeouts
      CONNECTION_TIMEOUT: parseInt(process.env.WEBRTC_TIMEOUT || '1500'), // 1.5s default
      HEALTH_CHECK_INTERVAL: 400, // <500ms performance budget
      ICE_TIMEOUT: parseInt(process.env.WEBRTC_ICE_TIMEOUT || '10000'),
      MAX_RECONNECTION_ATTEMPTS: parseInt(process.env.WEBRTC_RECONNECTION_ATTEMPTS || '3'),
      RECONNECTION_DELAY: 1000, // Base delay for exponential backoff
      MAX_RECONNECTION_DELAY: 30000, // Maximum 30s delay

      // WebRTC server configuration from environment
      iceServers: this.parseIceServers(process.env.EMULATOR_WEBRTC_ICE_SERVERS ||
        'stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302'),

      // Quality settings from environment
      videoResolution: process.env.WEBRTC_RESOLUTION || '720p',
      frameRate: parseInt(process.env.WEBRTC_FRAME_RATE || '15'),
      bitrate: parseInt(process.env.WEBRTC_BITRATE || '2000'),

      ...config
    };

    // Initialize metrics
    this.metrics = {
      connectionTime: 0,
      lastActivity: new Date(),
      reconnectAttempts: 0,
      totalDowntime: 0,
      dataTransferred: 0,
      iceCandidates: 0
    };

    logger.info('WebRTC Manager initialized', {
      config: {
        connectionTimeout: this.config.CONNECTION_TIMEOUT,
        healthCheckInterval: this.config.HEALTH_CHECK_INTERVAL,
        iceTimeout: this.config.ICE_TIMEOUT,
        maxReconnectionAttempts: this.config.MAX_RECONNECTION_ATTEMPTS,
        iceServers: this.config.iceServers.length
      }
    });
  }

  /**
   * Parse ICE servers from environment variable string
   */
  private parseIceServers(serversString: string): RTCIceServer[] {
    try {
      const servers = serversString.split(',').map(server => {
        server = server.trim();
        if (server.startsWith('stun:')) {
          return { urls: server };
        } else if (server.startsWith('turn:')) {
          // Basic TURN server configuration - in production, this should include credentials
          return { urls: server };
        }
        return { urls: server };
      }).filter(server => server.urls);

      return servers;
    } catch (error) {
      logger.warn('Failed to parse ICE servers, using defaults', {
        serversString,
        error: (error as Error).message
      });

      return [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
      ];
    }
  }

  /**
   * Create a new peer connection with constitution timeout
   */
  private createPeerConnection(): RTCPeerConnection {
    logger.debug('Creating new peer connection', {
      iceServers: this.config.iceServers.length,
      timeout: this.config.CONNECTION_TIMEOUT
    });

    const pc = new RTCPeerConnection({
      iceServers: this.config.iceServers,
      iceCandidatePoolSize: 10,
      bundlePolicy: 'max-bundle',
      rtcpMuxPolicy: 'require'
    });

    // Set up connection state monitoring
    pc.onconnectionstatechange = () => {
      this.handleConnectionStateChange(pc.connectionState);
    };

    pc.oniceconnectionstatechange = () => {
      this.handleICEConnectionStateChange(pc.iceConnectionState);
    };

    pc.onicegatheringstatechange = () => {
      this.handleICEGatheringStateChange(pc.iceGatheringState);
    };

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.metrics.iceCandidates++;
        this.emit('iceCandidate', event.candidate);
      }
    };

    return pc;
  }

  /**
   * Handle WebRTC connection state changes
   */
  private handleConnectionStateChange(state: RTCPeerConnectionState): void {
    const previousState = this.connectionState;

    switch (state) {
      case 'new':
        this.updateConnectionState('connecting');
        break;
      case 'connecting':
        this.updateConnectionState('connecting');
        break;
      case 'connected':
        this.updateConnectionState('connected');
        this.onConnectionEstablished();
        break;
      case 'disconnected':
        this.updateConnectionState('reconnecting');
        this.handleDisconnection();
        break;
      case 'failed':
        this.updateConnectionState('failed');
        this.handleConnectionFailure();
        break;
      case 'closed':
        this.updateConnectionState('closed');
        break;
    }

    logger.debug('WebRTC connection state changed', {
      from: previousState,
      to: state,
      metrics: this.metrics
    });
  }

  /**
   * Handle ICE connection state changes
   */
  private handleICEConnectionStateChange(state: RTCIceConnectionState): void {
    logger.debug('ICE connection state changed', {
      state,
      connectionState: this.connectionState
    });

    if (state === 'failed' || state === 'disconnected') {
      this.handleICEFailure();
    }
  }

  /**
   * Handle ICE gathering state changes
   */
  private handleICEGatheringStateChange(state: RTCIceGatheringState): void {
    if (state === 'complete') {
      logger.debug('ICE gathering completed', {
        candidates: this.metrics.iceCandidates,
        duration: Date.now() - this.metrics.lastActivity.getTime()
      });
    }
  }

  /**
   * Update connection state and emit events
   */
  private updateConnectionState(newState: WebRTCConnectionState, error?: Error): void {
    const previousState = this.connectionState;
    this.connectionState = newState;

    const event: ConnectionEvent = {
      timestamp: new Date(),
      state: newState,
      error,
      metrics: { ...this.metrics }
    };

    this.emit('stateChange', event);
    this.emit(newState, event);

    if (error) {
      this.emit('error', event);
    }
  }

  /**
   * Handle successful connection establishment
   */
  private onConnectionEstablished(): void {
    this.reconnectionAttempts = 0;
    this.metrics.connectionTime = Date.now() - this.metrics.lastActivity.getTime();
    this.metrics.lastActivity = new Date();

    // Start health monitoring
    this.startHealthChecks();

    logger.info('WebRTC connection established successfully', {
      connectionTime: this.metrics.connectionTime,
      iceCandidates: this.metrics.iceCandidates
    });
  }

  /**
   * Handle connection disconnection
   */
  private handleDisconnection(): void {
    this.stopHealthChecks();

    if (!this.isDestroyed && this.reconnectionAttempts < this.config.MAX_RECONNECTION_ATTEMPTS) {
      this.scheduleReconnection();
    } else {
      this.updateConnectionState('failed', new Error('Maximum reconnection attempts exceeded'));
    }
  }

  /**
   * Handle connection failure
   */
  private handleConnectionFailure(): void {
    this.stopHealthChecks();
    this.clearTimers();

    logger.error('WebRTC connection failed', {
      attempts: this.reconnectionAttempts,
      maxAttempts: this.config.MAX_RECONNECTION_ATTEMPTS,
      metrics: this.metrics
    });
  }

  /**
   * Handle ICE connection failure
   */
  private handleICEFailure(): void {
    logger.warn('ICE connection failed', {
      state: this.connectionState,
      candidates: this.metrics.iceCandidates
    });

    if (this.connectionState === 'connecting') {
      this.clearConnectionTimer();
      this.updateConnectionState('failed', new Error('ICE connection failed'));
    }
  }

  /**
   * Schedule reconnection with exponential backoff
   */
  private scheduleReconnection(): void {
    this.reconnectionAttempts++;
    this.metrics.reconnectAttempts = this.reconnectionAttempts;

    const delay = Math.min(
      this.config.RECONNECTION_DELAY * Math.pow(2, this.reconnectionAttempts - 1),
      this.config.MAX_RECONNECTION_DELAY
    );

    logger.info('Scheduling WebRTC reconnection', {
      attempt: this.reconnectionAttempts,
      delay,
      maxAttempts: this.config.MAX_RECONNECTION_ATTEMPTS
    });

    setTimeout(() => {
      if (!this.isDestroyed && this.connectionState !== 'connected') {
        this.connect().catch(error => {
          logger.error('Reconnection failed', {
            attempt: this.reconnectionAttempts,
            error: error.message
          });
        });
      }
    }, delay);
  }

  /**
   * Start health monitoring with <500ms performance budget
   */
  private startHealthChecks(): void {
    this.stopHealthChecks();

    this.healthCheckTimer = setInterval(() => {
      this.performHealthCheck();
    }, this.config.HEALTH_CHECK_INTERVAL);
  }

  /**
   * Stop health monitoring
   */
  private stopHealthChecks(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }

  /**
   * Perform health check within performance budget
   */
  private async performHealthCheck(): Promise<void> {
    const startTime = Date.now();

    try {
      if (!this.peerConnection || this.peerConnection.connectionState !== 'connected') {
        this.emit('healthCheckFailed', {
          reason: 'Peer connection not in connected state',
          state: this.peerConnection?.connectionState
        });
        return;
      }

      // Check data channel if it exists
      if (this.dataChannel && this.dataChannel.readyState !== 'open') {
        this.emit('healthCheckFailed', {
          reason: 'Data channel not open',
          state: this.dataChannel.readyState
        });
        return;
      }

      // Measure response time
      const responseTime = Date.now() - startTime;

      if (responseTime > this.config.HEALTH_CHECK_INTERVAL) {
        logger.warn('Health check exceeded performance budget', {
          responseTime,
          budget: this.config.HEALTH_CHECK_INTERVAL
        });
      }

      this.emit('healthCheckPassed', {
        responseTime,
        state: this.connectionState,
        timestamp: new Date()
      });

    } catch (error) {
      this.emit('healthCheckFailed', {
        error: (error as Error).message,
        responseTime: Date.now() - startTime
      });
    }
  }

  /**
   * Clear all active timers
   */
  private clearTimers(): void {
    this.clearConnectionTimer();
    this.clearIceGatherTimer();
    this.stopHealthChecks();
  }

  /**
   * Clear connection timeout timer
   */
  private clearConnectionTimer(): void {
    if (this.connectionTimer) {
      clearTimeout(this.connectionTimer);
      this.connectionTimer = null;
    }
  }

  /**
   * Clear ICE gathering timeout timer
   */
  private clearIceGatherTimer(): void {
    if (this.iceGatherTimer) {
      clearTimeout(this.iceGatherTimer);
      this.iceGatherTimer = null;
    }
  }

  /**
   * Establish WebRTC connection with 1.5s constitution timeout
   */
  public async connect(): Promise<void> {
    if (this.isDestroyed) {
      throw new Error('WebRTC manager has been destroyed');
    }

    if (this.connectionState === 'connected') {
      logger.debug('Connection already established');
      return;
    }

    if (this.connectionState === 'connecting') {
      throw new Error('Connection already in progress');
    }

    logger.info('Establishing WebRTC connection', {
      timeout: this.config.CONNECTION_TIMEOUT,
      attempt: this.reconnectionAttempts + 1
    });

    this.updateConnectionState('connecting');
    this.metrics.lastActivity = new Date();

    try {
      // Clean up existing connection
      this.cleanup();

      // Create new peer connection
      this.peerConnection = this.createPeerConnection();

      // Set connection timeout as per constitution requirement
      this.connectionTimer = setTimeout(() => {
        if (this.connectionState === 'connecting') {
          this.updateConnectionState('failed', new Error(`Connection timeout after ${this.config.CONNECTION_TIMEOUT}ms`));
          this.cleanup();
        }
      }, this.config.CONNECTION_TIMEOUT);

      // Create and configure data channel for emulator control
      this.dataChannel = this.peerConnection.createDataChannel('emulator-control', {
        ordered: true,
        maxRetransmits: 3
      });

      this.dataChannel.onopen = () => {
        logger.debug('Data channel opened');
      };

      this.dataChannel.onmessage = (event) => {
        this.handleDataChannelMessage(event);
      };

      this.dataChannel.onerror = (error) => {
        logger.error('Data channel error', { error });
      };

      // Start ICE gathering with timeout
      this.iceGatherTimer = setTimeout(() => {
        if (this.peerConnection?.iceGatheringState === 'gathering') {
          logger.warn('ICE gathering timeout, proceeding with available candidates');
        }
      }, this.config.ICE_TIMEOUT);

      // Create offer to initiate connection
      const offer = await this.peerConnection.createOffer({
        offerToReceiveVideo: true,
        offerToReceiveAudio: false
      });

      await this.peerConnection.setLocalDescription(offer);

      this.emit('offerCreated', offer);

      logger.debug('WebRTC offer created, waiting for connection', {
        sdp: offer.sdp?.substring(0, 100) + '...'
      });

    } catch (error) {
      this.clearTimers();
      this.updateConnectionState('failed', error as Error);
      this.cleanup();

      logger.error('Failed to establish WebRTC connection', {
        error: (error as Error).message,
        stack: (error as Error).stack
      });

      throw error;
    }
  }

  /**
   * Handle incoming data channel messages
   */
  private handleDataChannelMessage(event: MessageEvent): void {
    try {
      const data = JSON.parse(event.data);
      this.metrics.dataTransferred += event.data.length;
      this.metrics.lastActivity = new Date();

      this.emit('dataMessage', data);

      logger.debug('Data channel message received', {
        type: data.type,
        size: event.data.length
      });

    } catch (error) {
      logger.error('Failed to parse data channel message', {
        error: (error as Error).message,
        data: event.data
      });
    }
  }

  /**
   * Set remote answer to complete connection
   */
  public async setRemoteAnswer(answer: RTCSessionDescriptionInit): Promise<void> {
    if (!this.peerConnection) {
      throw new Error('No active peer connection');
    }

    if (this.connectionState !== 'connecting') {
      throw new Error(`Cannot set answer in state: ${this.connectionState}`);
    }

    try {
      await this.peerConnection.setRemoteDescription(answer);

      logger.info('Remote answer set successfully', {
        type: answer.type,
        state: this.peerConnection.connectionState
      });

    } catch (error) {
      this.updateConnectionState('failed', error as Error);
      logger.error('Failed to set remote answer', {
        error: (error as Error).message
      });
      throw error;
    }
  }

  /**
   * Add ICE candidate
   */
  public async addIceCandidate(candidate: RTCIceCandidateInit): Promise<void> {
    if (!this.peerConnection) {
      logger.warn('Cannot add ICE candidate: no active connection');
      return;
    }

    try {
      await this.peerConnection.addIceCandidate(candidate);
      logger.debug('ICE candidate added successfully');
    } catch (error) {
      logger.error('Failed to add ICE candidate', {
        error: (error as Error).message,
        candidate
      });
    }
  }

  /**
   * Send message through data channel
   */
  public sendMessage(message: Record<string, unknown>): void {
    if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
      throw new Error('Data channel not available');
    }

    try {
      const data = JSON.stringify(message);
      this.dataChannel.send(data);
      this.metrics.dataTransferred += data.length;
      this.metrics.lastActivity = new Date();

      logger.debug('Message sent via data channel', {
        type: message.type,
        size: data.length
      });

    } catch (error) {
      logger.error('Failed to send data channel message', {
        error: (error as Error).message,
        message
      });
      throw error;
    }
  }

  /**
   * Get current connection state
   */
  public getConnectionState(): WebRTCConnectionState {
    return this.connectionState;
  }

  /**
   * Get connection metrics
   */
  public getMetrics(): ConnectionMetrics {
    return { ...this.metrics };
  }

  /**
   * Get current stream information
   */
  public getStreamInfo(): StreamInfo | null {
    return this.currentStream;
  }

  /**
   * Check if connection is healthy
   */
  public isHealthy(): boolean {
    return this.connectionState === 'connected' &&
           (!this.healthCheckTimer || this.healthCheckTimer !== null);
  }

  /**
   * Disconnect and cleanup
   */
  public disconnect(): void {
    logger.info('Disconnecting WebRTC connection');

    this.updateConnectionState('disconnected');
    this.cleanup();
  }

  /**
   * Cleanup resources
   */
  private cleanup(): void {
    this.clearTimers();

    if (this.dataChannel) {
      this.dataChannel.close();
      this.dataChannel = null;
    }

    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }

    this.currentStream = null;
  }

  /**
   * Destroy the manager and release all resources
   */
  public destroy(): void {
    if (this.isDestroyed) {
      return;
    }

    logger.info('Destroying WebRTC manager');

    this.isDestroyed = true;
    this.updateConnectionState('closed');
    this.cleanup();

    // Remove all event listeners
    this.removeAllListeners();
  }
}

// Export singleton instance for use across the application
export const webrtcManager = new WebRTCManager();

// Export types and configuration for external use
export { WebRTCManager as WebRTCConnectionManager };