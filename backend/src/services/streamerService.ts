import { logger } from './logger';
import { sessionStore } from '../state/sessionStore';
import { streamConfig } from '../config/stream';

type StreamTicketOptions = {
  requestHost?: string;
  protocol?: string;
};

const PLACEHOLDER_HOSTS = new Set(['127.0.0.1', '0.0.0.0', 'localhost', 'host.docker.internal']);
const EXTERNAL_SERIAL = process.env.EXTERNAL_EMULATOR_SERIAL || 'external-emulator';

const normaliseProtocol = (value?: string) => {
  if (!value) {
    return 'http';
  }
  const lower = value.replace(/:$/, '').toLowerCase();
  return lower === 'https' ? 'https' : 'http';
};

const parseHostHeader = (value?: string): { host?: string; port?: string } => {
  if (!value) {
    return {};
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return {};
  }

  if (trimmed.startsWith('[')) {
    const closingIndex = trimmed.indexOf(']');
    if (closingIndex > 0) {
      const host = trimmed.slice(1, closingIndex);
      const portSegment = trimmed.slice(closingIndex + 1);
      const port = portSegment.startsWith(':') ? portSegment.slice(1) : undefined;
      return { host, port };
    }
  }

  const segments = trimmed.split(':');
  if (segments.length > 1) {
    const port = segments.pop();
    return { host: segments.join(':'), port };
  }
  return { host: trimmed };
};

const ensureTrailingSlash = (value: string) => (value.endsWith('/') ? value : `${value}/`);

const resolvePublicUrl = (options?: StreamTicketOptions): string => {
  const configured = streamConfig.publicUrl?.trim();
  const protocol = normaliseProtocol(options?.protocol);
  const { host: requestHost, port: requestPort } = parseHostHeader(options?.requestHost);

  if (configured) {
    try {
      const url = new URL(configured);
      if (requestHost && PLACEHOLDER_HOSTS.has(url.hostname)) {
        url.hostname = requestHost;
        if (requestPort) {
          url.port = requestPort;
        }
        url.protocol = `${protocol}:`;
      }
      if (!url.protocol) {
        url.protocol = `${protocol}:`;
      }
      return ensureTrailingSlash(url.toString());
    } catch (error) {
      logger.warn('Invalid EMULATOR_WEBRTC_PUBLIC_URL, falling back to request host', {
        configured,
        error: (error as Error).message
      });
    }
  }

  if (!requestHost) {
    return `${protocol}://127.0.0.1:9000/`;
  }

  const authority = requestPort ? `${requestHost}:${requestPort}` : requestHost;
  return `${protocol}://${authority}/`;
};

const resolveGrpcHealthEndpoint = (): string => {
  const base = streamConfig.grpcEndpoint?.trim();
  if (!base) {
    return 'http://envoy:8080/healthz';
  }
  try {
    const url = new URL(base);
    return `${ensureTrailingSlash(url.toString())}healthz`;
  } catch (error) {
    logger.warn('Invalid EMULATOR_GRPC_ENDPOINT, using default', {
      base,
      error: (error as Error).message
    });
    return 'http://envoy:8080/healthz';
  }
};

export const issueStreamTicket = async (options?: StreamTicketOptions) => {
  const session = sessionStore.getSession();
  if (session.state !== 'Running') {
    throw new Error('Stream configuration is available only when the emulator is running');
  }

  const record = sessionStore.generateStreamTicket(EXTERNAL_SERIAL);
  const publicUrl = resolvePublicUrl(options);

  return {
    token: record.token,
    url: publicUrl,
    grpcUrl: publicUrl,
    iceServers: streamConfig.iceServers,
    expiresAt: new Date(record.expiresAt).toISOString()
  };
};

export const isStreamerActive = async (): Promise<boolean> => {
  const target = resolveGrpcHealthEndpoint();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    const response = await fetch(target, { method: 'GET', signal: controller.signal });
    clearTimeout(timeout);
    return response.ok;
  } catch (error) {
    logger.warn('WebRTC gateway health check failed', {
      target,
      error: (error as Error).message
    });
    return false;
  }
};
