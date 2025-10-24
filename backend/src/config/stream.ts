const parseIceServers = (): string[] => {
  const raw = process.env.EMULATOR_WEBRTC_ICE_SERVERS;
  if (!raw) {
    return [];
  }
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

export const streamConfig = {
  grpcEndpoint: process.env.EMULATOR_GRPC_ENDPOINT || 'http://envoy:8080',
  publicUrl: process.env.EMULATOR_WEBRTC_PUBLIC_URL || 'http://127.0.0.1:9000',
  iceServers: parseIceServers()
};
