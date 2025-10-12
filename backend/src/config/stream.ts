export const streamConfig = {
  host: process.env.WS_SCRCPY_HOST || '0.0.0.0',
  port: parseInt(process.env.WS_SCRCPY_PORT || '8000', 10),
  player: process.env.WS_SCRCPY_PLAYER || 'webcodecs',
  remote: process.env.WS_SCRCPY_REMOTE || 'tcp:8886'
};
