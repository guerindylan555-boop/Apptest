export const streamConfig = {
  host: process.env.STREAM_HOST || '127.0.0.1',
  port: parseInt(process.env.STREAM_PORT || '8081', 10),
  timeoutMs: parseInt(process.env.STREAM_TIMEOUT_MS || '45000', 10),

  get bridgeUrl(): string {
    return `ws://${this.host}:${this.port}`;
  },

  get httpUrl(): string {
    return `http://${this.host}:${this.port}`;
  }
};