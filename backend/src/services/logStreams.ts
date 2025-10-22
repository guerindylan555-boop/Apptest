import { LogBuffer } from './logBuffer';

const DEFAULT_LIMIT = Number.parseInt(process.env.LOG_LINE_LIMIT ?? '1000', 10);

export const emulatorLogBuffer = new LogBuffer(DEFAULT_LIMIT);
export const streamerLogBuffer = new LogBuffer(DEFAULT_LIMIT);

export const getEmulatorLogs = () => emulatorLogBuffer.toArray();
export const getStreamerLogs = () => streamerLogBuffer.toArray();

export const clearAllLogs = () => {
  emulatorLogBuffer.clear();
  streamerLogBuffer.clear();
};
