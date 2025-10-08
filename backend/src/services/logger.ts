import { appendFileSync, existsSync, mkdirSync } from 'fs';
import { resolve } from 'path';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

type LogDetails = Record<string, unknown> | undefined;

const LOG_DIR = resolve(process.cwd(), '../var/log/autoapp');
const LOG_FILE = resolve(LOG_DIR, 'backend.log');

if (!existsSync(LOG_DIR)) {
  mkdirSync(LOG_DIR, { recursive: true });
}

const format = (level: LogLevel, message: string, details?: LogDetails) => {
  const payload: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    level,
    message
  };
  if (details && Object.keys(details).length > 0) {
    payload.details = details;
  }
  return JSON.stringify(payload);
};

const write = (line: string) => {
  appendFileSync(LOG_FILE, line.concat('\n'));
};

export const logger = {
  log(level: LogLevel, message: string, details?: LogDetails) {
    write(format(level, message, details));
    if (level === 'error') {
      console.error('[backend]', message, details ?? '');
    }
  },
  debug(message: string, details?: LogDetails) {
    this.log('debug', message, details);
  },
  info(message: string, details?: LogDetails) {
    this.log('info', message, details);
  },
  warn(message: string, details?: LogDetails) {
    this.log('warn', message, details);
  },
  error(message: string, details?: LogDetails) {
    this.log('error', message, details);
  }
};
