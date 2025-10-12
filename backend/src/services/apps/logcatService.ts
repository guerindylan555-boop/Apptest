import { spawn, ChildProcess } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import { appPaths } from '../../config';
import { randomUUID } from 'crypto';
import type { LogCapture, LogCaptureStatus } from '../../types/apps';

/**
 * Logcat Capture Service
 *
 * Manages logcat streaming sessions with file persistence.
 */

/** Active logcat sessions */
const activeSessions: Map<string, {
  capture: LogCapture;
  process: ChildProcess;
  fileStream: fs.FileHandle | null;
}> = new Map();

/**
 * Start a new logcat capture session
 */
export async function startCapture(
  filters: { packages?: string[]; tags?: string[] },
  apkId?: string
): Promise<LogCapture> {
  const sessionId = randomUUID();
  const logFilePath = path.join(appPaths.logsDir, `logcat-${sessionId}.txt`);

  // Build logcat command with filters
  const args = ['logcat', '-v', 'time'];

  // Add package filter if specified
  if (filters.packages && filters.packages.length > 0) {
    // For package filtering, we'll use grep in the pipeline
    args.push('*:V'); // Verbose for all, will filter later
  }

  // Add tag filter if specified
  if (filters.tags && filters.tags.length > 0) {
    filters.tags.forEach(tag => {
      args.push(`${tag}:V`);
    });
  }

  // Create capture record
  const capture: LogCapture = {
    id: sessionId,
    apkId: apkId || null,
    filters: {
      packages: filters.packages || [],
      tags: filters.tags || []
    },
    status: 'active' as LogCaptureStatus,
    startedAt: new Date().toISOString(),
    endedAt: null,
    filePath: logFilePath,
    sizeBytes: 0,
    downloaded: false
  };

  try {
    // Open file for writing
    const fileHandle = await fs.open(logFilePath, 'w');

    // Start logcat process
    const logcatProcess = spawn('adb', args);

    // Apply package filtering if needed
    let outputStream = logcatProcess.stdout;

    // Pipe to file
    logcatProcess.stdout.on('data', async (data) => {
      try {
        const text = data.toString();

        // Apply package filter if specified
        if (filters.packages && filters.packages.length > 0) {
          const lines = text.split('\n');
          const filtered = lines.filter((line: string) =>
            filters.packages!.some(pkg => line.includes(pkg))
          );
          if (filtered.length > 0) {
            await fileHandle.write(filtered.join('\n') + '\n');
          }
        } else {
          await fileHandle.write(text);
        }
      } catch (err) {
        console.error('[LogcatService] Write error:', err);
      }
    });

    logcatProcess.stderr.on('data', (data) => {
      console.warn('[LogcatService] stderr:', data.toString());
    });

    logcatProcess.on('exit', async (code) => {
      console.log(`[LogcatService] Session ${sessionId} exited with code ${code}`);
      await fileHandle.close();

      // Update session status
      const session = activeSessions.get(sessionId);
      if (session) {
        session.capture.status = 'stopped' as LogCaptureStatus;
        session.capture.endedAt = new Date().toISOString();

        // Get final file size
        try {
          const stats = await fs.stat(logFilePath);
          session.capture.sizeBytes = stats.size;
        } catch (err) {
          console.error('[LogcatService] Failed to get file size:', err);
        }
      }
    });

    // Store session
    activeSessions.set(sessionId, {
      capture,
      process: logcatProcess,
      fileStream: fileHandle
    });

    console.log(`[LogcatService] Started capture session ${sessionId}`);
    return capture;
  } catch (error) {
    console.error('[LogcatService] Failed to start capture:', error);
    throw error;
  }
}

/**
 * Pause a capture session
 */
export async function pauseCapture(sessionId: string): Promise<LogCapture | null> {
  const session = activeSessions.get(sessionId);
  if (!session) {
    return null;
  }

  // Kill the process to pause
  session.process.kill('SIGSTOP');
  session.capture.status = 'paused' as LogCaptureStatus;

  return session.capture;
}

/**
 * Resume a paused capture session
 */
export async function resumeCapture(sessionId: string): Promise<LogCapture | null> {
  const session = activeSessions.get(sessionId);
  if (!session) {
    return null;
  }

  // Resume the process
  session.process.kill('SIGCONT');
  session.capture.status = 'active' as LogCaptureStatus;

  return session.capture;
}

/**
 * Stop a capture session
 */
export async function stopCapture(sessionId: string): Promise<LogCapture | null> {
  const session = activeSessions.get(sessionId);
  if (!session) {
    return null;
  }

  // Kill the process
  session.process.kill('SIGTERM');

  // Close file stream
  if (session.fileStream) {
    await session.fileStream.close();
  }

  session.capture.status = 'stopped' as LogCaptureStatus;
  session.capture.endedAt = new Date().toISOString();

  // Get final file size
  try {
    const stats = await fs.stat(session.capture.filePath!);
    session.capture.sizeBytes = stats.size;
  } catch (err) {
    console.error('[LogcatService] Failed to get file size:', err);
  }

  // Remove from active sessions
  activeSessions.delete(sessionId);

  console.log(`[LogcatService] Stopped capture session ${sessionId}`);
  return session.capture;
}

/**
 * Get a capture session by ID
 */
export function getCapture(sessionId: string): LogCapture | null {
  const session = activeSessions.get(sessionId);
  return session ? session.capture : null;
}

/**
 * Get all active capture sessions
 */
export function getAllCaptures(): LogCapture[] {
  return Array.from(activeSessions.values()).map(s => s.capture);
}

/**
 * Read the captured log file
 */
export async function readCaptureFile(sessionId: string): Promise<string | null> {
  const session = activeSessions.get(sessionId);
  if (!session || !session.capture.filePath) {
    return null;
  }

  try {
    const content = await fs.readFile(session.capture.filePath, 'utf-8');
    return content;
  } catch (err) {
    console.error('[LogcatService] Failed to read capture file:', err);
    return null;
  }
}
