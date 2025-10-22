export class LogBuffer {
  private lines: string[] = [];

  private remainder = '';

  constructor(private readonly limit = 500) {}

  /**
   * Append raw chunk output. Handles newline framing and keeps only the latest `limit` lines.
   */
  append(chunk: string) {
    const combined = this.remainder + chunk;
    const parts = combined.split(/\r?\n/);
    this.remainder = parts.pop() ?? '';
    for (const line of parts) {
      this.pushLine(line);
    }
  }

  pushLine(line: string) {
    const trimmed = line.trimEnd();
    if (trimmed.length > 0) {
      this.lines.push(trimmed);
      if (this.lines.length > this.limit) {
        this.lines.splice(0, this.lines.length - this.limit);
      }
    }
  }

  /**
   * Flush any buffered remainder as a line (used when processes exit).
   */
  flushRemainder(prefix?: string) {
    if (this.remainder.length > 0) {
      const value = prefix ? `${prefix} ${this.remainder}` : this.remainder;
      this.pushLine(value);
      this.remainder = '';
    }
  }

  toArray() {
    return [...this.lines];
  }

  toString() {
    return this.lines.join('\n');
  }

  clear() {
    this.lines = [];
    this.remainder = '';
  }
}

export const attachProcessLoggers = (
  proc: import('child_process').ChildProcess,
  buffer: LogBuffer,
  label: string
) => {
  const createObserver = () => {
    let leftover = '';
    return {
      onData(data: unknown) {
        const chunk = typeof data === 'string' ? data : data?.toString?.() ?? '';
        const combined = leftover + chunk;
        const segments = combined.split(/\r?\n/);
        leftover = segments.pop() ?? '';
        for (const segment of segments) {
          const trimmed = segment.trimEnd();
          if (trimmed.length === 0) {
            continue;
          }
          buffer.pushLine(`[${label}] ${trimmed}`);
        }
      },
      flush() {
        if (leftover.trim().length > 0) {
          buffer.pushLine(`[${label}] ${leftover.trimEnd()}`);
        }
        leftover = '';
      }
    };
  };

  const stdoutObserver = createObserver();
  const stderrObserver = createObserver();

  proc.stdout?.on('data', (data) => stdoutObserver.onData(data));
  proc.stderr?.on('data', (data) => stderrObserver.onData(data));
  proc.on('close', () => {
    stdoutObserver.flush();
    stderrObserver.flush();
    buffer.flushRemainder(`[${label}]`);
  });
};
