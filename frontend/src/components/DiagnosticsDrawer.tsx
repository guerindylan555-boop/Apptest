import { useState } from 'react';

interface DiagnosticsDrawerProps {
  pid?: number;
  bootElapsedMs?: number;
  ports?: { console: number; adb: number };
  lastError?: { code: string; message: string; hint?: string };
}

const DiagnosticsDrawer = ({ pid, bootElapsedMs, ports, lastError }: DiagnosticsDrawerProps) => {
  const [isOpen, setOpen] = useState(false);
  const uptimeSeconds = bootElapsedMs ? Math.round(bootElapsedMs / 1000) : undefined;

  return (
    <section
      style={{
        background: 'rgba(30, 41, 59, 0.55)',
        borderRadius: '0.75rem',
        padding: '0.75rem 1rem'
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        style={{
          background: 'transparent',
          border: 'none',
          color: '#93c5fd',
          fontWeight: 600,
          cursor: 'pointer'
        }}
      >
        {isOpen ? 'Hide diagnostics ▲' : 'Show diagnostics ▼'}
      </button>
      {isOpen && (
        <dl style={{ marginTop: '0.75rem', display: 'grid', gap: '0.35rem' }}>
          {pid !== undefined && (
            <div>
              <dt style={{ fontWeight: 600 }}>PID</dt>
              <dd style={{ margin: 0 }}>{pid}</dd>
            </div>
          )}
          {uptimeSeconds !== undefined && (
            <div>
              <dt style={{ fontWeight: 600 }}>Boot uptime</dt>
              <dd style={{ margin: 0 }}>{uptimeSeconds}s</dd>
            </div>
          )}
          {ports && (
            <div>
              <dt style={{ fontWeight: 600 }}>Ports</dt>
              <dd style={{ margin: 0 }}>console {ports.console} / adb {ports.adb}</dd>
            </div>
          )}
          {lastError && (
            <div>
              <dt style={{ fontWeight: 600 }}>Last error</dt>
              <dd style={{ margin: 0 }}>{lastError.code}: {lastError.message}</dd>
            </div>
          )}
        </dl>
      )}
    </section>
  );
};

export default DiagnosticsDrawer;
