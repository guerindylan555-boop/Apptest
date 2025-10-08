interface ErrorBannerProps {
  message: string;
  hint?: string;
  logsHref?: string;
  logsPath?: string;
  actionLabel?: string;
  onAction?: () => void;
}

const ErrorBanner = ({ message, hint, logsHref, logsPath, actionLabel, onAction }: ErrorBannerProps) => (
  <aside
    style={{
      border: '1px solid rgba(248, 113, 113, 0.4)',
      borderRadius: '0.75rem',
      padding: '1rem',
      background: 'rgba(248, 113, 113, 0.1)',
      color: '#fee2e2',
      display: 'grid',
      gap: '0.5rem'
    }}
  >
    <div style={{ fontWeight: 600 }}>⚠️ {message}</div>
    {hint && <div style={{ color: '#fecaca' }}>{hint}</div>}
    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
      {logsHref ? (
        <a href={logsHref} style={{ textDecoration: 'underline' }}>
          View local logs
        </a>
      ) : (
        logsPath && <span>Logs: {logsPath}</span>
      )}
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          style={{
            background: '#ef4444',
            border: 'none',
            borderRadius: '0.5rem',
            padding: '0.45rem 0.9rem',
            color: '#fff',
            cursor: 'pointer'
          }}
        >
          {actionLabel}
        </button>
      )}
    </div>
  </aside>
);

export default ErrorBanner;
