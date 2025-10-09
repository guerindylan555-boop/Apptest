interface Action {
  label: string;
  onClick: () => void;
  primary?: boolean;
}

interface ErrorBannerProps {
  message: string;
  hint?: string;
  logsHref?: string;
  logsPath?: string;
  actions?: Action[];
  // Legacy support for single action
  actionLabel?: string;
  onAction?: () => void;
}

const ErrorBanner = ({
  message,
  hint,
  logsHref,
  logsPath,
  actions,
  actionLabel,
  onAction
}: ErrorBannerProps) => {
  // Combine legacy and new action formats
  const allActions: Action[] = [];

  if (actions) {
    allActions.push(...actions);
  }

  if (actionLabel && onAction) {
    allActions.push({ label: actionLabel, onClick: onAction, primary: true });
  }

  return (
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
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        {logsHref ? (
          <a href={logsHref} style={{ textDecoration: 'underline' }}>
            View local logs
          </a>
        ) : (
          logsPath && <span>Logs: {logsPath}</span>
        )}
        {allActions.map((action, index) => (
          <button
            key={index}
            type="button"
            onClick={action.onClick}
            style={{
              background: action.primary ? '#ef4444' : '#dc2626',
              border: 'none',
              borderRadius: '0.5rem',
              padding: '0.45rem 0.9rem',
              color: '#fff',
              cursor: 'pointer',
              opacity: action.primary ? 1 : 0.9
            }}
          >
            {action.label}
          </button>
        ))}
      </div>
    </aside>
  );
};

export default ErrorBanner;
