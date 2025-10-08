import clsx from 'clsx';

const stateColor: Record<string, string> = {
  Stopped: '#64748b',
  Booting: '#0ea5e9',
  Running: '#22c55e',
  Stopping: '#0ea5e9',
  Error: '#f87171'
};

export interface StateBadgeProps {
  state: 'Stopped' | 'Booting' | 'Running' | 'Stopping' | 'Error';
}

const StateBadge = ({ state }: StateBadgeProps) => (
  <span
    className={clsx('state-badge')}
    style={{
      background: stateColor[state],
      color: '#0f172a',
      borderRadius: '999px',
      padding: '0.35rem 0.85rem',
      fontWeight: 700,
      letterSpacing: '0.02em'
    }}
  >
    {state}
  </span>
);

export default StateBadge;
