interface ControlButtonProps {
  label: string;
  intent: 'start' | 'stop';
  disabled?: boolean;
  loading?: boolean;
  onClick?: () => void;
}

const intents: Record<ControlButtonProps['intent'], { background: string; disabled: string }> = {
  start: { background: '#2563eb', disabled: '#1f2937' },
  stop: { background: '#ef4444', disabled: '#7f1d1d' }
};

const ControlButton = ({ label, intent, disabled, loading, onClick }: ControlButtonProps) => {
  const colors = intents[intent];
  const isDisabled = disabled || loading;

  return (
    <button
      onClick={onClick}
      disabled={isDisabled}
      style={{
        width: '100%',
        padding: '0.9rem',
        borderRadius: '0.9rem',
        fontSize: '1.1rem',
        fontWeight: 600,
        border: 'none',
        background: isDisabled ? colors.disabled : colors.background,
        color: '#f8fafc',
        transition: 'background 0.2s ease-in-out',
        cursor: isDisabled ? 'not-allowed' : 'pointer',
        position: 'relative'
      }}
    >
      {loading && (
        <span
          aria-hidden
          style={{
            position: 'absolute',
            left: '1.25rem',
            top: '50%',
            transform: 'translateY(-50%)'
          }}
        >
          ⏳
        </span>
      )}
      {label}
    </button>
  );
};

export default ControlButton;
