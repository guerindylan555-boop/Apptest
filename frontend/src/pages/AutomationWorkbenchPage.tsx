import { useState, type ReactNode } from 'react';
import { runUiDiscovery, type UiDiscoveryResult } from '../services/backendClient';

type DiscoveryState =
  | { status: 'idle' }
  | { status: 'running' }
  | { status: 'error'; message: string }
  | { status: 'completed'; result: UiDiscoveryResult };

const Panel = ({ title, children }: { title: string; children?: ReactNode }) => (
  <section
    style={{
      flex: 1,
      backgroundColor: '#0f172a',
      color: '#e2e8f0',
      borderRadius: '0.75rem',
      padding: '1rem',
      minHeight: '240px',
      display: 'flex',
      flexDirection: 'column',
      gap: '0.75rem'
    }}
  >
    <header>
      <h2 style={{ margin: 0, fontSize: '1.2rem' }}>{title}</h2>
      <p style={{ margin: 0, fontSize: '0.85rem', color: '#94a3b8' }}>
        Work with the assistant best suited for the next automation step.
      </p>
    </header>
    <div
      style={{
        flex: 1,
        backgroundColor: '#16213b',
        borderRadius: '0.5rem',
        padding: '1rem',
        border: '1px solid #1d2b4f',
        minHeight: '180px'
      }}
    >
      {children ?? (
        <p style={{ margin: 0, color: '#cbd5f5' }}>
          Chat integration coming soon. Use this space to plan prompts and capture ideas for Codex or Claude.
        </p>
      )}
    </div>
  </section>
);

const DiscoverySummary = ({ result }: { result: UiDiscoveryResult }) => {
  if (result.screens.length === 0) {
    return <p style={{ color: '#64748b' }}>No screens captured during UI discovery.</p>;
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
        marginTop: '1rem'
      }}
    >
      <div
        style={{
          display: 'flex',
          gap: '2rem',
          flexWrap: 'wrap',
          fontSize: '0.95rem'
        }}
      >
        <span>
          <strong>Run:</strong> {result.runId}
        </span>
        <span>
          <strong>Screens:</strong> {result.screenCount}
        </span>
        <span>
          <strong>Transitions:</strong> {result.transitionCount}
        </span>
        <span>
          <strong>Serial:</strong> {result.deviceSerial}
        </span>
        <span>
          <strong>Artefacts:</strong> {result.runDirectory}
        </span>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '1rem'
        }}
      >
        {result.screens.map((screen) => (
          <div
            key={screen.id}
            style={{
              border: '1px solid #e2e8f0',
              borderRadius: '0.5rem',
              padding: '0.75rem',
              backgroundColor: '#fff',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem'
            }}
          >
            <header>
              <strong style={{ fontSize: '1rem' }}>{screen.id}</strong>
              <p style={{ margin: 0, color: '#475569', fontSize: '0.8rem' }}>
                Path: {screen.path.length > 0 ? screen.path.join(' → ') : 'Root'}
              </p>
            </header>
            <p style={{ margin: 0, color: '#475569', fontSize: '0.8rem' }}>
              XML: <code>{screen.xmlPath}</code>
            </p>
            <p style={{ margin: 0, color: '#475569', fontSize: '0.8rem' }}>
              Screenshot: <code>{screen.screenshotPath}</code>
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <span style={{ fontWeight: 600, fontSize: '0.85rem' }}>Actions ({screen.actions.length})</span>
              {screen.actions.slice(0, 5).map((action) => (
                <div key={`${screen.id}-${action.id}`} style={{ fontSize: '0.8rem', color: '#475569' }}>
                  <strong>{action.label}</strong>
                  <div>
                    <code>
                      ({action.center.x},{action.center.y})
                    </code>{' '}
                    {action.resourceId ? `• ${action.resourceId}` : ''}
                  </div>
                </div>
              ))}
              {screen.actions.length > 5 && (
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  +{screen.actions.length - 5} more actions recorded
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const AutomationWorkbenchPage = () => {
  const [discoveryState, setDiscoveryState] = useState<DiscoveryState>({ status: 'idle' });

  const runDiscovery = async () => {
    setDiscoveryState({ status: 'running' });
    try {
      const result = await runUiDiscovery();
      setDiscoveryState({ status: 'completed', result });
    } catch (error) {
      setDiscoveryState({
        status: 'error',
        message: error instanceof Error ? error.message : 'UI discovery failed'
      });
    }
  };

  return (
    <div style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h1 style={{ margin: 0 }}>Automation Workbench</h1>
          <p style={{ margin: 0, color: '#64748b' }}>
            Coordinate Codex and Claude, harvest UI maps, and plan automated security tests.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            type="button"
            onClick={runDiscovery}
            disabled={discoveryState.status === 'running'}
            style={{
              backgroundColor: '#2563eb',
              color: '#fff',
              border: 'none',
              borderRadius: '0.5rem',
              padding: '0.6rem 1.25rem',
              fontSize: '0.95rem',
              cursor: discoveryState.status === 'running' ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >
            {discoveryState.status === 'running'
              ? 'Discovering UI…'
              : (
              <>
                <span role="img" aria-label="radar">
                  🛰️
                </span>
                Discover UI
              </>
            )}
          </button>
        </div>
      </header>

      {discoveryState.status === 'error' && (
        <div
          style={{
            border: '1px solid #fecaca',
            backgroundColor: '#fef2f2',
            color: '#b91c1c',
            padding: '1rem',
            borderRadius: '0.5rem'
          }}
        >
          <strong>UI discovery failed.</strong>
          <div>{discoveryState.message}</div>
        </div>
      )}

      <div
        style={{
          display: 'flex',
          gap: '1rem',
          flexWrap: 'wrap'
        }}
      >
        <Panel title="Codex Assistant" />
        <Panel title="Claude Assistant" />
      </div>

      <section
        style={{
          backgroundColor: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: '0.75rem',
          padding: '1.25rem',
          minHeight: '220px'
        }}
      >
        <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h2 style={{ margin: 0 }}>UI Discovery</h2>
            <p style={{ margin: 0, fontSize: '0.85rem', color: '#64748b' }}>
              Generated maps, actionable controls, and navigation hints for automated testing.
            </p>
          </div>
          {discoveryState.status === 'running' && (
            <span style={{ fontSize: '0.85rem', color: '#2563eb' }}>Exploring interface…</span>
          )}
        </header>

        {discoveryState.status === 'completed' ? (
          <DiscoverySummary result={discoveryState.result} />
        ) : discoveryState.status === 'running' ? (
          <p style={{ marginTop: '1rem', color: '#64748b' }}>
            Crawling the application UI… this can take up to a minute depending on depth.
          </p>
        ) : (
          <p style={{ marginTop: '1rem', color: '#94a3b8' }}>
            Run a discovery sweep to map the app screens before planning automation.
          </p>
        )}
      </section>
    </div>
  );
};

export default AutomationWorkbenchPage;
