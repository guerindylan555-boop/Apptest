import { useEffect } from 'react';
import { useAppsLibraryStore } from '../state/appsLibraryStore';
import { fetchEntries } from '../services/appsClient';
import ApkUploader from '../components/apps/ApkUploader';
import ApkList from '../components/apps/ApkList';
import ApkDetailsPanel from '../components/apps/ApkDetailsPanel';
import ActivityFeed from '../components/apps/ActivityFeed';
import { LogcatPanel } from '../components/apps/LogcatPanel';
import { ProxyToggle } from '../components/apps/ProxyToggle';

/**
 * Apps Library & Instrumentation Hub
 *
 * Main page for APK management, installation, instrumentation, and logging tools.
 */

const AppsPage = () => {
  const { setEntries, setLoading, setError, error } = useAppsLibraryStore();

  // Load APK entries on mount
  useEffect(() => {
    async function loadEntries() {
      setLoading(true);
      setError(null);
      try {
        const entries = await fetchEntries();
        setEntries(entries);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load APK entries');
      } finally {
        setLoading(false);
      }
    }

    loadEntries();
  }, [setEntries, setLoading, setError]);

  return (
    <div style={{ padding: '2rem', maxWidth: '1400px', margin: '0 auto' }}>
      <header style={{ marginBottom: '2rem' }}>
        <h1 style={{ margin: '0 0 0.5rem 0' }}>Apps Library</h1>
        <p style={{ margin: 0, color: '#666' }}>
          Upload, manage, and instrument APK files for testing
        </p>
      </header>

      {error && (
        <div
          style={{
            padding: '1rem',
            marginBottom: '1.5rem',
            backgroundColor: '#ffebee',
            border: '1px solid #ef5350',
            borderRadius: '4px',
            color: '#c62828'
          }}
        >
          <strong>Error:</strong> {error}
        </div>
      )}

      <main>
        {/* Upload Section */}
        <section style={{ marginBottom: '2rem' }}>
          <ApkUploader />
        </section>

        {/* Library Section */}
        <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
          {/* APK List */}
          <div>
            <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem' }}>Library</h2>
            <ApkList />
          </div>

          {/* Details Panel */}
          <div>
            <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem' }}>Details</h2>
            <ApkDetailsPanel />
          </div>
        </section>

        {/* Activity Feed */}
        <section style={{ marginTop: '2rem' }}>
          <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.125rem' }}>Recent Activity</h2>
          <div
            style={{
              backgroundColor: '#fff',
              border: '1px solid #e0e0e0',
              borderRadius: '4px',
              overflow: 'hidden'
            }}
          >
            <ActivityFeed />
          </div>
        </section>

        {/* Device Tools Section */}
        <section style={{ marginTop: '2rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
          {/* Logcat Panel */}
          <div>
            <LogcatPanel />
          </div>

          {/* Proxy Toggle */}
          <div>
            <ProxyToggle />
          </div>
        </section>
      </main>
    </div>
  );
};

export default AppsPage;
