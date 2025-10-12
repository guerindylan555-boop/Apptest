import { useFilteredEntries, useAppsLibraryStore } from '../../state/appsLibraryStore';
import type { ApkEntry } from '../../types/apps';

/**
 * APK List Component
 *
 * Displays searchable and sortable list of APK entries.
 */

const ApkList = () => {
  const entries = useFilteredEntries();
  const { searchFilter, setSearchFilter, selectedEntryId, setSelectedEntryId } =
    useAppsLibraryStore();
  const isLoading = useAppsLibraryStore((state) => state.isLoading);

  const formatDate = (isoString: string | null) => {
    if (!isoString) return 'Never';
    return new Date(isoString).toLocaleString();
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const handleRowClick = (entry: ApkEntry) => {
    setSelectedEntryId(entry.id);
  };

  if (isLoading) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem', color: '#666' }}>
        Loading APK entries...
      </div>
    );
  }

  return (
    <div>
      {/* Search Bar */}
      <div style={{ marginBottom: '1rem' }}>
        <input
          type="text"
          placeholder="Search by name or package..."
          value={searchFilter}
          onChange={(e) => setSearchFilter(e.target.value)}
          style={{
            width: '100%',
            padding: '0.75rem',
            border: '1px solid #ccc',
            borderRadius: '4px',
            fontSize: '0.875rem',
            boxSizing: 'border-box'
          }}
        />
      </div>

      {/* List */}
      {entries.length === 0 ? (
        <div
          style={{
            textAlign: 'center',
            padding: '2rem',
            backgroundColor: '#f5f5f5',
            borderRadius: '4px',
            color: '#999'
          }}
        >
          {searchFilter ? 'No APKs match your search' : 'No APKs uploaded yet'}
        </div>
      ) : (
        <div style={{ border: '1px solid #e0e0e0', borderRadius: '4px', overflow: 'hidden' }}>
          {entries.map((entry) => (
            <div
              key={entry.id}
              onClick={() => handleRowClick(entry)}
              style={{
                padding: '1rem',
                borderBottom: '1px solid #e0e0e0',
                cursor: 'pointer',
                backgroundColor: selectedEntryId === entry.id ? '#e3f2fd' : '#fff',
                transition: 'background-color 0.2s ease'
              }}
              onMouseEnter={(e) => {
                if (selectedEntryId !== entry.id) {
                  e.currentTarget.style.backgroundColor = '#f5f5f5';
                }
              }}
              onMouseLeave={(e) => {
                if (selectedEntryId !== entry.id) {
                  e.currentTarget.style.backgroundColor = '#fff';
                }
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <strong style={{ fontSize: '0.95rem' }}>{entry.displayName}</strong>
                    {entry.pinned && (
                      <span
                        style={{
                          fontSize: '0.75rem',
                          padding: '0.125rem 0.5rem',
                          backgroundColor: '#fff3cd',
                          color: '#856404',
                          borderRadius: '12px',
                          fontWeight: 500
                        }}
                      >
                        Pinned
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.8125rem', color: '#666', marginBottom: '0.25rem' }}>
                    {entry.packageName}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#999' }}>
                    {entry.versionName && `v${entry.versionName}`}
                    {entry.versionName && entry.versionCode && ' • '}
                    {entry.versionCode && `(${entry.versionCode})`}
                    {' • '}
                    {formatSize(entry.sizeBytes)}
                  </div>
                  {entry.metadataWarnings.length > 0 && (
                    <div style={{ fontSize: '0.75rem', color: '#f57c00', marginTop: '0.25rem' }}>
                      ⚠ {entry.metadataWarnings[0]}
                    </div>
                  )}
                </div>
                <div style={{ textAlign: 'right', fontSize: '0.75rem', color: '#999' }}>
                  <div>Uploaded</div>
                  <div>{formatDate(entry.uploadedAt)}</div>
                  {entry.lastUsedAt && (
                    <>
                      <div style={{ marginTop: '0.25rem' }}>Last Used</div>
                      <div>{formatDate(entry.lastUsedAt)}</div>
                    </>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ApkList;
