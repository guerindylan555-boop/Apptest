import { useState, useCallback } from 'react';
import { useSelectedEntry, useAppsLibraryStore } from '../../state/appsLibraryStore';
import { updateEntry, deleteEntry } from '../../services/appsClient';
import { useInstallLaunch } from '../../hooks/useInstallLaunch';

/**
 * APK Details Panel
 *
 * Displays detailed metadata for the selected APK and provides actions.
 */

const ApkDetailsPanel = () => {
  const selectedEntry = useSelectedEntry();
  const { updateEntry: updateStoreEntry, removeEntry, setError } = useAppsLibraryStore();
  const [isEditing, setIsEditing] = useState(false);
  const [editedName, setEditedName] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  // Install & Launch state
  const { installAndLaunch, isInstalling, error: installError, result: installResult } = useInstallLaunch();
  const [allowDowngrade, setAllowDowngrade] = useState(false);
  const [autoGrantPermissions, setAutoGrantPermissions] = useState(true);

  const handlePinToggle = useCallback(async () => {
    if (!selectedEntry) return;

    try {
      const updated = await updateEntry(selectedEntry.id, {
        pinned: !selectedEntry.pinned
      });
      updateStoreEntry(selectedEntry.id, updated);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to update pin state');
    }
  }, [selectedEntry, updateStoreEntry, setError]);

  const handleStartEdit = useCallback(() => {
    if (selectedEntry) {
      setEditedName(selectedEntry.displayName);
      setIsEditing(true);
    }
  }, [selectedEntry]);

  const handleSaveEdit = useCallback(async () => {
    if (!selectedEntry || !editedName.trim()) return;

    try {
      const updated = await updateEntry(selectedEntry.id, {
        displayName: editedName.trim()
      });
      updateStoreEntry(selectedEntry.id, updated);
      setIsEditing(false);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to update display name');
    }
  }, [selectedEntry, editedName, updateStoreEntry, setError]);

  const handleDelete = useCallback(async () => {
    if (!selectedEntry) return;

    if (selectedEntry.pinned) {
      setError('Cannot delete pinned entry. Unpin it first.');
      return;
    }

    if (!window.confirm(`Are you sure you want to delete "${selectedEntry.displayName}"?`)) {
      return;
    }

    setIsDeleting(true);
    try {
      await deleteEntry(selectedEntry.id);
      removeEntry(selectedEntry.id);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to delete entry');
    } finally {
      setIsDeleting(false);
    }
  }, [selectedEntry, removeEntry, setError]);

  const handleInstallLaunch = useCallback(async () => {
    if (!selectedEntry) return;

    try {
      await installAndLaunch(selectedEntry.id, {
        allowDowngrade,
        autoGrantPermissions
      });
      // Reload the page or refresh data to show updated lastUsedAt
      updateStoreEntry(selectedEntry.id, { lastUsedAt: new Date().toISOString() });
    } catch (error) {
      // Error already handled by hook
    }
  }, [selectedEntry, installAndLaunch, allowDowngrade, autoGrantPermissions, updateStoreEntry]);

  if (!selectedEntry) {
    return (
      <div
        style={{
          padding: '2rem',
          textAlign: 'center',
          color: '#999',
          backgroundColor: '#fafafa',
          borderRadius: '4px',
          border: '1px solid #e0e0e0'
        }}
      >
        Select an APK to view details
      </div>
    );
  }

  return (
    <div
      style={{
        padding: '1.5rem',
        backgroundColor: '#fff',
        borderRadius: '4px',
        border: '1px solid #e0e0e0'
      }}
    >
      {/* Header with Name and Actions */}
      <div style={{ marginBottom: '1.5rem' }}>
        {isEditing ? (
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
            <input
              type="text"
              value={editedName}
              onChange={(e) => setEditedName(e.target.value)}
              style={{
                flex: 1,
                padding: '0.5rem',
                border: '1px solid #ccc',
                borderRadius: '4px',
                fontSize: '1rem'
              }}
              autoFocus
            />
            <button
              onClick={handleSaveEdit}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#2196f3',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Save
            </button>
            <button
              onClick={() => setIsEditing(false)}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#666',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Cancel
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <h2 style={{ margin: '0 0 0.5rem 0', fontSize: '1.25rem' }}>
              {selectedEntry.displayName}
            </h2>
            <button
              onClick={handleStartEdit}
              style={{
                padding: '0.25rem 0.75rem',
                backgroundColor: '#f5f5f5',
                border: '1px solid #ccc',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.875rem'
              }}
            >
              Rename
            </button>
          </div>
        )}

        {/* Install & Launch Section */}
        <div style={{ marginTop: '1.5rem', padding: '1rem', backgroundColor: '#f5f5f5', borderRadius: '4px' }}>
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem' }}>Install & Launch</h3>

          {/* Options */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={allowDowngrade}
                onChange={(e) => setAllowDowngrade(e.target.checked)}
              />
              Allow downgrade
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.875rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={autoGrantPermissions}
                onChange={(e) => setAutoGrantPermissions(e.target.checked)}
              />
              Auto-grant permissions
            </label>
          </div>

          {/* Install Button */}
          <button
            onClick={handleInstallLaunch}
            disabled={isInstalling}
            style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: isInstalling ? '#ccc' : '#4caf50',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              cursor: isInstalling ? 'not-allowed' : 'pointer',
              fontSize: '0.875rem',
              fontWeight: 500,
              width: '100%'
            }}
          >
            {isInstalling ? '⏳ Installing & Launching...' : '🚀 Install & Launch'}
          </button>

          {/* Status Messages */}
          {installError && (
            <div style={{ marginTop: '0.75rem', padding: '0.75rem', backgroundColor: '#ffebee', border: '1px solid #ef5350', borderRadius: '4px', fontSize: '0.875rem', color: '#c62828' }}>
              <strong>Error:</strong> {installError}
            </div>
          )}

          {installResult && (
            <div style={{ marginTop: '0.75rem', padding: '0.75rem', backgroundColor: '#e8f5e9', border: '1px solid #66bb6a', borderRadius: '4px', fontSize: '0.875rem', color: '#2e7d32' }}>
              <strong>Success:</strong> {installResult.message}
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <button
            onClick={handlePinToggle}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: selectedEntry.pinned ? '#fff3cd' : '#f5f5f5',
              border: `1px solid ${selectedEntry.pinned ? '#856404' : '#ccc'}`,
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.875rem',
              color: selectedEntry.pinned ? '#856404' : '#333'
            }}
          >
            {selectedEntry.pinned ? '📌 Unpin' : '📌 Pin'}
          </button>
          <button
            onClick={handleDelete}
            disabled={isDeleting || selectedEntry.pinned}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: selectedEntry.pinned ? '#e0e0e0' : '#ffebee',
              border: `1px solid ${selectedEntry.pinned ? '#bbb' : '#ef5350'}`,
              borderRadius: '4px',
              cursor: selectedEntry.pinned ? 'not-allowed' : 'pointer',
              fontSize: '0.875rem',
              color: selectedEntry.pinned ? '#999' : '#c62828'
            }}
          >
            {isDeleting ? 'Deleting...' : '🗑 Delete'}
          </button>
        </div>
      </div>

      {/* Metadata Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', fontSize: '0.875rem' }}>
        <MetadataField label="Package" value={selectedEntry.packageName} />
        <MetadataField
          label="Version"
          value={
            `${selectedEntry.versionName || 'N/A'}${selectedEntry.versionCode ? ` (${selectedEntry.versionCode})` : ''}`
          }
        />
        <MetadataField
          label="SDK"
          value={`Min: ${selectedEntry.minSdk || 'N/A'} | Target: ${selectedEntry.targetSdk || 'N/A'}`}
        />
        <MetadataField label="Signer" value={selectedEntry.signerDigest} />
        <MetadataField
          label="Size"
          value={`${(selectedEntry.sizeBytes / (1024 * 1024)).toFixed(2)} MB`}
        />
        <MetadataField label="SHA-256" value={selectedEntry.sha256.substring(0, 16) + '...'} />
        <MetadataField
          label="Launchable Activity"
          value={selectedEntry.launchableActivity || 'None'}
          fullWidth
        />
      </div>

      {/* Warnings */}
      {selectedEntry.metadataWarnings.length > 0 && (
        <div style={{ marginTop: '1rem' }}>
          <strong style={{ color: '#f57c00', fontSize: '0.875rem' }}>⚠ Warnings:</strong>
          <ul style={{ margin: '0.5rem 0 0 0', paddingLeft: '1.5rem', fontSize: '0.875rem', color: '#666' }}>
            {selectedEntry.metadataWarnings.map((warning, idx) => (
              <li key={idx}>{warning}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

interface MetadataFieldProps {
  label: string;
  value: string;
  fullWidth?: boolean;
}

const MetadataField = ({ label, value, fullWidth }: MetadataFieldProps) => (
  <div style={fullWidth ? { gridColumn: '1 / -1' } : undefined}>
    <div style={{ color: '#999', marginBottom: '0.25rem' }}>{label}</div>
    <div style={{ fontWeight: 500, wordBreak: 'break-all' }}>{value}</div>
  </div>
);

export default ApkDetailsPanel;
