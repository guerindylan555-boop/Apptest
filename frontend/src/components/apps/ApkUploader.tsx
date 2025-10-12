import { useCallback, useState } from 'react';
import { useAppsLibraryStore } from '../../state/appsLibraryStore';
import { uploadApk } from '../../services/appsClient';

/**
 * APK Uploader Component
 *
 * Provides drag-and-drop and file picker interface for uploading APK files.
 */

const ApkUploader = () => {
  const [isDragging, setIsDragging] = useState(false);
  const { addEntry, setUploadProgress, setError } = useAppsLibraryStore();

  const handleFile = useCallback(
    async (file: File) => {
      if (!file.name.toLowerCase().endsWith('.apk')) {
        setError('Only .apk files are allowed');
        return;
      }

      setError(null);
      setUploadProgress({
        apkId: null,
        filename: file.name,
        progress: 0,
        status: 'uploading'
      });

      try {
        const entry = await uploadApk(file, (progress) => {
          setUploadProgress({
            apkId: null,
            filename: file.name,
            progress,
            status: progress < 100 ? 'uploading' : 'analyzing'
          });
        });

        setUploadProgress({
          apkId: entry.id,
          filename: file.name,
          progress: 100,
          status: 'success',
          message: (entry as any)._deduplicated
            ? 'APK already exists (deduplicated)'
            : 'APK uploaded successfully'
        });

        addEntry(entry);

        // Clear progress after 3 seconds
        setTimeout(() => setUploadProgress(null), 3000);
      } catch (error) {
        setUploadProgress({
          apkId: null,
          filename: file.name,
          progress: 0,
          status: 'error',
          message: error instanceof Error ? error.message : 'Upload failed'
        });

        // Clear error after 5 seconds
        setTimeout(() => setUploadProgress(null), 5000);
      }
    },
    [addEntry, setUploadProgress, setError]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragging(false);

      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
        handleFile(files[0]);
      }
    },
    [handleFile]
  );

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        handleFile(files[0]);
      }
    },
    [handleFile]
  );

  const uploadProgress = useAppsLibraryStore((state) => state.uploadProgress);

  return (
    <div style={{ marginBottom: '1.5rem' }}>
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        style={{
          border: isDragging ? '2px solid #2196f3' : '2px dashed #ccc',
          borderRadius: '8px',
          padding: '2rem',
          textAlign: 'center',
          backgroundColor: isDragging ? '#e3f2fd' : '#fafafa',
          cursor: 'pointer',
          transition: 'all 0.2s ease'
        }}
        onClick={() => document.getElementById('apk-file-input')?.click()}
      >
        <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📦</div>
        <p style={{ margin: '0.5rem 0', fontWeight: 500 }}>
          Drag and drop an APK file here
        </p>
        <p style={{ margin: 0, fontSize: '0.875rem', color: '#666' }}>
          or click to browse
        </p>
        <input
          id="apk-file-input"
          type="file"
          accept=".apk"
          onChange={handleFileInput}
          style={{ display: 'none' }}
        />
      </div>

      {uploadProgress && (
        <div
          style={{
            marginTop: '1rem',
            padding: '1rem',
            borderRadius: '4px',
            backgroundColor:
              uploadProgress.status === 'error'
                ? '#ffebee'
                : uploadProgress.status === 'success'
                ? '#e8f5e9'
                : '#e3f2fd',
            border: `1px solid ${
              uploadProgress.status === 'error'
                ? '#ef5350'
                : uploadProgress.status === 'success'
                ? '#66bb6a'
                : '#2196f3'
            }`
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontWeight: 500, fontSize: '0.875rem' }}>
              {uploadProgress.filename}
            </span>
            <span style={{ fontSize: '0.875rem', color: '#666' }}>
              {uploadProgress.status === 'uploading' && `${Math.round(uploadProgress.progress)}%`}
              {uploadProgress.status === 'analyzing' && 'Analyzing...'}
              {uploadProgress.status === 'success' && '✓ Complete'}
              {uploadProgress.status === 'error' && '✗ Failed'}
            </span>
          </div>
          {uploadProgress.status === 'uploading' && (
            <div
              style={{
                height: '4px',
                backgroundColor: '#e0e0e0',
                borderRadius: '2px',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  height: '100%',
                  width: `${uploadProgress.progress}%`,
                  backgroundColor: '#2196f3',
                  transition: 'width 0.3s ease'
                }}
              />
            </div>
          )}
          {uploadProgress.message && (
            <p style={{ margin: '0.5rem 0 0', fontSize: '0.875rem', color: '#666' }}>
              {uploadProgress.message}
            </p>
          )}
        </div>
      )}
    </div>
  );
};

export default ApkUploader;
