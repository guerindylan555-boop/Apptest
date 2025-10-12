/**
 * Frontend Types: Apps Library
 *
 * Mirrors backend types for APK management and instrumentation.
 */

export interface ApkEntry {
  id: string;
  sha256: string;
  filePath: string;
  displayName: string;
  packageName: string;
  versionName: string | null;
  versionCode: string | null;
  minSdk: number | null;
  targetSdk: number | null;
  launchableActivity: string | null;
  signerDigest: string;
  sizeBytes: number;
  uploadedAt: string;
  lastUsedAt: string | null;
  pinned: boolean;
  metadataWarnings: string[];
  artifacts: {
    installLogs: string[];
    logcatCaptures: string[];
    fridaScripts: string[];
  };
}

export interface UploadProgress {
  apkId: string | null;
  filename: string;
  progress: number;
  status: 'uploading' | 'analyzing' | 'success' | 'error';
  message?: string;
}

export interface ActivityLogEntry {
  timestamp: string;
  type: 'upload' | 'install' | 'launch' | 'frida' | 'logcat' | 'proxy' | 'retention' | 'error';
  message: string;
  entityId: string | null;
  metadata?: Record<string, unknown>;
}
