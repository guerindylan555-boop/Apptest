/**
 * Domain Types: Apps Library & Instrumentation Hub
 *
 * Core data structures for APK management, installation, instrumentation, and logging.
 */

/**
 * APK Entry - Represents a stored APK file with extracted metadata
 */
export interface ApkEntry {
  /** Internal identifier for UI routing */
  id: string;
  /** SHA-256 hash - primary dedupe key */
  sha256: string;
  /** Absolute path to stored APK */
  filePath: string;
  /** User-editable label (defaults to manifest label or filename) */
  displayName: string;
  /** Package identifier from manifest */
  packageName: string;
  /** Version name from manifest */
  versionName: string | null;
  /** Version code from manifest */
  versionCode: string | null;
  /** Minimum SDK version */
  minSdk: number | null;
  /** Target SDK version */
  targetSdk: number | null;
  /** Fully qualified launchable activity name */
  launchableActivity: string | null;
  /** Shortened signer digest for display */
  signerDigest: string;
  /** File size in bytes at ingestion */
  sizeBytes: number;
  /** ISO timestamp when APK was uploaded */
  uploadedAt: string;
  /** ISO timestamp of last install/launch (nullable) */
  lastUsedAt: string | null;
  /** Exempts from retention sweeps when true */
  pinned: boolean;
  /** Warnings from metadata extraction (e.g., missing activity) */
  metadataWarnings: string[];
  /** References to associated artifacts (logs, scripts) */
  artifacts: {
    installLogs: string[];
    logcatCaptures: string[];
    fridaScripts: string[];
  };
}

/**
 * Launch Resolution Strategy
 */
export enum LaunchResolution {
  Explicit = 'explicit',         // User-specified activity
  Resolved = 'resolved',          // Resolved via package manager
  Fallback = 'fallback',          // Default fallback activity
  Monkey = 'monkey',              // Monkey tool launch
  Failed = 'failed'               // Could not launch
}

/**
 * Install/Launch Session Status
 */
export enum InstallStatus {
  Success = 'success',
  Failed = 'failed'
}

/**
 * Install Session - History of installation attempts
 */
export interface InstallSession {
  /** Session identifier */
  id: string;
  /** Foreign key to APK Entry */
  apkId: string;
  /** ISO timestamp when install started */
  startedAt: string;
  /** ISO timestamp when completed (nullable on failure) */
  completedAt: string | null;
  /** Whether downgrade was requested */
  downgradeRequested: boolean;
  /** Whether auto-grant permissions was requested */
  autoGrantRequested: boolean;
  /** How the app was launched */
  launchResolution: LaunchResolution;
  /** Overall install/launch status */
  status: InstallStatus;
  /** Failure message if status is failed */
  error: string | null;
  /** Path to installation log file */
  logsPath: string | null;
}

/**
 * Frida Session State - Current instrumentation status
 */
export interface FridaSession {
  /** Whether frida-server is running */
  active: boolean;
  /** Process ID of frida-server (nullable) */
  serverPid: number | null;
  /** Package currently attached to (nullable) */
  attachedPackage: string | null;
  /** Path to loaded script (nullable) */
  scriptPath: string | null;
  /** Rolling buffer of recent console output */
  lastOutputLines: string[];
  /** ISO timestamp of last state change */
  updatedAt: string;
}

/**
 * Log Capture Status
 */
export enum LogCaptureStatus {
  Active = 'active',
  Paused = 'paused',
  Stopped = 'stopped'
}

/**
 * Log Capture - Logcat recording session
 */
export interface LogCapture {
  /** Session identifier */
  id: string;
  /** Foreign key to APK Entry (nullable for device-wide captures) */
  apkId: string | null;
  /** Filters applied to logcat */
  filters: {
    packages: string[];
    tags: string[];
  };
  /** Current capture status */
  status: LogCaptureStatus;
  /** ISO timestamp when capture started */
  startedAt: string;
  /** ISO timestamp when capture ended (nullable) */
  endedAt: string | null;
  /** Path to stored log file (nullable until stopped) */
  filePath: string | null;
  /** File size in bytes */
  sizeBytes: number;
  /** Whether file has been downloaded by user */
  downloaded: boolean;
}

/**
 * Proxy State - Emulator proxy configuration
 */
export interface ProxyState {
  /** Whether proxy is enabled */
  enabled: boolean;
  /** Proxy host (typically 127.0.0.1) */
  host: string;
  /** Proxy port */
  port: number;
}

/**
 * Retention Sweep Log - History of automated cleanup
 */
export interface RetentionSweepLog {
  /** ISO timestamp when sweep ran */
  runAt: string;
  /** APK IDs that were deleted */
  deletedEntries: string[];
  /** Artifact file paths that were deleted */
  deletedArtifacts: string[];
  /** Duration of sweep operation in milliseconds */
  durationMs: number;
}

/**
 * Activity Log Entry - Records user actions and system events
 */
export interface ActivityLogEntry {
  /** ISO timestamp of event */
  timestamp: string;
  /** Event type identifier */
  type: 'upload' | 'install' | 'launch' | 'frida' | 'logcat' | 'proxy' | 'retention' | 'error';
  /** Human-readable event message */
  message: string;
  /** Optional reference to related entity ID */
  entityId: string | null;
  /** Optional metadata for the event */
  metadata?: Record<string, unknown>;
}

/**
 * Install/Launch Request Body
 */
export interface InstallLaunchRequest {
  /** Allow downgrade during install */
  allowDowngrade?: boolean;
  /** Auto-grant runtime permissions */
  autoGrantPermissions?: boolean;
}

/**
 * Install/Launch Response
 */
export interface InstallLaunchResponse {
  /** Install/launch status */
  status: InstallStatus;
  /** Launch resolution strategy used */
  launchResolution: LaunchResolution;
  /** Human-readable message */
  message: string;
  /** Path to install log file */
  installLogPath: string | null;
}

/**
 * Frida Server Control Request
 */
export interface FridaServerRequest {
  /** Action to perform */
  action: 'start' | 'stop';
}

/**
 * Frida Attach Request
 */
export interface FridaAttachRequest {
  /** Package name to attach to */
  packageName: string;
  /** Optional path to Frida script */
  scriptPath?: string;
}

/**
 * Frida Attach Response
 */
export interface FridaAttachResponse {
  /** Attachment status */
  status: 'attached' | 'failed';
  /** Human-readable message */
  message: string;
  /** Path to loaded script (nullable) */
  scriptPath: string | null;
}

/**
 * Logcat Session Start Request
 */
export interface LogcatStartRequest {
  /** Package name filters */
  packageFilters?: string[];
  /** Tag filters */
  tagFilters?: string[];
}

/**
 * Logcat Session Control Request
 */
export interface LogcatControlRequest {
  /** Action to perform */
  action: 'pause' | 'resume' | 'stop';
}

/**
 * Proxy Toggle Request
 */
export interface ProxyToggleRequest {
  /** Enable or disable proxy */
  enabled: boolean;
  /** Proxy host (default: 127.0.0.1) */
  host?: string;
  /** Proxy port */
  port?: number;
}
