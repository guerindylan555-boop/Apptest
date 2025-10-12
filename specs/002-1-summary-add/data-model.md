# Data Model – Apps Library & Instrumentation Hub

## Overview
Artifacts live on the local filesystem under `var/autoapp/apps/` with lightweight JSON indexes. The backend maintains in-memory caches hydrated from disk at startup and persisted after mutations.

## Entities

### APK Entry
| Field | Type | Notes |
|-------|------|-------|
| `id` | string (UUID) | Internal identifier for UI routing |
| `sha256` | string | Primary dedupe key (hex) |
| `filePath` | string | Absolute path to stored APK |
| `displayName` | string | User-editable label (defaults to manifest label or filename) |
| `packageName` | string | Extracted from metadata |
| `versionName` | string | From metadata; optional |
| `versionCode` | number/string | Preserve original format |
| `minSdk` | number | Nullable if unknown |
| `targetSdk` | number | Nullable if unknown |
| `launchableActivity` | string | Fully qualified; nullable |
| `signerDigest` | string | Shortened digest for display |
| `sizeBytes` | number | File size at ingestion |
| `uploadedAt` | ISO timestamp | When stored |
| `lastUsedAt` | ISO timestamp | Updated on install/launch |
| `pinned` | boolean | Exempts from retention |
| `metadataWarnings` | string[] | E.g., missing activity |
| `artifacts` | object | References to log captures, scripts |

**Relationships**:  
- One-to-many with **Install Session** (history).  
- One-to-many with **Log Capture**.

### Install Session
| Field | Type | Notes |
|-------|------|-------|
| `id` | string (UUID) | |
| `apkId` | string | FK → APK Entry |
| `startedAt` | ISO timestamp | |
| `completedAt` | ISO timestamp | Nullable on failure |
| `downgradeRequested` | boolean | Mirrors UI toggle |
| `autoGrantRequested` | boolean | Mirrors UI toggle |
| `launchResolution` | enum (`explicit`, `resolved`, `fallback`, `monkey`, `failed`) | |
| `status` | enum (`success`, `failed`) | |
| `error` | string | Failure message, optional |
| `logsPath` | string | Pointer to textual log |

### Frida Session
| Field | Type | Notes |
|-------|------|-------|
| `active` | boolean | Server running |
| `serverPid` | number | Optional |
| `attachedPackage` | string | Current target |
| `scriptPath` | string | Loaded script |
| `lastOutputLines` | string[] | Rolling buffer |
| `updatedAt` | ISO timestamp | |

### Log Capture
| Field | Type | Notes |
|-------|------|-------|
| `id` | string (UUID) | |
| `apkId` | string | FK → APK Entry |
| `filters` | object | `{ packages: string[], tags: string[] }` |
| `startedAt` | ISO timestamp | |
| `endedAt` | ISO timestamp | |
| `filePath` | string | Stored text file |
| `sizeBytes` | number | |
| `downloaded` | boolean | Flag for UI |

### Retention Sweep Log
| Field | Type | Notes |
|-------|------|-------|
| `runAt` | ISO timestamp | |
| `deletedEntries` | string[] | APK IDs removed |
| `deletedArtifacts` | string[] | Paths |
| `durationMs` | number | Runtime |

## State Transitions
- **APK Entry**: `pinned` toggled manually; `lastUsedAt` updated on install/launch; deletion removes associated artifacts and dependent sessions.
- **Install Session**: write-once per attempt; transitions from in-progress to success/failure.
- **Frida Session**: idle → active (server running) → attached (script loaded); resets to idle on stop/error.
- **Log Capture**: pending (started) → active (streaming) → closed (file finalized).

## Validation Rules
- APK uploads must be `.apk` extension and unique by SHA-256.
- Pinned entries bypass retention; retention script must respect `pinned === true`.
- Downgrade installs require explicit toggle acknowledgement.
- Frida attachments only allowed when server active and target package matches running process list.
- Log captures cannot exceed configured size threshold (default 50 MB) – abort with warning.
