# Data Model: APK Upload & Install + Frida & Tooling

**Feature**: 002-apk-upload-install
**Date**: 2025-10-09

## Entities

### APKProject

Represents an uploaded APK with all associated artifacts.

**Fields**:
- `id`: string (generated from `${packageName}_${sha256.substring(0,8)}`)
- `packageName`: string (e.g., "com.example.app")
- `versionName`: string (e.g., "1.2.3")
- `versionCode`: number
- `minSdkVersion`: number
- `targetSdkVersion`: number
- `sha256`: string (full hash)
- `apkPath`: string (absolute path to stored APK)
- `signingCert`: object
  - `issuer`: string (DN)
  - `sha256`: string
- `uploadedAt`: Date
- `isPinned`: boolean
- `artifactsPath`: string (project folder path)

**Relationships**:
- Has many `EventLogEntry`
- Has zero or one `FridaSession` (current)
- Has zero or one `TrafficCaptureSession` (current)
- Has zero or many `MobSFScanResult`

**Validation**:
- `packageName` must match Android package naming (reverse domain)
- `sha256` must be 64 hex characters
- `versionCode` must be positive integer

**State Transitions**: None (immutable after creation except `isPinned`)

---

### FridaSession

Represents active Frida instrumentation state.

**Fields**:
- `projectId`: string (references APKProject)
- `status`: enum (`Stopped`, `Starting`, `Running`, `Stopping`, `Error`)
- `deviceArch`: string (e.g., "x86_64")
- `serverVersion`: string (e.g., "16.1.0")
- `hostVersion`: string
- `serverPid`: number | null
- `serverPort`: number (default 27042)
- `errorMessage`: string | null
- `startedAt`: Date | null

**Relationships**:
- Belongs to one `APKProject`

**Validation**:
- `serverVersion` must match `hostVersion` (enforced before transition to Running)
- `serverPid` required when status = Running

**State Transitions**:
```
Stopped → Starting → Running
                  ↘ Error
Running → Stopping → Stopped
                   ↘ Error
```

---

### TrafficCaptureSession

Represents active mitmproxy capture.

**Fields**:
- `projectId`: string
- `status`: enum (`Stopped`, `Starting`, `Running`, `Stopping`, `Error`)
- `proxyPort`: number (default 8080)
- `caStatus`: enum (`NotInstalled`, `UserTrusted`, `SystemTrusted`)
- `mitmproxyPid`: number | null
- `flowCount`: number (flows captured this session)
- `flowsPath`: string (path to .mitm file)
- `errorMessage`: string | null
- `startedAt`: Date | null

**Relationships**:
- Belongs to one `APKProject`

**Validation**:
- `proxyPort` must be 1024-65535
- `caStatus` = UserTrusted after successful install (SystemTrusted unlikely per clarification)

**State Transitions**: Same as FridaSession

---

### MobSFScanResult

Represents completed static scan.

**Fields**:
- `projectId`: string
- `scanId`: string (MobSF-generated)
- `status`: enum (`Queued`, `Scanning`, `Complete`, `Error`)
- `permissions`: string[] (requested permissions)
- `trackers`: string[] (known tracker SDKs detected)
- `vulnerableLibs`: object[] (lib name + CVE if applicable)
- `securityScore`: number (0-100)
- `reportPath`: string (local HTML report path)
- `errorMessage`: string | null
- `scannedAt`: Date

**Relationships**:
- Belongs to one `APKProject`

**Validation**:
- `securityScore` must be 0-100
- `reportPath` must exist when status = Complete

**State Transitions**:
```
Queued → Scanning → Complete
                 ↘ Error
```

---

### EventLogEntry

Represents logged operation.

**Fields**:
- `projectId`: string (may be null for system-level events)
- `timestamp`: Date
- `type`: enum (`ApkUploaded`, `ApkVerified`, `ApkInstalled`, `ApkLaunched`, `FridaStarted`, `FridaStopped`, `TrafficCaptureStarted`, `TrafficCaptureStopped`, `CAInstalled`, `ScanStarted`, `ScanComplete`, `Error`)
- `status`: enum (`Success`, `Failure`)
- `details`: object (type-specific metadata)
- `errorMessage`: string | null

**Relationships**:
- Belongs to zero or one `APKProject`

**Validation**:
- `errorMessage` required when status = Failure

**State Transitions**: None (append-only log)

---

## Persistence Strategy

**Storage**: Filesystem-based (no database)

- **APKProject metadata**: `${projectPath}/metadata.json`
- **FridaSession/TrafficCaptureSession**: In-memory (backend `projectStore.ts`), not persisted (recreated on restart)
- **MobSFScanResult**: `${projectPath}/scans/${scanId}.json`
- **EventLogEntry**: `${projectPath}/logs/events.jsonl` (newline-delimited JSON)

**Rationale**: Single-user, low volume (~100 projects max), no need for query complexity or ACID transactions.

**Retention**: Daily cron job scans `~/apptest-projects/`, deletes projects where `uploadedAt` > 30 days ago and `.pinned` file absent.
