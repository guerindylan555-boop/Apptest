# Data Model — Web UI: Read-Only Android Stream + Start/Stop Emulator (v1)

## EmulatorSession
- **Key**: singleton (named AVD)
- **State**: `Stopped | Booting | Running | Stopping | Error`
- **Attributes**:
  - `avdName` (string) — configured AVD identifier
  - `state` (enum) — current lifecycle phase
  - `bootStartedAt` (ISO timestamp | null)
  - `bootCompletedAt` (ISO timestamp | null)
  - `pid` (int | null) — emulator process id when active
  - `ports` (object) — `{ console: number, adb: number }`
  - `lastError` (object | null) — `{ code: string, message: string, occurredAt: ISO timestamp }`
  - `streamToken` (string | null) — active single-use token mapped to ws-scrcpy session
- **Relationships**:
  - Generates `StreamTicket` entries on transition to `Running`
  - Exposes data to `HealthSnapshot`
- **Validation Rules**:
  - Only one session may exist at a time
  - `state` transitions must follow state machine (Stopped→Booting→Running and Running→Stopping→Stopped)
  - `streamToken` must be regenerated on every Running entry

## StreamTicket
- **Key**: token (UUID)
- **Attributes**:
  - `token` (string)
  - `expiresAt` (ISO timestamp)
  - `wsUrl` (string) — e.g., `ws://127.0.0.1:8081/stream/<token>`
  - `emulatorSerial` (string) — adb serial, e.g., `emulator-5554`
- **Relationships**:
  - References `EmulatorSession`
- **Validation Rules**:
  - Tickets are single-use; expire after successful stream attach or timeout (≤60 s)
  - Only issued when session state is `Running`

## HealthSnapshot
- **Key**: generated per `/health` request (no persistence)
- **Attributes**:
  - `state` (enum) — mirrors `EmulatorSession.state`
  - `avdName` (string)
  - `bootElapsedMs` (number | null)
  - `pid` (int | null)
  - `ports` (object | null)
  - `streamAttached` (boolean)
  - `lastError` (object | null)
- **Validation Rules**:
  - If `state === "Running"`, `bootElapsedMs` MUST be defined
  - `lastError` present only when `state === "Error"`

## LogEntry (filesystem-based)
- **Key**: timestamped line in structured log
- **Attributes**:
  - `timestamp` (ISO string)
  - `level` (enum: debug|info|warn|error)
  - `source` (string) — e.g., `emulator`, `backend`, `streamer`
  - `message` (string)
  - `details` (object | null) — structured metadata (e.g., command, duration, exitCode)
- **Validation Rules**:
  - Log file rotation keeps ≤30 days unless pinned by broader retention policy
  - Sensitive values (tokens, file paths) redacted where appropriate

## State Machine Summary
- `Stopped` → `Booting`: triggered by POST `/emulator/start` when no active session
- `Booting` → `Running`: achieved after readiness checks pass and stream ticket issued
- `Booting` → `Error`: boot timeout, CLI failure, or readiness error
- `Running` → `Stopping`: triggered by POST `/emulator/stop`
- `Running` → `Error`: unexpected emulator crash or `ws-scrcpy` failure
- `Stopping` → `Stopped`: clean shutdown verified (ports freed)
- `Stopping` → `Error`: stop ladder exhausted without success
- `Error` → `Booting`: POST `/emulator/start` with recovery path clears error and restarts emulator
