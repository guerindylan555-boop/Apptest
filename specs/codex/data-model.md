# Data Model — Emulator Streaming UI

## EmulatorSession
- `avdName` (string): Local AVD identifier under control.
- `state` (enum): `Stopped | Booting | Running | Stopping | Error` — lifecycle state driving UI badge/button.
- `bootStartedAt` (ISO string, optional): Timestamp when boot began, used for elapsed calculations.
- `bootCompletedAt` (ISO string, optional): Marks readiness for stream attach and latency metrics.
- `pid` (number, optional): Emulator process id for diagnostics.
- `ports` (object, optional): `{ console: number; adb: number }` — surfaced for debugging adb connectivity.
- `streamToken` (string, optional): Most recent issued ticket token; cleared when unused/expired.
- `lastError` (SessionError, optional): Captures code/message/hint for UI error banner.
- `forceStopRequired` (boolean): Flag instructing UI to offer Force Stop.

## SessionError
- `code` (string): Stable identifier (e.g., `BOOT_FAILED`, `STREAM_TIMEOUT`).
- `message` (string): Human-readable summary for banner content.
- `hint` (string, optional): Local recovery guidance/link text.
- `occurredAt` (ISO string): Timestamp for diagnostics drawer.

## StreamTicket
- `token` (string): One-time token granting access to websocket pipeline.
- `url` (string): Stream URL using ws-scrcpy bridge.
- `expiresAt` (ISO string): Expiration for ticket; UI retries when elapsed.
- `emulatorSerial` (string, internal): Serial the ticket binds to (not sent to UI).

## HealthPayload (API contract summary)
- `state` (EmulatorSession.state): Mirrors lifecycle status.
- `avd` (string): Echoed AVD name.
- `bootElapsedMs` (number, optional): Derived value for diagnostics.
- `pid`, `ports`, `forceStopRequired` — propagate from EmulatorSession.
- `streamAttached` (boolean): Indicates whether a stream ticket is currently active.
- `lastError` (SessionError | undefined): Mirrors session error.
- `timestamps` (object): `{ bootStartedAt?: string; bootCompletedAt?: string }` for UI timeline.
