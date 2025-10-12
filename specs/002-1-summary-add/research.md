# Research Summary – Apps Library & Instrumentation Hub

## Decision: Handle APK metadata extraction with `aapt2 dump badging`
- **Rationale**: Provides consistent offline metadata (package identifiers, versioning, SDK targets, launchable activity) and is already part of Android SDK CLI bundle. Integrates cleanly with existing backend Node tooling via child processes.
- **Alternatives considered**:
  - Parsing `AndroidManifest.xml` manually – rejected due to higher complexity handling binary XML edge cases.
  - Third-party parsers (e.g., apk-parser libraries) – rejected to preserve offline, vendor-supported tooling.

## Decision: Store APK artifacts and indexes on local filesystem
- **Rationale**: Aligns with single-user, localhost-only constraints and leverages existing `var/autoapp/` footprint. Simplifies 30-day retention sweeps and pinning metadata.
- **Alternatives considered**:
  - Embedding SQLite/LowDB – unnecessary overhead for modest data volume.
  - Cloud/object storage – violates constitution’s local-only principle.

## Decision: Automate install & launch via ADB CLI commands
- **Rationale**: `adb install` with `-r`/`-d` flags and `cmd package resolve-activity` cover reinstall/downgrade needs, while `am start`/Monkey fallback matches Android docs. Reuses current backend process management patterns.
- **Alternatives considered**:
  - Integrating Gradle/Android Studio tooling – heavyweight, slower, and redundant.
  - Custom instrumentation APK – unnecessary for v1 scope.

## Decision: Proceed with Frida integration pending constitutional exception
- **Rationale**: Feature spec mandates simple Frida controls; treating them as first-class keeps tester workflow cohesive. Documented here that governance approval (constitution amendment or explicit exception) is required before implementation merges.
- **Alternatives considered**:
  - Dropping Frida support – contradicts user stories and success criteria.
  - Bundling alternative dynamic analysis tool – still conflicts with constitution; no net benefit.

## Decision: Provide optional proxy integration via mitmproxy
- **Rationale**: mitmproxy is already established for local traffic capture with clear CA guidance. Only toggling emulator proxy settings keeps implementation bounded and respects local-only rule.
- **Alternatives considered**:
  - Building custom proxy – unnecessary engineering.
  - Recommending external manual setup only – reduces usability, conflicts with spec goals.
