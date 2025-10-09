# Research: APK Upload & Install + Frida & Tooling

**Feature**: 002-apk-upload-install
**Date**: 2025-10-09

## APK Parsing & Metadata Extraction

**Decision**: Use `androguard` Python library via child process or `apk-parser` npm package

**Rationale**: Need to extract package name, version, SDK levels, and signing cert info. `androguard` is industry-standard for APK analysis; `apk-parser` (npm) offers pure-JS alternative with lower overhead.

**Recommendation**: Start with `apk-parser` (npm) for simplicity; fall back to `androguard` if signing cert extraction insufficient.

**Alternatives Considered**:
- Manual ZIP parsing + XML parsing (rejected: reinvents wheel, complex)
- `aapt` from Android SDK (rejected: requires full SDK install, heavyweight)

## Frida Version Matching & Binary Management

**Decision**: Query host `frida --version`, download matching `frida-server` from GitHub releases API

**Rationale**: Frida client/server versions must match exactly. GitHub releases provide official binaries for all architectures.

**Implementation**:
- Detect device arch via `adb shell getprop ro.product.cpu.abi`
- Cache downloaded binaries in `~/.cache/apptest/frida-server/<version>-<arch>`
- Verify SHA-256 from GitHub release metadata

**Alternatives Considered**:
- Bundle frida-server binaries (rejected: version drift, large repo size)
- User manual download (rejected: poor UX, error-prone)

## mitmproxy CA Installation (Android 14+)

**Decision**: Install CA as user-trusted; provide Frida-based pinning bypass guidance

**Rationale**: Per clarification session, avoid Magisk complexity. User-trusted CA works for most apps; strict apps require Frida bypass.

**Implementation**:
- Extract mitmproxy CA: `~/.mitmproxy/mitmproxy-ca-cert.cer`
- Convert to PEM if needed
- Push to emulator: `adb push cert.pem /sdcard/`
- Guide user through Settings > Security > Install from storage
- Display link to Frida SSL pinning bypass scripts (frida-codesh are community resources)

**Alternatives Considered**:
- Magisk module for system CA (rejected per clarification: too complex)
- Automated Settings navigation via UIAutomator (rejected: fragile across Android versions)

## MobSF Integration

**Decision**: Use MobSF Docker container with local-only API

**Rationale**: MobSF official Docker image provides isolated, reproducible environment. Local-only mode prevents external network calls.

**Implementation**:
- Check for `docker` command availability
- Start MobSF container: `docker run -p 127.0.0.1:8000:8000 opensecurity/mobile-security-framework-mobsf:latest`
- POST APK to `/api/v1/upload`
- Poll `/api/v1/scan_status` until complete
- Fetch summary from `/api/v1/report_json`

**Alternatives Considered**:
- Native MobSF install (rejected: complex dependencies, harder to isolate)
- Pre-installed MobSF assumption (rejected: poor first-run UX)

## Project Folder Structure & Retention

**Decision**: `~/apptest-projects/<package>_<sha256-prefix>/`

**Rationale**: Package name provides human readability; SHA-256 prefix ensures uniqueness across versions.

**Structure**:
```
~/apptest-projects/
└── com.example.app_a1b2c3d4/
    ├── app.apk
    ├── metadata.json
    ├── logs/
    │   ├── install.log
    │   ├── frida.log
    │   └── mitmproxy.log
    ├── traffic/
    │   └── flows.mitm
    ├── scans/
    │   └── mobsf-report.json
    └── .pinned            # Marker file to exempt from 30-day cleanup
```

**Retention**: Background job runs daily, deletes projects older than 30 days unless `.pinned` exists.

**Alternatives Considered**:
- Database storage (rejected: overkill for single-user, adds dependency)
- UUID-only naming (rejected: poor discoverability)

## Performance Targets Validation

**APK Upload → Metadata (3s)**:
- File I/O: ~500ms for 100MB APK
- `apk-parser` extraction: ~1-2s
- SHA-256 computation: ~500ms (streaming hash)
- **Total**: ~2-3s ✅

**Frida Start (3s)**:
- Version query: ~100ms
- Binary download (cached): 0ms
- ADB push: ~500ms
- Start + verify: ~1s
- **Total**: ~1.6s ✅

**mitmproxy Start (2s)**:
- Process spawn: ~500ms
- Port check: ~100ms
- Proxy config via ADB: ~300ms
- **Total**: ~900ms ✅

All targets achievable with proposed architecture.
