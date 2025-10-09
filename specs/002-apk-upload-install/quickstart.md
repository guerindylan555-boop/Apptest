# Quickstart: APK Upload & Install + Frida & Tooling

**Feature**: 002-apk-upload-install
**Prerequisites**: Feature 001 (emulator running), Node.js 20.x, Docker (for MobSF)

## Setup

1. **Install dependencies**:
   ```bash
   cd backend && npm install apk-parser frida-tools mitmproxy
   cd ../frontend && npm install
   ```

2. **Configure project storage**:
   ```bash
   mkdir -p ~/apptest-projects
   export APPTEST_PROJECTS_DIR=~/apptest-projects
   ```

3. **Start services** (from feature 001):
   ```bash
   npm run dev:backend   # Terminal 1
   npm run dev:frontend  # Terminal 2
   ```

4. **Optional: Start MobSF** (for static scanning):
   ```bash
   docker run -d -p 127.0.0.1:8000:8000 --name mobsf opensecurity/mobile-security-framework-mobsf:latest
   ```

## Usage Workflow

### Upload & Install APK

1. Open `http://127.0.0.1:8080` in browser
2. Click "Upload APK" → select `.apk` file
3. Wait for metadata display (package name, version, SHA-256, signer info)
4. Click "Install" → wait for success confirmation
5. Click "Launch" → app appears in emulator stream

**Project created**: `~/apptest-projects/com.example.app_a1b2c3d4/`

### Enable Frida Instrumentation

1. In Frida panel, click "Start Frida"
2. Verify status shows "Running" with version match indicator
3. Frida server now listening on `127.0.0.1:27042` (ADB-forwarded)
4. Attach with: `frida -U -n <package-name>`

**To stop**: Click "Stop Frida"

### Capture Network Traffic

1. In Traffic Capture panel, click "Start Traffic Capture"
2. Click "Install Proxy CA (emulator)" → follow guided helper
   - Settings > Security > Install from storage
   - Select mitmproxy cert from `/sdcard/`
3. Launch app and trigger network activity
4. View flows in Traffic panel (method, URL, status, timestamp)
5. Click flow to see full request/response details

**For apps with pinning**: Follow Frida pinning bypass link in UI

**To stop**: Click "Stop Traffic Capture" → flows saved to `~/apptest-projects/<project>/traffic/flows.mitm`

### Run Static Scan (Optional)

1. Ensure MobSF Docker container is running
2. In MobSF panel, click "Run MobSF"
3. Wait for scan progress (typically 2-5 minutes)
4. View summary: permissions, trackers, vulnerable libs, security score
5. Click "View Full Report" → opens local HTML report

**Report saved**: `~/apptest-projects/<project>/scans/mobsf-report.json`

## Troubleshooting

**Frida version mismatch**:
- UI shows warning with download link
- Run: `pip install frida-tools --upgrade`
- Backend auto-downloads matching `frida-server`

**mitmproxy port conflict (8080 in use)**:
- Change proxy port in Traffic panel settings
- Default alternatives: 8888, 9000

**MobSF not available**:
- Check Docker: `docker ps | grep mobsf`
- Restart: `docker start mobsf`

**APK install fails (signature mismatch)**:
- Uninstall existing app first
- Or upload different version

## Project Management

**View logs**: Status panel → "View local logs" → opens `~/apptest-projects/<project>/logs/`

**Pin project** (exempt from 30-day deletion):
```bash
touch ~/apptest-projects/<project>/.pinned
```

**Manual cleanup**:
```bash
rm -rf ~/apptest-projects/<project-id>
```

## Next Steps

- Implement recording/replay (future feature)
- Add Frida script library (future feature)
- Integrate additional security scanners (future feature)
