# Troubleshooting – Apps Library & Instrumentation Hub

## Installation Issues

### APK Upload Fails
**Symptom:** Upload completes but metadata extraction fails or shows errors.

**Solutions:**
- Ensure `aapt2` is installed and available on PATH: `which aapt2`
- Verify APK file integrity: `aapt2 dump badging <apk-file>`
- Check backend logs for detailed error messages
- Ensure sufficient disk space in `var/autoapp/apps/library/`

### Install Fails with "INSTALL_FAILED_UPDATE_INCOMPATIBLE"
**Symptom:** Installation fails when trying to update an existing app.

**Solutions:**
- Enable **Allow downgrade** checkbox before installing
- Manually uninstall the existing app: `adb uninstall <package-name>`
- Check if app signatures differ (debug vs release)

### Install Fails with "INSTALL_FAILED_INSUFFICIENT_STORAGE"
**Symptom:** Installation fails due to storage constraints.

**Solutions:**
- Clear emulator cache: `adb shell pm clear <package-name>`
- Wipe emulator data: `adb shell pm list packages | xargs -n1 adb shell pm clear`
- Create a new emulator with larger storage

### App Launch Fails (Resolution: "failed")
**Symptom:** Install succeeds but launch fails.

**Solutions:**
- Check if app requires specific permissions not auto-granted
- Verify app is compatible with emulator API level (34)
- Review logcat for crash details: start a logcat capture with package filter
- Try launching manually: `adb shell monkey -p <package-name> -c android.intent.category.LAUNCHER 1`

## Frida Issues

### Frida Server Won't Start
**Symptom:** Frida server toggle shows error or remains inactive.

**Solutions:**
- Ensure `ENABLE_FRIDA=true` in backend environment variables
- Verify `frida-server` binary is present at `/data/local/tmp/frida-server` on emulator
- Check emulator root access: `adb shell su -c 'id'`
- Push Frida server manually: `adb push frida-server /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/frida-server`

### Cannot Attach to Process
**Symptom:** Frida attach operation fails or times out.

**Solutions:**
- Ensure Frida server is running and active
- Verify process is running: `adb shell ps | grep <package-name>`
- Check Frida version compatibility between server and tools: `frida --version`
- Try attaching with CLI: `frida -U -n <package-name>`

### Script Execution Errors
**Symptom:** Frida attaches but script fails to execute.

**Solutions:**
- Validate script syntax: `frida -U -n <package-name> -l <script-path> --no-pause`
- Check script compatibility with Frida version
- Review Frida console output for detailed error messages
- Test with a minimal script first (e.g., `console.log('Hello from Frida')`)

## Logcat Issues

### Logcat Capture Shows No Data
**Symptom:** Capture starts but file remains empty or very small.

**Solutions:**
- Verify filters are not too restrictive (try without filters first)
- Check if package name matches exactly: `adb shell pm list packages | grep <package>`
- Ensure app is actively logging: trigger app functionality
- Review logcat manually: `adb logcat -v time`

### Cannot Download Captured Logs
**Symptom:** Download button fails or returns empty file.

**Solutions:**
- Ensure capture is stopped (not active/paused)
- Check file exists: `ls -lh var/autoapp/apps/logs/`
- Verify backend has read permissions for log files
- Try viewing inline first, then download

### Logcat Session Exits Unexpectedly
**Symptom:** Active capture changes to stopped without user action.

**Solutions:**
- Check if ADB connection is stable: `adb devices`
- Restart ADB server: `adb kill-server && adb start-server`
- Review backend logs for process termination errors
- Ensure emulator hasn't been restarted

## Proxy Issues

### Proxy Doesn't Intercept Traffic
**Symptom:** Proxy enabled but no traffic appears in mitmproxy/Burp.

**Solutions:**
- Verify proxy tool is listening on specified host:port
- Check proxy settings on emulator: `adb shell settings get global http_proxy`
- Restart emulator or network stack: `adb shell svc wifi disable && adb shell svc wifi enable`
- Test with `curl` on emulator: `adb shell curl -I http://example.com`

### HTTPS Traffic Not Decrypted
**Symptom:** HTTP traffic works but HTTPS shows SSL errors or is encrypted.

**Solutions:**
- Ensure CA certificate is properly installed (Settings → Security → Trusted credentials → User)
- For API 24+ apps, modify network security config to trust user certificates:
  ```xml
  <network-security-config>
    <base-config>
      <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
      </trust-anchors>
    </base-config>
  </network-security-config>
  ```
- Rebuild and reinstall APK with updated security config
- Check certificate is valid: navigate to `mitm.it` and verify cert details

### Cannot Install CA Certificate
**Symptom:** Certificate download fails or installation is blocked.

**Solutions:**
- Download certificate manually: `curl http://mitm.it/cert/pem -o cert.pem`
- Push to emulator: `adb push cert.pem /sdcard/Download/`
- Install via Settings → Security → Install from storage
- Ensure emulator has screen lock enabled (required for user certs)

## General Issues

### Backend API Returns 500 Errors
**Symptom:** Frontend operations fail with "Internal Server Error".

**Solutions:**
- Check backend console logs for stack traces
- Verify all required directories exist: `ls -la var/autoapp/apps/`
- Ensure ADB is accessible: `adb devices`
- Restart backend service

### Frontend Shows Stale Data
**Symptom:** UI doesn't reflect recent changes (uploads, installs, etc.).

**Solutions:**
- Hard refresh browser: Ctrl+Shift+R (Cmd+Shift+R on Mac)
- Check browser console for fetch errors
- Verify BACKEND_URL is correctly configured
- Clear browser cache and reload

### Activity Feed Empty or Outdated
**Symptom:** Recent actions don't appear in activity feed.

**Solutions:**
- Check backend logs are being written: `tail -f var/autoapp/apps/logs/activity.log`
- Verify activity log file permissions
- Restart backend to reinitialize log watcher
- Force refresh by toggling between pages

### Retention Sweep Deletes Wanted APKs
**Symptom:** APKs disappear after 30 days despite being needed.

**Solutions:**
- Pin important APKs using the pin toggle in APK list
- Adjust retention threshold if needed (modify `RETENTION_DAYS_THRESHOLD` in backend)
- Manually backup critical APKs outside the library directory
- Review retention sweep logs for deletion history

## Environment Issues

### ADB Devices Shows "unauthorized"
**Symptom:** ADB cannot connect to emulator.

**Solutions:**
- Accept authorization prompt on emulator screen
- Reset ADB keys: `adb kill-server && rm ~/.android/adbkey* && adb start-server`
- Restart emulator

### Missing Dependencies (aapt2, adb, Frida)
**Symptom:** Backend fails to execute system commands.

**Solutions:**
- Install Android SDK platform tools: `sudo apt install android-sdk-platform-tools`
- Install aapt2: `sudo apt install aapt2` or download from Android SDK
- Install Frida: `pip install frida-tools`
- Verify all tools are on PATH: `which adb aapt2 frida`

### Port Conflicts
**Symptom:** Backend or frontend fails to start due to port in use.

**Solutions:**
- Change backend port: `PORT=3002 npm run dev`
- Change frontend port: `VITE_PORT=5174 npm run dev`
- Kill existing processes: `lsof -ti:3001 | xargs kill -9`

## Getting Help

If issues persist:
1. Enable debug logging in backend (`LOG_LEVEL=debug`)
2. Capture backend and frontend logs
3. Check browser DevTools Network and Console tabs
4. Review emulator logcat output
5. Consult project maintainers with detailed error context
