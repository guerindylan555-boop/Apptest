# Quickstart — Emulator UI Stream Fix

1. **Install dependencies**
   - `cd backend && npm install`
   - `cd frontend && npm install`
2. **Start backend in dev mode**
   - `npm run dev` inside `backend/`
   - Exposes API on `http://127.0.0.1:7070`
3. **Start streamer (ws-scrcpy)**
   - Backend fix will auto-spawn the ws-scrcpy bridge; ensure Android emulator image and `adb` are available in PATH.
4. **Run frontend**
   - `npm run dev` inside `frontend/`
   - Visit `http://127.0.0.1:8080`
5. **Validate stream**
   - Click “Start Emulator”, wait for state badge to reach **Running**.
   - Confirm canvas renders emulator feed (no black screen) and error banner stays cleared.
6. **Stop emulator**
   - Click “Stop Emulator” and verify stream disconnects with placeholder view.
7. **Review logs if issues occur**
   - Backend logs: `var/log/autoapp/backend.log`
   - Streamer process output will surface under backend logger.
