# autoapp Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-10-08

## Active Technologies
- Node.js 20 LTS with TypeScript 5.x for backend and frontend tooling + Express 4 (backend API), ws-scrcpy (streamer service + browser client), axios/fetch for HTTP polling, Zustand (lightweight state store), Android SDK CLI tools (sdkmanager, avdmanager, emulator, adb), pm2/nodemon for local orchestration scripts (001-web-ui-read)
- TypeScript (Node.js 20) backend, TypeScript (React 18 + Vite) frontend + Express 4, ws-scrcpy integration hooks, Zustand store, local CLI tools (ADB, aapt2, frida-server, mitmproxy) (002-1-summary-add)
- Local filesystem (structured under `var/` or feature-specific directories) with JSON indexes for metadata (002-1-summary-add)

## Project Structure
```
backend/
frontend/
tests/
```

## Commands
npm test [ONLY COMMANDS FOR ACTIVE TECHNOLOGIES][ONLY COMMANDS FOR ACTIVE TECHNOLOGIES] npm run lint

## Code Style
Node.js 20 LTS with TypeScript 5.x for backend and frontend tooling: Follow standard conventions

## Recent Changes
- 002-1-summary-add: Added TypeScript (Node.js 20) backend, TypeScript (React 18 + Vite) frontend + Express 4, ws-scrcpy integration hooks, Zustand store, local CLI tools (ADB, aapt2, frida-server, mitmproxy)
- 001-web-ui-read: Added Node.js 20 LTS with TypeScript 5.x for backend and frontend tooling + Express 4 (backend API), ws-scrcpy (streamer service + browser client), axios/fetch for HTTP polling, Zustand (lightweight state store), Android SDK CLI tools (sdkmanager, avdmanager, emulator, adb), pm2/nodemon for local orchestration scripts

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
