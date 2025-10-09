# autoapp Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-10-08

## Active Technologies
- Node.js 20 LTS with TypeScript 5.x for backend and frontend tooling + Express 4 (backend API), ws-scrcpy (streamer service + browser client), axios/fetch for HTTP polling, Zustand (lightweight state store), Android SDK CLI tools (sdkmanager, avdmanager, emulator, adb), pm2/nodemon for local orchestration scripts (001-web-ui-read)
- Node.js 20 LTS + TypeScript 5.x (backend + tooling), React 18 + Vite 5 (frontend) + Express 5, ws-scrcpy toolchain (wrapper + scrcpyws-client), Zustand, Media Source Extensions API (001-web-ui-read)
- N/A (runtime state held in memory) (001-web-ui-read)

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
- 001-web-ui-read: Added Node.js 20 LTS + TypeScript 5.x (backend + tooling), React 18 + Vite 5 (frontend) + Express 5, ws-scrcpy toolchain (wrapper + scrcpyws-client), Zustand, Media Source Extensions API
- 001-web-ui-read: Added Node.js 20 LTS with TypeScript 5.x for backend and frontend tooling + Express 4 (backend API), ws-scrcpy (streamer service + browser client), axios/fetch for HTTP polling, Zustand (lightweight state store), Android SDK CLI tools (sdkmanager, avdmanager, emulator, adb), pm2/nodemon for local orchestration scripts

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
