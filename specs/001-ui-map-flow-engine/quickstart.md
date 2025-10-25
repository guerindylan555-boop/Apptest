# Quickstart — AutoApp UI Map & Intelligent Flow Engine

## 1. Prerequisites
1. Docker + Docker Compose (required by constitution — containers only).
2. Node.js 20.x + npm (host usage limited to lint/build tooling).
3. Android emulator images already configured via `docker-compose.yml`.

## 2. Environment Setup
```bash
# Install dependencies
cd backend && npm install
cd ../frontend && npm install

# Copy env templates
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```
Populate envs with constitution-required variables:
- `EMULATOR_WEBRTC_PUBLIC_URL`
- `EMULATOR_WEBRTC_ICE_SERVERS`
- `EMULATOR_GRPC_ENDPOINT`
- `NODE_ENV`, `PORT`, `EXTERNAL_EMULATOR*`, feature-specific vars (`GRAPH_ROOT`, `FLOW_ROOT`, `REPLAY_RETRY_LIMIT`, etc.).

## 3. Launch the stack
```bash
docker compose up --build
```
Services started:
- `backend`: Express API (`/api`) + `/healthz`
- `frontend`: React/Vite app served via Traefik on :5173
- `envoy`: gRPC-Web proxy
- `emulator`: Android device with WebRTC bridge

## 4. Capture a UI state
1. Open the frontend dashboard (`https://<traefik-host>/`).
2. Confirm WebRTC stream is connected (Device Stream card).
3. In Discovery panel, press **Snapshot State**.
4. Verify new node exists in `var/autoapp/graphs/<graph-id>.json`.

CLI alternative:
```bash
docker compose exec backend npm run discovery:capture
```

## 5. Author a flow
1. Navigate to the **Flows** tab in the Discovery panel.
2. Click **New flow** → seed entry/exit predicates using current state.
3. Save to create `var/autoapp/flows/<flow-slug>.json`.
4. Validate via backend:
```bash
docker compose exec backend npm run flows:validate -- flows/login.json
```

## 6. Replay a flow with recovery
```bash
docker compose exec backend npm run flows:replay -- flows/unlock.json
```
The replay engine:
- Localizes current state before each step.
- Executes prerequisite flows (e.g., login) when preconditions fail.
- Logs structured events under `var/autoapp/logs/replay-*.json`.

## 7. Testing & linting
```bash
# Frontend
cd frontend
npm run lint

# Backend
cd backend
npm run lint
npm run test:integration    # emulator-backed scenarios (see research)
```
CI MUST run lint + integration suites; failures block merges.

## 8. Artifact management
- Graphs/flows live in `var/autoapp/{graphs,flows}` with semantic version headers.
- Use `npm run graph:lint` before committing JSON changes.
- Conflicts produce `.conflict` files—resolve manually and re-run lint.

## 9. Updating Claude agent context
After design changes, run:
```bash
.specify/scripts/bash/update-agent-context.sh claude
```
This keeps the Claude-specific memory aligned with new tech stacks/features.
