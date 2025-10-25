<!--
SYNC IMPACT REPORT
Version: 0.0.0 → 1.0.0 (MAJOR - Initial constitution ratification)
Ratification Date: 2025-10-25
Last Amended: 2025-10-25

Principles Defined:
1. Identity & Workflow - SDD-based governance with /specify → /plan → /tasks → /implement
2. Runtimes & Packaging - Container-only deployment with immutable tags
3. Dockploy & Ingress - Traefik-managed public ingress with internal-only tooling
4. Streaming Path (WebRTC) - Native WebRTC bridge configuration requirements
5. Envoy Gateway - gRPC-Web gateway routing and health checks
6. Reverse-Engineering Tooling - Frida instrumentation model and UI surfaces
7. Captures & Artifacts - Single volume for pcaps/dumps/logs with retention policy
8. Build Artifacts - Production build requirements and versioning
9. Tooling & Quality - TypeScript strict mode, CI-blocking linters
10. Health, Logs, Metrics - Healthz endpoints and structured logging
11. Release & Rollback - Immutable tag deployment via Dockploy
12. Config Surface - Environment variable documentation requirements
13. Acceptance Template - Performance and reliability criteria
14. Legacy/Disabled - ws-scrcpy marked as disabled

Templates Requiring Updates:
⚠ .specify/templates/plan-template.md - PENDING (not yet read)
⚠ .specify/templates/spec-template.md - PENDING (not yet read)
⚠ .specify/templates/tasks-template.md - PENDING (not yet read)

Follow-up TODOs: None
-->

# AutoApp Constitution

**Purpose:** Android emulator automation platform for app testing, traffic capture, and dynamic instrumentation via WebRTC streaming, Frida hooks, and ADB control.

## Core Principles

### 1. Identity & Workflow

AutoApp follows Specification-Driven Development (SDD):

- **SDD Loop:** `/specify` → `/plan` → `/tasks` → `/implement`
- **Branch Naming:** `feat/*`, `fix/*`, `chore/*`
- **PR Requirements:** MUST link spec.md, plan.md, tasks.md
- **No Vibe Coding:** All changes grounded in documented design artifacts

**Rationale:** Prevents ad-hoc changes that break cross-service contracts; ensures traceability from requirement to implementation.

---

### 2. Runtimes & Packaging

**Containers Only:**

- No bare-metal processes; all services run in Docker containers
- Pinned base images (NEVER `latest` tags)
  - Backend: `node:20-slim`
  - Frontend builder: `node:20-slim`, runtime: `nginx:alpine`
  - Emulator: `us-docker.pkg.dev/android-emulator-268719/images/30-google-x64:30.1.2`
  - Envoy: `envoyproxy/envoy:v1.30-latest` (exception: official stable channel)
- Single Docker Compose application
- `depends_on`, healthchecks, and resource limits REQUIRED for all services

**Rationale:** Immutable infrastructure prevents configuration drift; pinned versions ensure reproducible builds.

---

### 3. Dockploy & Ingress

**Traefik is the Only Public Ingress:**

- No host-port publishes for production services (exception: dev mode only)
- Frontend served via Traefik router on public interface
- Backend/Envoy/internal services MUST remain private (Docker network only)
- Current state: Frontend on `:5173` through proxy (migrate to Traefik router)

**Rationale:** Single ingress point simplifies TLS termination, rate limiting, and access control.

---

### 4. Streaming Path (WebRTC)

**Native WebRTC Bridge (NOT ws-scrcpy):**

- **Required Environment Variables:**
  - `EMULATOR_GRPC_ENDPOINT` - gRPC endpoint for emulator control (default: `http://envoy:8080`)
  - `EMULATOR_WEBRTC_PUBLIC_URL` - Public URL for WebRTC signaling (default: `http://127.0.0.1:9000`)
  - `EMULATOR_WEBRTC_ICE_SERVERS` - Comma-separated STUN/TURN servers (default: `stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302`)
- **Bridge Behavior:**
  - Stateless, auto-recovering on connection loss
  - Exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s max
  - Connection keepalive via `poll={true}`
- **Emulator Crash Handling:**
  - Container MUST exit non-zero on emulator crash
  - Dockploy restart policy handles recovery

**Configuration Source:** `backend/src/config/stream.ts` (lines 1-16)

**Rationale:** Native WebRTC provides lower latency and better browser compatibility than WebSocket-based screen mirroring.

---

### 5. Envoy Gateway

**gRPC-Web Gateway Configuration:**

- **Routes:**
  - `/android.emulation.control.Rtc` → emulator gRPC (infinite timeout)
  - `/android.emulation.control` → emulator gRPC (infinite timeout)
  - `/healthz` → direct response `200 OK`
  - `OPTIONS /*` → CORS preflight handler
- **Ports:**
  - Gateway listener: `8080` (internal)
  - Admin interface: `8001` (internal)
  - Public via Traefik: `:9000` → `envoy:8080`
- **Upstream:** `host.docker.internal:8554` (emulator gRPC server)
- **Healthcheck:** `/healthz` endpoint REQUIRED, checked every 1.5s (timeout)

**Configuration Source:** `infra/envoy/envoy.yaml` (lines 1-115)

**Rationale:** Envoy translates browser-compatible gRPC-Web to native gRPC for emulator control.

---

### 6. Reverse-Engineering Tooling

**Frida Dynamic Instrumentation:**

- **Model:** Attach to running process PID, load/unload scripts, bidirectional message IO
- **UI Surfaces:**
  - `FridaPanel.tsx` - Server start/stop, process selection, script injection
  - `useFridaControls.ts` - API: `startServer()`, `stopServer()`, `attachToProcess()`, `listProcesses()`
- **Feature Flag:** `ENABLE_FRIDA` environment variable (default: disabled)
- **Security Constraint:** ADB/Frida NEVER exposed publicly (internal Docker network only)

**Configuration Sources:**

- `frontend/src/components/apps/FridaPanel.tsx` (lines 1-214)
- `frontend/src/hooks/useFridaControls.ts` (lines 1-161)
- `frontend/src/state/featureFlagsStore.ts` (lines 1-44)

**Rationale:** Dynamic instrumentation required for API capture and behavioral analysis; feature-flagged pending security governance approval.

---

### 7. Captures & Artifacts

**Single Mounted Volume:**

- **Path:** `./var/autoapp:/var/autoapp`
- **Contents:**
  - `dumps/` - UI XML dumps from uiautomator
  - `captures/` - Frida hook outputs
  - `pcaps/` - Network traffic captures (mitmproxy)
  - `logs/` - Application logs
- **Retention Policy:** Time-based cleanup (implement 7-day retention for non-critical artifacts)

**Rationale:** Centralized artifact storage simplifies backup/analysis; retention prevents unbounded disk growth.

---

### 8. Build Artifacts

**Frontend:**

- Production: `npm run build` → static assets in `dist/`
- Served via `nginx:alpine` (NOT Vite dev server)
- Build command: `tsc --noEmit && vite build` (type-check + build)

**Backend:**

- Build: `npm run build` → compiled JS in `dist/`
- Runtime: `node dist/index.js`
- Build command: `tsc` (TypeScript compilation)

**Versioning:**

- Docker images and manifests share the same `x.y.z` semantic version tag
- NO `latest` tags in production

**Rationale:** Separate build/runtime stages reduce image size; shared versioning ensures service compatibility.

---

### 9. Tooling & Quality

**Non-Negotiable:**

- **TypeScript Strict Mode:** `"strict": true` in all `tsconfig.json` files
- **Linters:** Prettier + ESLint MUST pass before merge (CI-blocking)
- **Package Manager:** `npm` only (no mixing yarn/pnpm)
- **Validation:** `docker compose config` MUST pass without errors

**Scripts:**

- `npm run check` → lint + build (MUST pass in CI)
- `npm run lint` → ESLint
- `npm run format` → Prettier auto-fix

**Configuration Sources:**

- `backend/tsconfig.json:8` - `"strict": true`
- `frontend/tsconfig.app.json:7` - `"strict": true`

**Rationale:** Strict mode catches type errors at compile time; consistent formatting reduces diff noise.

---

### 10. Health, Logs, Metrics

**Healthcheck Endpoints:**

- Frontend: `/` (nginx default)
- Backend: `/api/health` or embed in root route
- Envoy: `/healthz` (returns `200 OK`)

**Structured Logging:**

- Format: JSON with fields `{service, event, severity, trace_id, timestamp}`
- Severity levels: `error`, `warn`, `info`, `debug`
- Backend uses Winston-style logger (`backend/src/services/logger.ts`)

**Metrics (Optional):**

- Minimal Prometheus endpoint for stream connection count, emulator uptime

**Rationale:** Healthz enables automated restart; structured logs support centralized log aggregation.

---

### 11. Release & Rollback

**Dockploy Deployment:**

- Immutable tags only (e.g., `apptest-backend:1.2.3`)
- Keep previous tag available for instant rollback
- Rollback procedure: Update docker-compose.yml tag, redeploy

**Rationale:** Immutable tags prevent "works on my machine" issues; previous tag enables fast rollback.

---

### 12. Config Surface

**Environment Variables (Backend):**

| Variable                        | Default                           | Required | Consumer | Description                          |
|---------------------------------|-----------------------------------|----------|----------|--------------------------------------|
| `NODE_ENV`                      | `production`                      | No       | Backend  | Runtime environment                  |
| `PORT`                          | `3001`                            | No       | Backend  | HTTP server port                     |
| `HOST`                          | `0.0.0.0`                         | No       | Backend  | Bind address                         |
| `LOG_LEVEL`                     | `info`                            | No       | Backend  | Logging verbosity                    |
| `CORS_ALLOWED_ORIGINS`          | `*`                               | No       | Backend  | CORS origin whitelist                |
| `EXTERNAL_EMULATOR`             | `true`                            | No       | Backend  | Use external emulator instance       |
| `EXTERNAL_EMULATOR_HOST`        | `host.docker.internal`            | No       | Backend  | Emulator ADB host                    |
| `EXTERNAL_EMULATOR_ADB_PORT`    | `5555`                            | No       | Backend  | Emulator ADB port                    |
| `EMULATOR_GRPC_ENDPOINT`        | `http://envoy:8080`               | No       | Backend  | gRPC control endpoint                |
| `EMULATOR_WEBRTC_PUBLIC_URL`    | `http://82.165.175.97:9000`       | No       | Backend  | WebRTC signaling URL (public IP)     |
| `EMULATOR_WEBRTC_ICE_SERVERS`   | `stun:stun.l.google.com:19302,...`| No       | Backend  | STUN/TURN server list                |

**Environment Variables (Emulator):**

| Variable            | Default | Required | Consumer  | Description              |
|---------------------|---------|----------|-----------|--------------------------|
| `AVD_CONFIG`        | -       | No       | Emulator  | AVD hardware config      |
| `ADBKEY`            | -       | No       | Emulator  | ADB key (from volume)    |
| `WEBRTC_PORT_RANGE` | -       | No       | Emulator  | WebRTC port range        |

**Documentation Requirement:**

- Add `CONFIG.md` with full variable table (name, default, required, consumer, description)
- Update on every new environment variable

**Configuration Sources:**

- `docker-compose.yml` (lines 10-20, 36-39)
- `backend/src/config/stream.ts` (lines 1-16)

**Rationale:** Centralized config docs prevent deployment errors; explicit defaults reduce configuration drift.

---

### 13. Acceptance Template

**Given/When/Then Criteria:**

1. **Service Health:**
   - Given: All services started via `docker compose up`
   - When: Healthcheck probes run
   - Then: All services report healthy within 30s

2. **WebRTC Connection:**
   - Given: Frontend loaded in browser
   - When: User opens StreamViewer
   - Then: WebRTC stream connects within ≤ 5s

3. **Input Round-Trip Latency:**
   - Given: Active WebRTC stream
   - When: User taps screen coordinate
   - Then: P95 latency ≤ 150ms (tap → visual feedback)

**Rationale:** Quantitative acceptance criteria prevent regressions in core user experience.

---

### 14. Legacy/Disabled

**ws-scrcpy:**

- Directory: `ws-scrcpy/*`
- Status: DISABLED (legacy WebSocket-based screen mirroring)
- Reason: Replaced by native WebRTC bridge (lower latency, better browser support)
- **Cannot Enable Without:** New spec.md + plan.md + tasks.md documenting migration path

**Rationale:** Deprecated code remains for reference but requires governance approval to re-enable.

---

## Exceptions

**Any deviation from this constitution MUST be documented in the PR with:**

1. Rationale for exception
2. Time-bound plan to remove exception (e.g., "Temporary workaround until Q2 2025")
3. Approval from project maintainer

**Examples of Valid Exceptions:**

- Hot-fix bypassing SDD loop (MUST create retroactive spec within 48h)
- Emergency deployment with untagged image (MUST tag and redeploy within 24h)

---

## Governance

**Amendment Procedure:**

1. Propose change via PR to `.specify/memory/constitution.md`
2. Version bump following semantic versioning:
   - **MAJOR:** Backward-incompatible principle changes (e.g., remove mandatory section)
   - **MINOR:** New principle or materially expanded guidance
   - **PATCH:** Clarifications, wording fixes, non-semantic refinements
3. Update dependent templates (plan, spec, tasks) in same PR
4. Require approval from 1+ maintainer
5. Update `LAST_AMENDED_DATE` to date of merge

**Compliance Review:**

- Every PR MUST verify compliance with all applicable principles
- Use `/speckit.analyze` after task generation to cross-check consistency

**Version**: 1.0.0 | **Ratified**: 2025-10-25 | **Last Amended**: 2025-10-25
