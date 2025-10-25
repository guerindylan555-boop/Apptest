# AutoApp (APPtest) Constitution

## 1. Identity & Workflow
AutoApp is a containerized Android app automation platform with WebRTC streaming and dynamic instrumentation.

- SDD loop: `/specify` → `/plan` → `/tasks` → `/implement`
- Branch naming: `feat/*`, `fix/*`, `chore/*`
- PRs must link spec/plan/tasks artifacts
- Single purpose: mobile app reverse engineering and automation

## 2. Runtimes & Packaging
All services run in containers with immutable configuration.

- Containers only; no host binaries or runtime dependencies
- Pinned base images: `node:20-slim`, `envoyproxy/envoy:v1.30-latest`, Android emulator images
- Single Docker Compose app with service dependencies
- All services require `depends_on`, `healthchecks`, and resource limits
- No `latest` tags; explicit version pins required

## 3. Dockploy & Ingress
Traefik is the only public ingress pathway.

- Deployed via Dockploy on single VPS
- Traefik routes all public traffic; no host port publishes
- Frontend served on :5173 through Traefik proxy
- Backend and internal services are private to the compose network
- All external exposure must go through Traefik routers

## 4. Streaming Path (WebRTC)
WebRTC provides the primary app interaction surface.

- Required environment variables:
  - `EMULATOR_WEBRTC_PUBLIC_URL`: Public WebRTC endpoint (default: http://82.165.175.97:9000)
  - `EMULATOR_WEBRTC_ICE_SERVERS`: STUN/TURN servers (default: stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302)
  - `EMULATOR_GRPC_ENDPOINT`: gRPC gateway URL (default: http://envoy:8080)
- Bridge is stateless and auto-recovering
- Emulator crash must cause container exit with non-zero code for Dockploy restart
- WebRTC connection timeout: 1500ms for health checks

## 5. Envoy Gateway
Envoy provides gRPC-Web translation for emulator control.

- Listens on :8080 internally, exposed via Traefik on :9000
- Routes `/android.emulation.control.Rtc*` and `/android.emulation.control*` to emulator gRPC
- Health check endpoint: `/healthz` returns "ok"
- CORS headers configured for cross-origin WebRTC
- Routes only via Traefik; no direct external access

## 6. Reverse-Engineering Tooling
Frida enables dynamic instrumentation and API capture.

- Frida model: attach/detach to processes, load/unload scripts, message I/O
- UI surfaces: `FridaPanel.tsx` and `useFridaControls.ts` hooks
- ADB/Frida never exposed publicly; internal services only
- Feature-gated: `ENABLE_FRIDA=true` required for UI access
- All Frida operations must be containerized

## 7. Captures & Artifacts
Technical artifacts stored in structured volumes.

- Single mounted volume: `./var/autoapp:/var/autoapp`
- Subdirectories: `dumps/`, `captures/`, `logs/`, `screenshots/`
- Retention policy: automatic cleanup after 30 days for capture files
- All captures must be timestamped and indexed
- No sensitive data in artifact filenames

## 8. Build Artifacts
Production builds use optimized static assets.

- Frontend: `npm run build` produces static files served by lightweight web server
- Backend: `node dist/index.js` with production dependencies only
- Images and manifests share semantic version tags (x.y.z)
- No development servers in production containers
- Build artifacts must be reproducible

## 9. Tooling & Quality
Strict development standards enforced in CI.

- TypeScript `"strict": true` mandatory
- Prettier + ESLint are CI-blocking failures
- Single package manager: npm for all Node.js projects
- Docker Compose config must pass validation (`docker compose config`)
- All services must implement `/healthz` endpoint

## 10. Health, Logs, Metrics
Standardized observability across all services.

- `/healthz` endpoint for all frontend/backend services
- JSON structured logs with fields: `service`, `event`, `severity`, `trace_id`
- Optional minimal metrics endpoint (`/metrics`) for Prometheus
- Centralized log aggregation via volume mounts
- Health check failures trigger automatic restarts

## 11. Release & Rollback
Immutable deployments with instant rollback capability.

- Dockploy deploys immutable tags; no in-place modifications
- Previous tag kept available for instant rollback
- All config changes require new image build
- Database migrations are explicit and versioned
- Rollback must be tested in staging

## 12. Config Surface
All configuration via environment variables.

**Required Variables:**
- `NODE_ENV`: production/staging (default: production)
- `PORT`: Backend port (default: 3001)
- `EXTERNAL_EMULATOR`: true/false (default: false)
- `EXTERNAL_EMULATOR_HOST`: Host for external emulator (default: host.docker.internal)
- `EXTERNAL_EMULATOR_ADB_PORT`: ADB port (default: 5555)

**Optional Variables:**
- `ENABLE_FRIDA`: Enable Frida features (default: false)
- `LOG_LEVEL`: Logging verbosity (default: info)
- `CORS_ALLOWED_ORIGINS`: CORS origins (default: *)
- `WEBRTC_PORT_RANGE`: WebRTC port range (default: 53000-53100)

Add CONFIG.md table documenting all service-specific variables.

## 13. Acceptance Template
Given/When/Then criteria for service validation.

- **Service Health**: Given all containers are running, When accessing `/healthz`, Then response is 200 OK within 500ms
- **WebRTC Connection**: Given emulator is running, When requesting stream ticket, Then WebRTC connects ≤ 5s with stable video
- **Input Latency**: Given stream is active, When sending touch event, Then UI response P95 ≤ 200ms round-trip
- **Frida Operations**: Given ENABLE_FRIDA=true, When attaching to process, Then hooks load and capture events within 2s

## 14. Legacy/Disabled
Legacy components require spec/plan for re-enablement.

- `ws-scrcpy/*`: Present but disabled; WebRTC native bridge replaced this functionality
- Cannot enable ws-scrcpy without new spec and migration plan
- All references to ws-scrcpy must be removed from documentation

## 15. Exceptions
Deviations require documented time-bound removal.

- Any deviation from constitution must be documented in PR description
- Exception must include removal timeline (max 90 days)
- Exceptions require maintainer approval and tracking
- All exceptions listed in project EXCEPTIONS.md

## Governance

This constitution supersedes all other project practices and documentation.

- Amendments require proposal, approval, and migration plan
- All PRs must verify constitution compliance
- Complexity must be justified with measurable benefit
- Use `/plan` and `/tasks` templates for runtime development guidance
- Constitution violations block PR merge
- Regular reviews: quarterly compliance audit mandatory

**Version**: 1.0.0 | **Ratified**: 2025-10-25 | **Last Amended**: 2025-10-25