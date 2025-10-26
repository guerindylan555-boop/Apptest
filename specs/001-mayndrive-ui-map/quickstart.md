# Quickstart: MaynDrive State-Aware UI Mapping

## 1. Prerequisites
- Docker + Docker Compose (per repo `docker-compose.yml`).
- Node.js 20 + npm (workspaces already configured).
- Android emulator artifacts installed (run `scripts/setup-emulator.sh`).
- MaynDrive APK under `app apk/` and valid login/OTP credentials.

## 2. Boot the stack
```bash
npm run bootstrap       # installs backend + frontend deps
docker compose up backend frontend envoy emulator -d
```
- Wait for backend healthcheck + Envoy `/healthz` to succeed.
- Visit `http://localhost:5173` (Traefik proxy in Dockploy) to confirm WebRTC bridge loads.

## 3. Capture a screen node
1. Open the operator console in the frontend.
2. Navigate the emulator to an unmapped screen (clean boot, login form, post-login home, rented scooter view).
3. Use **Capture Screen** to enter name + hints, choose a **Start State Tag**, and trigger artifact capture.
4. Verify node files under `var/captures/<nodeId>/` and graph update in `var/graphs/<version>/ui-graph.json`.

## 4. Add an action edge
1. From the node detail pane choose **Add Action**.
2. Select action kind (tap/type/wait/back/intent) and bind to a selector or text payload.
3. Execute; the tool records the resulting screen and creates the edge (plus destination node if new).

## 5. Run the detector manually
```bash
npm run detector -- --dump var/captures/<nodeId>/ui.xml
```
- Inspect output for top-K scores. Accept mapping if ≥70, otherwise choose `map_new` or `merge`.

## 6. Author a flow
1. Copy `var/flows/templates/flow-example.yaml` to a new file (e.g., `login-home.yaml`).
2. Fill metadata, variables (phone/email/OTP placeholders), reference edges via `edgeId`, and declare the required `startStateProfile` plus `unlockPolicy` (`any_available` vs `existing_rental_only`).
3. Define recovery rules for `unexpected_node`, `system_dialog`, and `timeout`.
4. Validate structure:
```bash
npm run flows:lint -- var/flows/login-home.yaml
```

## 7. Execute a flow
```bash
npm run flows:run -- --flow var/flows/login-home.yaml
```
- Runner detects current node, pathfinds to precondition, and executes steps with per-step re-detection logs.
- Respond to prompts when manual intervention is needed (e.g., OTP entry) or when the unlock policy requires operator confirmation.

## 8. Update README for LLM contributors
- Append naming rules, safe-action reminders, and new node ids to `var/flows/README.md`.
- Keep artifact bundles <1 MB by pruning redundant screenshots per spec success criteria.

## 9. Shut down
```bash
docker compose down
```
- Artifacts remain under `var/` (Constitution §7) for future capture/flow sessions.
