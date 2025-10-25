# Quick Start: UI Discovery & Map System

**Phase 1 Feature**: Manual State Discovery & UI Map Building
**Target Users**: Security researchers, automation engineers
**Prerequisites**: Android emulator with MaynDrive app installed

## Overview

The UI Discovery system enables manual exploration of Android apps with automatic state capture, graph building, and transition recording. This Phase 1 implementation focuses on **discovery only** - no automated flow replay yet.

## What You Can Do (Phase 1)

- ✅ **Capture UI States**: Snapshot current screen with automatic element detection
- ✅ **Build UI Graph**: Automatically connect states with transitions
- ✅ **Edit Graph**: Merge duplicate states, annotate transitions
- ✅ **Visualize Map**: View states and connections in the Discovery panel
- ✅ **Export Data**: Download graph JSON and session logs

## Setup Requirements

### Environment Variables

Add these to your `.env` file or Docker Compose configuration:

```bash
# Discovery System Configuration
ENABLE_DISCOVERY=true
DISCOVERY_PANEL=true
GPS_PANEL=false

# ADB Configuration
ADB_HOST=host.docker.internal
ADB_PORT=5555
ANDROID_SERIAL=emulator-5554

# Data Storage
GRAPH_PATH=/app/data/graph.json
SESSIONS_DIR=/app/data/sessions
SCREENSHOTS_DIR=/app/data/screenshots

# Performance Settings
SNAPSHOT_TIMEOUT_MS=5000
UIXML_TMP=/tmp/view.xml
MERGE_THRESHOLD=0.9
```

### Docker Compose Updates

Add data volume to existing backend service:

```yaml
services:
  backend:
    # ... existing config
    volumes:
      - ./var/autoapp:/var/autoapp
      - emulator-home:/root/.android
      - discovery-data:/app/data  # Add this line
    # ... rest of config

volumes:
  emulator-home:
  discovery-data:  # Add this volume
```

## Getting Started

### 1. Start the System

```bash
# Start all services
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 2. Launch MaynDrive App

```bash
# Start the Android emulator (if not already running)
# Launch MaynDrive app and ensure user is logged in
adb -s emulator-5554 shell am start -n fr.mayndrive.app/.MainActivity
```

### 3. Open Discovery Interface

1. Navigate to `http://localhost:5173` (or your deployed URL)
2. Open the **Apps** section
3. Select **Discovery Panel** (replaces GPS panel)
4. Verify the WebRTC stream is showing the emulator

## Basic Workflow

### Step 1: Capture Your First State

1. Navigate to any screen in MaynDrive app
2. In the Discovery panel, click **"Snapshot State"**
3. Wait for capture to complete (should be <1 second)
4. Verify the state appears in the Current State section

**What happens**:
- System captures activity name, UI hierarchy, screenshot
- Creates SHA256 state ID for deduplication
- Extracts interactive elements with selectors
- Saves to `graph.json` and creates session log entry

### Step 2: Navigate and Capture Another State

1. Perform an action in the app (tap button, navigate to different screen)
2. Click **"Snapshot State"** again
3. Observe the new state appearing in the graph

### Step 3: Create a Transition

1. Before navigating, click **"Mark Transition"** (this puts the system in "record" mode)
2. Perform the UI action (e.g., tap Login button)
3. Take another snapshot to complete the transition
4. The transition will appear connecting the two states

### Step 4: Merge Duplicate States

If you capture the same screen multiple times:

1. Select two similar states in the graph
2. Click **"Merge with..."**
3. Choose the target state to keep
4. System will merge states and update all transitions

## Understanding the Discovery Panel

### Layout

```
┌─────────────────┬─────────────────────────────────┐
│                 │                                 │
│  WebRTC Stream  │      Discovery Panel            │
│                 │                                 │
│                 │ ┌─────────────────────────────┐ │
│                 │ │   Current State            │ │
│                 │ │   Activity: MainActivity    │ │
│                 │ │   Digest: abc123...        │ │
│                 │ │   Screenshot: [image]       │ │
│                 │ └─────────────────────────────┘ │
│                 │                                 │
│                 │ ┌─────────────────────────────┐ │
│                 │ │   Elements (selectors)      │ │
│                 │ │ • btn_login (rid)          │ │
│                 │ │ • "Email" (text)          │ │
│                 │ │ • input_email (cls)        │ │
│                 │ └─────────────────────────────┘ │
│                 │                                 │
│                 │ ┌─────────────────────────────┐ │
│                 │ │   Actions                  │ │
│                 │ │ [Snapshot State]           │ │
│                 │ │ [Mark Transition]          │ │
│                 │ │ [Merge States]             │ │
│                 │ └─────────────────────────────┘ │
│                 │                                 │
│                 │ ┌─────────────────────────────┐ │
│                 │ │   Graph Mini-Map           │ │
│                 │ │ State1 (Login)             │ │
│                 │ │ State2 (Dashboard)          │ │
│                 │ │ └─→ transition1            │ │
│                 │ └─────────────────────────────┘ │
└─────────────────┴─────────────────────────────────┘
```

### Controls

- **Snapshot State**: Capture current UI state
- **Mark Transition**: Enter transition recording mode
- **Annotate Element**: Add notes to selected UI element
- **Merge with...**: Combine duplicate states

## Advanced Usage

### State Analysis

Each captured state includes:

```typescript
{
  "id": "sha256hash",
  "package": "fr.mayndrive.app",
  "activity": "MainActivity",
  "digest": "normalized-ui-hash",
  "selectors": [
    {
      "rid": "btn_login",
      "text": "Login",
      "cls": "android.widget.Button",
      "bounds": [540, 1200, 900, 1350]
    }
  ],
  "visibleText": ["Login", "Email", "Password"],
  "screenshot": "abc123def.png",
  "metadata": {
    "captureMethod": "adb",
    "captureDuration": 750,
    "elementCount": 15,
    "hierarchyDepth": 5
  }
}
```

### Transition Recording

Transitions capture the full action context:

```typescript
{
  "from": "state1-hash",
  "to": "state2-hash",
  "action": {
    "type": "tap",
    "target": { "rid": "btn_login" },
    "metadata": { "confidence": 0.95 }
  },
  "evidence": {
    "beforeDigest": "state1-hash",
    "afterDigest": "state2-hash",
    "timestamp": "2025-10-25T16:45:02.500Z",
    "notes": "User tapped login button"
  }
}
```

### Keyboard Shortcuts

- **S**: Quick snapshot state
- **T**: Mark transition mode
- **M**: Merge selected states
- **R**: Refresh current state detection

## Data Management

### File Locations

```
/app/data/
├── graph.json           # Complete UI graph
├── sessions/           # Capture session logs
│   ├── 2025-10-25T15-30.jsonl
│   └── 2025-10-25T16-45.jsonl
└── screenshots/        # State screenshots
    ├── abc123def.png
    └── fed456cba.png
```

### Exporting Data

1. **Graph JSON**: Click **"Download Graph"** in the panel
2. **Session Logs**: Click **"Export Session"** for detailed logs
3. **Screenshots**: Available in `/app/data/screenshots/` directory

### Version Control

The `graph.json` file is Git-friendly:

```bash
# Commit graph changes
git add data/graph.json
git commit -m "Added login flow states and transitions"

# View changes
git diff data/graph.json

# Revert to previous version
git checkout HEAD~1 -- data/graph.json
```

## Troubleshooting

### Common Issues

**"State capture taking too long"**
- Check emulator performance: `adb shell dumpsys cpuinfo`
- Increase `SNAPSHOT_TIMEOUT_MS` if needed
- Verify ADB connection stability

**"Duplicate states not merging"**
- Check `MERGE_THRESHOLD` (default 0.9)
- Manually merge states using **"Merge with..."**
- Review state similarity in session logs

**"WebRTC stream not showing"**
- Verify emulator is running: `adb devices`
- Check stream ticket generation
- Ensure `EMULATOR_WEBRTC_PUBLIC_URL` is correct

**"Selectors not detected"**
- Verify UI hierarchy is accessible: `adb shell uiautomator dump`
- Check if app has accessibility restrictions
- Review element bounds in captured state

### Debug Mode

Enable detailed logging:

```bash
# Backend debug mode
LOG_LEVEL=debug docker-compose up backend

# Frontend debug mode
# Open browser dev tools, check Console tab
```

### Performance Optimization

For large graphs (>100 states):

1. Increase merge threshold: `MERGE_THRESHOLD=0.8`
2. Enable state filtering in graph display
3. Use session filtering for recent captures only

## Next Steps (Phase 2)

Phase 2 will add:

- 🔮 **Flow Definition**: Create automated sequences from captured states
- 🔮 **Intelligent Replay**: Execute flows with state recovery
- 🔮 **Advanced Graph Visualization**: Interactive graph canvas
- 🔮 **LLM Integration**: Natural language flow creation with Claude Code

## Support

- **Documentation**: `/specs/001-ui-map-flow-engine/`
- **API Reference**: `/contracts/api.yaml`
- **Type Definitions**: `/contracts/types.ts`
- **Issues**: Create GitHub issue for bugs or feature requests

---

**Happy Discovery!** 🎯

*This is Phase 1 of the UI Map & Flow Engine. Focus on capturing comprehensive app states and building accurate transition graphs.*