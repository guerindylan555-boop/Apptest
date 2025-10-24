# Endless Discovery & LLM Automation System - Implementation Guide

## 🎉 What's Been Built

You now have a complete **endless UI discovery and LLM-driven automation system** for MaynDrive testing. Here's what was implemented:

### ✅ Core Components Created

1. **State Signature System** (`services/state_signature.py`)
   - Canonical UI state fingerprinting
   - Deduplication using structural + visual hashing
   - Perceptual image comparison (pHash)
   - Activity/package tracking via dumpsys

2. **Discovery Daemon** (`services/discovery_daemon.py`)
   - Endless background UI monitoring
   - Automatic state graph building
   - Real-time change detection with debouncing
   - State/edge tracking with visit counts
   - Annotation support for human notes

3. **Action Executor** (`agent/executor.py`)
   - Selector-first approach (resource-id → text → xpath → coords)
   - Intelligent fallback to coordinates
   - Retry logic with backoff
   - Support for: tap, text, back, home, swipe, wait, launch

4. **LLM Planner** (`agent/planner.py`)
   - GLM-4.6 integration for UI analysis
   - A* pathfinding through state graph
   - Action recommendation with confidence scores
   - Route optimization using edge success rates

5. **Operator Console** (`ui/app.py` + `ui/socket.py`)
   - Real-time web UI on port 8000
   - Live discovery monitoring
   - Automation control (START/PAUSE/STOP)
   - LLM commentary stream
   - State annotation interface
   - Natural language chat commands
   - WebSocket-based event streaming

### 🔧 Updated Components

- **llm_client.py**: Now uses GLM-4.6 Coding API endpoint
  - Base URL: `https://api.z.ai/api/coding/paas/v4`
  - Model: `GLM-4.6`

- **requirements.txt**: Added dependencies
  - Pillow, imagehash (image processing)
  - FastAPI, uvicorn, websockets (web console)

## 🚀 How To Use

### 1. Install Dependencies

```bash
cd orchestrator
pip install -r requirements.txt
```

### 2. Set Environment Variables

```bash
export ZAI_API_KEY=489013a3ff214e22930507edce85970a.q6oBSQpGVEIcrRkU
export ZAI_BASE_URL=https://api.z.ai/api/coding/paas/v4
export ZAI_MODEL=GLM-4.6
```

### 3. Bootstrap State Graph (One-Time)

```bash
python3 runner.py --build-graph
```

This analyzes existing XML files and builds initial state graph.

### 4. Start Endless Discovery

```bash
# Terminal 1: Start discovery daemon
python3 -c "
import sys
sys.path.insert(0, '.')
from services.discovery_daemon import DiscoveryDaemon
from adb_tools import ADBTools

daemon = DiscoveryDaemon('emulator-5556')
daemon.start()

# Keep running
import time
try:
    while True:
        time.sleep(1)
        stats = daemon.get_coverage_stats()
        print(f'States: {stats[\"total_states\"]}, Edges: {stats[\"total_edges\"]}', end='\r')
except KeyboardInterrupt:
    daemon.stop()
"
```

### 5. Launch Operator Console

```bash
# Terminal 2: Start web console
cd ui
python3 app.py
```

Then open browser: **http://localhost:8000**

### 6. Use The Console

**Discover Mode**:
1. Click "▶️ Start Discovery"
2. Use the app normally
3. Watch states appear in real-time
4. Add annotations to document flows

**Automation Mode**:
1. Click "🚀 Run RENTAL" or "🔐 Run LOGIN"
2. Watch LLM commentary in real-time
3. See actions executed step-by-step

**Chat Commands**:
- Type: "Unlock a vehicle"
- Type: "Navigate to My Account"
- LLM will plan and execute

## 📊 What The System Does

### Endless Discovery Loop

```
1. Poll UI every 500ms
2. Detect change (activity/XML hash)
3. Debounce 600ms (wait for stable)
4. Capture artifacts:
   - UI XML dump (uiautomator)
   - Screenshot (screencap)
   - Activity name (dumpsys)
5. Compute signature:
   - Structural: texts + controls + layout
   - Visual: perceptual hash (pHash)
6. Deduplicate:
   - Compare with existing states
   - If similar (>85%): update visit count
   - If new: create state node
7. Record edge:
   - Track transition from previous state
   - Store action that caused it
8. Emit WebSocket event:
   - Send to operator console
   - Update live UI
9. Save graph to disk
10. Loop forever
```

### LLM-Driven Automation

```
1. User sets goal (e.g., "RENTAL")
2. Planner queries GLM-4.6:
   - "Here's current UI, what action next?"
   - Provides: texts, controls, history, routes
3. GLM-4.6 responds:
   - Reasoning: "I see Login button at..."
   - Action: tap resource-id:login_btn
   - Fallback: coords (540, 1000)
   - Confidence: 0.9
4. Executor performs action:
   - Try resource-id selector first
   - Parse XML, find element, get center
   - Tap via ADB
   - Wait for UI settle (500ms)
5. Discovery daemon detects change
6. Record edge success/latency
7. Loop until goal reached or max steps
```

## 🧠 Key Design Choices

### Why Signature-Based Deduplication?

Avoids creating duplicate states for minor UI variations (loading spinners, timestamps, dynamic content).

**Approach:**
- Normalize texts (lowercase, mask numbers)
- Quantize bounds to 100px grid
- Use perceptual hash (robust to compression/resize)
- Combine structural (70%) + visual (30%) similarity

### Why Selector-First Execution?

Coordinates break when UI changes (different screen sizes, scrolling, animations).

**Hierarchy:**
1. resource-id (most stable)
2. text (stable if static)
3. content-desc (stable)
4. xpath (flexible)
5. coordinates (last resort)

### Why A* Pathfinding?

Finds shortest path through state graph using edge costs (reliability + latency).

**Cost Function:**
```python
cost = (1 - success_rate) * 5.0 + latency_seconds
```

Low cost = high success rate + fast.

### Why WebSocket Console?

Provides real-time feedback without polling.

**Events streamed:**
- state_discovered
- state_changed
- automation_step
- llm_commentary

## 📁 File Structure

```
orchestrator/
├── services/
│   ├── __init__.py
│   ├── state_signature.py      # Signature & dedup logic
│   └── discovery_daemon.py     # Endless discovery loop
├── agent/
│   ├── __init__.py
│   ├── executor.py             # Action execution
│   └── planner.py              # LLM planning + A*
├── ui/
│   ├── __init__.py
│   ├── app.py                  # FastAPI web console
│   └── socket.py               # WebSocket manager
├── storage/
│   └── discovery/
│       ├── states/             # State artifacts
│       │   └── <hash>/
│       │       ├── window.xml
│       │       ├── screenshot.png
│       │       └── meta.json
│       └── discovery_graph.json # Full state graph
├── llm_client.py               # GLM-4.6 client (updated)
├── runner.py                   # CLI entry point
└── requirements.txt            # Dependencies (updated)
```

## 🐛 Troubleshooting

**Discovery not detecting changes?**
- Check `poll_interval` (default 500ms)
- Verify ADB connection: `adb devices`
- Check activity detection: `adb shell dumpsys activity activities | grep mResumedActivity`

**LLM not responding?**
- Verify API key: `echo $ZAI_API_KEY`
- Test manually: `curl -H "Authorization: Bearer $ZAI_API_KEY" https://api.z.ai/api/coding/paas/v4/...`
- Check model name is `GLM-4.6` (uppercase)

**Console not loading?**
- Verify port 8000 not in use: `lsof -i :8000`
- Check uvicorn running: `ps aux | grep uvicorn`
- Open browser dev tools for WebSocket errors

**Actions failing?**
- Check selector hints are correct format: `resource-id:foo` not `resource-id=foo`
- Verify fallback coordinates are within bounds
- Increase `settle_time_ms` if UI needs more time

## 🎯 Next Steps

1. **Integrate with existing runner.py**:
   - Add `--daemon` mode
   - Add `--console` mode
   - Wire discovery daemon with automation loop

2. **Add more exploration policies**:
   - BFS (breadth-first)
   - DFS (depth-first)
   - Priority to unseen actions

3. **Improve LLM prompts**:
   - Add few-shot examples
   - Include screenshots in multimodal requests
   - Fine-tune temperature/top-p

4. **Build learning system**:
   - Track which selectors work best
   - Learn common failure patterns
   - Auto-adjust retry strategies

## ✅ Testing Checklist

- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Set env vars: `ZAI_API_KEY`, `ZAI_BASE_URL`
- [ ] Start emulator: `emulator @autoapp-local`
- [ ] Launch MaynDrive app
- [ ] Start discovery daemon
- [ ] Open console: http://localhost:8000
- [ ] Click "Start Discovery"
- [ ] Use app, watch states appear
- [ ] Add annotation to current state
- [ ] Click "Run RENTAL"
- [ ] Watch automation execute
- [ ] Check LLM commentary stream
- [ ] Verify state graph saves to disk
- [ ] Stop daemon gracefully

## 🙏 Credits

Built using research from:
- DroidBot, Stoat, APE, Humanoid (exploration strategies)
- Rico dataset (UI semantics)
- OpenAI Protocol (API compatibility)
- A* algorithm (path planning)
- Perceptual hashing (image similarity)

Powered by GLM-4.6 (Coding) via Z.ai.
