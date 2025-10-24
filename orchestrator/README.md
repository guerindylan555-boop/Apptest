# MaynDrive LLM-Supervised Automation System

A production-ready automation framework for MaynDrive that combines UI state discovery, LLM supervision, and adaptive learning to achieve reliable interaction goals.

## 🎯 Overview

This system implements the comprehensive plan for LLM-driven, state-aware MaynDrive automation using:
- **GLM-4.6** via Z.ai API for intelligent UI state analysis
- **ADB Tools** for deterministic device interaction
- **GPS Sidecar** integration for location services
- **State Graph** built from existing discovery data
- **Learning System** for continuous improvement
- **Orchestration Loop** that coordinates all components

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Main Orchestration Loop                 │
├─────────────────────────────────────────────────────────────┤
│  • UI State Capture (ADB Tools)                      │
│  • LLM Analysis (GLM-4.6 Client)                  │
│  • Action Execution (Action Layer)                    │
│  • GPS Management (GPS Client)                       │
│  • State Tracking (State Graph)                       │
│  • Learning & Adaptation (Learning Manager)              │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Repository Structure

```
orchestrator/
├── runner.py              # Main entry point
├── loop.py                # LLM-supervised orchestration loop
├── schemas.py             # Data contracts and JSON schemas
├── llm_client.py          # GLM-4.6 client via Z.ai API
├── adb_tools.py           # ADB wrapper for UI interaction
├── gps_client.py          # GPS sidecar communication
├── actions.py             # Deterministic action layer
├── state_graph.py         # State graph builder from discovery data
├── learning.py            # Learning and adaptation system
├── storage/               # Session and learning data
│   ├── sessions/          # Per-session logs and snapshots
│   └── learning/          # Persistent learning data
└── docs/ADRs/           # Architecture decision records
```

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Required tools
- Python 3.8+
- Android SDK with ADB
- Docker (for GPS sidecar)
- Z.ai API key for GLM-4.6

# Environment variables
export ZAI_API_KEY="your_zai_api_key_here"
export ZAI_BASE_URL="https://open.bigmodel.cn/api/paas/v4"  # Optional
```

### 2. Device Setup

```bash
# Start Android emulator (emulator-5556 recommended)
emulator -avd autoapp-local -no-window -gpu host

# Verify ADB connection
adb devices

# Ensure MaynDrive app is installed
adb -s emulator-5556 install -r MaynDrive.apk
```

### 3. GPS Sidecar Setup

```bash
# Start GPS sidecar container (if not already running)
docker run -d --name apptest-gpsd \
  -p 8765:8765 \
  your-gpsd-image:latest

# Verify GPS sidecar
curl http://localhost:8765/health
```

### 4. Initialize System

```bash
cd orchestrator

# Initialize environment and check dependencies
python runner.py --init

# Build state graph from discovery data
python runner.py --build-graph

# Check system status
python runner.py --status
```

### 5. Run Automation

```bash
# Unlock a vehicle (most common goal)
python runner.py --goal UNLOCK_VEHICLE

# Login to the app
python runner.py --goal LOGIN --max-steps 30

# Sign up for new account
python runner.py --goal SIGNUP

# Start rental flow
python runner.py --goal RENTAL
```

## 📊 Available Goals

| Goal | Description | Target State |
|------|-------------|---------------|
| `UNLOCK_VEHICLE` | Complete vehicle unlock flow | `UNLOCK` |
| `LOGIN` | Login to existing account | `MAIN_MAP_LOGGED_IN` |
| `SIGNUP` | Create new account | `MAIN_MAP_LOGGED_IN` |
| `RENTAL` | Start vehicle rental process | `UNLOCK` |
| `MAP_ACCESS` | Access main map (logged out) | `MAIN_MAP_LOGGED_OUT` |

## 🔄 Learning System

The system continuously learns from each automation session:

### Session Learning
- UI state patterns discovered during execution
- Transition success/failure rates
- Action execution metrics (timing, retries)
- Route performance analysis

### Persistent Learning
- `storage/learning/transition_metrics.json` - Transition performance
- `storage/learning/learned_patterns.json` - UI state detection patterns
- `storage/learning/route_success_rates.json` - Route success metrics
- `storage/learning/failed_patterns.json` - Failed pattern analysis

### Merge Learning Data

```bash
# Merge all session learning into persistent storage
python runner.py --merge-learning

# View learning report (auto-generated)
ls storage/learning/learning_report_*.json
```

## 🎛️ Configuration

### Device Configuration
```bash
# Custom device ID
python runner.py --goal UNLOCK_VEHICLE --device emulator-5554

# Maximum steps (default: 50)
python runner.py --goal LOGIN --max-steps 100

# Custom session directory
python runner.py --goal UNLOCK_VEHICLE --session-dir custom_session
```

### Advanced Options
```bash
# Verbose logging
python runner.py --goal UNLOCK_VEHICLE --verbose

# Check system status only
python runner.py --status

# Rebuild state graph from discovery data
python runner.py --build-graph
```

## 📈 State Graph

The system builds a comprehensive state graph from your existing XML discovery data:

### Core States
- `CLEAN` - Fresh app launch
- `MAIN_MAP_LOGGED_OUT` - Map view, not logged in
- `LOGIN_FORM` - Login screen
- `MAIN_MAP_LOGGED_IN` - Map view, logged in
- `QR_SCANNER` - QR code scanning
- `SELECT_VEHICLE` - Vehicle selection
- `UNLOCK` - Vehicle unlock screen
- `SAFETY_RULES` - Safety instructions
- `NAVIGATION_MENU` - App menu
- `MY_ACCOUNT` - Account management
- `ERROR_DIALOG` - Error handling

### Routes
- `CLEAN_TO_UNLOCK` - Full vehicle unlock flow
- `CLEAN_TO_MAP` - Access main map
- `SIGNUP_FLOW` - New user registration
- `RENTAL_FLOW` - Vehicle rental process

## 📝 Session Data

Each automation session creates detailed documentation:

```
storage/sessions/<session_id>/
├── session_info.json      # Session metadata
├── session_summary.json   # Final results
├── step_0000.json       # Step-by-step actions
├── step_0001.json
├── snapshot_0000.xml     # UI state dumps
├── snapshot_0000.png     # Screenshots
└── ...
```

## 🔧 Components

### ADB Tools (`adb_tools.py`)
- UI XML dumping and parsing
- Screenshot capture
- Device info detection
- Element finding by text/ID/XPath
- UI stability waiting

### GPS Client (`gps_client.py`)
- GPS sidecar health monitoring
- Location setting and verification
- Mock location management
- Continuous updates coordination

### LLM Client (`llm_client.py`)
- GLM-4.6 API communication
- UI state analysis requests
- JSON response validation
- Error handling and retries
- Response repair mechanisms

### Action Layer (`actions.py`)
- Deterministic action execution
- Coordinate scaling for device density
- Retry logic with jitter
- Multi-action support (tap, text, swipe, etc.)
- Safety mechanisms

### Learning Manager (`learning.py`)
- Transition metrics tracking
- Pattern recognition and storage
- Route success rate analysis
- Failed pattern detection
- Performance optimization

## 🐛 Troubleshooting

### Common Issues

**Device Not Connected**
```bash
# Check ADB
adb devices
# Restart ADB server
adb kill-server && adb start-server
# Restart emulator
```

**GPS Sidecar Not Responding**
```bash
# Check container
docker ps | grep apptest-gpsd
# Restart sidecar
docker restart apptest-gpsd
# Verify health
curl http://localhost:8765/health
```

**LLM API Connection Failed**
```bash
# Check API key
echo $ZAI_API_KEY
# Test connection manually
curl -H "Authorization: Bearer $ZAI_API_KEY" \
  https://open.bigmodel.cn/api/paas/v4/chat/completions
```

**State Graph Missing**
```bash
# Rebuild from discovery data
python runner.py --build-graph
# Verify XML files exist
ls ../*.xml | wc -l
```

### Debug Mode

```bash
# Enable verbose logging
python runner.py --goal UNLOCK_VEHICLE --verbose

# Check individual components
python -c "from adb_tools import ADBTools; print(ADBTools().is_device_connected())"
python -c "from gps_client import GPSClient; print(GPSClient().health_check())"
python -c "from llm_client import GLMClient; print(GLMClient().test_connection())"
```

## 📊 Performance Metrics

The system tracks comprehensive performance metrics:

### Success Rates
- Goal achievement rate per goal type
- Route success rates
- Transition success rates
- Action execution success

### Timing Metrics
- Average step execution time
- Total session duration
- UI stability wait times
- LLM response times

### Learning Metrics
- Pattern discovery rate
- Confidence score improvements
- Failed pattern reduction
- Route optimization gains

## 🔒 Security & Safety

### Non-Invasive Approach
- No app signature modification
- No APK resigning required
- Uses standard ADB commands only
- Frida for observability only (when needed)

### Data Privacy
- All data stored locally
- No external data transmission
- Session data isolated per run
- API key stored as environment variable

### Error Handling
- Comprehensive exception handling
- Graceful degradation on failures
- Safe fallback mechanisms
- Detailed error logging

## 🤝 Contributing

### Adding New Goals

1. Define goal in `runner.py` argument parser
2. Add target states in `loop.py` `_check_goal_completion()`
3. Update route mapping in `loop.py` `_get_current_route()`
4. Test with various starting states

### Extending State Patterns

1. Add XML filename mapping in `state_graph.py`
2. Define detection patterns with XPath
3. Add logical transitions in `_define_logical_transitions()`
4. Update route definitions in `_create_routes()`

### Improving LLM Prompts

1. Modify system prompt in `llm_client.py`
2. Update JSON schema definitions
3. Add new action types in `schemas.py`
4. Test with various UI states

## 📚 API Reference

### Main Runner Commands

```bash
# Environment setup
python runner.py --init

# System checks
python runner.py --status
python runner.py --build-graph
python runner.py --merge-learning

# Automation execution
python runner.py --goal GOAL [OPTIONS]
```

### Environment Variables

| Variable | Required | Description |
|----------|-----------|-------------|
| `ZAI_API_KEY` | Yes | Z.ai API key for GLM-4.6 |
| `ZAI_BASE_URL` | No | Custom API endpoint (default: official) |

### Exit Codes

- `0` - Success
- `1` - General failure
- `130` - User interruption (Ctrl+C)

## 📄 License

This automation framework is provided for authorized security testing, defensive security, CTF challenges, and educational contexts only.

## 🔗 Links

- [GLM-4.6 Documentation](https://open.bigmodel.cn/)
- [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb)
- [MaynDrive App](https://play.google.com/store/apps/details?id=fr.mayndrive.app)

---

**Built with 🤖 by GLM-4.6 + Z.ai for intelligent UI automation**