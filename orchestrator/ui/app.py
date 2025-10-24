#!/usr/bin/env python3
"""
Operator Console Web UI

FastAPI application providing real-time discovery monitoring,
automation control, and LLM interaction.
"""

import os
import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from ui.ws_handler import socket_manager

logger = logging.getLogger(__name__)


# Request models
class DiscoveryCommand(BaseModel):
    action: str  # start, pause, resume, stop


class AnnotationRequest(BaseModel):
    text: str


class AutomationRequest(BaseModel):
    goal: str  # LOGIN, UNLOCK_VEHICLE, RENTAL, etc.
    max_steps: int = 30


# Global state (will be injected)
_discovery_daemon = None
_automation_controller = None


def create_app(discovery_daemon=None, automation_controller=None):
    """Create FastAPI application"""
    global _discovery_daemon, _automation_controller

    app = FastAPI(title="MaynDrive Operator Console")

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Startup: Initialize discovery daemon, watchdog, and logging
    @app.on_event("startup")
    async def startup_event():
        global _discovery_daemon, _automation_controller

        # Import here to avoid circular dependencies
        from services.discovery_daemon import DiscoveryDaemon
        from services.app_watchdog import AppWatchdog

        # Initialize discovery daemon if not provided
        if _discovery_daemon is None:
            _discovery_daemon = DiscoveryDaemon("emulator-5556")
            logger.info("Discovery daemon initialized")

        # Store in app state for access from routes
        app.state.discovery = _discovery_daemon
        app.state.automation = _automation_controller

        # WebSocket log handler - forwards logs to UI in real-time
        class WebSocketLogHandler(logging.Handler):
            def emit(self, record):
                try:
                    msg = self.format(record)
                    asyncio.get_event_loop().call_soon_threadsafe(
                        lambda: asyncio.create_task(
                            socket_manager.broadcast_json({
                                "type": "llm_log",
                                "level": record.levelname,
                                "msg": msg,
                                "logger": record.name
                            })
                        )
                    )
                except Exception:
                    pass

        # Attach handler to relevant loggers
        ws_handler = WebSocketLogHandler()
        ws_handler.setLevel(logging.INFO)
        logging.getLogger("planner").addHandler(ws_handler)
        logging.getLogger("llm").addHandler(ws_handler)
        logging.getLogger("discovery").addHandler(ws_handler)
        logging.getLogger("executor").addHandler(ws_handler)

        logger.info("WebSocket log handler attached")

        # Watchdog: auto-start/pause discovery based on app lifecycle
        def broadcast_sync(data: dict):
            """Thread-safe broadcast wrapper"""
            asyncio.get_event_loop().call_soon_threadsafe(
                lambda: asyncio.create_task(socket_manager.broadcast_json(data))
            )

        def on_app_started():
            """Called when MaynDrive app starts"""
            _discovery_daemon.ensure_running()
            broadcast_sync({
                "type": "discovery_status",
                "running": True,
                "reason": "app_started"
            })
            logger.info("Auto-started discovery: app launched")

        def on_app_stopped():
            """Called when MaynDrive app stops"""
            _discovery_daemon.ensure_paused()
            broadcast_sync({
                "type": "discovery_status",
                "running": False,
                "reason": "app_stopped"
            })
            logger.info("Auto-paused discovery: app closed")

        # Create and start watchdog
        app.state.watchdog = AppWatchdog(
            package="fr.mayndrive.app",
            device_serial="emulator-5556",
            poll_interval=1.0,
            on_started=on_app_started,
            on_stopped=on_app_stopped,
            ws_broadcast=broadcast_sync
        )
        app.state.watchdog.start()
        logger.info("App watchdog started")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown"""
        if hasattr(app.state, "watchdog"):
            app.state.watchdog.stop()
            logger.info("App watchdog stopped")

        if _discovery_daemon:
            _discovery_daemon.stop()
            logger.info("Discovery daemon stopped")

    # Routes
    @app.get("/", response_class=HTMLResponse)
    async def get_console():
        """Serve the operator console UI"""
        html_path = Path(__file__).parent / "console.html"
        if html_path.exists():
            with open(html_path) as f:
                return f.read()
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>MaynDrive Operator Console</title>
            <style>
                body {
                    font-family: monospace;
                    background: #1e1e1e;
                    color: #d4d4d4;
                    margin: 0;
                    padding: 20px;
                }
                .container { max-width: 1400px; margin: 0 auto; }
                .header {
                    background: #252526;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }
                .controls { display: flex; gap: 10px; margin-bottom: 20px; }
                button {
                    background: #0e639c;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 14px;
                }
                button:hover { background: #1177bb; }
                button.danger { background: #d13438; }
                button.danger:hover { background: #e81123; }
                .panels { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
                .panel {
                    background: #252526;
                    padding: 20px;
                    border-radius: 8px;
                    min-height: 400px;
                }
                .panel h2 {
                    margin: 0 0 15px 0;
                    color: #4ec9b0;
                    font-size: 18px;
                }
                .status {
                    background: #1e1e1e;
                    padding: 10px;
                    border-radius: 4px;
                    margin-bottom: 10px;
                    border-left: 3px solid #4ec9b0;
                }
                .event-log {
                    height: 350px;
                    overflow-y: auto;
                    background: #1e1e1e;
                    padding: 10px;
                    border-radius: 4px;
                    font-size: 12px;
                }
                .event {
                    padding: 5px;
                    border-bottom: 1px solid #333;
                    margin-bottom: 5px;
                }
                .event.new { color: #4ec9b0; }
                .event.change { color: #dcdcaa; }
                .event.llm { color: #c586c0; }
                .chat-input {
                    width: 100%;
                    padding: 10px;
                    background: #1e1e1e;
                    border: 1px solid #404040;
                    color: #d4d4d4;
                    border-radius: 4px;
                    margin-top: 10px;
                }
                .annotation-box {
                    width: 100%;
                    min-height: 60px;
                    padding: 10px;
                    background: #1e1e1e;
                    border: 1px solid #404040;
                    color: #d4d4d4;
                    border-radius: 4px;
                    margin-bottom: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🤖 MaynDrive Operator Console</h1>
                    <p>Endless Discovery & LLM-Driven Automation</p>
                </div>

                <div class="controls">
                    <button onclick="startDiscovery()">▶️ Start Discovery</button>
                    <button onclick="pauseDiscovery()">⏸️ Pause</button>
                    <button onclick="stopDiscovery()" class="danger">⏹️ Stop</button>
                    <button onclick="runAutomation('RENTAL')">🚀 Run RENTAL</button>
                    <button onclick="runAutomation('LOGIN')">🔐 Run LOGIN</button>
                </div>

                <div class="panels">
                    <div class="panel">
                        <h2>📊 Discovery Status</h2>
                        <div class="status" id="status">
                            <div>Status: <span id="disc-status">Idle</span></div>
                            <div>States: <span id="state-count">0</span></div>
                            <div>Edges: <span id="edge-count">0</span></div>
                            <div>Current: <span id="current-state">-</span></div>
                        </div>
                        <h3>📝 Annotate Current State</h3>
                        <textarea class="annotation-box" id="annotation-text" placeholder="Add notes about what you see..."></textarea>
                        <button onclick="addAnnotation()">Add Annotation</button>
                    </div>

                    <div class="panel">
                        <h2>🧠 LLM Commentary</h2>
                        <div class="event-log" id="llm-log"></div>
                    </div>

                    <div class="panel">
                        <h2>📡 Live Events</h2>
                        <div class="event-log" id="event-log"></div>
                    </div>

                    <div class="panel">
                        <h2>💬 Chat Commands</h2>
                        <div class="event-log" id="chat-log" style="height: 250px"></div>
                        <input type="text" class="chat-input" id="chat-input" placeholder="Type command (e.g., 'Unlock a vehicle', 'Go to My Account')..." onkeypress="handleChatKey(event)">
                        <button onclick="sendChat()" style="margin-top: 10px; width: 100%">Send Command</button>
                    </div>
                </div>
            </div>

            <script>
                const ws = new WebSocket('ws://localhost:8000/ws');

                ws.onopen = () => {
                    log('Connected to console', 'event-log');
                };

                ws.onmessage = (event) => {
                    const msg = JSON.parse(event.data);
                    handleMessage(msg);
                };

                ws.onerror = (error) => {
                    log('WebSocket error: ' + error, 'event-log');
                };

                function handleMessage(msg) {
                    if (msg.type === 'discovery') {
                        handleDiscoveryEvent(msg);
                    } else if (msg.type === 'automation') {
                        log(`🤖 ${msg.event}: ${JSON.stringify(msg.data)}`, 'event-log', 'change');
                    } else if (msg.type === 'llm_commentary') {
                        log(`🧠 ${msg.commentary}`, 'llm-log', 'llm');
                    } else if (msg.type === 'status') {
                        updateStatus(msg.data);
                    }
                }

                function handleDiscoveryEvent(msg) {
                    if (msg.event === 'state_discovered') {
                        log(`🆕 New state: ${msg.data.state_id}`, 'event-log', 'new');
                    } else if (msg.event === 'state_changed') {
                        log(`🔄 State changed: ${msg.data.from} → ${msg.data.to}`, 'event-log', 'change');
                    }
                }

                function updateStatus(data) {
                    if (data.total_states !== undefined) {
                        document.getElementById('state-count').textContent = data.total_states;
                    }
                    if (data.total_edges !== undefined) {
                        document.getElementById('edge-count').textContent = data.total_edges;
                    }
                    if (data.current_state) {
                        document.getElementById('current-state').textContent = data.current_state.substring(0, 8);
                    }
                }

                function log(message, elementId, className = '') {
                    const logDiv = document.getElementById(elementId);
                    const entry = document.createElement('div');
                    entry.className = 'event ' + className;
                    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
                    logDiv.insertBefore(entry, logDiv.firstChild);

                    // Keep only last 100 entries
                    while (logDiv.children.length > 100) {
                        logDiv.removeChild(logDiv.lastChild);
                    }
                }

                async function startDiscovery() {
                    const res = await fetch('/api/discovery', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'start'})
                    });
                    const data = await res.json();
                    document.getElementById('disc-status').textContent = data.status;
                    log('Discovery started', 'event-log');
                }

                async function pauseDiscovery() {
                    const res = await fetch('/api/discovery', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'pause'})
                    });
                    document.getElementById('disc-status').textContent = 'Paused';
                    log('Discovery paused', 'event-log');
                }

                async function stopDiscovery() {
                    const res = await fetch('/api/discovery', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({action: 'stop'})
                    });
                    document.getElementById('disc-status').textContent = 'Stopped';
                    log('Discovery stopped', 'event-log');
                }

                async function runAutomation(goal) {
                    log(`Starting automation: ${goal}`, 'event-log');
                    const res = await fetch('/api/automation/run', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({goal: goal, max_steps: 30})
                    });
                    const data = await res.json();
                    log(`Automation response: ${data.message}`, 'event-log');
                }

                async function addAnnotation() {
                    const text = document.getElementById('annotation-text').value;
                    if (!text.trim()) return;

                    const res = await fetch('/api/annotate', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({text: text})
                    });

                    document.getElementById('annotation-text').value = '';
                    log(`Annotation added: ${text}`, 'event-log');
                }

                function handleChatKey(event) {
                    if (event.key === 'Enter') {
                        sendChat();
                    }
                }

                async function sendChat() {
                    const input = document.getElementById('chat-input');
                    const text = input.value.trim();
                    if (!text) return;

                    log(`You: ${text}`, 'chat-log');
                    input.value = '';

                    // Send to backend (would be processed by LLM)
                    const res = await fetch('/api/chat', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({message: text})
                    });
                    const data = await res.json();
                    log(`Assistant: ${data.response}`, 'chat-log', 'llm');
                }

                // Request status update every 2 seconds
                setInterval(async () => {
                    try {
                        const res = await fetch('/api/status');
                        const data = await res.json();
                        updateStatus(data);
                    } catch (e) {
                        // Ignore errors
                    }
                }, 2000);
            </script>
        </body>
        </html>
        """

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket endpoint for real-time updates"""
        await socket_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive
                data = await websocket.receive_text()
                # Could handle client messages here if needed
        except WebSocketDisconnect:
            socket_manager.disconnect(websocket)

    @app.post("/api/discovery")
    async def control_discovery(command: DiscoveryCommand):
        """Control discovery daemon"""
        if not _discovery_daemon:
            raise HTTPException(status_code=503, detail="Discovery daemon not available")

        action = command.action
        if action == "start":
            _discovery_daemon.start()
            status = "Running"
        elif action == "pause":
            _discovery_daemon.pause()
            status = "Paused"
        elif action == "resume":
            _discovery_daemon.resume()
            status = "Running"
        elif action == "stop":
            _discovery_daemon.stop()
            status = "Stopped"
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {action}")

        return {"status": status, "action": action}

    @app.post("/api/annotate")
    async def add_annotation(request: AnnotationRequest):
        """Add annotation to current state"""
        if not _discovery_daemon:
            raise HTTPException(status_code=503, detail="Discovery daemon not available")

        _discovery_daemon.annotate_current_state(request.text)
        return {"success": True}

    @app.post("/api/automation/run")
    async def run_automation(request: AutomationRequest):
        """Run automation with a goal"""
        if not _automation_controller:
            raise HTTPException(status_code=503, detail="Automation controller not available")

        # Start automation in background
        asyncio.create_task(_automation_controller.run(request.goal, request.max_steps))

        return {"message": f"Automation started: {request.goal}", "goal": request.goal}

    @app.post("/api/chat")
    async def process_chat(request: dict):
        """Process natural language command"""
        message = request.get("message", "")

        # Simple processing (would use LLM in production)
        response = f"Processing: {message} (LLM integration pending)"

        return {"response": response}

    @app.get("/api/status")
    async def get_status():
        """Get current system status"""
        if _discovery_daemon:
            return _discovery_daemon.get_coverage_stats()
        return {"total_states": 0, "total_edges": 0, "current_state": None}

    @app.get("/control/status")
    async def control_status():
        """Get control panel status (for auto-mode toggle)"""
        return {
            "running": _discovery_daemon.is_running() if _discovery_daemon else False,
            "app_detected": app.state.watchdog.is_app_running if hasattr(app.state, "watchdog") else False,
            "auto_mode": True  # Auto-mode enabled by default
        }

    return app


# For running standalone
if __name__ == "__main__":
    import uvicorn
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)
