#!/usr/bin/env python3
"""
WebSocket handler for real-time console updates
"""

import json
import logging
import asyncio
from typing import Set, Dict
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConsoleSocket:
    """Manages WebSocket connections for the operator console"""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected (total: {len(self.active_connections)})")

    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected (total: {len(self.active_connections)})")

    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients"""
        if not self.active_connections:
            return

        message_json = json.dumps(message)
        dead_connections = set()

        for connection in self.active_connections:
            try:
                await connection.send_text(message_json)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket: {e}")
                dead_connections.add(connection)

        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn)

    async def send_discovery_event(self, event_type: str, data: Dict):
        """Send discovery event to clients"""
        await self.broadcast({
            "type": "discovery",
            "event": event_type,
            "data": data,
            "timestamp": data.get("timestamp", 0)
        })

    async def send_automation_event(self, event_type: str, data: Dict):
        """Send automation event to clients"""
        await self.broadcast({
            "type": "automation",
            "event": event_type,
            "data": data
        })

    async def send_llm_commentary(self, commentary: str, reasoning: Dict = None):
        """Send LLM commentary to clients"""
        await self.broadcast({
            "type": "llm_commentary",
            "commentary": commentary,
            "reasoning": reasoning or {}
        })

    async def send_status_update(self, status: Dict):
        """Send general status update"""
        await self.broadcast({
            "type": "status",
            "data": status
        })


# Global socket manager
socket_manager = ConsoleSocket()
