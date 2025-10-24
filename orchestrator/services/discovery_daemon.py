#!/usr/bin/env python3
"""
Endless UI Discovery Daemon

Continuously watches the app UI, detects state changes, captures artifacts,
and builds a comprehensive state graph.
"""

import time
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Callable, Tuple
import threading
from dataclasses import dataclass, asdict

from services.state_signature import StateSignature, get_current_activity
from adb_tools import ADBTools

logger = logging.getLogger(__name__)


@dataclass
class StateNode:
    """Represents a discovered UI state"""
    state_id: str
    package: str
    activity: str
    signature: Dict
    xml_path: str
    screenshot_path: str
    first_seen: float
    last_seen: float
    visit_count: int
    entry_action: Optional[Dict] = None  # Action that led to this state
    annotations: List[str] = None  # User annotations

    def to_dict(self):
        return asdict(self)


@dataclass
class StateEdge:
    """Represents a transition between states"""
    from_state: str
    to_state: str
    action: Dict
    success_count: int
    fail_count: int
    avg_latency_ms: float
    first_seen: float
    last_seen: float

    def to_dict(self):
        return asdict(self)


class DiscoveryDaemon:
    """
    Endless UI discovery daemon that builds a complete app state graph
    """

    def __init__(self, device_serial: str, storage_dir: str = "storage/discovery",
                 poll_interval: float = 0.5, debounce_ms: int = 600):
        """
        Args:
            device_serial: ADB device serial
            storage_dir: Where to store discovered states
            poll_interval: How often to check for UI changes (seconds)
            debounce_ms: Wait this long after detecting change before capturing
        """
        self.device_serial = device_serial
        self.storage_dir = Path(storage_dir)
        self.poll_interval = poll_interval
        self.debounce_ms = debounce_ms

        # Core components
        self.adb = ADBTools(device_serial)
        self.signature_engine = StateSignature(similarity_threshold=0.85)

        # State graph
        self.states: Dict[str, StateNode] = {}  # state_id -> StateNode
        self.edges: Dict[Tuple[str, str], StateEdge] = {}  # (from, to) -> StateEdge
        self.current_state_id: Optional[str] = None
        self.last_action: Optional[Dict] = None

        # Control
        self.running = False
        self.paused = False
        self.thread: Optional[threading.Thread] = None

        # Event callbacks
        self.on_state_discovered: Optional[Callable] = None
        self.on_state_changed: Optional[Callable] = None
        self.on_edge_discovered: Optional[Callable] = None

        # Initialize storage
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        (self.storage_dir / "states").mkdir(exist_ok=True)

        # Load existing graph
        self._load_graph()

        logger.info(f"Discovery daemon initialized: {len(self.states)} states loaded")

    def start(self):
        """Start the discovery daemon"""
        if self.running:
            logger.warning("Daemon already running")
            return

        self.running = True
        self.paused = False
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info("Discovery daemon started")

    def pause(self):
        """Pause discovery (observation only, no actions)"""
        self.paused = True
        logger.info("Discovery daemon paused")

    def resume(self):
        """Resume discovery"""
        self.paused = False
        logger.info("Discovery daemon resumed")

    def stop(self):
        """Stop the discovery daemon"""
        if not self.running:
            return

        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self._save_graph()
        logger.info("Discovery daemon stopped")

    def _run_loop(self):
        """Main discovery loop"""
        last_signature = None
        last_change_time = 0

        while self.running:
            try:
                # Check for UI change
                changed, signature = self._check_ui_change(last_signature)

                if changed:
                    last_change_time = time.time()
                    last_signature = signature

                    # Debounce: wait for UI to stabilize
                    time.sleep(self.debounce_ms / 1000.0)

                    # Capture and process
                    self._capture_and_process(signature)

                else:
                    # No change, keep polling
                    time.sleep(self.poll_interval)

            except Exception as e:
                logger.error(f"Discovery loop error: {e}", exc_info=True)
                time.sleep(1)  # Back off on error

    def _check_ui_change(self, last_signature: Optional[Dict]) -> Tuple[bool, Optional[Dict]]:
        """
        Check if UI has changed by comparing quick signature

        Returns:
            (changed, current_signature)
        """
        try:
            # Get current activity
            package, activity = get_current_activity(self.device_serial)

            # Quick check: if activity changed, definitely changed
            if last_signature:
                if (package != last_signature.get("package") or
                    activity != last_signature.get("activity")):
                    return True, {"package": package, "activity": activity}

            # Deeper check: sample UI hierarchy hash
            # For speed, we just check a quick XML dump hash
            xml_path = self.storage_dir / "temp_check.xml"
            self.adb.dump_ui(str(xml_path))

            # Compute quick hash
            import hashlib
            with open(xml_path, 'rb') as f:
                quick_hash = hashlib.md5(f.read()).hexdigest()

            current_sig = {
                "package": package,
                "activity": activity,
                "quick_hash": quick_hash
            }

            # Compare
            if last_signature is None:
                return True, current_sig

            if last_signature.get("quick_hash") != quick_hash:
                return True, current_sig

            return False, current_sig

        except Exception as e:
            logger.warning(f"UI change check failed: {e}")
            return False, last_signature

    def _capture_and_process(self, quick_sig: Dict):
        """Capture full UI state and process it"""
        try:
            timestamp = int(time.time() * 1000)
            package = quick_sig.get("package", "unknown")
            activity = quick_sig.get("activity", "unknown")

            # Create temp paths
            xml_path = self.storage_dir / f"temp_{timestamp}.xml"
            screenshot_path = self.storage_dir / f"temp_{timestamp}.png"

            # Capture artifacts
            self.adb.dump_ui(str(xml_path))
            self.adb.screenshot(str(screenshot_path))

            # Compute full signature
            signature = self.signature_engine.compute_signature(
                str(xml_path),
                str(screenshot_path),
                package,
                activity
            )

            # Check if this is a new state
            state_id, is_new = self._find_or_create_state(
                signature,
                str(xml_path),
                str(screenshot_path),
                package,
                activity
            )

            # Record edge if we have previous state
            if self.current_state_id and self.current_state_id != state_id:
                self._record_edge(
                    self.current_state_id,
                    state_id,
                    self.last_action or {"type": "unknown"}
                )

            # Update current state
            old_state = self.current_state_id
            self.current_state_id = state_id

            # Fire callbacks
            if is_new and self.on_state_discovered:
                self.on_state_discovered(self.states[state_id])

            if old_state != state_id and self.on_state_changed:
                self.on_state_changed(old_state, state_id)

            logger.info(f"State: {state_id} ({'NEW' if is_new else 'KNOWN'}), "
                       f"Package: {package}, Activity: {activity}")

        except Exception as e:
            logger.error(f"Capture and process failed: {e}", exc_info=True)

    def _find_or_create_state(self, signature: Dict, xml_path: str,
                             screenshot_path: str, package: str,
                             activity: str) -> Tuple[str, bool]:
        """
        Find existing state or create new one

        Returns:
            (state_id, is_new)
        """
        # Check if similar state exists
        for state_id, node in self.states.items():
            is_similar, similarity = self.signature_engine.are_similar(
                signature,
                node.signature
            )

            if is_similar:
                # Update existing state
                node.last_seen = time.time()
                node.visit_count += 1
                logger.debug(f"Matched existing state {state_id} (similarity: {similarity:.2f})")
                return state_id, False

        # Create new state
        state_id = signature["hash"]
        timestamp = time.time()

        # Move artifacts to permanent storage
        state_dir = self.storage_dir / "states" / state_id
        state_dir.mkdir(parents=True, exist_ok=True)

        final_xml = state_dir / "window.xml"
        final_screenshot = state_dir / "screenshot.png"

        Path(xml_path).rename(final_xml)
        Path(screenshot_path).rename(final_screenshot)

        # Create state node
        node = StateNode(
            state_id=state_id,
            package=package,
            activity=activity,
            signature=signature,
            xml_path=str(final_xml),
            screenshot_path=str(final_screenshot),
            first_seen=timestamp,
            last_seen=timestamp,
            visit_count=1,
            entry_action=self.last_action,
            annotations=[]
        )

        self.states[state_id] = node

        # Save metadata
        with open(state_dir / "meta.json", 'w') as f:
            json.dump(node.to_dict(), f, indent=2)

        logger.info(f"Created new state: {state_id}")
        return state_id, True

    def _record_edge(self, from_state: str, to_state: str, action: Dict):
        """Record transition between states"""
        edge_key = (from_state, to_state)

        if edge_key in self.edges:
            # Update existing edge
            edge = self.edges[edge_key]
            edge.success_count += 1
            edge.last_seen = time.time()
        else:
            # Create new edge
            edge = StateEdge(
                from_state=from_state,
                to_state=to_state,
                action=action,
                success_count=1,
                fail_count=0,
                avg_latency_ms=0.0,
                first_seen=time.time(),
                last_seen=time.time()
            )
            self.edges[edge_key] = edge

            if self.on_edge_discovered:
                self.on_edge_discovered(edge)

            logger.info(f"New edge: {from_state[:8]} -> {to_state[:8]} via {action.get('type')}")

    def record_action(self, action: Dict):
        """Record action that was just performed (for edge tracking)"""
        self.last_action = action

    def annotate_current_state(self, text: str):
        """Add user annotation to current state"""
        if self.current_state_id and self.current_state_id in self.states:
            node = self.states[self.current_state_id]
            if node.annotations is None:
                node.annotations = []
            node.annotations.append({
                "text": text,
                "timestamp": time.time()
            })
            logger.info(f"Annotated state {self.current_state_id}: {text}")

    def get_state_digest(self, state_id: str) -> Optional[Dict]:
        """Get compact digest of state for LLM"""
        if state_id not in self.states:
            return None

        node = self.states[state_id]
        sig = node.signature

        return {
            "state_id": state_id,
            "package": node.package,
            "activity": node.activity,
            "dominant_texts": sig.get("texts", [])[:10],
            "key_controls": [
                {
                    "id": c.get("resource-id", ""),
                    "text": c.get("text", ""),
                    "desc": c.get("content-desc", ""),
                    "class": c.get("class", "")
                }
                for c in sig.get("controls", [])[:15]
            ],
            "screenshot_path": node.screenshot_path,
            "xml_path": node.xml_path,
            "visit_count": node.visit_count,
            "annotations": node.annotations or []
        }

    def get_coverage_stats(self) -> Dict:
        """Get discovery coverage statistics"""
        if not self.states:
            return {
                "total_states": 0,
                "total_edges": 0,
                "avg_visit_count": 0,
                "new_states_last_hour": 0
            }

        now = time.time()
        hour_ago = now - 3600

        new_last_hour = sum(
            1 for node in self.states.values()
            if node.first_seen >= hour_ago
        )

        avg_visits = sum(n.visit_count for n in self.states.values()) / len(self.states)

        return {
            "total_states": len(self.states),
            "total_edges": len(self.edges),
            "avg_visit_count": round(avg_visits, 1),
            "new_states_last_hour": new_last_hour,
            "current_state": self.current_state_id
        }

    def _save_graph(self):
        """Save state graph to disk"""
        try:
            graph_file = self.storage_dir / "discovery_graph.json"

            graph_data = {
                "states": {sid: node.to_dict() for sid, node in self.states.items()},
                "edges": {
                    f"{edge.from_state}_{edge.to_state}": edge.to_dict()
                    for edge, edge in self.edges.items()
                },
                "metadata": {
                    "total_states": len(self.states),
                    "total_edges": len(self.edges),
                    "last_updated": time.time()
                }
            }

            with open(graph_file, 'w') as f:
                json.dump(graph_data, f, indent=2)

            logger.info(f"Saved graph: {len(self.states)} states, {len(self.edges)} edges")

        except Exception as e:
            logger.error(f"Failed to save graph: {e}")

    def _load_graph(self):
        """Load existing state graph from disk"""
        try:
            graph_file = self.storage_dir / "discovery_graph.json"
            if not graph_file.exists():
                return

            with open(graph_file, 'r') as f:
                graph_data = json.load(f)

            # Load states
            for state_id, state_dict in graph_data.get("states", {}).items():
                self.states[state_id] = StateNode(**state_dict)

            # Load edges
            for edge_key, edge_dict in graph_data.get("edges", {}).items():
                from_state = edge_dict["from_state"]
                to_state = edge_dict["to_state"]
                self.edges[(from_state, to_state)] = StateEdge(**edge_dict)

            logger.info(f"Loaded graph: {len(self.states)} states, {len(self.edges)} edges")

        except Exception as e:
            logger.error(f"Failed to load graph: {e}")

    def is_running(self) -> bool:
        """Check if daemon is currently running"""
        return self.running and not self.paused

    def ensure_running(self):
        """Ensure daemon is running (start if stopped, resume if paused)"""
        if not self.running:
            self.start()
            logger.info("Discovery daemon started by watchdog")
        elif self.paused:
            self.resume()
            logger.info("Discovery daemon resumed by watchdog")

    def ensure_paused(self):
        """Ensure daemon is paused (pause if running)"""
        if self.running and not self.paused:
            self.pause()
            logger.info("Discovery daemon paused by watchdog")
