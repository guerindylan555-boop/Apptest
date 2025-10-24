#!/usr/bin/env python3
"""
Main LLM-supervised orchestration loop.
Coordinates all components for automated UI interaction with GLM-4.6 supervision.
"""

import os
import sys
import json
import time
import uuid
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from schemas import (
    UISnapshot, LLMSupervisorRequest, LLMSupervisorResponse,
    HistoryEntry, UIAnalysis, SessionInfo, ActionType
)
from adb_tools import ADBTools
from gps_client import GPSClient
from llm_client import GLMClient
from actions import ActionExecutor
from state_graph import StateGraphBuilder

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OrchestrationLoop:
    """Main LLM-supervised orchestration loop"""

    def __init__(self, device_id: str = "emulator-5556", session_dir: Optional[str] = None):
        self.device_id = device_id

        # Initialize session directory
        if session_dir is None:
            self.session_dir = f"storage/sessions/{uuid.uuid4().hex[:8]}"
        else:
            self.session_dir = session_dir

        Path(self.session_dir).mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.adb_tools = ADBTools(device_id)
        self.gps_client = GPSClient()
        self.llm_client = GLMClient()
        self.action_executor = ActionExecutor(device_id, self.adb_tools)
        self.state_graph_builder = StateGraphBuilder()

        # State management
        self.session_info: Optional[SessionInfo] = None
        self.current_state: Optional[str] = None
        self.history: List[HistoryEntry] = []
        self.step_count = 0
        self.max_steps = 50

        # Load state graph
        self.state_graph = self._load_state_graph()
        self.routes = self._load_routes()

        logger.info(f"Initialized orchestration loop for device: {device_id}")
        logger.info(f"Session directory: {self.session_dir}")

    def _load_state_graph(self) -> Dict[str, Any]:
        """Load state graph from file or build from discovery data"""
        graph_file = "state_graph.json"

        if os.path.exists(graph_file):
            try:
                if self.state_graph_builder.load_graph(graph_file):
                    graph = self.state_graph_builder.build_state_graph()
                    logger.info(f"Loaded existing state graph with {len(graph['states'])} states")
                    return graph
            except Exception as e:
                logger.error(f"Failed to load state graph: {e}")

        # Build new graph from discovery data
        logger.info("Building new state graph from discovery data...")
        return self.state_graph_builder.build_state_graph()

    def _load_routes(self) -> Dict[str, List[str]]:
        """Load routes from file or use defaults"""
        routes_file = "state_graph_routes.json"

        if os.path.exists(routes_file):
            try:
                with open(routes_file, 'r', encoding='utf-8') as f:
                    routes = json.load(f)
                logger.info(f"Loaded {len(routes)} routes")
                return routes
            except Exception as e:
                logger.error(f"Failed to load routes: {e}")

        # Use default routes from state graph builder
        return self.state_graph_builder.routes

    def _start_session(self, goal: str) -> bool:
        """Initialize session for automation goal"""
        try:
            self.session_info = SessionInfo(
                session_id=uuid.uuid4().hex[:8],
                start_time=time.time(),
                goal=goal,
                device=self.device_id,
                status="running"
            )

            self.step_count = 0
            self.history.clear()
            self.current_state = None

            # Save session info
            session_file = os.path.join(self.session_dir, "session_info.json")
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(self.session_info.model_dump(), f, indent=2, ensure_ascii=False)

            logger.info(f"Started session {self.session_info.session_id} for goal: {goal}")
            return True

        except Exception as e:
            logger.error(f"Failed to start session: {e}")
            return False

    def _create_ui_snapshot(self) -> Optional[UISnapshot]:
        """Create UI snapshot and return UISnapshot object"""
        try:
            snapshot_data = self.adb_tools.create_ui_snapshot(self.session_dir, self.step_count)

            snapshot = UISnapshot(
                timestamp=snapshot_data['timestamp'],
                device=snapshot_data['device'],
                xml_path=snapshot_data['xml_path'],
                screenshot_path=snapshot_data['screenshot_path'],
                window=snapshot_data['window']
            )

            return snapshot

        except Exception as e:
            logger.error(f"Failed to create UI snapshot: {e}")
            return None

    def _create_llm_request(self, snapshot: UISnapshot, expected_state: Optional[str] = None) -> LLMSupervisorRequest:
        """Create LLM supervisor request from UI snapshot"""

        # Parse UI XML for analysis
        ui_data = self.adb_tools.parse_ui_xml(snapshot.xml_path)

        ui_analysis = UIAnalysis(
            xml=ui_data['xml'],
            screenshot_path=snapshot.screenshot_path,
            detected_elements=ui_data['all_elements'],
            interactive_elements=ui_data['interactive_elements'],
            text_elements=ui_data['text_elements']
        )

        # Determine current goal and route
        goal = self.session_info.goal if self.session_info else "UNKNOWN"
        current_route = self._get_current_route(goal)

        request = LLMSupervisorRequest(
            goal=goal,
            expected_state=expected_state,
            candidate_state=self.current_state,
            history=self.history[-5:],  # Last 5 actions
            ui=ui_analysis,
            state_graph=self.state_graph,
            routes=current_route,
            current_step=self.step_count,
            max_steps=self.max_steps
        )

        return request

    def _get_current_route(self, goal: str) -> Dict[str, Any]:
        """Get current route based on goal"""
        route_mapping = {
            'UNLOCK_VEHICLE': 'CLEAN_TO_UNLOCK',
            'LOGIN': 'CLEAN_TO_MAP',
            'SIGNUP': 'SIGNUP_FLOW',
            'RENTAL': 'RENTAL_FLOW'
        }

        route_key = route_mapping.get(goal.upper(), 'CLEAN_TO_UNLOCK')

        if route_key in self.routes:
            return {'current_route': self.routes[route_key], 'route_name': route_key}
        else:
            return {'current_route': [], 'route_name': 'unknown'}

    def _execute_action(self, action) -> bool:
        """Execute recommended action and update history"""
        try:
            from schemas import RecommendedAction

            # Convert action to RecommendedAction if needed
            if not isinstance(action, RecommendedAction):
                # Create RecommendedAction from dict or other format
                if isinstance(action, dict):
                    action = RecommendedAction(**action)
                else:
                    logger.error(f"Invalid action format: {type(action)}")
                    return False

            logger.info(f"Executing action: {action.type.value}")

            # Execute action via action executor
            result = self.action_executor.execute_action(action, self._get_latest_xml_path())

            # Add to history
            history_entry = HistoryEntry(
                state=self.current_state or "UNKNOWN",
                action=action.type,
                success=result.success,
                confidence=action.confidence,
                timestamp=time.time(),
                notes=f"Action: {action.type.value}, Success: {result.success}"
            )

            self.history.append(history_entry)

            # Save history step
            self._save_history_step(result, action)

            return result.success

        except Exception as e:
            logger.error(f"Failed to execute action: {e}")
            return False

    def _get_latest_xml_path(self) -> Optional[str]:
        """Get path to most recent XML dump"""
        try:
            xml_files = list(Path(self.session_dir).glob("snapshot_*.xml"))
            if xml_files:
                latest_xml = max(xml_files, key=os.path.getctime)
                return str(latest_xml)
        except Exception:
            pass
        return None

    def _save_history_step(self, result, action):
        """Save detailed history step information"""
        try:
            step_data = {
                'step': self.step_count,
                'timestamp': time.time(),
                'current_state': self.current_state,
                'action': {
                    'type': action.type.value if hasattr(action, 'type') else str(action),
                    'coordinates': (action.x, action.y) if hasattr(action, 'x') and action.x else None,
                    'text': action.text if hasattr(action, 'text') else None,
                    'confidence': action.confidence if hasattr(action, 'confidence') else 1.0
                },
                'result': {
                    'success': result.success,
                    'execution_time_ms': result.execution_time_ms,
                    'retry_count': result.retry_count,
                    'error_message': result.error_message
                }
            }

            step_file = os.path.join(self.session_dir, f"step_{self.step_count:04d}.json")
            with open(step_file, 'w', encoding='utf-8') as f:
                json.dump(step_data, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Failed to save history step: {e}")

    def _update_session_state(self, llm_response: LLMSupervisorResponse):
        """Update current state based on LLM analysis"""
        self.current_state = llm_response.analysis.detected_state

        # Update learning
        if llm_response.learning:
            self.session_info.learning_updates.append(llm_response.learning)

        logger.info(f"Updated current state to: {self.current_state}")
        logger.info(f"State confidence: {llm_response.analysis.confidence:.2f}")

    def _check_goal_completion(self, goal: str) -> bool:
        """Check if the goal has been achieved"""
        goal_states = {
            'UNLOCK_VEHICLE': ['UNLOCK'],
            'LOGIN': ['MAIN_MAP_LOGGED_IN'],
            'SIGNUP': ['MAIN_MAP_LOGGED_IN'],
            'RENTAL': ['UNLOCK', 'MAIN_MAP_LOGGED_IN'],
            'MAP_ACCESS': ['MAIN_MAP_LOGGED_OUT', 'MAIN_MAP_LOGGED_IN']
        }

        target_states = goal_states.get(goal.upper(), [])
        return self.current_state in target_states

    def _save_session_summary(self):
        """Save final session summary"""
        try:
            summary = {
                'session_info': self.session_info.model_dump() if self.session_info else {},
                'final_state': self.current_state,
                'total_steps': self.step_count,
                'history_count': len(self.history),
                'goal_achieved': self._check_goal_completion(self.session_info.goal) if self.session_info else False,
                'completion_time': time.time()
            }

            summary_file = os.path.join(self.session_dir, "session_summary.json")
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

            logger.info(f"Session summary saved to: {summary_file}")

        except Exception as e:
            logger.error(f"Failed to save session summary: {e}")

    def run_automation(self, goal: str, max_steps: int = 50) -> bool:
        """
        Run complete automation loop for specified goal

        Args:
            goal: Automation goal (e.g., 'UNLOCK_VEHICLE', 'LOGIN')
            max_steps: Maximum number of steps to attempt

        Returns:
            True if goal achieved, False otherwise
        """
        logger.info(f"Starting automation loop for goal: {goal}")

        # Start session
        if not self._start_session(goal):
            logger.error("Failed to start session")
            return False

        self.max_steps = max_steps

        try:
            # Initialize GPS
            if not self.gps_client.ensure_maps_ready():
                logger.warning("GPS not ready, continuing anyway...")

            # Launch MaynDrive app if needed
            if not self.adb_tools.is_device_connected():
                logger.error("Device not connected")
                return False

            # Main automation loop
            while self.step_count < self.max_steps:
                self.step_count += 1
                logger.info(f"Step {self.step_count}/{self.max_steps}")

                # Create UI snapshot
                snapshot = self._create_ui_snapshot()
                if not snapshot:
                    logger.error("Failed to create UI snapshot")
                    continue

                # Check if UI is stable
                if not self.adb_tools.wait_for_ui_stable(timeout_ms=1000):
                    logger.warning("UI may not be stable, continuing...")

                # Create LLM request
                llm_request = self._create_llm_request(snapshot)

                # Get LLM recommendation
                try:
                    llm_response = self.llm_client.analyze_ui_state(llm_request)

                    # Update session state
                    self._update_session_state(llm_response)

                    # Check if goal is achieved
                    if self._check_goal_completion(goal):
                        logger.info(f"✅ Goal '{goal}' achieved in {self.step_count} steps!")
                        if self.session_info:
                            self.session_info.status = "completed"
                        break

                    # Execute recommended action
                    action_success = self._execute_action(llm_response.recommendation)

                    if not action_success:
                        logger.warning("Action execution failed, LLM should adapt...")

                    # Wait between steps
                    time.sleep(2.0)

                except Exception as e:
                    logger.error(f"LLM analysis failed: {e}")
                    # Continue with fallback behavior
                    time.sleep(3.0)

                # Update session info
                if self.session_info:
                    self.session_info.steps_completed = self.step_count
                    self.session_info.current_state = self.current_state

            # Final goal check
            goal_achieved = self._check_goal_completion(goal)

            if not goal_achieved and self.step_count >= self.max_steps:
                logger.warning(f"❌ Goal '{goal}' not achieved after {self.max_steps} steps")
                if self.session_info:
                    self.session_info.status = "timeout"

            # Save session summary
            self._save_session_summary()

            return goal_achieved

        except KeyboardInterrupt:
            logger.info("Automation interrupted by user")
            if self.session_info:
                self.session_info.status = "interrupted"
            self._save_session_summary()
            return False

        except Exception as e:
            logger.error(f"Automation failed with error: {e}")
            if self.session_info:
                self.session_info.status = "failed"
            self._save_session_summary()
            return False

def main():
    """Main entry point for orchestration loop"""
    import argparse

    parser = argparse.ArgumentParser(description="LLM-supervised MaynDrive automation")
    parser.add_argument("--goal", default="UNLOCK_VEHICLE",
                       help="Automation goal (UNLOCK_VEHICLE, LOGIN, SIGNUP, RENTAL)")
    parser.add_argument("--device", default="emulator-5556",
                       help="Device ID")
    parser.add_argument("--max-steps", type=int, default=50,
                       help="Maximum number of steps")
    parser.add_argument("--session-dir",
                       help="Session directory path")

    args = parser.parse_args()

    # Create and run orchestration loop
    loop = OrchestrationLoop(args.device, args.session_dir)

    try:
        success = loop.run_automation(args.goal, args.max_steps)

        if success:
            print(f"\n✅ SUCCESS: Goal '{args.goal}' achieved!")
            print(f"📁 Session saved to: {loop.session_dir}")
        else:
            print(f"\n❌ FAILED: Goal '{args.goal}' not achieved")
            print(f"📁 Session data saved to: {loop.session_dir}")

        return 0 if success else 1

    except Exception as e:
        print(f"❌ FATAL ERROR: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())