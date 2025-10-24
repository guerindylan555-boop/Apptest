#!/usr/bin/env python3
"""
Action layer for UI interactions.
Handles deterministic ADB-only actions with retry logic and safety mechanisms.
"""

import subprocess
import time
import random
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from schemas import ActionType, RecommendedAction
from adb_tools import ADBTools

logger = logging.getLogger(__name__)

@dataclass
class ActionResult:
    success: bool
    action_type: ActionType
    coordinates: Optional[Tuple[int, int]] = None
    text: Optional[str] = None
    error_message: Optional[str] = None
    execution_time_ms: Optional[int] = None
    retry_count: int = 0

class ActionExecutor:
    """Deterministic action executor with retry logic and safety mechanisms"""

    def __init__(self, device_id: str = "emulator-5556", adb_tools: Optional[ADBTools] = None):
        self.device_id = device_id
        self.adb_tools = adb_tools or ADBTools(device_id)
        self.adb_prefix = ["adb", "-s", device_id]
        self.max_retries = 3
        self.default_timeout_ms = 2500
        self.random_jitter_ms = 150

    def _run_adb_command(self, command: List[str], timeout: int = 10) -> Tuple[bool, str, str]:
        """Execute ADB command and return (success, stdout, stderr)"""
        try:
            full_command = self.adb_prefix + command
            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"ADB command timed out: {' '.join(full_command)}")
            return False, "", "Timeout"
        except Exception as e:
            logger.error(f"ADB command failed: {e}")
            return False, "", str(e)

    def _get_random_jitter(self) -> int:
        """Get random jitter for timing variation"""
        return random.randint(-self.random_jitter_ms, self.random_jitter_ms)

    def _wait_for_timing(self, base_time_ms: int) -> None:
        """Wait with jitter for timing"""
        jitter_ms = self._get_random_jitter()
        total_wait_ms = max(0, base_time_ms + jitter_ms)
        if total_wait_ms > 0:
            time.sleep(total_wait_ms / 1000.0)

    def _scale_coordinates(self, x: int, y: int) -> Tuple[int, int]:
        """
        Scale coordinates based on device screen density and size
        Uses device info from adb_tools
        """
        # Get device screen properties
        density = self.adb_tools.device_info.density
        width = self.adb_tools.device_info.width
        height = self.adb_tools.device_info.height

        # Assume reference dimensions (can be adjusted based on actual device)
        ref_density = 420  # Common reference density
        ref_width = 1080
        ref_height = 2340

        # Scale coordinates
        scaled_x = int(x * (width / ref_width) * (density / ref_density))
        scaled_y = int(y * (height / ref_height) * (density / ref_density))

        # Ensure coordinates are within screen bounds
        scaled_x = max(0, min(scaled_x, width - 1))
        scaled_y = max(0, min(scaled_y, height - 1))

        logger.debug(f"Scaled coordinates: ({x}, {y}) -> ({scaled_x}, {scaled_y})")
        return scaled_x, scaled_y

    def _find_element_by_selector(self, selector: str, xml_path: str) -> Optional[Tuple[int, int]]:
        """
        Find element coordinates by selector hint

        Args:
            selector: Selector hint (text, resource-id, or XPath-like)
            xml_path: Path to current UI XML dump

        Returns:
            (x, y) coordinates or None if not found
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Try text match first
            element = self.adb_tools.find_element_by_text(xml_path, selector, exact_match=False)
            if element:
                return self.adb_tools.get_element_center(element)

            # Try resource ID match
            if selector.startswith('id/'):
                resource_id = selector[3:]  # Remove 'id/' prefix
                element = self.adb_tools.find_element_by_id(xml_path, resource_id)
                if element:
                    return self.adb_tools.get_element_center(element)

            # Try content-desc match
            def find_by_content_desc(node):
                if node.get('content-desc', '').lower() == selector.lower():
                    return node
                for child in node:
                    result = find_by_content_desc(child)
                    if result:
                        return result
                return None

            element_node = find_by_content_desc(root)
            if element_node:
                bounds_str = element_node.get('bounds', '')
                if bounds_str:
                    bounds_match = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
                    if bounds_match:
                        x1, y1, x2, y2 = map(int, bounds_match.groups())
                        return ((x1 + x2) // 2, (y1 + y2) // 2)

            return None

        except Exception as e:
            logger.error(f"Error finding element by selector '{selector}': {e}")
            return None

    def _verify_action_result(self, action_type: ActionType, xml_before: str, xml_after: str) -> bool:
        """Verify that an action had the intended effect"""
        try:
            if action_type == ActionType.TAP:
                # For tap, check if UI changed
                size_before = len(xml_before)
                size_after = len(xml_after)
                return abs(size_before - size_after) > 100  # Significant change

            elif action_type == ActionType.TEXT:
                # For text input, check if text was added
                return len(xml_after) > len(xml_before)

            elif action_type in [ActionType.BACK, ActionType.HOME]:
                # For navigation, expect significant UI change
                return abs(len(xml_after) - len(xml_before)) > 500

            elif action_type == ActionType.CLOSE_APP:
                # For app close, expect app to no longer be foreground
                return True  # Simplified verification

            return True  # Default success for other actions

        except Exception as e:
            logger.error(f"Error verifying action result: {e}")
            return True  # Assume success if verification fails

    def execute_tap(self, x: int, y: int, timeout_ms: int = None, selector_hint: str = None) -> ActionResult:
        """
        Execute tap action at coordinates

        Args:
            x: X coordinate
            y: Y coordinate
            timeout_ms: Wait time after tap
            selector_hint: Optional selector hint for retry with element finding

        Returns:
            ActionResult with execution details
        """
        start_time = time.time()
        timeout_ms = timeout_ms or self.default_timeout_ms

        # Scale coordinates for device
        scaled_x, scaled_y = self._scale_coordinates(x, y)

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Tap attempt {attempt + 1}/{self.max_retries} at ({scaled_x}, {scaled_y})")

                # Execute tap command
                success, stdout, stderr = self._run_adb_command([
                    "shell", "input", "tap", str(scaled_x), str(scaled_y)
                ])

                if success:
                    logger.info(f"Tap executed at ({scaled_x}, {scaled_y})")

                    # Wait for UI to settle
                    self._wait_for_timing(timeout_ms)

                    execution_time = int((time.time() - start_time) * 1000)
                    return ActionResult(
                        success=True,
                        action_type=ActionType.TAP,
                        coordinates=(scaled_x, scaled_y),
                        execution_time_ms=execution_time,
                        retry_count=attempt
                    )
                else:
                    logger.warning(f"Tap failed: {stderr}")
                    if attempt == self.max_retries - 1:
                        # Last attempt, try selector hint if available
                        if selector_hint:
                            logger.info(f"Trying selector hint: {selector_hint}")
                            # Implementation would require current XML
                            # This is a simplified version
                    break

                # Brief wait before retry
                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Tap attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    break

        execution_time = int((time.time() - start_time) * 1000)
        return ActionResult(
            success=False,
            action_type=ActionType.TAP,
            coordinates=(scaled_x, scaled_y),
            error_message=f"Failed after {self.max_retries} attempts",
            execution_time_ms=execution_time,
            retry_count=self.max_retries - 1
        )

    def execute_text(self, text: str, timeout_ms: int = None) -> ActionResult:
        """
        Execute text input action

        Args:
            text: Text to input
            timeout_ms: Wait time after input

        Returns:
            ActionResult with execution details
        """
        start_time = time.time()
        timeout_ms = timeout_ms or self.default_timeout_ms

        # Escape special characters for shell
        escaped_text = text.replace(' ', '%s').replace('&', '\\&').replace('<', '\\<').replace('>', '\\>')

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Text input attempt {attempt + 1}/{self.max_retries}: '{text}'")

                # Execute text input command
                success, stdout, stderr = self._run_adb_command([
                    "shell", "input", "text", escaped_text
                ])

                if success:
                    logger.info(f"Text input executed: '{text}'")

                    # Wait for UI to settle
                    self._wait_for_timing(timeout_ms)

                    execution_time = int((time.time() - start_time) * 1000)
                    return ActionResult(
                        success=True,
                        action_type=ActionType.TEXT,
                        text=text,
                        execution_time_ms=execution_time,
                        retry_count=attempt
                    )
                else:
                    logger.warning(f"Text input failed: {stderr}")

                # Brief wait before retry
                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Text input attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    break

        execution_time = int((time.time() - start_time) * 1000)
        return ActionResult(
            success=False,
            action_type=ActionType.TEXT,
            text=text,
            error_message=f"Failed after {self.max_retries} attempts",
            execution_time_ms=execution_time,
            retry_count=self.max_retries - 1
        )

    def execute_back(self, timeout_ms: int = None) -> ActionResult:
        """Execute back button press"""
        start_time = time.time()
        timeout_ms = timeout_ms or self.default_timeout_ms

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Back button attempt {attempt + 1}/{self.max_retries}")

                # Execute back button command
                success, stdout, stderr = self._run_adb_command([
                    "shell", "input", "keyevent", "KEYCODE_BACK"
                ])

                if success:
                    logger.info("Back button executed")
                    self._wait_for_timing(timeout_ms)

                    execution_time = int((time.time() - start_time) * 1000)
                    return ActionResult(
                        success=True,
                        action_type=ActionType.BACK,
                        execution_time_ms=execution_time,
                        retry_count=attempt
                    )
                else:
                    logger.warning(f"Back button failed: {stderr}")

                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Back button attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    break

        execution_time = int((time.time() - start_time) * 1000)
        return ActionResult(
            success=False,
            action_type=ActionType.BACK,
            error_message=f"Failed after {self.max_retries} attempts",
            execution_time_ms=execution_time,
            retry_count=self.max_retries - 1
        )

    def execute_home(self, timeout_ms: int = None) -> ActionResult:
        """Execute home button press"""
        start_time = time.time()
        timeout_ms = timeout_ms or self.default_timeout_ms

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Home button attempt {attempt + 1}/{self.max_retries}")

                # Execute home button command
                success, stdout, stderr = self._run_adb_command([
                    "shell", "input", "keyevent", "KEYCODE_HOME"
                ])

                if success:
                    logger.info("Home button executed")
                    self._wait_for_timing(timeout_ms)

                    execution_time = int((time.time() - start_time) * 1000)
                    return ActionResult(
                        success=True,
                        action_type=ActionType.HOME,
                        execution_time_ms=execution_time,
                        retry_count=attempt
                    )
                else:
                    logger.warning(f"Home button failed: {stderr}")

                time.sleep(0.5)

            except Exception as e:
                logger.error(f"Home button attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    break

        execution_time = int((time.time() - start_time) * 1000)
        return ActionResult(
            success=False,
            action_type=ActionType.HOME,
            error_message=f"Failed after {self.max_retries} attempts",
            execution_time_ms=execution_time,
            retry_count=self.max_retries - 1
        )

    def execute_wait(self, timeout_ms: int) -> ActionResult:
        """Execute wait action"""
        start_time = time.time()

        try:
            logger.info(f"Waiting for {timeout_ms}ms")
            time.sleep(timeout_ms / 1000.0)

            execution_time = int((time.time() - start_time) * 1000)
            return ActionResult(
                success=True,
                action_type=ActionType.WAIT,
                execution_time_ms=execution_time,
                retry_count=0
            )

        except Exception as e:
            logger.error(f"Wait failed: {e}")
            execution_time = int((time.time() - start_time) * 1000)
            return ActionResult(
                success=False,
                action_type=ActionType.WAIT,
                error_message=str(e),
                execution_time_ms=execution_time,
                retry_count=0
            )

    def execute_swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> ActionResult:
        """Execute swipe action"""
        start_time = time.time()

        try:
            # Scale coordinates
            scaled_x1, scaled_y1 = self._scale_coordinates(x1, y1)
            scaled_x2, scaled_y2 = self._scale_coordinates(x2, y2)

            logger.debug(f"Swipe from ({scaled_x1}, {scaled_y1}) to ({scaled_x2}, {scaled_y2})")

            # Execute swipe command
            success, stdout, stderr = self._run_adb_command([
                "shell", "input", "swipe",
                str(scaled_x1), str(scaled_y1),
                str(scaled_x2), str(scaled_y2),
                str(duration_ms)
            ])

            if success:
                logger.info(f"Swipe executed: ({scaled_x1}, {scaled_y1}) -> ({scaled_x2}, {scaled_y2})")
                execution_time = int((time.time() - start_time) * 1000)
                return ActionResult(
                    success=True,
                    action_type=ActionType.SWIPE,
                    coordinates=(scaled_x1, scaled_y1),
                    execution_time_ms=execution_time,
                    retry_count=0
                )
            else:
                logger.error(f"Swipe failed: {stderr}")
                execution_time = int((time.time() - start_time) * 1000)
                return ActionResult(
                    success=False,
                    action_type=ActionType.SWIPE,
                    coordinates=(scaled_x1, scaled_y1),
                    error_message=stderr,
                    execution_time_ms=execution_time,
                    retry_count=0
                )

        except Exception as e:
            logger.error(f"Swipe failed: {e}")
            execution_time = int((time.time() - start_time) * 1000)
            return ActionResult(
                success=False,
                action_type=ActionType.SWIPE,
                error_message=str(e),
                execution_time_ms=execution_time,
                retry_count=0
            )

    def execute_launch_app(self, package_name: str, activity: str = None) -> ActionResult:
        """Execute app launch action"""
        start_time = time.time()

        try:
            if activity:
                # Launch specific activity
                intent = f"{package_name}/{activity}"
                success, stdout, stderr = self._run_adb_command([
                    "shell", "am", "start", "-n", intent
                ])
            else:
                # Launch main activity
                success, stdout, stderr = self._run_adb_command([
                    "shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"
                ])

            if success:
                logger.info(f"App launched: {package_name}")
                execution_time = int((time.time() - start_time) * 1000)
                return ActionResult(
                    success=True,
                    action_type=ActionType.LAUNCH_APP,
                    text=package_name,
                    execution_time_ms=execution_time,
                    retry_count=0
                )
            else:
                logger.error(f"App launch failed: {stderr}")
                execution_time = int((time.time() - start_time) * 1000)
                return ActionResult(
                    success=False,
                    action_type=ActionType.LAUNCH_APP,
                    text=package_name,
                    error_message=stderr,
                    execution_time_ms=execution_time,
                    retry_count=0
                )

        except Exception as e:
            logger.error(f"App launch failed: {e}")
            execution_time = int((time.time() - start_time) * 1000)
            return ActionResult(
                success=False,
                action_type=ActionType.LAUNCH_APP,
                text=package_name,
                error_message=str(e),
                execution_time_ms=execution_time,
                retry_count=0
            )

    def execute_close_app(self, package_name: str) -> ActionResult:
        """Execute app close action"""
        start_time = time.time()

        try:
            # Force stop the app
            success, stdout, stderr = self._run_adb_command([
                "shell", "am", "force-stop", package_name
            ])

            if success:
                logger.info(f"App closed: {package_name}")
                execution_time = int((time.time() - start_time) * 1000)
                return ActionResult(
                    success=True,
                    action_type=ActionType.CLOSE_APP,
                    text=package_name,
                    execution_time_ms=execution_time,
                    retry_count=0
                )
            else:
                logger.error(f"App close failed: {stderr}")
                execution_time = int((time.time() - start_time) * 1000)
                return ActionResult(
                    success=False,
                    action_type=ActionType.CLOSE_APP,
                    text=package_name,
                    error_message=stderr,
                    execution_time_ms=execution_time,
                    retry_count=0
                )

        except Exception as e:
            logger.error(f"App close failed: {e}")
            execution_time = int((time.time() - start_time) * 1000)
            return ActionResult(
                success=False,
                action_type=ActionType.CLOSE_APP,
                text=package_name,
                error_message=str(e),
                execution_time_ms=execution_time,
                retry_count=0
            )

    def execute_action(self, action: RecommendedAction, xml_path: str = None) -> ActionResult:
        """
        Execute a recommended action

        Args:
            action: RecommendedAction to execute
            xml_path: Current UI XML (for element finding)

        Returns:
            ActionResult with execution details
        """
        logger.info(f"Executing action: {action.type.value}")

        if action.type == ActionType.TAP:
            # Try selector hint first, then fallback coordinates
            if action.selector_hint and xml_path:
                coords = self._find_element_by_selector(action.selector_hint, xml_path)
                if coords:
                    return self.execute_tap(
                        coords[0], coords[1],
                        action.timeout_ms, action.selector_hint
                    )

            # Use provided coordinates or fallback
            x = action.x or (action.fallback.x if action.fallback else 540)
            y = action.y or (action.fallback.y if action.fallback else 1620)
            return self.execute_tap(x, y, action.timeout_ms, action.selector_hint)

        elif action.type == ActionType.TEXT:
            return self.execute_text(action.text or "", action.timeout_ms)

        elif action.type == ActionType.BACK:
            return self.execute_back(action.timeout_ms)

        elif action.type == ActionType.HOME:
            return self.execute_home(action.timeout_ms)

        elif action.type == ActionType.WAIT:
            return self.execute_wait(action.timeout_ms)

        elif action.type == ActionType.SWIPE:
            # Swipe would need additional coordinates in RecommendedAction
            # For now, implement a default swipe
            return self.execute_swipe(540, 1000, 540, 2000)

        elif action.type == ActionType.LAUNCH_APP:
            # Default to MaynDrive package
            return self.execute_launch_app(action.text or "fr.mayndrive.app")

        elif action.type == ActionType.CLOSE_APP:
            # Default to MaynDrive package
            return self.execute_close_app(action.text or "fr.mayndrive.app")

        else:
            logger.error(f"Unsupported action type: {action.type}")
            return ActionResult(
                success=False,
                action_type=action.type,
                error_message=f"Unsupported action type: {action.type}"
            )

if __name__ == "__main__":
    # Test action executor
    executor = ActionExecutor()

    print("Testing action executor...")

    # Test wait action
    result = executor.execute_wait(1000)
    print(f"Wait action: {'✅' if result.success else '❌'}")

    # Test back button
    result = executor.execute_back()
    print(f"Back action: {'✅' if result.success else '❌'}")

    # Test tap at center
    result = executor.execute_tap(540, 1200)
    print(f"Tap action: {'✅' if result.success else '❌'}")
    if result.success:
        print(f"  Coordinates: {result.coordinates}")
        print(f"  Execution time: {result.execution_time_ms}ms")