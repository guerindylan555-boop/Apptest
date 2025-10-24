#!/usr/bin/env python3
"""
Action Executor

Performs UI actions with selector-first approach (ID/text/xpath) and
coordinate fallback. Handles retries and state validation.
"""

import time
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass

from adb_tools import ADBTools

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Result of executing an action"""
    success: bool
    execution_time_ms: float
    retry_count: int
    error_message: Optional[str] = None
    final_method: Optional[str] = None  # How it was executed (id/text/xpath/coords)


class ActionExecutor:
    """
    Executes UI actions with intelligent selector resolution and fallback
    """

    def __init__(self, device_serial: str, settle_time_ms: int = 500,
                 max_retries: int = 2):
        """
        Args:
            device_serial: ADB device serial
            settle_time_ms: Wait this long after action for UI to settle
            max_retries: Number of retry attempts on failure
        """
        self.device_serial = device_serial
        self.settle_time_ms = settle_time_ms
        self.max_retries = max_retries

        self.adb = ADBTools(device_serial)

    def execute(self, action: Dict, ui_xml_path: Optional[str] = None) -> ActionResult:
        """
        Execute an action

        Action dict format:
        {
            "type": "tap" | "text" | "back" | "home" | "swipe" | "wait" | "launch_app",
            "selector_hint": "resource-id:foo" | "text:Login" | "xpath://node[@text='...']",
            "fallback": {"x": 100, "y": 200},
            "text": "input text" (for text actions),
            "timeout_ms": 2000
        }

        Returns:
            ActionResult
        """
        action_type = action.get("type", "wait")
        start_time = time.time()

        logger.info(f"Executing action: {action_type}")

        for attempt in range(self.max_retries + 1):
            try:
                if action_type == "tap":
                    result = self._execute_tap(action, ui_xml_path)
                elif action_type == "text":
                    result = self._execute_text(action)
                elif action_type == "back":
                    result = self._execute_back()
                elif action_type == "home":
                    result = self._execute_home()
                elif action_type == "swipe":
                    result = self._execute_swipe(action)
                elif action_type == "wait":
                    result = self._execute_wait(action)
                elif action_type == "launch_app":
                    result = self._execute_launch(action)
                else:
                    result = ActionResult(
                        success=False,
                        execution_time_ms=0,
                        retry_count=attempt,
                        error_message=f"Unknown action type: {action_type}"
                    )

                # If successful, return
                if result.success:
                    result.retry_count = attempt
                    result.execution_time_ms = (time.time() - start_time) * 1000
                    logger.info(f"Action succeeded (attempt {attempt + 1})")
                    return result

                # If failed and not last attempt, retry
                if attempt < self.max_retries:
                    logger.warning(f"Action failed, retrying ({attempt + 1}/{self.max_retries})")
                    time.sleep(0.5)  # Brief wait before retry

            except Exception as e:
                logger.error(f"Action execution error: {e}", exc_info=True)
                if attempt == self.max_retries:
                    return ActionResult(
                        success=False,
                        execution_time_ms=(time.time() - start_time) * 1000,
                        retry_count=attempt,
                        error_message=str(e)
                    )

        # All retries exhausted
        return ActionResult(
            success=False,
            execution_time_ms=(time.time() - start_time) * 1000,
            retry_count=self.max_retries,
            error_message="Max retries exhausted"
        )

    def _execute_tap(self, action: Dict, ui_xml_path: Optional[str]) -> ActionResult:
        """Execute tap action with selector-first approach"""
        selector_hint = action.get("selector_hint", "")
        fallback = action.get("fallback", {})

        # Try selector-based tap first
        if selector_hint and ui_xml_path:
            coords, method = self._resolve_selector(selector_hint, ui_xml_path)
            if coords:
                logger.debug(f"Tapping via {method}: {coords}")
                self.adb.tap(coords[0], coords[1])
                time.sleep(self.settle_time_ms / 1000.0)
                return ActionResult(success=True, execution_time_ms=0, retry_count=0, final_method=method)

        # Fallback to coordinates
        if fallback and "x" in fallback and "y" in fallback:
            x, y = fallback["x"], fallback["y"]
            logger.debug(f"Tapping via fallback coords: ({x}, {y})")
            self.adb.tap(x, y)
            time.sleep(self.settle_time_ms / 1000.0)
            return ActionResult(success=True, execution_time_ms=0, retry_count=0, final_method="coords")

        return ActionResult(
            success=False,
            execution_time_ms=0,
            retry_count=0,
            error_message="No valid selector or fallback coordinates"
        )

    def _execute_text(self, action: Dict) -> ActionResult:
        """Execute text input action"""
        text = action.get("text", "")
        if not text:
            return ActionResult(success=False, execution_time_ms=0, retry_count=0,
                              error_message="No text provided")

        logger.debug(f"Inputting text: {text}")
        self.adb.input_text(text)
        time.sleep(self.settle_time_ms / 1000.0)
        return ActionResult(success=True, execution_time_ms=0, retry_count=0, final_method="text")

    def _execute_back(self) -> ActionResult:
        """Execute back button press"""
        logger.debug("Pressing back button")
        self.adb.press_back()
        time.sleep(self.settle_time_ms / 1000.0)
        return ActionResult(success=True, execution_time_ms=0, retry_count=0, final_method="back")

    def _execute_home(self) -> ActionResult:
        """Execute home button press"""
        logger.debug("Pressing home button")
        self.adb.press_home()
        time.sleep(self.settle_time_ms / 1000.0)
        return ActionResult(success=True, execution_time_ms=0, retry_count=0, final_method="home")

    def _execute_swipe(self, action: Dict) -> ActionResult:
        """Execute swipe gesture"""
        start_x = action.get("start_x", 500)
        start_y = action.get("start_y", 1000)
        end_x = action.get("end_x", 500)
        end_y = action.get("end_y", 500)
        duration_ms = action.get("duration_ms", 300)

        logger.debug(f"Swiping from ({start_x},{start_y}) to ({end_x},{end_y})")
        self.adb.swipe(start_x, start_y, end_x, end_y, duration_ms)
        time.sleep(self.settle_time_ms / 1000.0)
        return ActionResult(success=True, execution_time_ms=0, retry_count=0, final_method="swipe")

    def _execute_wait(self, action: Dict) -> ActionResult:
        """Execute wait"""
        wait_ms = action.get("timeout_ms", 1000)
        logger.debug(f"Waiting {wait_ms}ms")
        time.sleep(wait_ms / 1000.0)
        return ActionResult(success=True, execution_time_ms=wait_ms, retry_count=0, final_method="wait")

    def _execute_launch(self, action: Dict) -> ActionResult:
        """Execute app launch"""
        package = action.get("package", "")
        if not package:
            return ActionResult(success=False, execution_time_ms=0, retry_count=0,
                              error_message="No package specified")

        logger.debug(f"Launching app: {package}")
        self.adb.launch_app(package)
        time.sleep(self.settle_time_ms / 1000.0)
        return ActionResult(success=True, execution_time_ms=0, retry_count=0, final_method="launch")

    def _resolve_selector(self, selector_hint: str, ui_xml_path: str) -> Tuple[Optional[Tuple[int, int]], str]:
        """
        Resolve selector to coordinates

        Selector formats:
        - "resource-id:com.app:id/button"
        - "text:Login"
        - "content-desc:Submit"
        - "xpath://node[@text='Login']"

        Returns:
            ((x, y), method) or (None, "")
        """
        try:
            tree = ET.parse(ui_xml_path)
            root = tree.getroot()

            if selector_hint.startswith("resource-id:"):
                resource_id = selector_hint.split(":", 1)[1]
                node = self._find_by_resource_id(root, resource_id)
                if node:
                    return self._get_center_coords(node), "resource-id"

            elif selector_hint.startswith("text:"):
                text = selector_hint.split(":", 1)[1]
                node = self._find_by_text(root, text)
                if node:
                    return self._get_center_coords(node), "text"

            elif selector_hint.startswith("content-desc:"):
                desc = selector_hint.split(":", 1)[1]
                node = self._find_by_content_desc(root, desc)
                if node:
                    return self._get_center_coords(node), "content-desc"

            elif selector_hint.startswith("xpath:"):
                xpath = selector_hint.split(":", 1)[1]
                # Simple xpath support (would need full XPath library for complex queries)
                node = self._find_by_simple_xpath(root, xpath)
                if node:
                    return self._get_center_coords(node), "xpath"

            return None, ""

        except Exception as e:
            logger.warning(f"Selector resolution failed: {e}")
            return None, ""

    def _find_by_resource_id(self, root: ET.Element, resource_id: str) -> Optional[ET.Element]:
        """Find element by resource-id"""
        for elem in root.iter():
            if elem.get("resource-id") == resource_id:
                return elem
        return None

    def _find_by_text(self, root: ET.Element, text: str) -> Optional[ET.Element]:
        """Find element by text (exact or partial match)"""
        # Try exact match first
        for elem in root.iter():
            if elem.get("text") == text:
                return elem

        # Try partial match
        for elem in root.iter():
            elem_text = elem.get("text", "")
            if text.lower() in elem_text.lower():
                return elem

        return None

    def _find_by_content_desc(self, root: ET.Element, desc: str) -> Optional[ET.Element]:
        """Find element by content-desc"""
        for elem in root.iter():
            if elem.get("content-desc") == desc:
                return elem
        return None

    def _find_by_simple_xpath(self, root: ET.Element, xpath: str) -> Optional[ET.Element]:
        """
        Simple XPath support (limited)
        Examples: //node[@text='Login'], //node[@resource-id='foo']
        """
        # This is a very simplified XPath - for production use lxml
        import re

        # Parse pattern like //node[@text='Login']
        match = re.search(r"//node\[@(\w+)='([^']+)'\]", xpath)
        if match:
            attr, value = match.groups()
            for elem in root.iter():
                if elem.get(attr) == value:
                    return elem

        return None

    def _get_center_coords(self, node: ET.Element) -> Tuple[int, int]:
        """Get center coordinates of a node"""
        bounds = node.get("bounds", "")
        if not bounds:
            return (0, 0)

        # Parse bounds like "[0,0][1080,1920]"
        import re
        match = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
        if not match:
            return (0, 0)

        x1, y1, x2, y2 = map(int, match.groups())
        center_x = (x1 + x2) // 2
        center_y = (y1 + y2) // 2

        return (center_x, center_y)
