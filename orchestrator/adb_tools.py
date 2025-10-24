#!/usr/bin/env python3
"""
ADB tools wrapper for UI automation.
Handles XML dumping, screenshots, device info, and UI element detection.
"""

import subprocess
import os
import time
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import json
import re
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    device: str
    rotation: int = 0
    density: int = 420
    width: int = 1080
    height: int = 2340

@dataclass
class UIElement:
    bounds: Tuple[int, int, int, int]  # (x1, y1, x2, y2)
    text: Optional[str] = None
    resource_id: Optional[str] = None
    content_desc: Optional[str] = None
    class_name: Optional[str] = None
    clickable: bool = False
    enabled: bool = True
    focused: bool = False

class ADBTools:
    """ADB utilities for UI automation"""

    def __init__(self, device_id: str = "emulator-5556"):
        self.device_id = device_id
        self.adb_prefix = ["adb", "-s", device_id]
        self.device_info = self._get_device_info()

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

    def _get_device_info(self) -> DeviceInfo:
        """Get device information"""
        try:
            # Get window size
            success, wm_size, _ = self._run_adb_command(["shell", "wm", "size"])
            width, height = 1080, 2340  # defaults
            if success and "Physical size:" in wm_size:
                size_match = re.search(r'Physical size: (\d+)x(\d+)', wm_size)
                if size_match:
                    width, height = int(size_match.group(1)), int(size_match.group(2))

            # Get density
            success, wm_density, _ = self._run_adb_command(["shell", "wm", "density"])
            density = 420  # default
            if success and wm_density.isdigit():
                density = int(wm_density)

            # Get rotation
            success, dumpsys_display, _ = self._run_adb_command(["shell", "dumpsys", "input", "|", "grep", "'SurfaceOrientation'"])
            rotation = 0  # default
            if success:
                rotation_match = re.search(r'SurfaceOrientation=(\d+)', dumpsys_display)
                if rotation_match:
                    rotation = int(rotation_match.group(1))

            return DeviceInfo(
                device=self.device_id,
                rotation=rotation,
                density=density,
                width=width,
                height=height
            )

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")
            return DeviceInfo(device=self.device_id)

    def is_device_connected(self) -> bool:
        """Check if device is connected and responsive"""
        success, _, _ = self._run_adb_command(["shell", "echo", "ping"])
        return success

    def dump_ui_xml(self, output_path: Optional[str] = None) -> str:
        """
        Dump UI hierarchy to XML and save to file

        Args:
            output_path: Optional path to save XML file

        Returns:
            Path to the saved XML file
        """
        try:
            if output_path is None:
                timestamp = int(time.time())
                output_path = f"ui_dump_{timestamp}.xml"

            # Use uiautomator dump
            success, _, stderr = self._run_adb_command(["shell", "uiautomator", "dump"])
            if not success:
                logger.error(f"UI dump failed: {stderr}")
                raise Exception(f"UI dump failed: {stderr}")

            # Pull the XML file
            success, _, stderr = self._run_adb_command(["pull", "/sdcard/window_dump.xml", output_path])
            if not success:
                logger.error(f"Failed to pull XML dump: {stderr}")
                raise Exception(f"Failed to pull XML dump: {stderr}")

            logger.info(f"UI XML dump saved to: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to dump UI XML: {e}")
            raise

    def take_screenshot(self, output_path: Optional[str] = None) -> str:
        """
        Take device screenshot and save to file

        Args:
            output_path: Optional path to save screenshot

        Returns:
            Path to the saved screenshot file
        """
        try:
            if output_path is None:
                timestamp = int(time.time())
                output_path = f"screenshot_{timestamp}.png"

            # Take screenshot on device
            device_screenshot_path = "/sdcard/screenshot.png"
            success, _, stderr = self._run_adb_command(["shell", "screencap", "-p", device_screenshot_path])
            if not success:
                logger.error(f"Screenshot failed: {stderr}")
                raise Exception(f"Screenshot failed: {stderr}")

            # Pull the screenshot file
            success, _, stderr = self._run_adb_command(["pull", device_screenshot_path, output_path])
            if not success:
                logger.error(f"Failed to pull screenshot: {stderr}")
                raise Exception(f"Failed to pull screenshot: {stderr}")

            logger.info(f"Screenshot saved to: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to take screenshot: {e}")
            raise

    def parse_ui_xml(self, xml_path: str) -> Dict[str, Any]:
        """
        Parse UI XML and extract interactive elements

        Args:
            xml_path: Path to UI XML file

        Returns:
            Dictionary with parsed UI data
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            interactive_elements = []
            text_elements = []
            all_elements = []

            def extract_element_info(node):
                """Extract information from UI node"""
                bounds_str = node.get('bounds', '')
                text = node.get('text', '')
                resource_id = node.get('resource-id', '')
                content_desc = node.get('content-desc', '')
                class_name = node.get('class', '')
                clickable = node.get('clickable', 'false').lower() == 'true'
                enabled = node.get('enabled', 'true').lower() == 'true'
                focused = node.get('focused', 'false').lower() == 'true'

                # Parse bounds
                bounds = None
                if bounds_str:
                    bounds_match = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
                    if bounds_match:
                        bounds = (
                            int(bounds_match.group(1)),
                            int(bounds_match.group(2)),
                            int(bounds_match.group(3)),
                            int(bounds_match.group(4))
                        )

                element = {
                    'bounds': bounds,
                    'text': text if text else None,
                    'resource_id': resource_id if resource_id else None,
                    'content_desc': content_desc if content_desc else None,
                    'class_name': class_name if class_name else None,
                    'clickable': clickable,
                    'enabled': enabled,
                    'focused': focused
                }

                return element

            def traverse_tree(node):
                """Traverse UI tree and collect elements"""
                element = extract_element_info(node)
                all_elements.append(element)

                if element['clickable'] and element['enabled']:
                    interactive_elements.append(element)

                if element['text'] and element['text'].strip():
                    text_elements.append(element['text'].strip())

                for child in node:
                    traverse_tree(child)

            traverse_tree(root)

            # Get XML content as string
            with open(xml_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()

            return {
                'xml': xml_content,
                'interactive_elements': interactive_elements,
                'text_elements': text_elements,
                'all_elements': all_elements,
                'total_elements': len(all_elements),
                'interactive_count': len(interactive_elements)
            }

        except Exception as e:
            logger.error(f"Failed to parse UI XML: {e}")
            raise

    def wait_for_ui_stable(self, timeout_ms: int = 2000, check_interval_ms: int = 500) -> bool:
        """
        Wait for UI to become stable (no layout changes)

        Args:
            timeout_ms: Maximum time to wait
            check_interval_ms: Interval between stability checks

        Returns:
            True if UI became stable, False if timeout
        """
        try:
            start_time = time.time()
            timeout_seconds = timeout_ms / 1000
            check_interval_seconds = check_interval_ms / 1000

            # Take initial UI dump
            initial_dump = self.dump_ui_xml("temp_initial.xml")
            initial_size = os.path.getsize(initial_dump)

            while time.time() - start_time < timeout_seconds:
                time.sleep(check_interval_seconds)

                # Take new dump
                current_dump = self.dump_ui_xml("temp_current.xml")
                current_size = os.path.getsize(current_dump)

                # Check if stable (size similar and no major layout changes)
                if abs(current_size - initial_size) < 1000:  # Within 1KB
                    logger.info("UI appears to be stable")
                    # Clean up temp files
                    for temp_file in ["temp_initial.xml", "temp_current.xml"]:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                    return True

                # Update initial for next comparison
                initial_size = current_size
                os.rename(current_dump, initial_dump)

            logger.warning("UI did not stabilize within timeout")
            # Clean up temp files
            for temp_file in ["temp_initial.xml", "temp_current.xml"]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            return False

        except Exception as e:
            logger.error(f"Error waiting for UI stability: {e}")
            return False

    def find_element_by_text(self, xml_path: str, search_text: str, exact_match: bool = False) -> Optional[UIElement]:
        """
        Find UI element by text content

        Args:
            xml_path: Path to UI XML file
            search_text: Text to search for
            exact_match: Whether to require exact match

        Returns:
            UIElement if found, None otherwise
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            def find_text(node):
                text = node.get('text', '')
                if text:
                    if exact_match:
                        if text == search_text:
                            return node
                    else:
                        if search_text.lower() in text.lower():
                            return node

                for child in node:
                    result = find_text(child)
                    if result:
                        return result
                return None

            element_node = find_text(root)
            if not element_node:
                return None

            # Create UIElement from node
            bounds_str = element_node.get('bounds', '')
            bounds = None
            if bounds_str:
                bounds_match = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
                if bounds_match:
                    bounds = (
                        int(bounds_match.group(1)),
                        int(bounds_match.group(2)),
                        int(bounds_match.group(3)),
                        int(bounds_match.group(4))
                    )

            return UIElement(
                bounds=bounds,
                text=element_node.get('text'),
                resource_id=element_node.get('resource-id'),
                content_desc=element_node.get('content-desc'),
                class_name=element_node.get('class'),
                clickable=element_node.get('clickable', 'false').lower() == 'true',
                enabled=element_node.get('enabled', 'true').lower() == 'true',
                focused=element_node.get('focused', 'false').lower() == 'true'
            )

        except Exception as e:
            logger.error(f"Error finding element by text: {e}")
            return None

    def find_element_by_id(self, xml_path: str, resource_id: str) -> Optional[UIElement]:
        """
        Find UI element by resource ID

        Args:
            xml_path: Path to UI XML file
            resource_id: Resource ID to search for

        Returns:
            UIElement if found, None otherwise
        """
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            def find_id(node):
                node_id = node.get('resource-id', '')
                if node_id == resource_id:
                    return node

                for child in node:
                    result = find_id(child)
                    if result:
                        return result
                return None

            element_node = find_id(root)
            if not element_node:
                return None

            # Create UIElement from node
            bounds_str = element_node.get('bounds', '')
            bounds = None
            if bounds_str:
                bounds_match = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
                if bounds_match:
                    bounds = (
                        int(bounds_match.group(1)),
                        int(bounds_match.group(2)),
                        int(bounds_match.group(3)),
                        int(bounds_match.group(4))
                    )

            return UIElement(
                bounds=bounds,
                text=element_node.get('text'),
                resource_id=element_node.get('resource-id'),
                content_desc=element_node.get('content-desc'),
                class_name=element_node.get('class'),
                clickable=element_node.get('clickable', 'false').lower() == 'true',
                enabled=element_node.get('enabled', 'true').lower() == 'true',
                focused=element_node.get('focused', 'false').lower() == 'true'
            )

        except Exception as e:
            logger.error(f"Error finding element by ID: {e}")
            return None

    def get_element_center(self, element: UIElement) -> Tuple[int, int]:
        """Get center coordinates of UI element"""
        if not element.bounds:
            raise ValueError("Element has no bounds")

        x1, y1, x2, y2 = element.bounds
        center_x = (x1 + x2) // 2
        center_y = (y1 + y2) // 2
        return center_x, center_y

    def create_ui_snapshot(self, session_dir: str, step: int = 0) -> Dict[str, Any]:
        """
        Create a complete UI snapshot with XML dump and screenshot

        Args:
            session_dir: Directory to save snapshot files
            step: Step number for file naming

        Returns:
            Dictionary with snapshot information
        """
        try:
            timestamp = int(time.time())
            xml_filename = f"snapshot_{step:04d}_{timestamp}.xml"
            screenshot_filename = f"snapshot_{step:04d}_{timestamp}.png"

            xml_path = os.path.join(session_dir, xml_filename)
            screenshot_path = os.path.join(session_dir, screenshot_filename)

            # Dump UI XML and take screenshot
            self.dump_ui_xml(xml_path)
            self.take_screenshot(screenshot_path)

            # Parse UI XML
            ui_data = self.parse_ui_xml(xml_path)

            snapshot = {
                'timestamp': timestamp,
                'device': self.device_id,
                'xml_path': xml_path,
                'screenshot_path': screenshot_path,
                'window': {
                    'device': self.device_info.device,
                    'rotation': self.device_info.rotation,
                    'density': self.device_info.density,
                    'width': self.device_info.width,
                    'height': self.device_info.height
                },
                'ui_data': ui_data
            }

            logger.info(f"UI snapshot created: step {step}, {len(ui_data['interactive_elements'])} interactive elements")
            return snapshot

        except Exception as e:
            logger.error(f"Failed to create UI snapshot: {e}")
            raise

if __name__ == "__main__":
    # Test ADB tools
    adb_tools = ADBTools()

    if adb_tools.is_device_connected():
        print("✅ Device connected")
        print(f"Device info: {adb_tools.device_info}")

        # Test UI dump
        try:
            xml_path = adb_tools.dump_ui_xml("test_ui.xml")
            print(f"✅ UI dump saved to: {xml_path}")

            # Parse XML
            ui_data = adb_tools.parse_ui_xml(xml_path)
            print(f"✅ Found {ui_data['interactive_count']} interactive elements")
            print(f"✅ Found {len(ui_data['text_elements'])} text elements")

        except Exception as e:
            print(f"❌ UI dump failed: {e}")

        # Test screenshot
        try:
            screenshot_path = adb_tools.take_screenshot("test_screenshot.png")
            print(f"✅ Screenshot saved to: {screenshot_path}")
        except Exception as e:
            print(f"❌ Screenshot failed: {e}")
    else:
        print("❌ Device not connected")