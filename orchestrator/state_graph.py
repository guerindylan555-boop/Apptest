#!/usr/bin/env python3
"""
State graph builder from existing discovery data.
Builds a comprehensive state graph and routes from XML dumps and discovery reports.
"""

import json
import xml.etree.ElementTree as ET
import os
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

@dataclass
class StatePattern:
    state_name: str
    xpath: str
    text_content: Optional[str] = None
    resource_id: Optional[str] = None
    content_desc: Optional[str] = None
    confidence: float = 1.0
    alternative_patterns: List[str] = None

    def __post_init__(self):
        if self.alternative_patterns is None:
            self.alternative_patterns = []

@dataclass
class StateTransition:
    from_state: str
    to_state: str
    action: str
    action_type: str  # tap, text, back, etc.
    xpath: Optional[str] = None
    coordinates: Optional[Tuple[int, int]] = None
    text_input: Optional[str] = None
    confidence: float = 1.0
    success_rate: float = 0.0
    retry_count: int = 0
    expected_delay_ms: int = 2500
    notes: Optional[str] = None

@dataclass
class StateNode:
    name: str
    patterns: List[StatePattern]
    transitions: List[StateTransition]
    description: str = ""
    is_start: bool = False
    is_goal: bool = False
    xml_file: Optional[str] = None
    screenshot_file: Optional[str] = None

class StateGraphBuilder:
    """Builds state graph from XML discovery data"""

    def __init__(self, discovery_dir: str = "."):
        self.discovery_dir = Path(discovery_dir)
        self.state_nodes: Dict[str, StateNode] = {}
        self.routes: Dict[str, List[str]] = {}
        self.discovered_states: Set[str] = set()

    def parse_xml_state(self, xml_file: str) -> Optional[str]:
        """
        Extract state name from XML filename and parse its content

        Args:
            xml_file: Path to XML file

        Returns:
            Inferred state name or None if parsing failed
        """
        try:
            # Extract state name from filename
            filename = Path(xml_file).stem

            # Map common filename patterns to state names
            state_mapping = {
                'clean_app_state': 'CLEAN',
                'clean_launch_state': 'CLEAN',
                'main_map_logged_out_state': 'MAIN_MAP_LOGGED_OUT',
                'current_main_state': 'MAIN_MAP_LOGGED_IN',  # Assuming logged in
                'login_form_state': 'LOGIN_FORM',
                'login_form_discovery_state': 'LOGIN_FORM',
                'login_sheet_state': 'LOGIN_FORM',
                'signup_form_state': 'SIGNUP_FORM',
                'email_signup_form_state': 'EMAIL_SIGNUP_FORM',
                'login_error_state': 'LOGIN_ERROR',
                'login_empty_validation_state': 'LOGIN_VALIDATION_ERROR',
                'post_login_success_state': 'MAIN_MAP_LOGGED_IN',
                'post_successful_login_state': 'MAIN_MAP_LOGGED_IN',
                'post_login_attempt_state': 'LOGIN_PROCESSING',
                'login_processing_state': 'LOGIN_PROCESSING',
                'authentication_menu_state': 'AUTH_MENU',
                'authenticated_menu_state': 'MAIN_MAP_LOGGED_IN',
                'my_account_state': 'MY_ACCOUNT',
                'my_account_scrolled_state': 'MY_ACCOUNT_SCROLLED',
                'contact_help_state': 'CONTACT_HELP',
                'legal_state': 'LEGAL',
                'navigation_menu_state': 'NAVIGATION_MENU',
                'safety_rules_state': 'SAFETY_RULES',
                'safety_rule_2_state': 'SAFETY_RULES_DETAIL',
                'location_permission_state': 'LOCATION_PERMISSION',
                'location_enabled_state': 'LOCATION_ENABLED',
                'current_location_state': 'LOCATION_SET',
                'forgot_password_state': 'FORGOT_PASSWORD',
                'back_to_login_state': 'LOGIN_FORM',
                'error_dialog_state': 'ERROR_DIALOG',
                'current_discovery_state': 'UNKNOWN',
                'current_ui_state': 'UNKNOWN',
                'ui_check': 'UNKNOWN',
                'ui_now': 'UNKNOWN',
                'ui_rental': 'RENTAL_FLOW',
                'ui_current': 'CURRENT_RENTAL',
                'ui_unlock_stuck': 'UNLOCK_ERROR'
            }

            state_name = state_mapping.get(filename, filename.upper().replace('_STATE', '').replace('_', ' '))

            # Parse XML content for additional patterns
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Extract key UI elements for pattern matching
            text_elements = self._extract_text_elements(root)
            clickable_elements = self._extract_clickable_elements(root)

            logger.info(f"Parsed XML state: {filename} -> {state_name}")
            logger.info(f"  Found {len(text_elements)} text elements, {len(clickable_elements)} clickable elements")

            return state_name

        except Exception as e:
            logger.error(f"Failed to parse XML {xml_file}: {e}")
            return None

    def _extract_text_elements(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Extract text elements from XML hierarchy"""
        text_elements = []

        def extract_text_recursive(node):
            text = node.get('text', '').strip()
            if text and len(text) > 0:
                bounds = node.get('bounds', '')
                coords = None
                if bounds:
                    match = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
                    if match:
                        coords = {
                            'x1': int(match.group(1)),
                            'y1': int(match.group(2)),
                            'x2': int(match.group(3)),
                            'y2': int(match.group(4))
                        }

                text_elements.append({
                    'text': text,
                    'resource_id': node.get('resource-id'),
                    'content_desc': node.get('content-desc'),
                    'class': node.get('class'),
                    'clickable': node.get('clickable', 'false') == 'true',
                    'bounds': coords
                })

            for child in node:
                extract_text_recursive(child)

        extract_text_recursive(root)
        return text_elements

    def _extract_clickable_elements(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Extract clickable elements from XML hierarchy"""
        clickable_elements = []

        def extract_clickable_recursive(node):
            clickable = node.get('clickable', 'false') == 'true'
            enabled = node.get('enabled', 'true') == 'true'

            if clickable and enabled:
                text = node.get('text', '').strip()
                content_desc = node.get('content-desc', '').strip()
                resource_id = node.get('resource-id', '').strip()

                bounds = node.get('bounds', '')
                coords = None
                if bounds:
                    match = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
                    if match:
                        coords = {
                            'x1': int(match.group(1)),
                            'y1': int(match.group(2)),
                            'x2': int(match.group(3)),
                            'y2': int(match.group(4))
                        }

                clickable_elements.append({
                    'text': text if text else content_desc if content_desc else resource_id,
                    'resource_id': resource_id,
                    'content_desc': content_desc,
                    'class': node.get('class'),
                    'bounds': coords,
                    'xpath': self._generate_xpath(node)
                })

            for child in node:
                extract_clickable_recursive(child)

        extract_clickable_recursive(root)
        return clickable_elements

    def _generate_xpath(self, node: ET.Element) -> str:
        """Generate XPath for a node"""
        # Simplified XPath generation
        class_name = node.get('class', '')
        text = node.get('text', '')
        resource_id = node.get('resource-id', '')

        if resource_id:
            return f"//*[@resource-id='{resource_id}']"
        elif text:
            return f"//*[@text='{text}']"
        elif class_name:
            # Get class name without package
            simple_class = class_name.split('.')[-1]
            return f"//{simple_class}"
        else:
            return "*"

    def build_state_graph(self) -> Dict[str, Any]:
        """
        Build complete state graph from discovery data

        Returns:
            Complete state graph dictionary
        """
        logger.info("Building state graph from discovery data...")

        # 1. Scan for XML files and extract states
        xml_files = list(self.discovery_dir.glob("*.xml"))
        logger.info(f"Found {len(xml_files)} XML files to analyze")
        logger.info(f"Scanning for XML files in: {self.discovery_dir}")
        logger.info(f"Found XML files: {[f.name for f in xml_files[:5]]}")

        # 2. Parse each XML and create state nodes
        for xml_file in xml_files:
            state_name = self.parse_xml_state(str(xml_file))
            if state_name:
                if state_name not in self.state_nodes:
                    # Extract patterns for this state
                    patterns = self._create_state_patterns(xml_file)

                    state_node = StateNode(
                        name=state_name,
                        patterns=patterns,
                        transitions=[],
                        description=f"State from {xml_file.name}",
                        xml_file=str(xml_file),
                        is_start=(state_name == 'CLEAN'),
                        is_goal=(state_name in ['UNLOCK', 'MAIN_MAP_LOGGED_IN'])
                    )

                    self.state_nodes[state_name] = state_node
                    self.discovered_states.add(state_name)

        # 3. Define logical transitions based on app flow knowledge
        self._define_logical_transitions()

        # 4. Create routes for common goals
        self._create_routes()

        # 5. Build final graph structure
        graph = {
            'states': {},
            'transitions': [],
            'routes': self.routes,
            'metadata': {
                'total_states': len(self.state_nodes),
                'discovered_from_xml': len(xml_files),
                'build_timestamp': ET.Element.__module__  # Simple timestamp
            }
        }

        # Add state nodes to graph
        for state_name, node in self.state_nodes.items():
            graph['states'][state_name] = {
                'name': node.name,
                'description': node.description,
                'patterns': [asdict(p) for p in node.patterns],
                'is_start': node.is_start,
                'is_goal': node.is_goal,
                'xml_file': node.xml_file
            }

        # Add transitions to graph
        for node in self.state_nodes.values():
            for transition in node.transitions:
                graph['transitions'].append(asdict(transition))

        logger.info(f"Built state graph with {len(self.state_nodes)} states and {len(graph['transitions'])} transitions")
        return graph

    def _create_state_patterns(self, xml_file: Path) -> List[StatePattern]:
        """Create detection patterns for a state from XML file"""
        patterns = []

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Get text elements for pattern creation
            text_elements = self._extract_text_elements(root)
            clickable_elements = self._extract_clickable_elements(root)

            # Create patterns based on key text elements
            key_texts = ['Login', 'Sign up', 'Menu', 'Scan & ride', 'Login to rent',
                        'My account', 'Help', 'Legal', 'Safety', 'Location']

            for elem in text_elements:
                text = elem['text']
                if any(key.lower() in text.lower() for key in key_texts):
                    xpath = f"//*[@text='{text}']"
                    pattern = StatePattern(
                        state_name="",  # Will be filled by caller
                        xpath=xpath,
                        text_content=text,
                        confidence=0.8
                    )
                    patterns.append(pattern)

            # Create patterns for clickable elements with unique identifiers
            for elem in clickable_elements:
                if elem['resource_id']:
                    xpath = f"//*[@resource-id='{elem['resource_id']}']"
                    pattern = StatePattern(
                        state_name="",  # Will be filled by caller
                        xpath=xpath,
                        resource_id=elem['resource_id'],
                        confidence=0.9
                    )
                    patterns.append(pattern)

        except Exception as e:
            logger.error(f"Error creating patterns for {xml_file}: {e}")

        return patterns

    def _define_logical_transitions(self):
        """Define logical state transitions based on app flow knowledge"""

        # Define common transitions
        logical_transitions = [
            # From CLEAN
            ('CLEAN', 'MAIN_MAP_LOGGED_OUT', 'tap', 'Launch app', (540, 1200)),

            # From MAIN_MAP_LOGGED_OUT
            ('MAIN_MAP_LOGGED_OUT', 'LOGIN_FORM', 'tap', 'Login to rent button', (540, 1690)),
            ('MAIN_MAP_LOGGED_OUT', 'LOCATION_PERMISSION', 'tap', 'Location permission', None),
            ('MAIN_MAP_LOGGED_OUT', 'NAVIGATION_MENU', 'tap', 'Menu button', (77, 154)),

            # From LOGIN_FORM
            ('LOGIN_FORM', 'MAIN_MAP_LOGGED_IN', 'text', 'Enter credentials', None),
            ('LOGIN_FORM', 'LOGIN_ERROR', 'text', 'Invalid credentials', None),
            ('LOGIN_FORM', 'FORGOT_PASSWORD', 'tap', 'Forgot password', (540, 1600)),
            ('LOGIN_FORM', 'SIGNUP_FORM', 'tap', 'Sign up', (540, 1700)),
            ('LOGIN_FORM', 'MAIN_MAP_LOGGED_OUT', 'back', 'Back', None),

            # From SIGNUP_FORM
            ('SIGNUP_FORM', 'MAIN_MAP_LOGGED_IN', 'text', 'Complete signup', None),
            ('SIGNUP_FORM', 'LOGIN_FORM', 'back', 'Back to login', None),

            # From MAIN_MAP_LOGGED_IN
            ('MAIN_MAP_LOGGED_IN', 'QR_SCANNER', 'tap', 'Scan & ride', (540, 1620)),
            ('MAIN_MAP_LOGGED_IN', 'NAVIGATION_MENU', 'tap', 'Menu button', (77, 154)),
            ('MAIN_MAP_LOGGED_IN', 'MY_ACCOUNT', 'tap', 'Account menu', None),

            # From QR_SCANNER
            ('QR_SCANNER', 'SELECT_VEHICLE', 'scan', 'Scan QR code', None),
            ('QR_SCANNER', 'MAIN_MAP_LOGGED_IN', 'back', 'Back to map', None),

            # From SELECT_VEHICLE
            ('SELECT_VEHICLE', 'UNLOCK', 'tap', 'Unlock vehicle', (540, 1200)),
            ('SELECT_VEHICLE', 'SAFETY_RULES', 'tap', 'Safety rules', (540, 1400)),
            ('SELECT_VEHICLE', 'MAIN_MAP_LOGGED_IN', 'back', 'Back', None),

            # From UNLOCK
            ('UNLOCK', 'MAIN_MAP_LOGGED_IN', 'tap', 'Back to map', (540, 1600)),
            ('UNLOCK', 'UNLOCK_ERROR', 'error', 'Unlock failed', None),

            # From NAVIGATION_MENU
            ('NAVIGATION_MENU', 'MY_ACCOUNT', 'tap', 'My account', (540, 800)),
            ('NAVIGATION_MENU', 'CONTACT_HELP', 'tap', 'Help', (540, 1000)),
            ('NAVIGATION_MENU', 'LEGAL', 'tap', 'Legal', (540, 1200)),
            ('NAVIGATION_MENU', 'MAIN_MAP_LOGGED_IN', 'back', 'Close menu', None),

            # Error states
            ('LOGIN_ERROR', 'LOGIN_FORM', 'tap', 'Try again', (540, 1600)),
            ('ERROR_DIALOG', 'PREVIOUS_STATE', 'tap', 'Dismiss error', (540, 1200)),
            ('UNLOCK_ERROR', 'SELECT_VEHICLE', 'tap', 'Try again', (540, 1600)),

            # Permission states
            ('LOCATION_PERMISSION', 'LOCATION_ENABLED', 'tap', 'Allow location', (540, 1400)),
            ('LOCATION_ENABLED', 'MAIN_MAP_LOGGED_OUT', 'tap', 'Continue', (540, 1600)),
        ]

        # Add transitions to state nodes
        for from_state, to_state, action_type, action_desc, coords in logical_transitions:
            if from_state in self.state_nodes:
                transition = StateTransition(
                    from_state=from_state,
                    to_state=to_state,
                    action=action_desc,
                    action_type=action_type,
                    coordinates=coords,
                    confidence=0.8,
                    expected_delay_ms=2500
                )
                self.state_nodes[from_state].transitions.append(transition)

    def _create_routes(self):
        """Create common routes for typical user goals"""

        self.routes = {
            'CLEAN_TO_UNLOCK': [
                'CLEAN',
                'MAIN_MAP_LOGGED_OUT',
                'LOGIN_FORM',
                'MAIN_MAP_LOGGED_IN',
                'QR_SCANNER',
                'SELECT_VEHICLE',
                'UNLOCK'
            ],

            'CLEAN_TO_MAP': [
                'CLEAN',
                'MAIN_MAP_LOGGED_OUT'
            ],

            'LOGOUT_FLOW': [
                'MAIN_MAP_LOGGED_IN',
                'NAVIGATION_MENU',
                'MY_ACCOUNT',
                'LOGIN_FORM'
            ],

            'SIGNUP_FLOW': [
                'MAIN_MAP_LOGGED_OUT',
                'LOGIN_FORM',
                'SIGNUP_FORM',
                'MAIN_MAP_LOGGED_IN'
            ],

            'RENTAL_FLOW': [
                'MAIN_MAP_LOGGED_IN',
                'QR_SCANNER',
                'SELECT_VEHICLE',
                'UNLOCK'
            ]
        }

    def save_graph(self, output_file: str = "state_graph.json"):
        """Save state graph to JSON file"""
        graph = self.build_state_graph()

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(graph, f, indent=2, ensure_ascii=False)

            logger.info(f"State graph saved to: {output_file}")

            # Also save routes separately
            routes_file = output_file.replace('.json', '_routes.json')
            with open(routes_file, 'w', encoding='utf-8') as f:
                json.dump(self.routes, f, indent=2, ensure_ascii=False)

            logger.info(f"Routes saved to: {routes_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to save state graph: {e}")
            return False

    def load_graph(self, graph_file: str) -> bool:
        """Load state graph from JSON file"""
        try:
            with open(graph_file, 'r', encoding='utf-8') as f:
                graph_data = json.load(f)

            # Reconstruct state nodes from graph data
            self.state_nodes.clear()
            for state_name, state_data in graph_data['states'].items():
                patterns = []
                for pattern_data in state_data['patterns']:
                    pattern = StatePattern(**pattern_data)
                    patterns.append(pattern)

                node = StateNode(
                    name=state_data['name'],
                    patterns=patterns,
                    transitions=[],
                    description=state_data['description'],
                    is_start=state_data['is_start'],
                    is_goal=state_data['is_goal'],
                    xml_file=state_data.get('xml_file')
                )
                self.state_nodes[state_name] = node

            # Load transitions
            for transition_data in graph_data['transitions']:
                transition = StateTransition(**transition_data)
                if transition.from_state in self.state_nodes:
                    self.state_nodes[transition.from_state].transitions.append(transition)

            # Load routes if available
            routes_file = graph_file.replace('.json', '_routes.json')
            if os.path.exists(routes_file):
                with open(routes_file, 'r', encoding='utf-8') as f:
                    self.routes = json.load(f)

            logger.info(f"Loaded state graph with {len(self.state_nodes)} states")
            return True

        except Exception as e:
            logger.error(f"Failed to load state graph: {e}")
            return False

if __name__ == "__main__":
    # Test state graph builder
    builder = StateGraphBuilder()

    print("Building state graph from discovery data...")

    # Build and save graph
    if builder.save_graph("state_graph.json"):
        print("✅ State graph built successfully")

        # Display summary
        graph = builder.build_state_graph()
        print(f"📊 Found {graph['metadata']['total_states']} states")
        print(f"📋 Created {len(graph['transitions'])} transitions")
        print(f"🛣️  Defined {len(builder.routes)} routes")

        print("\n🎯 Available routes:")
        for route_name, route_states in builder.routes.items():
            print(f"  {route_name}: {' → '.join(route_states)}")
    else:
        print("❌ Failed to build state graph")