#!/usr/bin/env python3
"""
Data contracts and JSON schemas for MaynDrive automation system.
Based on the LLM-driven automation plan specifications.
"""

from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
from enum import Enum
import json
from datetime import datetime

class ActionType(str, Enum):
    TAP = "tap"
    TEXT = "text"
    BACK = "back"
    HOME = "home"
    WAIT = "wait"
    SWIPE = "swipe"
    LAUNCH_APP = "launch_app"
    CLOSE_APP = "close_app"

class DeviceInfo(BaseModel):
    device: str = Field(..., description="Device identifier like 'emulator-5556'")
    rotation: int = Field(default=0, description="Screen rotation in degrees")
    density: int = Field(default=420, description="Screen density")
    width: int = Field(default=1080, description="Screen width in pixels")
    height: int = Field(default=2340, description="Screen height in pixels")

class LastAction(BaseModel):
    type: ActionType
    x: Optional[int] = None
    y: Optional[int] = None
    text: Optional[str] = None
    desc: Optional[str] = None
    selector_hint: Optional[str] = None
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())

class UISnapshot(BaseModel):
    timestamp: float = Field(..., description="Unix timestamp")
    device: str = Field(..., description="Device identifier")
    xml_path: str = Field(..., description="Path to XML dump file")
    screenshot_path: str = Field(..., description="Path to screenshot file")
    window: DeviceInfo
    last_action: Optional[LastAction] = None
    xml_content: Optional[str] = None  # For in-memory XML

class HistoryEntry(BaseModel):
    state: str = Field(..., description="UI state name")
    action: ActionType = Field(..., description="Action taken")
    success: bool = Field(default=True)
    confidence: float = Field(default=1.0)
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())
    notes: Optional[str] = None

class UIAnalysis(BaseModel):
    xml: str = Field(..., description="UI XML content")
    screenshot_path: Optional[str] = None
    detected_elements: List[Dict[str, Any]] = Field(default_factory=list)
    interactive_elements: List[Dict[str, Any]] = Field(default_factory=list)
    text_elements: List[str] = Field(default_factory=list)

class StateAnalysis(BaseModel):
    detected_state: str = Field(..., description="Detected UI state")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in state detection")
    notes: str = Field(..., description="Analysis notes and reasoning")
    alternative_states: List[Dict[str, float]] = Field(default_factory=list)

class AlignmentCheck(BaseModel):
    is_expected: bool = Field(..., description="Whether detected state matches expected")
    reason: str = Field(..., description="Reason for alignment result")
    deviation_severity: Optional[str] = None  # "low", "medium", "high"
    recovery_suggested: Optional[str] = None

class FallbackAction(BaseModel):
    x: int = Field(..., description="Fallback X coordinate")
    y: int = Field(..., description="Fallback Y coordinate")

class RecommendedAction(BaseModel):
    type: ActionType = Field(..., description="Action type")
    selector_hint: Optional[str] = None
    fallback: Optional[FallbackAction] = None
    x: Optional[int] = None
    y: Optional[int] = None
    text: Optional[str] = None
    timeout_ms: int = Field(default=2500, description="Timeout in milliseconds")
    confidence: float = Field(default=1.0, description="Confidence in this action")

class StatePattern(BaseModel):
    state: str = Field(..., description="State name")
    xpath: str = Field(..., description="XPath pattern for this state")
    confidence: float = Field(default=1.0)
    element_text: Optional[str] = None
    element_id: Optional[str] = None
    content_desc: Optional[str] = None

class RouteAdjustment(BaseModel):
    from_state: str
    to_state: str
    original_action: RecommendedAction
    adjusted_action: RecommendedAction
    reason: str
    success_rate: float = Field(default=0.0)

class LearningUpdate(BaseModel):
    state_patterns: List[StatePattern] = Field(default_factory=list)
    route_adjustments: List[RouteAdjustment] = Field(default_factory=list)
    new_discovered_states: List[str] = Field(default_factory=list)
    failed_patterns: List[Dict[str, Any]] = Field(default_factory=list)

class LLMSupervisorRequest(BaseModel):
    goal: str = Field(..., description="Target goal (e.g., 'UNLOCK_VEHICLE')")
    expected_state: Optional[str] = None
    candidate_state: Optional[str] = None
    history: List[HistoryEntry] = Field(default_factory=list)
    ui: UIAnalysis
    state_graph: Dict[str, Any] = Field(default_factory=dict)
    routes: Dict[str, Any] = Field(default_factory=dict)
    current_step: int = Field(default=0)
    max_steps: int = Field(default=50)

class LLMSupervisorResponse(BaseModel):
    analysis: StateAnalysis
    alignment: AlignmentCheck
    recommendation: RecommendedAction
    learning: LearningUpdate

class SessionInfo(BaseModel):
    session_id: str
    start_time: float
    goal: str
    device: str
    status: str = "running"  # running, completed, failed, timeout
    current_state: Optional[str] = None
    steps_completed: int = 0
    learning_updates: List[LearningUpdate] = Field(default_factory=list)

# JSON Schema exports for validation
UI_SNAPSHOT_SCHEMA = UISnapshot.model_json_schema()
LLM_REQUEST_SCHEMA = LLMSupervisorRequest.model_json_schema()
LLM_RESPONSE_SCHEMA = LLMSupervisorResponse.model_json_schema()
SESSION_INFO_SCHEMA = SessionInfo.model_json_schema()

def validate_json_schema(data: dict, schema: dict) -> tuple[bool, Optional[str]]:
    """Validate JSON data against a schema"""
    try:
        # Simple validation using pydantic
        if schema == UI_SNAPSHOT_SCHEMA:
            UISnapshot(**data)
        elif schema == LLM_REQUEST_SCHEMA:
            LLMSupervisorRequest(**data)
        elif schema == LLM_RESPONSE_SCHEMA:
            LLMSupervisorResponse(**data)
        elif schema == SESSION_INFO_SCHEMA:
            SessionInfo(**data)
        else:
            return False, f"Unknown schema type"
        return True, None
    except Exception as e:
        return False, str(e)

def load_schema_file(schema_type: str) -> dict:
    """Load schema for external use"""
    schemas = {
        "ui_snapshot": UI_SNAPSHOT_SCHEMA,
        "llm_request": LLM_REQUEST_SCHEMA,
        "llm_response": LLM_RESPONSE_SCHEMA,
        "session_info": SESSION_INFO_SCHEMA
    }
    return schemas.get(schema_type, {})

if __name__ == "__main__":
    # Test schema validation
    test_snapshot = {
        "timestamp": 1730072100,
        "device": "emulator-5556",
        "xml_path": "test.xml",
        "screenshot_path": "test.png",
        "window": {
            "device": "emulator-5556",
            "rotation": 0,
            "density": 420,
            "width": 1080,
            "height": 2340
        }
    }

    is_valid, error = validate_json_schema(test_snapshot, UI_SNAPSHOT_SCHEMA)
    print(f"Schema validation: {'✅ PASS' if is_valid else '❌ FAIL'}")
    if error:
        print(f"Error: {error}")