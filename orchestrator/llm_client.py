#!/usr/bin/env python3
"""
GLM-4.6 client via Z.ai API for LLM-supervised automation.
Handles communication with GLM-4.6 model for UI state analysis and action recommendations.
"""

import os
import json
import requests
import time
from typing import Dict, Any, Optional, List
import logging
from schemas import LLMSupervisorRequest, LLMSupervisorResponse, validate_json_schema

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GLMClient:
    """Client for GLM-4.6 via Z.ai API"""

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize GLM client

        Args:
            base_url: Z.ai API base URL (defaults to env ZAI_BASE_URL)
            api_key: Z.ai API key (defaults to env ZAI_API_KEY)
        """
        self.base_url = base_url or os.getenv("ZAI_BASE_URL", "https://api.z.ai/api/coding/paas/v4")
        self.api_key = api_key or os.getenv("ZAI_API_KEY")
        self.model = "GLM-4.6"  # GLM-4.6 model identifier

        if not self.api_key:
            raise ValueError("ZAI_API_KEY environment variable must be set")

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        })

        logger.info(f"GLM client initialized with model: {self.model}")

    def _compress_xml(self, xml_content: str, max_length: int = 10000) -> str:
        """Compress XML content to fit within token limits"""
        if len(xml_content) <= max_length:
            return xml_content

        # Remove excessive whitespace
        compressed = ' '.join(xml_content.split())

        # If still too long, truncate intelligently
        if len(compressed) > max_length:
            # Try to keep the structure by truncating middle sections
            lines = compressed.split('\n')
            keep_count = max_length // len(compressed) * len(lines)

            if keep_count < len(lines):
                # Keep beginning and end, truncate middle
                keep_start = keep_count // 2
                keep_end = keep_count - keep_start
                compressed = '\n'.join(lines[:keep_start] + ['... truncated ...'] + lines[-keep_end:])

        return compressed

    def _build_system_prompt(self) -> str:
        """Build the system prompt for GLM-4.6"""
        return """You are the UI State Supervisor for MaynDrive automation. Your task is to:

1. Analyze the provided UI XML and screenshot path to determine the current application state
2. Check if this state matches what was expected in the automation flow
3. Recommend the next action to progress toward the goal

You must respond with valid JSON only, following this exact schema:
{
  "analysis": {
    "detected_state": "STATE_NAME",
    "confidence": 0.0-1.0,
    "notes": "Detailed reasoning about state detection",
    "alternative_states": [{"state": "ALT_STATE", "confidence": 0.0-1.0}]
  },
  "alignment": {
    "is_expected": true/false,
    "reason": "Explanation of why this state is/isn't expected",
    "deviation_severity": "low/medium/high",
    "recovery_suggested": "How to recover if off track"
  },
  "recommendation": {
    "type": "tap/text/back/home/wait/swipe/launch_app/close_app",
    "selector_hint": "XPath or text hint for element selection",
    "fallback": {"x": 540, "y": 1620},
    "x": 540,
    "y": 1620,
    "text": "text to input (for text actions)",
    "timeout_ms": 2500,
    "confidence": 0.0-1.0
  },
  "learning": {
    "state_patterns": [
      {
        "state": "STATE_NAME",
        "xpath": "//node[@text='button text']",
        "confidence": 0.0-1.0,
        "element_text": "button text",
        "element_id": "element_id",
        "content_desc": "content description"
      }
    ],
    "route_adjustments": [],
    "new_discovered_states": [],
    "failed_patterns": []
  }
}

Common MaynDrive states: CLEAN, CONSENT, MAIN_MAP_LOGGED_OUT, LOGIN_FLOW, MAIN_MAP_LOGGED_IN, QR_SCANNER, SELECT_VEHICLE, UNLOCK, ERROR_DIALOG, SAFETY_RULES, LOCATION_PERMISSION, etc.

Be precise in your analysis and provide actionable recommendations. Always include fallback coordinates for tap actions."""

    def _build_user_prompt(self, request: LLMSupervisorRequest) -> str:
        """Build user prompt from supervisor request"""
        prompt = f"""Goal: {request.goal}
Expected State: {request.expected_state or 'Any'}
Current Step: {request.current_step}/{request.max_steps}

Recent History:
"""
        for i, entry in enumerate(request.history[-5:]):  # Last 5 actions
            prompt += f"{i+1}. State: {entry.state} -> Action: {entry.action.value}"
            if not entry.success:
                prompt += " (FAILED)"
            prompt += f" (confidence: {entry.confidence:.2f})\n"

        prompt += f"""
Current UI XML Analysis:
{self._compress_xml(request.ui.xml)}

Interactive Elements Found:
{json.dumps(request.ui.interactive_elements, indent=2)}

Text Elements:
{', '.join(request.ui.text_elements[:20])}  # Limit text elements

State Graph Context:
{json.dumps(request.state_graph, indent=2)[:1000]}...

Available Routes:
{json.dumps(request.routes, indent=2)[:1000]}...

Please analyze this state and recommend the next action following the JSON schema exactly."""

        return prompt

    def analyze_ui_state(self, request: LLMSupervisorRequest) -> LLMSupervisorResponse:
        """
        Send request to GLM-4.6 for UI state analysis

        Args:
            request: Supervisor request with UI data and context

        Returns:
            LLMSupervisorResponse with analysis and recommendations
        """
        try:
            # Validate input
            LLMSupervisorRequest(**request.model_dump())

            # Build messages for the API
            messages = [
                {"role": "system", "content": self._build_system_prompt()},
                {"role": "user", "content": self._build_user_prompt(request)}
            ]

            # Prepare API request
            api_request = {
                "model": self.model,
                "messages": messages,
                "temperature": 0.1,  # Low temperature for consistent responses
                "max_tokens": 2000,  # Reasonable limit for JSON response
                "stream": False
            }

            logger.info(f"Sending request to GLM-4.6 for goal: {request.goal}")

            # Make API call
            response = self.session.post(
                f"{self.base_url}/chat/completions",
                json=api_request,
                timeout=30
            )

            response.raise_for_status()
            api_response = response.json()

            # Extract content
            content = api_response["choices"][0]["message"]["content"]

            # Parse JSON response
            try:
                # Extract JSON from content (in case there's extra text)
                json_start = content.find('{')
                json_end = content.rfind('}') + 1

                if json_start == -1 or json_end == 0:
                    raise ValueError("No JSON found in response")

                json_content = content[json_start:json_end]
                response_data = json.loads(json_content)

                # Validate response schema
                is_valid, error = validate_json_schema(response_data, LLMSupervisorResponse.model_json_schema())
                if not is_valid:
                    logger.error(f"Invalid response schema: {error}")
                    # Try to repair with a retry
                    return self._repair_response(request, response_data, error)

                response_obj = LLMSupervisorResponse(**response_data)
                logger.info(f"GLM-4.6 analysis complete. State: {response_obj.analysis.detected_state}, "
                          f"Action: {response_obj.recommendation.type.value}")

                return response_obj

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                logger.error(f"Raw content: {content}")
                return self._create_fallback_response(request, f"JSON parse error: {e}")

        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return self._create_fallback_response(request, f"API error: {e}")

        except Exception as e:
            logger.error(f"Unexpected error in GLM analysis: {e}")
            return self._create_fallback_response(request, f"Unexpected error: {e}")

    def _repair_response(self, request: LLMSupervisorRequest,
                        invalid_response: Dict[str, Any], error: str) -> LLMSupervisorResponse:
        """Attempt to repair an invalid response by making a follow-up request"""
        try:
            repair_messages = [
                {"role": "system", "content": self._build_system_prompt()},
                {"role": "user", "content": self._build_user_prompt(request)},
                {"role": "assistant", "content": json.dumps(invalid_response, indent=2)},
                {"role": "user", "content": f"Your response is invalid. Error: {error}. Please fix it and return valid JSON only."}
            ]

            api_request = {
                "model": self.model,
                "messages": repair_messages,
                "temperature": 0.1,
                "max_tokens": 2000,
                "stream": False
            }

            response = self.session.post(
                f"{self.base_url}/chat/completions",
                json=api_request,
                timeout=20
            )

            response.raise_for_status()
            api_response = response.json()
            content = api_response["choices"][0]["message"]["content"]

            # Extract and validate JSON
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            json_content = content[json_start:json_end]
            response_data = json.loads(json_content)

            return LLMSupervisorResponse(**response_data)

        except Exception as e:
            logger.error(f"Failed to repair response: {e}")
            return self._create_fallback_response(request, f"Repair failed: {e}")

    def _create_fallback_response(self, request: LLMSupervisorRequest, error_reason: str) -> LLMSupervisorResponse:
        """Create a safe fallback response when LLM analysis fails"""
        from schemas import StateAnalysis, AlignmentCheck, RecommendedAction, LearningUpdate

        fallback_analysis = StateAnalysis(
            detected_state="UNKNOWN",
            confidence=0.1,
            notes=f"LLM analysis failed: {error_reason}. Using fallback detection.",
            alternative_states=[]
        )

        fallback_alignment = AlignmentCheck(
            is_expected=False,
            reason=f"LLM analysis unavailable: {error_reason}",
            deviation_severity="high",
            recovery_suggested="Retry UI capture or use manual intervention"
        )

        fallback_action = RecommendedAction(
            type="wait",
            timeout_ms=5000,
            confidence=0.1,
            desc="Fallback wait due to LLM failure"
        )

        fallback_learning = LearningUpdate()

        return LLMSupervisorResponse(
            analysis=fallback_analysis,
            alignment=fallback_alignment,
            recommendation=fallback_action,
            learning=fallback_learning
        )

    def test_connection(self) -> bool:
        """Test connection to GLM API"""
        try:
            test_request = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Respond with JSON: {\"status\": \"ok\", \"message\": \"test\"}"}
                ],
                "temperature": 0.1,
                "max_tokens": 100
            }

            response = self.session.post(
                f"{self.base_url}/chat/completions",
                json=test_request,
                timeout=10
            )

            if response.status_code == 200:
                logger.info("GLM API connection test successful")
                return True
            else:
                logger.error(f"GLM API test failed with status: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"GLM API connection test failed: {e}")
            return False

if __name__ == "__main__":
    # Test the GLM client
    client = GLMClient()

    # Test connection
    if client.test_connection():
        print("✅ GLM client connection test passed")
    else:
        print("❌ GLM client connection test failed")