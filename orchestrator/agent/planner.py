#!/usr/bin/env python3
"""
LLM-based Planner with A* Pathfinding

Uses GLM-4.6 to analyze UI states and plan actions to reach goals.
Integrates with the state graph for path planning.
"""

import json
import logging
import heapq
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from llm_client import GLMClient

logger = logging.getLogger(__name__)


@dataclass
class PlannedAction:
    """An action planned by the LLM"""
    type: str  # tap, text, back, etc.
    selector_hint: Optional[str]
    fallback: Optional[Dict]
    text: Optional[str]
    timeout_ms: int
    confidence: float
    reasoning: str  # Why this action was chosen


class LLMPlanner:
    """
    LLM-driven planner that analyzes UI and decides next actions
    """

    def __init__(self, llm_client: Optional[GLMClient] = None):
        """
        Args:
            llm_client: GLM client instance (creates one if not provided)
        """
        self.llm_client = llm_client or GLMClient()

    def plan_next_action(self, current_state_digest: Dict, goal: str,
                         history: List[Dict], routes: Dict) -> PlannedAction:
        """
        Plan the next action to take toward a goal

        Args:
            current_state_digest: Compact state representation
            goal: User goal (e.g., "Unlock vehicle", "Login")
            history: Recent actions taken
            routes: Known routes from state graph

        Returns:
            PlannedAction
        """
        try:
            # Build prompt
            prompt = self._build_planning_prompt(
                current_state_digest,
                goal,
                history,
                routes
            )

            # Get LLM response
            response = self._query_llm(prompt)

            # Parse action from response
            action = self._parse_action_response(response)

            return action

        except Exception as e:
            logger.error(f"Planning failed: {e}", exc_info=True)
            # Fallback: wait action
            return PlannedAction(
                type="wait",
                selector_hint=None,
                fallback=None,
                text=None,
                timeout_ms=2000,
                confidence=0.1,
                reasoning=f"Planning failed: {e}"
            )

    def _build_planning_prompt(self, state_digest: Dict, goal: str,
                              history: List[Dict], routes: Dict) -> str:
        """Build prompt for LLM planner"""
        prompt = f"""You are an intelligent UI automation planner. Analyze the current app state and plan the next action to achieve the goal.

**Goal**: {goal}

**Current State**:
- State ID: {state_digest.get('state_id', 'unknown')}
- Package: {state_digest.get('package', 'unknown')}
- Activity: {state_digest.get('activity', 'unknown')}

**Visible Texts**:
{json.dumps(state_digest.get('dominant_texts', []), indent=2)}

**Interactive Controls**:
{json.dumps(state_digest.get('key_controls', [])[:10], indent=2)}

**Recent Actions** (last 5):
{json.dumps(history[-5:], indent=2)}

**Known Routes to Goal**:
{json.dumps(routes, indent=2)[:500]}...

**Task**: Analyze the UI and decide the BEST next action to progress toward the goal.

**Response Format** (JSON only):
{{
  "reasoning": "Explain what you see and why this action makes sense",
  "action": {{
    "type": "tap|text|back|home|swipe|wait",
    "selector_hint": "resource-id:foo" or "text:Button" or "content-desc:Submit",
    "fallback": {{"x": 540, "y": 1000}},
    "text": "text to input (if type=text)",
    "timeout_ms": 1000,
    "confidence": 0.0-1.0
  }}
}}

**Action Guidelines**:
1. **Prefer selectors** (resource-id, text, content-desc) over coordinates
2. **Always include fallback coordinates** for tap actions
3. **Check recent history** to avoid repeating failed actions
4. **Use known routes** if available to speed up navigation
5. **If stuck**, try back button or different approach
6. **Be patient**: sometimes UI needs time to load (use wait)

Respond with JSON only:"""

        return prompt

    def _query_llm(self, prompt: str) -> Dict:
        """Query GLM-4.6 for planning"""
        try:
            messages = [
                {"role": "system", "content": "You are an expert UI automation planner. Always respond with valid JSON."},
                {"role": "user", "content": prompt}
            ]

            request = {
                "model": self.llm_client.model,
                "messages": messages,
                "temperature": 0.2,  # Low temp for consistent planning
                "max_tokens": 1000
            }

            response = self.llm_client.session.post(
                f"{self.llm_client.base_url}/chat/completions",
                json=request,
                timeout=30
            )

            response.raise_for_status()
            data = response.json()

            content = data["choices"][0]["message"]["content"]

            # Extract JSON from content
            json_start = content.find('{')
            json_end = content.rfind('}') + 1

            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON in LLM response")

            json_str = content[json_start:json_end]
            return json.loads(json_str)

        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            raise

    def _parse_action_response(self, response: Dict) -> PlannedAction:
        """Parse LLM response into PlannedAction"""
        reasoning = response.get("reasoning", "No reasoning provided")
        action_data = response.get("action", {})

        return PlannedAction(
            type=action_data.get("type", "wait"),
            selector_hint=action_data.get("selector_hint"),
            fallback=action_data.get("fallback"),
            text=action_data.get("text"),
            timeout_ms=action_data.get("timeout_ms", 1000),
            confidence=action_data.get("confidence", 0.5),
            reasoning=reasoning
        )


class PathPlanner:
    """
    A* path planning using the state graph
    """

    def __init__(self, state_graph: Dict, edges: Dict):
        """
        Args:
            state_graph: Dict of state_id -> state_data
            edges: Dict of (from, to) -> edge_data
        """
        self.state_graph = state_graph
        self.edges = edges

    def find_path(self, start_state: str, goal_state: str) -> Optional[List[Dict]]:
        """
        Find shortest path from start to goal using A*

        Returns:
            List of actions to take, or None if no path found
        """
        if start_state == goal_state:
            return []

        if start_state not in self.state_graph or goal_state not in self.state_graph:
            logger.warning(f"States not in graph: {start_state}, {goal_state}")
            return None

        # A* search
        open_set = []
        heapq.heappush(open_set, (0, start_state))

        came_from = {}
        g_score = {start_state: 0}
        f_score = {start_state: self._heuristic(start_state, goal_state)}

        while open_set:
            _, current = heapq.heappop(open_set)

            if current == goal_state:
                return self._reconstruct_path(came_from, current)

            # Explore neighbors
            for (from_state, to_state), edge in self.edges.items():
                if from_state != current:
                    continue

                # Cost is based on edge success rate and latency
                cost = self._edge_cost(edge)
                tentative_g = g_score[current] + cost

                if to_state not in g_score or tentative_g < g_score[to_state]:
                    came_from[to_state] = (current, edge)
                    g_score[to_state] = tentative_g
                    f = tentative_g + self._heuristic(to_state, goal_state)
                    f_score[to_state] = f
                    heapq.heappush(open_set, (f, to_state))

        logger.warning(f"No path found from {start_state} to {goal_state}")
        return None

    def _heuristic(self, state1: str, state2: str) -> float:
        """
        Heuristic for A* (estimated cost to goal)
        Simple: constant, since we don't have spatial info
        """
        return 1.0 if state1 != state2 else 0.0

    def _edge_cost(self, edge: Dict) -> float:
        """
        Calculate cost of traversing an edge
        Lower cost = better (more reliable, faster)
        """
        success_count = edge.get("success_count", 0)
        fail_count = edge.get("fail_count", 0)
        latency = edge.get("avg_latency_ms", 1000)

        if success_count == 0:
            return 10.0  # High cost for untried edges

        success_rate = success_count / (success_count + fail_count)
        latency_factor = latency / 1000.0

        # Cost combines reliability and speed
        cost = (1.0 - success_rate) * 5.0 + latency_factor

        return max(0.1, cost)  # Minimum cost

    def _reconstruct_path(self, came_from: Dict, current: str) -> List[Dict]:
        """Reconstruct path of actions from came_from map"""
        path = []

        while current in came_from:
            prev_state, edge = came_from[current]
            path.insert(0, edge.get("action", {}))
            current = prev_state

        return path


def find_best_route(state_graph: Dict, edges: Dict, current_state: str,
                    goal: str) -> Optional[List[Dict]]:
    """
    Find best route to accomplish a goal from current state

    Args:
        state_graph: State graph
        edges: Edge graph
        current_state: Current state ID
        goal: Goal string (LOGIN, UNLOCK_VEHICLE, etc.)

    Returns:
        List of actions, or None
    """
    # Map goals to target state patterns
    goal_patterns = {
        "LOGIN": ["LOGIN_FORM", "MAIN_MAP_LOGGED_IN"],
        "UNLOCK_VEHICLE": ["QR_SCANNER", "SELECT_VEHICLE", "UNLOCK"],
        "RENTAL": ["QR_SCANNER", "SELECT_VEHICLE"],
        "MAP_ACCESS": ["MAIN_MAP_LOGGED_IN", "MAIN_MAP_LOGGED_OUT"]
    }

    target_states = goal_patterns.get(goal, [])
    if not target_states:
        logger.warning(f"Unknown goal: {goal}")
        return None

    # Find closest target state
    planner = PathPlanner(state_graph, edges)
    best_path = None
    best_cost = float('inf')

    for target in target_states:
        # Find states matching this pattern
        matching_states = [
            sid for sid, state in state_graph.items()
            if target in state.get("activity", "") or target in str(state)
        ]

        for target_state in matching_states:
            path = planner.find_path(current_state, target_state)
            if path is not None:
                cost = len(path)
                if cost < best_cost:
                    best_cost = cost
                    best_path = path

    return best_path
