#!/usr/bin/env python3
"""
Learning and adaptation system.
Handles persistence and merging of learned patterns and route adjustments.
"""

import os
import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime
import statistics

from schemas import StatePattern, RouteAdjustment, LearningUpdate

logger = logging.getLogger(__name__)

@dataclass
class TransitionMetrics:
    """Metrics for state transitions"""
    from_state: str
    to_state: str
    action: str
    success_count: int = 0
    failure_count: int = 0
    total_attempts: int = 0
    avg_execution_time_ms: float = 0.0
    last_attempt: float = 0.0
    confidence_score: float = 1.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_attempts == 0:
            return 0.0
        return self.success_count / self.total_attempts

    def update_success(self, execution_time_ms: float):
        """Update metrics on successful execution"""
        self.success_count += 1
        self.total_attempts += 1
        self.last_attempt = time.time()

        # Update average execution time
        if self.success_count == 1:
            self.avg_execution_time_ms = execution_time_ms
        else:
            self.avg_execution_time_ms = (
                (self.avg_execution_time_ms * (self.success_count - 1) + execution_time_ms) / self.success_count
            )

    def update_failure(self):
        """Update metrics on failed execution"""
        self.failure_count += 1
        self.total_attempts += 1
        self.last_attempt = time.time()

    def calculate_confidence(self) -> float:
        """Calculate confidence score based on metrics"""
        if self.total_attempts < 3:
            return 0.5  # Low confidence with few attempts

        success_rate_weight = 0.7
        recency_weight = 0.3

        # Success rate component
        success_component = min(1.0, self.success_rate * 1.2)  # Boost good rates slightly

        # Recency component (more recent attempts get higher weight)
        hours_since_last = (time.time() - self.last_attempt) / 3600
        recency_component = max(0.3, 1.0 - (hours_since_last / 24))  # Decay over 24 hours

        confidence = (success_component * success_rate_weight) + (recency_component * recency_weight)
        return min(1.0, max(0.0, confidence))

@dataclass
class LearnedPattern:
    """Learned UI state pattern"""
    state_name: str
    xpath: str
    confidence: float = 1.0
    occurrence_count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0
    elements: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.first_seen == 0.0:
            self.first_seen = time.time()
        if self.last_seen == 0.0:
            self.last_seen = time.time()
        if self.elements is None:
            self.elements = []

    def add_occurrence(self, elements: List[Dict[str, Any]]):
        """Add occurrence of this pattern"""
        self.occurrence_count += 1
        self.last_seen = time.time()
        if elements:
            self.elements.extend(elements)

        # Update confidence based on frequency
        if self.occurrence_count > 1:
            self.confidence = min(1.0, self.occurrence_count / 5.0)  # Approaches 1.0 after 5 occurrences

class LearningManager:
    """Manages learning and adaptation for automation"""

    def __init__(self, learning_dir: str = "storage/learning"):
        self.learning_dir = Path(learning_dir)
        self.learning_dir.mkdir(parents=True, exist_ok=True)

        # Learning data
        self.transition_metrics: Dict[str, TransitionMetrics] = {}
        self.learned_patterns: Dict[str, LearnedPattern] = {}
        self.route_success_rates: Dict[str, float] = {}
        self.failed_patterns: List[Dict[str, Any]] = []

        # Load existing learning data
        self._load_learning_data()

        logger.info(f"Learning manager initialized with {len(self.learned_patterns)} patterns")

    def _load_learning_data(self):
        """Load existing learning data from files"""
        try:
            # Load transition metrics
            metrics_file = self.learning_dir / "transition_metrics.json"
            if metrics_file.exists():
                with open(metrics_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for key, metrics_data in data.items():
                        self.transition_metrics[key] = TransitionMetrics(**metrics_data)

            # Load learned patterns
            patterns_file = self.learning_dir / "learned_patterns.json"
            if patterns_file.exists():
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for key, pattern_data in data.items():
                        self.learned_patterns[key] = LearnedPattern(**pattern_data)

            # Load route success rates
            routes_file = self.learning_dir / "route_success_rates.json"
            if routes_file.exists():
                with open(routes_file, 'r', encoding='utf-8') as f:
                    self.route_success_rates = json.load(f)

            # Load failed patterns
            failed_file = self.learning_dir / "failed_patterns.json"
            if failed_file.exists():
                with open(failed_file, 'r', encoding='utf-8') as f:
                    self.failed_patterns = json.load(f)

            logger.info(f"Loaded learning data: {len(self.transition_metrics)} transitions, "
                       f"{len(self.learned_patterns)} patterns, {len(self.route_success_rates)} routes")

        except Exception as e:
            logger.error(f"Failed to load learning data: {e}")

    def save_learning_data(self):
        """Save current learning data to files"""
        try:
            # Save transition metrics
            metrics_data = {}
            for key, metrics in self.transition_metrics.items():
                metrics_data[key] = asdict(metrics)

            metrics_file = self.learning_dir / "transition_metrics.json"
            with open(metrics_file, 'w', encoding='utf-8') as f:
                json.dump(metrics_data, f, indent=2, ensure_ascii=False)

            # Save learned patterns
            patterns_data = {}
            for key, pattern in self.learned_patterns.items():
                patterns_data[key] = asdict(pattern)

            patterns_file = self.learning_dir / "learned_patterns.json"
            with open(patterns_file, 'w', encoding='utf-8') as f:
                json.dump(patterns_data, f, indent=2, ensure_ascii=False)

            # Save route success rates
            routes_file = self.learning_dir / "route_success_rates.json"
            with open(routes_file, 'w', encoding='utf-8') as f:
                json.dump(self.route_success_rates, f, indent=2, ensure_ascii=False)

            # Save failed patterns
            failed_file = self.learning_dir / "failed_patterns.json"
            with open(failed_file, 'w', encoding='utf-8') as f:
                json.dump(self.failed_patterns, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved learning data to {self.learning_dir}")

        except Exception as e:
            logger.error(f"Failed to save learning data: {e}")

    def update_transition_metrics(self, from_state: str, to_state: str, action: str,
                              success: bool, execution_time_ms: float = 0.0):
        """Update transition metrics based on execution result"""
        key = f"{from_state}->{to_state}:{action}"

        if key not in self.transition_metrics:
            self.transition_metrics[key] = TransitionMetrics(
                from_state=from_state,
                to_state=to_state,
                action=action
            )

        metrics = self.transition_metrics[key]

        if success:
            metrics.update_success(execution_time_ms)
        else:
            metrics.update_failure()

        # Update confidence score
        metrics.confidence_score = metrics.calculate_confidence()

        logger.debug(f"Updated transition {key}: success_rate={metrics.success_rate:.2f}, "
                    f"confidence={metrics.confidence_score:.2f}")

    def add_learned_pattern(self, state_name: str, xpath: str,
                          elements: List[Dict[str, Any]] = None,
                          confidence: float = 1.0):
        """Add or update a learned UI pattern"""
        if state_name not in self.learned_patterns:
            self.learned_patterns[state_name] = LearnedPattern(
                state_name=state_name,
                xpath=xpath,
                confidence=confidence,
                elements=elements or []
            )
        else:
            pattern = self.learned_patterns[state_name]
            pattern.add_occurrence(elements or [])

        logger.info(f"Added/updated learned pattern for state: {state_name}")

    def add_route_success_rate(self, route_name: str, success: bool):
        """Update route success rate"""
        if route_name not in self.route_success_rates:
            self.route_success_rates[route_name] = 0.5  # Start with neutral

        current_rate = self.route_success_rates[route_name]

        # Exponential moving average with alpha=0.2
        new_rate = (current_rate * 0.8) + (1.0 if success else 0.0) * 0.2
        self.route_success_rates[route_name] = new_rate

        logger.debug(f"Updated route {route_name} success rate: {new_rate:.2f}")

    def add_failed_pattern(self, state_name: str, pattern: str, error: str):
        """Record a failed pattern for analysis"""
        failed_entry = {
            'timestamp': time.time(),
            'state_name': state_name,
            'pattern': pattern,
            'error': error,
            'occurrence_count': 1
        }

        # Check if this pattern has failed before
        for existing in self.failed_patterns:
            if (existing['state_name'] == state_name and
                existing['pattern'] == pattern):
                existing['occurrence_count'] += 1
                existing['timestamp'] = time.time()
                break
        else:
            self.failed_patterns.append(failed_entry)

        # Keep only recent failures (last 100)
        self.failed_patterns.sort(key=lambda x: x['timestamp'], reverse=True)
        self.failed_patterns = self.failed_patterns[:100]

        logger.warning(f"Recorded failed pattern for {state_name}: {error}")

    def get_best_transition(self, from_state: str, to_state: str,
                         possible_actions: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Get the best transition action based on learned metrics"""
        best_action = None
        best_score = 0.0

        for action in possible_actions:
            key = f"{from_state}->{to_state}:{action.get('type', 'unknown')}"

            if key in self.transition_metrics:
                metrics = self.transition_metrics[key]

                # Score based on success rate and confidence
                score = metrics.success_rate * metrics.confidence_score

                # Prefer faster actions for equal success rates
                if metrics.avg_execution_time_ms > 0:
                    speed_bonus = min(1.0, 5000.0 / metrics.avg_execution_time_ms)
                    score *= speed_bonus

                if score > best_score:
                    best_score = score
                    best_action = action
                    best_action['learned_confidence'] = metrics.confidence_score
                    best_action['learned_success_rate'] = metrics.success_rate

        return best_action

    def get_state_patterns(self, state_name: str) -> List[StatePattern]:
        """Get all learned patterns for a state"""
        patterns = []

        if state_name in self.learned_patterns:
            learned = self.learned_patterns[state_name]

            pattern = StatePattern(
                state_name=state_name,
                xpath=learned.xpath,
                confidence=learned.confidence,
                alternative_patterns=[p['xpath'] for p in self.learned_patterns.values()
                                 if p.state_name != state_name][:3]  # Top 3 alternatives
            )
            patterns.append(pattern)

        return patterns

    def get_learning_update(self) -> LearningUpdate:
        """Get learning update for current session"""
        state_patterns = []
        for state_name, pattern in self.learned_patterns.items():
            if pattern.confidence > 0.7:  # Only include high-confidence patterns
                state_patterns.append(StatePattern(
                    state_name=state_name,
                    xpath=pattern.xpath,
                    confidence=pattern.confidence
                ))

        route_adjustments = []
        for key, metrics in self.transition_metrics.items():
            if metrics.total_attempts >= 3 and metrics.success_rate < 0.5:
                # This transition has poor performance
                parts = key.split(':')
                if len(parts) == 2:
                    transition_part = parts[0]
                    action_part = parts[1]

                    if '->' in transition_part:
                        from_state, to_state = transition_part.split('->')

                        route_adjustments.append(RouteAdjustment(
                            from_state=from_state,
                            to_state=to_state,
                            original_action={'type': action_part},
                            adjusted_action={'type': 'fallback', 'recommendation': 'Use alternative navigation'},
                            reason=f"Low success rate: {metrics.success_rate:.2f}",
                            success_rate=metrics.success_rate
                        ))

        new_discovered_states = [
            state for state in self.learned_patterns.keys()
            if state not in ['CLEAN', 'MAIN_MAP_LOGGED_OUT', 'LOGIN_FORM']  # Exclude common states
        ]

        return LearningUpdate(
            state_patterns=state_patterns,
            route_adjustments=route_adjustments,
            new_discovered_states=new_discovered_states,
            failed_patterns=self.failed_patterns[-10:]  # Last 10 failures
        )

    def merge_session_learning(self, session_dir: str):
        """Merge learning data from a completed session"""
        try:
            session_path = Path(session_dir)
            summary_file = session_path / "session_summary.json"

            if not summary_file.exists():
                logger.warning(f"No session summary found in {session_dir}")
                return

            with open(summary_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)

            # Extract learning from session
            goal = session_data.get('session_info', {}).get('goal', 'UNKNOWN')
            final_state = session_data.get('final_state', 'UNKNOWN')
            total_steps = session_data.get('total_steps', 0)
            goal_achieved = session_data.get('goal_achieved', False)

            # Update route success rate
            route_mapping = {
                'UNLOCK_VEHICLE': 'CLEAN_TO_UNLOCK',
                'LOGIN': 'CLEAN_TO_MAP',
                'SIGNUP': 'SIGNUP_FLOW',
                'RENTAL': 'RENTAL_FLOW'
            }

            route_name = route_mapping.get(goal.upper())
            if route_name:
                self.add_route_success_rate(route_name, goal_achieved)

            # Process step data
            steps_file = session_path / "session_info.json"
            if steps_file.exists():
                # This would contain step-by-step learning data
                pass  # Implementation for detailed step learning

            logger.info(f"Merged learning from session: {session_dir}, "
                       f"goal: {goal}, achieved: {goal_achieved}")

        except Exception as e:
            logger.error(f"Failed to merge session learning: {e}")

    def generate_learning_report(self) -> Dict[str, Any]:
        """Generate comprehensive learning report"""
        try:
            report = {
                'timestamp': time.time(),
                'summary': {
                    'total_patterns': len(self.learned_patterns),
                    'total_transitions': len(self.transition_metrics),
                    'total_routes': len(self.route_success_rates),
                    'failed_patterns_count': len(self.failed_patterns)
                },
                'top_performing_transitions': [],
                'problematic_transitions': [],
                'route_success_rates': self.route_success_rates.copy(),
                'recent_failures': [],
                'recommendations': []
            }

            # Find top performing transitions
            transition_scores = []
            for key, metrics in self.transition_metrics.items():
                if metrics.total_attempts >= 3:
                    transition_scores.append((key, metrics.success_rate * metrics.confidence_score))

            transition_scores.sort(key=lambda x: x[1], reverse=True)
            report['top_performing_transitions'] = [
                {'transition': key, 'score': score}
                for key, score in transition_scores[:5]
            ]

            # Find problematic transitions
            problematic = [
                {'transition': key, 'success_rate': metrics.success_rate, 'attempts': metrics.total_attempts}
                for key, metrics in self.transition_metrics.items()
                if metrics.total_attempts >= 5 and metrics.success_rate < 0.4
            ]
            report['problematic_transitions'] = problematic

            # Recent failures
            report['recent_failures'] = self.failed_patterns[:10]

            # Generate recommendations
            if problematic:
                report['recommendations'].append(
                    "Review and update problematic transitions with low success rates"
                )

            if len(self.learned_patterns) < 10:
                report['recommendations'].append(
                    "Run more discovery sessions to expand pattern recognition"
                )

            # Save report
            report_file = self.learning_dir / f"learning_report_{int(time.time())}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            logger.info(f"Generated learning report: {report_file}")
            return report

        except Exception as e:
            logger.error(f"Failed to generate learning report: {e}")
            return {}

if __name__ == "__main__":
    # Test learning manager
    learning_manager = LearningManager()

    print("Testing learning manager...")

    # Test adding a transition
    learning_manager.update_transition_metrics("LOGIN_FORM", "MAIN_MAP_LOGGED_IN", "text", True, 2000)
    learning_manager.update_transition_metrics("LOGIN_FORM", "MAIN_MAP_LOGGED_IN", "text", True, 1800)
    learning_manager.update_transition_metrics("LOGIN_FORM", "MAIN_MAP_LOGGED_IN", "text", False, 0)

    # Test adding a pattern
    learning_manager.add_learned_pattern("NEW_STATE", "//node[@text='New Button']",
                                      [{"text": "New Button", "clickable": True}])

    # Test route success rate
    learning_manager.add_route_success_rate("CLEAN_TO_UNLOCK", True)
    learning_manager.add_route_success_rate("CLEAN_TO_UNLOCK", False)
    learning_manager.add_route_success_rate("CLEAN_TO_UNLOCK", True)

    # Save learning data
    learning_manager.save_learning_data()

    print("✅ Learning manager test completed")
    print(f"📊 Transition metrics: {len(learning_manager.transition_metrics)}")
    print(f"🔍 Learned patterns: {len(learning_manager.learned_patterns)}")
    print(f"🛣️  Route success rates: {len(learning_manager.route_success_rates)}")