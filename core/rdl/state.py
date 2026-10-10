"""Generic state-transition analysis and normalized lifetime events."""

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Tuple


@dataclass(frozen=True)
class StateEvent:
    event: str
    object_id: str
    entity_id: str
    function_id: str
    sequence: int
    location: object
    detail: str = ""
    call_path: Tuple[str, ...] = ()


@dataclass(frozen=True)
class StateStep:
    event: StateEvent
    before: str
    after: str
    violation: bool = False


@dataclass(frozen=True)
class StateTrace:
    object_id: str
    initial_state: str
    steps: Tuple[StateStep, ...]

    @property
    def violation(self):
        return next((step for step in self.steps if step.violation), None)


class StateMachineAnalyzer:
    """Executes an RDL-declared machine over identity-preserving event streams."""

    def __init__(self, max_events=100000, max_objects=50000):
        self.max_events = max_events
        self.max_objects = max_objects

    def evaluate(self, planned_state, events: Iterable[StateEvent]) -> Tuple[Optional[StateTrace], bool]:
        ordered = sorted(events, key=lambda item: (item.function_id, item.sequence))
        if len(ordered) > self.max_events:
            return None, True
        objects: Dict[str, list] = {}
        for event in ordered:
            objects.setdefault(event.object_id, []).append(event)
        if len(objects) > self.max_objects:
            return None, True
        transitions = {(event, source): target for event, source, target in planned_state.transitions}
        violations = {(event, state) for event, state in planned_state.violations}
        for object_id, object_events in objects.items():
            state = planned_state.initial_state
            steps = []
            for event in object_events:
                if (event.event, state) in violations:
                    steps.append(StateStep(event, state, state, True))
                    return StateTrace(object_id, planned_state.initial_state, tuple(steps)), False
                next_state = transitions.get((event.event, state), state)
                steps.append(StateStep(event, state, next_state))
                state = next_state
        return None, False
