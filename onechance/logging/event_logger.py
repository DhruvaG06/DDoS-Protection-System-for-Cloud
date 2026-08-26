"""Security Event Logger & Buffer Module (Phase 3).

Stores, buffers, and persists security events for real-time dashboard telemetry.
"""

import json
from collections import deque
from pathlib import Path
from typing import Deque, List, Optional

from onechance.config import settings
from onechance.models.events import SecurityEvent


class SecurityEventLogger:
    """Buffers security events in-memory and appends to disk log."""

    def __init__(self, log_path: Optional[Path] = None, buffer_size: int = 1000):
        self.log_path = log_path or Path("logs/security_events.jsonl")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.buffer_size = buffer_size
        self._event_buffer: Deque[SecurityEvent] = deque(maxlen=buffer_size)

    def log_event(self, event: SecurityEvent) -> None:
        """Add event to buffer and append to jsonl log file."""
        self._event_buffer.append(event)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
        except Exception:
            pass

    def get_recent_events(
        self,
        limit: int = 50,
        decision_filter: Optional[str] = None,
        source_filter: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Retrieve recent security events from buffer."""
        events = list(self._event_buffer)
        if decision_filter:
            events = [e for e in events if e.decision.value.upper() == decision_filter.upper()]
        if source_filter:
            events = [e for e in events if e.source == source_filter]
        
        # Return latest first
        return list(reversed(events))[:limit]

    def clear(self) -> None:
        """Clear memory buffer."""
        self._event_buffer.clear()
