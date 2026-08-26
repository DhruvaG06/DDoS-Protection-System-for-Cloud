"""Structured Traffic Logging Module for OneChance Gateway."""

import json
import logging
import os
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional
from onechance.models.traffic import TrafficRecord

# Set up JSON structured traffic logger
logger = logging.getLogger("onechance.traffic")


class TrafficLogger:
    """Captures, buffers, and persists structured traffic records for telemetry & feature extraction."""

    def __init__(self, buffer_size: int = 1000, log_file_path: Optional[str] = "logs/traffic.jsonl"):
        self.buffer_size = buffer_size
        self.log_file_path = log_file_path
        self._buffer: Deque[TrafficRecord] = deque(maxlen=buffer_size)

        if self.log_file_path:
            os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)

    def log_request(
        self,
        request_id: str,
        timestamp: float,
        source: str,
        method: str,
        endpoint: str,
        user_agent: Optional[str],
        status_code: int,
        latency_ms: float,
    ) -> TrafficRecord:
        """Create, store in buffer, and output a structured traffic record."""
        record = TrafficRecord(
            request_id=request_id,
            timestamp=timestamp,
            source=source,
            method=method,
            endpoint=endpoint,
            user_agent=user_agent or "Unknown",
            status_code=status_code,
            latency_ms=round(latency_ms, 2),
        )

        # Append to in-memory buffer
        self._buffer.append(record)

        # Log as structured JSON string
        log_json = record.model_dump_json()
        logger.info(log_json)

        # Write to log file if configured
        if self.log_file_path:
            try:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    f.write(log_json + "\n")
            except Exception as e:
                logger.error(f"Failed to append to log file {self.log_file_path}: {e}")

        return record

    def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent structured logs from the buffer."""
        logs = list(self._buffer)
        if limit and limit > 0:
            logs = logs[-limit:]
        return [record.model_dump() for record in reversed(logs)]

    def get_total_logged_count(self) -> int:
        """Return number of records currently buffered."""
        return len(self._buffer)

    def clear(self) -> None:
        """Clear memory buffer."""
        self._buffer.clear()


# Global traffic logger instance
traffic_logger = TrafficLogger()
