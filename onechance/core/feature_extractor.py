"""Behavioral Feature Extraction Interface & Module.

Extracts multi-dimensional behavioral signals from raw incoming requests over sliding time windows:
- Request Rate
- Endpoint Concentration / Entropy
- Burstiness Score
- Repeated Pattern Score
- Source Distribution (External vs Internal Compromised Workload)
"""

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple
from onechance.models.traffic import AttackSourceType, IncomingRequest, TrafficFeatures


class FeatureExtractor:
    """Extracts behavioral traffic metrics per client IP over rolling time windows."""

    def __init__(self, window_duration_seconds: float = 10.0):
        self.window_duration_seconds = window_duration_seconds
        # client_ip -> deque of (timestamp, path, method)
        self._request_history: Dict[str, Deque[Tuple[float, str, str]]] = defaultdict(deque)

    def record_request(self, request: IncomingRequest) -> None:
        """Record an incoming request in the sliding window buffer."""
        now = request.timestamp or time.time()
        queue = self._request_history[request.client_ip]
        queue.append((now, request.path, request.method))
        self._prune(request.client_ip, now)

    def _prune(self, client_ip: str, current_time: float) -> None:
        """Remove requests outside the rolling window."""
        queue = self._request_history[client_ip]
        cutoff = current_time - self.window_duration_seconds
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def extract_features(self, request: IncomingRequest) -> TrafficFeatures:
        """Extract behavioral features for the specified client IP.

        NOTE: In Phase 0, this provides the interface and basic sliding-window feature
        placeholders. Advanced statistical entropy and ML feature processing are refined in Phase 1.
        """
        now = request.timestamp or time.time()
        self.record_request(request)
        queue = self._request_history[request.client_ip]

        total_requests = len(queue)
        request_rate = total_requests / max(self.window_duration_seconds, 1.0)

        # Baseline placeholders for entropy & burstiness
        endpoint_counts: Dict[str, int] = defaultdict(int)
        for _, path, _ in queue:
            endpoint_counts[path] += 1

        # Placeholder entropy calculation (uniform vs single endpoint concentration)
        distinct_endpoints = len(endpoint_counts)
        endpoint_entropy = float(distinct_endpoints / max(total_requests, 1))

        # Placeholder burstiness metric (requests in last 1 second vs average window rate)
        one_sec_cutoff = now - 1.0
        burst_count = sum(1 for ts, _, _ in queue if ts >= one_sec_cutoff)
        burstiness_score = float(burst_count / max(request_rate, 1.0))

        return TrafficFeatures(
            client_ip=request.client_ip,
            request_rate_per_sec=round(request_rate, 2),
            endpoint_entropy=round(endpoint_entropy, 3),
            burstiness_score=round(burstiness_score, 2),
            error_rate=0.0,
            repeated_pattern_score=0.0,
            source_type=request.source_type or AttackSourceType.EXTERNAL,
            window_duration_seconds=self.window_duration_seconds,
        )
