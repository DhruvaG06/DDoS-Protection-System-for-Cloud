"""Behavioral Feature Extraction Interface & Module (Phase 2).

Extracts 10 multi-dimensional behavioral signals from raw incoming requests over sliding time windows:
1. requests_per_source
2. request_rate_per_sec
3. endpoint_concentration
4. burstiness_score
5. repeated_pattern_score
6. source_distribution_ratio
7. endpoint_distribution_ratio
8. endpoint_entropy (Shannon Entropy)
9. error_ratio (4xx/5xx HTTP errors)
10. average_latency_ms
"""

import math
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple
from onechance.models.traffic import AttackSourceType, IncomingRequest, TrafficFeatures


class RequestEntry:
    """Internal record for sliding window telemetry."""
    __slots__ = ("timestamp", "path", "method", "status_code", "latency_ms")

    def __init__(self, timestamp: float, path: str, method: str, status_code: int = 200, latency_ms: float = 0.0):
        self.timestamp = timestamp
        self.path = path
        self.method = method
        self.status_code = status_code
        self.latency_ms = latency_ms


class FeatureExtractor:
    """Extracts 10 behavioral traffic metrics per client IP over rolling time windows."""

    def __init__(self, window_duration_seconds: float = 10.0):
        self.window_duration_seconds = window_duration_seconds
        # client_ip -> deque of RequestEntry
        self._client_history: Dict[str, Deque[RequestEntry]] = defaultdict(deque)
        # Global rolling window history of (timestamp, client_ip) for source distribution calculation
        self._global_history: Deque[Tuple[float, str]] = deque()

    def record_request(self, request: IncomingRequest) -> None:
        """Record an incoming request in the sliding window buffer."""
        now = request.timestamp if request.timestamp > 0 else time.time()
        entry = RequestEntry(
            timestamp=now,
            path=request.path,
            method=request.method,
            status_code=request.status_code,
            latency_ms=request.latency_ms,
        )
        self._client_history[request.client_ip].append(entry)
        self._global_history.append((now, request.client_ip))
        self._prune(now)

    def _prune(self, current_time: float) -> None:
        """Remove requests outside the rolling window."""
        cutoff = current_time - self.window_duration_seconds
        
        # Prune global history
        while self._global_history and self._global_history[0][0] < cutoff:
            self._global_history.popleft()

        # Prune per-client history for active IPs
        empty_ips: List[str] = []
        for ip, queue in self._client_history.items():
            while queue and queue[0].timestamp < cutoff:
                queue.popleft()
            if not queue:
                empty_ips.append(ip)
        for ip in empty_ips:
            del self._client_history[ip]

    def extract_features(self, request: IncomingRequest) -> TrafficFeatures:
        """Extract all 10 behavioral features for the specified client IP."""
        now = request.timestamp if request.timestamp > 0 else time.time()
        self.record_request(request)

        queue = self._client_history[request.client_ip]
        total_client_requests = len(queue)

        if total_client_requests == 0:
            return TrafficFeatures(
                client_ip=request.client_ip,
                source_type=request.source_type or AttackSourceType.EXTERNAL,
                window_duration_seconds=self.window_duration_seconds,
            )

        # 1. Requests per source
        requests_per_source = total_client_requests

        # 2. Requests per second
        request_rate_per_sec = round(requests_per_source / max(self.window_duration_seconds, 1.0), 2)

        # Endpoint stats & counts
        endpoint_counts: Dict[str, int] = defaultdict(int)
        error_count = 0
        total_latency = 0.0

        prev_path: str = ""
        current_repeat_run = 0
        max_repeat_run = 0

        # Bins for burstiness calculation (1-second intervals)
        second_bins: Dict[int, int] = defaultdict(int)

        for entry in queue:
            endpoint_counts[entry.path] += 1
            if entry.status_code >= 400:
                error_count += 1
            total_latency += entry.latency_ms

            # 1-second binning for burstiness
            sec_bin = int(entry.timestamp)
            second_bins[sec_bin] += 1

            # Consecutive repeated pattern check
            if entry.path == prev_path:
                current_repeat_run += 1
            else:
                current_repeat_run = 1
                prev_path = entry.path
            max_repeat_run = max(max_repeat_run, current_repeat_run)

        # 3. Endpoint concentration (max requests to a single endpoint / total)
        max_endpoint_reqs = max(endpoint_counts.values()) if endpoint_counts else 0
        endpoint_concentration = round(max_endpoint_reqs / total_client_requests, 3)

        # 4. Burstiness score (peak 1-sec request count / average per-second rate)
        peak_1sec_count = max(second_bins.values()) if second_bins else total_client_requests
        avg_rate = max(request_rate_per_sec, 1.0)
        burstiness_score = round(peak_1sec_count / avg_rate, 2)

        # 5. Repeated pattern score (max consecutive identical path requests / total)
        repeated_pattern_score = round(max_repeat_run / total_client_requests, 3)

        # 6. Source distribution ratio (client requests / total global requests in window)
        total_global_requests = max(len(self._global_history), 1)
        source_distribution_ratio = round(total_client_requests / total_global_requests, 3)

        # 7. Endpoint distribution ratio (unique endpoints / total requests)
        unique_endpoints_count = len(endpoint_counts)
        endpoint_distribution_ratio = round(unique_endpoints_count / total_client_requests, 3)

        # 8. Endpoint entropy (Shannon entropy: -sum(p * log2(p)))
        entropy = 0.0
        for count in endpoint_counts.values():
            p = count / total_client_requests
            if p > 0:
                entropy -= p * math.log2(p)
        endpoint_entropy = round(entropy, 3)

        # 9. Error ratio (4xx/5xx errors / total requests)
        error_ratio = round(error_count / total_client_requests, 3)

        # 10. Average latency in ms
        average_latency_ms = round(total_latency / total_client_requests, 2)

        return TrafficFeatures(
            client_ip=request.client_ip,
            requests_per_source=requests_per_source,
            request_rate_per_sec=request_rate_per_sec,
            endpoint_concentration=endpoint_concentration,
            burstiness_score=burstiness_score,
            repeated_pattern_score=repeated_pattern_score,
            source_distribution_ratio=source_distribution_ratio,
            endpoint_distribution_ratio=endpoint_distribution_ratio,
            endpoint_entropy=endpoint_entropy,
            error_ratio=error_ratio,
            average_latency_ms=average_latency_ms,
            source_type=request.source_type or AttackSourceType.EXTERNAL,
            window_duration_seconds=self.window_duration_seconds,
        )

    def clear(self) -> None:
        """Clear rolling window traffic request buffer."""
        self._client_history.clear()
        self._global_history.clear()
