"""Lightweight Source & Endpoint-Aware Rate Limiter Module (Phase 3).

Supports:
- Per-source IP rate limiting
- Endpoint-aware path rate limits (e.g. login, expensive operations)
- In-memory sliding window request tracking
"""

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple


class RateLimiter:
    """Enforces source-based and endpoint-aware rate limits."""

    def __init__(
        self,
        default_per_ip_limit: int = 20,
        window_seconds: float = 1.0,
        endpoint_limits: Optional[Dict[str, int]] = None,
    ):
        self.default_per_ip_limit = default_per_ip_limit
        self.window_seconds = window_seconds
        self.endpoint_limits = endpoint_limits or {
            "/api/login": 5,
            "/api/expensive-operation": 5,
        }

        # (client_ip) -> deque of timestamps
        self._ip_history: Dict[str, Deque[float]] = defaultdict(deque)
        # (client_ip, endpoint_path) -> deque of timestamps
        self._endpoint_history: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

    def is_rate_limited(self, client_ip: str, endpoint: str) -> Tuple[bool, Optional[str]]:
        """Check if request exceeds source or endpoint rate limit."""
        now = time.time()
        cutoff = now - self.window_seconds

        # 1. Clean & check per-IP limit
        ip_deque = self._ip_history[client_ip]
        while ip_deque and ip_deque[0] < cutoff:
            ip_deque.popleft()

        if len(ip_deque) >= self.default_per_ip_limit:
            return True, f"Global IP rate limit exceeded ({len(ip_deque)} req/s > max {self.default_per_ip_limit})"

        # 2. Clean & check per-endpoint limit (matching path base)
        normalized_endpoint = endpoint.split("?")[0].rstrip("/") or "/"
        endpoint_limit = self.endpoint_limits.get(normalized_endpoint)

        if endpoint_limit:
            ep_key = (client_ip, normalized_endpoint)
            ep_deque = self._endpoint_history[ep_key]
            while ep_deque and ep_deque[0] < cutoff:
                ep_deque.popleft()

            if len(ep_deque) >= endpoint_limit:
                return True, f"Endpoint rate limit exceeded on '{normalized_endpoint}' ({len(ep_deque)} req/s > max {endpoint_limit})"

        # Record attempt
        ip_deque.append(now)
        if endpoint_limit:
            self._endpoint_history[(client_ip, normalized_endpoint)].append(now)

        return False, None

    def clear(self) -> None:
        """Clear rate limiting history."""
        self._ip_history.clear()
        self._endpoint_history.clear()
