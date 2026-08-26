"""Mitigation & Policy Enforcement Module (Phase 3).

Enforces real-time access controls:
- Tracks active IP blocks with automatic timestamp-based expiration
- Manages active challenge tokens and verification states
- Tracks failed challenge verification attempts with adaptive escalation to BLOCK
"""

import time
from typing import Dict, Optional, Tuple
from onechance.config import settings
from onechance.models.decisions import ActionEnum, PolicyDecision


class Mitigator:
    """Enforces active mitigation rules and manages challenge/block tables."""

    def __init__(self):
        # client_ip -> block_expiry_timestamp
        self._blocked_ips: Dict[str, float] = {}
        # client_ip -> challenge_token
        self._active_challenges: Dict[str, str] = {}
        # client_ip -> failed_challenge_attempts
        self._failed_challenges: Dict[str, int] = {}
        # client_ip -> verified_challenge_timestamp
        self._verified_sessions: Dict[str, float] = {}

    def is_blocked(self, client_ip: str) -> Tuple[bool, Optional[float]]:
        """Check if an IP is currently blocked and return remaining duration in seconds."""
        now = time.time()
        expiry = self._blocked_ips.get(client_ip)
        if expiry:
            if now < expiry:
                return True, round(expiry - now, 1)
            # Auto-expire block
            del self._blocked_ips[client_ip]
        return False, None

    def is_session_verified(self, client_ip: str, max_age_seconds: float = 300.0) -> bool:
        """Check if client IP holds a recently verified challenge session."""
        now = time.time()
        verified_at = self._verified_sessions.get(client_ip)
        if verified_at and (now - verified_at) <= max_age_seconds:
            return True
        return False

    def apply_decision(self, decision: PolicyDecision) -> None:
        """Apply policy decision to active block/challenge enforcement tables."""
        now = time.time()
        action = decision.decision if hasattr(decision, "decision") else decision.action

        if action == ActionEnum.BLOCK:
            duration = decision.block_duration_seconds or getattr(settings, "BLOCK_DURATION_SECONDS", 60)
            self._blocked_ips[decision.client_ip] = now + duration
            # Clear challenge tables if blocked
            self._active_challenges.pop(decision.client_ip, None)
            self._verified_sessions.pop(decision.client_ip, None)

        elif action == ActionEnum.CHALLENGE:
            if decision.challenge_token:
                self._active_challenges[decision.client_ip] = decision.challenge_token

        elif action == ActionEnum.ALLOW:
            pass

    def verify_challenge(self, client_ip: str, token: str) -> Tuple[bool, int]:
        """Verify if a client passed their security challenge token.
        
        Returns:
            Tuple[bool, int]: (success_status, failed_attempt_count)
        """
        active_token = self._active_challenges.get(client_ip)
        if active_token and active_token == token:
            # Token matched! Clear active challenge and failed count, mark verified session
            self._active_challenges.pop(client_ip, None)
            self._failed_challenges.pop(client_ip, None)
            self._verified_sessions[client_ip] = time.time()
            return True, 0

        # Verification failed
        failed_count = self._failed_challenges.get(client_ip, 0) + 1
        self._failed_challenges[client_ip] = failed_count

        max_failures = getattr(settings, "MAX_CHALLENGE_FAILURES_BEFORE_BLOCK", 3)
        if failed_count >= max_failures:
            # Adaptive transition: Elevate to temporary BLOCK
            now = time.time()
            block_duration = getattr(settings, "BLOCK_DURATION_SECONDS", 60)
            self._blocked_ips[client_ip] = now + block_duration
            self._active_challenges.pop(client_ip, None)

        return False, failed_count

    def unblock_ip(self, client_ip: str) -> bool:
        """Manually remove an IP from active block list."""
        self._failed_challenges.pop(client_ip, None)
        return self._blocked_ips.pop(client_ip, None) is not None

    def clear(self) -> None:
        """Clear all active blocks, challenges, and verified sessions."""
        self._blocked_ips.clear()
        self._active_challenges.clear()
        self._failed_challenges.clear()
        self._verified_sessions.clear()

    def get_mitigation_status(self) -> Dict[str, Any]:
        """Return status metrics of active blocks, challenges, and verified sessions."""
        now = time.time()
        # Clean expired blocks
        self._blocked_ips = {ip: exp for ip, exp in self._blocked_ips.items() if exp > now}
        return {
            "active_blocks_count": len(self._blocked_ips),
            "active_challenges_count": len(self._active_challenges),
            "verified_sessions_count": len(self._verified_sessions),
            "blocked_ips": [
                {"ip": ip, "remaining_seconds": round(exp - now, 1)}
                for ip, exp in self._blocked_ips.items()
            ],
            "active_challenges": list(self._active_challenges.keys()),
        }
