"""Mitigation & Policy Enforcement Module.

Enforces real-time access controls:
- Tracks active IP blocks with expiry
- Manages active challenge tokens
- Provides direct fast-path mitigation checks
"""

import time
from typing import Dict, Optional, Tuple
from onechance.models.decisions import ActionEnum, PolicyDecision


class Mitigator:
    """Enforces active mitigation rules on incoming traffic."""

    def __init__(self):
        # client_ip -> block_expiry_timestamp
        self._blocked_ips: Dict[str, float] = {}
        # client_ip -> challenge_token
        self._active_challenges: Dict[str, str] = {}

    def is_blocked(self, client_ip: str) -> Tuple[bool, Optional[float]]:
        """Check if an IP is currently blocked and return remaining seconds."""
        now = time.time()
        expiry = self._blocked_ips.get(client_ip)
        if expiry:
            if now < expiry:
                return True, round(expiry - now, 1)
            # Expired block
            del self._blocked_ips[client_ip]
        return False, None

    def apply_decision(self, decision: PolicyDecision) -> None:
        """Apply a policy engine decision to the enforcement tables."""
        now = time.time()
        if decision.action == ActionEnum.BLOCK:
            duration = decision.block_duration_seconds or 60
            self._blocked_ips[decision.client_ip] = now + duration
            # Clear challenge if blocked
            self._active_challenges.pop(decision.client_ip, None)

        elif decision.action == ActionEnum.CHALLENGE:
            if decision.challenge_token:
                self._active_challenges[decision.client_ip] = decision.challenge_token

        elif decision.action == ActionEnum.ALLOW:
            # If previously challenged or cleared, clean up
            pass

    def verify_challenge(self, client_ip: str, token: str) -> bool:
        """Verify if a client passed their security challenge."""
        active_token = self._active_challenges.get(client_ip)
        if active_token and active_token == token:
            del self._active_challenges[client_ip]
            return True
        return False

    def unblock_ip(self, client_ip: str) -> bool:
        """Manually remove an IP from block list."""
        return self._blocked_ips.pop(client_ip, None) is not None

    def get_mitigation_status(self) -> Dict[str, int]:
        """Return counts of currently blocked IPs and challenged sessions."""
        now = time.time()
        # Clean expired
        self._blocked_ips = {ip: exp for ip, exp in self._blocked_ips.items() if exp > now}
        return {
            "active_blocks_count": len(self._blocked_ips),
            "active_challenges_count": len(self._active_challenges),
        }
