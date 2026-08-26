"""Adaptive Policy Engine Interface & Module.

Implements the three-tiered Risk-Adaptive Response:
- ALLOW: Clean traffic, forwarded immediately
- CHALLENGE: Suspicious traffic, triggered verification/rate-throttle
- BLOCK: High-confidence malicious traffic, dropped at gateway edge
"""

import uuid
from onechance.models.decisions import ActionEnum, PolicyDecision, RiskAssessment


class PolicyEngine:
    """Evaluates risk assessments against dynamic policies to choose mitigation actions."""

    def __init__(
        self,
        challenge_threshold: float = 40.0,
        block_threshold: float = 75.0,
        block_duration_seconds: int = 60,
    ):
        self.challenge_threshold = challenge_threshold
        self.block_threshold = block_threshold
        self.block_duration_seconds = block_duration_seconds

    def evaluate(self, assessment: RiskAssessment) -> PolicyDecision:
        """Map risk assessment to ALLOW / CHALLENGE / BLOCK action."""
        score = assessment.risk_score
        client_ip = assessment.client_ip
        reasons_summary = "; ".join(assessment.contributing_reasons) or "Normal traffic profile"

        if score >= self.block_threshold:
            return PolicyDecision(
                action=ActionEnum.BLOCK,
                client_ip=client_ip,
                risk_score=score,
                reason=f"Risk score {score:.1f} exceeds block threshold ({self.block_threshold}). {reasons_summary}",
                block_duration_seconds=self.block_duration_seconds,
            )

        if score >= self.challenge_threshold:
            challenge_token = f"chal_{uuid.uuid4().hex[:12]}"
            return PolicyDecision(
                action=ActionEnum.CHALLENGE,
                client_ip=client_ip,
                risk_score=score,
                reason=f"Risk score {score:.1f} exceeds challenge threshold ({self.challenge_threshold}). {reasons_summary}",
                challenge_token=challenge_token,
            )

        return PolicyDecision(
            action=ActionEnum.ALLOW,
            client_ip=client_ip,
            risk_score=score,
            reason="Risk score within safe normal bounds.",
        )
