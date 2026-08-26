"""Adaptive Policy Engine Interface & Module (Phase 3).

Implements the three-tiered Risk-Adaptive Response:
- ALLOW: Clean traffic, forwarded to target backend
- CHALLENGE: Suspicious traffic, issued short-lived verification challenge
- BLOCK: High-risk traffic / repeated challenge failures, temporary IP block enforced
"""

import uuid
from typing import Any, Dict, List, Optional
from onechance.config import settings
from onechance.models.decisions import ActionEnum, PolicyDecision, RiskAssessment, ThreatLevel


class PolicyEngine:
    """Evaluates risk assessments and request metadata against adaptive policies."""

    def __init__(
        self,
        challenge_threshold: Optional[float] = None,
        block_threshold: Optional[float] = None,
        block_duration_seconds: Optional[int] = None,
        policy_version: Optional[str] = None,
    ):
        self.challenge_threshold = challenge_threshold if challenge_threshold is not None else getattr(settings, "RISK_THRESHOLD_CHALLENGE", 40.0)
        self.block_threshold = block_threshold if block_threshold is not None else getattr(settings, "RISK_THRESHOLD_BLOCK", 70.0)
        self.block_duration_seconds = block_duration_seconds if block_duration_seconds is not None else getattr(settings, "BLOCK_DURATION_SECONDS", 60)
        self.policy_version = policy_version if policy_version is not None else getattr(settings, "POLICY_VERSION", "v3.0-adaptive-policy")

    def evaluate(
        self,
        assessment: RiskAssessment,
        endpoint: str = "/",
        request_metadata: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        has_valid_challenge: bool = False,
        **kwargs: Any,
    ) -> PolicyDecision:
        """Map risk assessment and request metadata to ALLOW / CHALLENGE / BLOCK policy decision."""
        metadata = dict(request_metadata or {})
        if has_valid_challenge:
            metadata["challenge_verified"] = True
        if kwargs.get("challenge_verified"):
            metadata["challenge_verified"] = True

        score = assessment.risk_score
        threat_level = assessment.threat_level
        final_client_ip = client_ip or getattr(assessment, "client_ip", None) or "127.0.0.1"
        reasons = list(assessment.contributing_reasons)

        # 1. Check if client holds a verified challenge token for this session
        if metadata.get("challenge_verified", False):
            return PolicyDecision(
                decision=ActionEnum.ALLOW,
                action=ActionEnum.ALLOW,
                client_ip=final_client_ip,
                endpoint=endpoint,
                risk_score=score,
                threat_level=threat_level,
                action_type="challenge_passed",
                reason=f"Challenge verification successful. Traffic allowed for IP {final_client_ip}.",
                reasons=reasons or ["Security challenge verified successfully"],
                policy_version=self.policy_version,
            )

        # 2. Check if client attempted challenge verification and failed
        if metadata.get("challenge_failed", False):
            failed_count = metadata.get("failed_count", 1)
            reasons.append(f"Failed security challenge verification attempt ({failed_count})")
            if failed_count >= getattr(settings, "MAX_CHALLENGE_FAILURES_BEFORE_BLOCK", 3):
                return PolicyDecision(
                    decision=ActionEnum.BLOCK,
                    action=ActionEnum.BLOCK,
                    client_ip=final_client_ip,
                    endpoint=endpoint,
                    risk_score=max(score, 85.0),
                    threat_level=ThreatLevel.HIGH,
                    action_type="temporary_block",
                    reason=f"Repeated challenge failures ({failed_count}). IP temporarily blocked.",
                    reasons=reasons,
                    block_duration_seconds=self.block_duration_seconds,
                    policy_version=self.policy_version,
                )

        # 3. Check rate limiting trigger
        if metadata.get("is_rate_limited", False):
            rate_reason = metadata.get("rate_limit_reason", "Rate limit exceeded")
            reasons.append(rate_reason)
            # If high risk or already medium, elevate to BLOCK, else CHALLENGE
            if score >= self.challenge_threshold:
                return PolicyDecision(
                    decision=ActionEnum.BLOCK,
                    action=ActionEnum.BLOCK,
                    client_ip=final_client_ip,
                    endpoint=endpoint,
                    risk_score=max(score, 75.0),
                    threat_level=ThreatLevel.HIGH,
                    action_type="rate_limit_throttled",
                    reason=f"Rate limit exceeded on '{endpoint}'. Enforcing temporary block.",
                    reasons=reasons,
                    block_duration_seconds=self.block_duration_seconds,
                    policy_version=self.policy_version,
                )
            else:
                challenge_token = f"chal_{uuid.uuid4().hex[:12]}"
                return PolicyDecision(
                    decision=ActionEnum.CHALLENGE,
                    action=ActionEnum.CHALLENGE,
                    client_ip=final_client_ip,
                    endpoint=endpoint,
                    risk_score=max(score, 45.0),
                    threat_level=ThreatLevel.MEDIUM,
                    action_type="challenge_issued",
                    reason=f"Rate limit exceeded on '{endpoint}'. Security challenge issued.",
                    reasons=reasons,
                    challenge_token=challenge_token,
                    policy_version=self.policy_version,
                )

        # 4. BLOCK Decision (High Risk: 70 - 100)
        if score >= self.block_threshold:
            return PolicyDecision(
                decision=ActionEnum.BLOCK,
                action=ActionEnum.BLOCK,
                client_ip=final_client_ip,
                endpoint=endpoint,
                risk_score=score,
                threat_level=threat_level,
                action_type="temporary_block",
                reason=f"High risk score ({score:.1f}) exceeds block threshold ({self.block_threshold}). Temporary block enforced.",
                reasons=reasons,
                block_duration_seconds=self.block_duration_seconds,
                policy_version=self.policy_version,
            )

        # 5. CHALLENGE Decision (Medium Risk: 40 - 69)
        if score >= self.challenge_threshold:
            challenge_token = f"chal_{uuid.uuid4().hex[:12]}"
            return PolicyDecision(
                decision=ActionEnum.CHALLENGE,
                action=ActionEnum.CHALLENGE,
                client_ip=final_client_ip,
                endpoint=endpoint,
                risk_score=score,
                threat_level=threat_level,
                action_type="challenge_issued",
                reason=f"Medium risk score ({score:.1f}) exceeds challenge threshold ({self.challenge_threshold}). Verification challenge issued.",
                reasons=reasons,
                challenge_token=challenge_token,
                policy_version=self.policy_version,
            )

        # 6. ALLOW Decision (Low Risk: 0 - 39)
        return PolicyDecision(
            decision=ActionEnum.ALLOW,
            action=ActionEnum.ALLOW,
            client_ip=final_client_ip,
            endpoint=endpoint,
            risk_score=score,
            threat_level=threat_level,
            action_type="forward",
            reason=f"Low risk score ({score:.1f}). Traffic permitted.",
            reasons=reasons or ["Normal behavioral metrics observed"],
            policy_version=self.policy_version,
        )
