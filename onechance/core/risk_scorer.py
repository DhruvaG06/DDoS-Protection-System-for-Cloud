"""Multi-Signal Risk Scoring Module & Interface.

Combines behavioral signals, anomaly predictions, burst metrics, and internal/external context
into a composite Risk Score from 0.0 (Benign) to 100.0 (Severe Malicious).
"""

from typing import List
from onechance.models.decisions import RiskAssessment
from onechance.models.traffic import AttackSourceType, TrafficFeatures


class RiskScorer:
    """Calculates composite risk score across multiple behavioral signals."""

    def __init__(
        self,
        weight_ml_anomaly: float = 0.40,
        weight_rate_burst: float = 0.35,
        weight_entropy: float = 0.15,
        weight_source_context: float = 0.10,
    ):
        self.weight_ml_anomaly = weight_ml_anomaly
        self.weight_rate_burst = weight_rate_burst
        self.weight_entropy = weight_entropy
        self.weight_source_context = weight_source_context

    def calculate_risk(
        self,
        features: TrafficFeatures,
        anomaly_probability: float,
    ) -> RiskAssessment:
        """Calculate composite risk score (0 - 100) and contribution breakdown."""
        reasons: List[str] = []

        # 1. ML Anomaly Contribution (0 - 100)
        ml_score = anomaly_probability * 100.0
        if anomaly_probability > 0.6:
            reasons.append(f"High ML behavioral anomaly probability ({anomaly_probability:.2f})")

        # 2. Rate & Burst Contribution (0 - 100)
        rate_score = min(100.0, (features.request_rate_per_sec / 30.0) * 100.0)
        if features.request_rate_per_sec > 15.0:
            reasons.append(f"Elevated request rate ({features.request_rate_per_sec} req/s)")

        # 3. Entropy / Endpoint Concentration (0 - 100)
        # Low entropy = high concentration on a single target endpoint
        entropy_score = max(0.0, (1.0 - features.endpoint_entropy) * 100.0)
        if features.endpoint_entropy < 0.2 and features.request_rate_per_sec > 5.0:
            reasons.append("High endpoint concentration / low entropy flood pattern")

        # 4. Source Context (External vs Internal Compromised Workload)
        source_score = 0.0
        if features.source_type == AttackSourceType.INTERNAL_COMPROMISED:
            source_score = 80.0
            reasons.append("Abnormal traffic originating from internal cloud workload")

        # Weighted aggregate
        composite_score = (
            (ml_score * self.weight_ml_anomaly)
            + (rate_score * self.weight_rate_burst)
            + (entropy_score * self.weight_entropy)
            + (source_score * self.weight_source_context)
        )

        composite_score = min(100.0, max(0.0, composite_score))

        signal_breakdown = {
            "ml_anomaly": round(ml_score, 2),
            "rate_burst": round(rate_score, 2),
            "endpoint_concentration": round(entropy_score, 2),
            "source_risk": round(source_score, 2),
        }

        return RiskAssessment(
            client_ip=features.client_ip,
            risk_score=round(composite_score, 2),
            anomaly_probability=round(anomaly_probability, 3),
            signal_breakdown=signal_breakdown,
            contributing_reasons=reasons,
        )
