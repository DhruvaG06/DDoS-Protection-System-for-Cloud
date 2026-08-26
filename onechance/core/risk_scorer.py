"""Multi-Signal Risk Scoring Module & Explainability Engine (Phase 2).

Combines 10-signal behavioral telemetry, anomaly predictions, burst metrics, and internal/external context
into a normalized 0.0 to 100.0 Risk Score with categorical Threat Levels (LOW, MEDIUM, HIGH)
and human-readable explainability reasoning.
"""

from typing import Dict, List, Optional
from onechance.config import settings
from onechance.models.decisions import RiskAssessment, ThreatLevel
from onechance.models.traffic import AttackSourceType, TrafficFeatures


class RiskScorer:
    """Calculates composite 0-100 risk score and provides explainability reasons."""

    def __init__(
        self,
        weight_ml_anomaly: float = 0.35,
        weight_rate_burst: float = 0.25,
        weight_pattern_concentration: float = 0.20,
        weight_error_latency: float = 0.10,
        weight_source_context: float = 0.10,
        low_max: float = 39.0,
        medium_max: float = 69.0,
    ):
        self.weight_ml_anomaly = weight_ml_anomaly
        self.weight_rate_burst = weight_rate_burst
        self.weight_pattern_concentration = weight_pattern_concentration
        self.weight_error_latency = weight_error_latency
        self.weight_source_context = weight_source_context
        self.low_max = getattr(settings, "RISK_LOW_MAX", low_max)
        self.medium_max = getattr(settings, "RISK_MEDIUM_MAX", medium_max)

    def determine_threat_level(self, risk_score: float) -> ThreatLevel:
        """Map 0-100 risk score to categorical ThreatLevel."""
        if risk_score <= self.low_max:
            return ThreatLevel.LOW
        elif risk_score <= self.medium_max:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.HIGH

    def calculate_risk(
        self,
        features: TrafficFeatures,
        anomaly_probability: float,
        detector_version: str = "v2.0-hybrid-rf",
    ) -> RiskAssessment:
        """Calculate composite 0-100 risk score, signal breakdown, and explainability reasons."""
        reasons: List[str] = []

        # 1. ML Anomaly Signal (0 - 100)
        ml_score = anomaly_probability * 100.0
        if anomaly_probability >= 0.5:
            reasons.append(f"High ML behavioral anomaly probability ({anomaly_probability:.2f})")

        # 2. Rate & Burst Signal (0 - 100)
        rate_factor = min(1.0, features.request_rate_per_sec / 25.0)
        burst_factor = min(1.0, max(0.0, (features.burstiness_score - 1.0) / 4.0))
        rate_burst_score = ((rate_factor * 0.6) + (burst_factor * 0.4)) * 100.0

        if features.request_rate_per_sec > 10.0:
            reasons.append(f"Abnormal request rate ({features.request_rate_per_sec} req/s)")
        if features.burstiness_score > 3.0:
            reasons.append(f"Traffic burstiness spike (burst multiplier {features.burstiness_score:.1f}x)")

        # 3. Endpoint Concentration & Repetition Signal (0 - 100)
        conc_factor = features.endpoint_concentration ** 2
        repeat_factor = features.repeated_pattern_score ** 2
        # Low entropy indicates targeted endpoint flood
        entropy_risk = max(0.0, (1.5 - features.endpoint_entropy) / 1.5) if features.requests_per_source > 3 else 0.0
        
        pattern_score = ((conc_factor * 0.4) + (repeat_factor * 0.4) + (entropy_risk * 0.2)) * 100.0
        pattern_score = min(100.0, pattern_score)

        if features.endpoint_concentration >= 0.70 and features.requests_per_source >= 5:
            reasons.append(f"High endpoint concentration ({features.endpoint_concentration * 100:.0f}% of requests on single URL)")
        if features.repeated_pattern_score >= 0.60 and features.requests_per_source >= 5:
            reasons.append(f"Repeated request pattern (sequential identical path access ratio {features.repeated_pattern_score:.2f})")
        if features.endpoint_entropy <= 0.40 and features.requests_per_source >= 5:
            reasons.append(f"Endpoint entropy anomaly (Shannon entropy {features.endpoint_entropy:.2f} bits)")
        if features.source_distribution_ratio >= 0.50 and features.requests_per_source >= 10:
            reasons.append(f"Source distribution anomaly ({features.source_distribution_ratio * 100:.0f}% of overall window traffic from single IP)")

        # 4. Error Ratio & Latency Signal (0 - 100)
        error_score = features.error_ratio * 100.0
        latency_score = min(100.0, (features.average_latency_ms / 1000.0) * 100.0)
        error_latency_score = (error_score * 0.7) + (latency_score * 0.3)

        if features.error_ratio >= 0.25:
            reasons.append(f"Elevated HTTP error ratio ({features.error_ratio * 100:.0f}% 4xx/5xx responses)")
        if features.average_latency_ms >= 800.0:
            reasons.append(f"High average request latency ({features.average_latency_ms:.0f} ms)")

        # 5. Source Context Signal (0 - 100)
        source_score = 0.0
        if features.source_type == AttackSourceType.INTERNAL_COMPROMISED:
            source_score = 90.0
            reasons.append("Abnormal traffic originating from internal cloud workload")

        # Weighted aggregate score
        composite_score = (
            (ml_score * self.weight_ml_anomaly)
            + (rate_burst_score * self.weight_rate_burst)
            + (pattern_score * self.weight_pattern_concentration)
            + (error_latency_score * self.weight_error_latency)
            + (source_score * self.weight_source_context)
        )

        composite_score = round(min(100.0, max(0.0, composite_score)), 2)
        threat_level = self.determine_threat_level(composite_score)

        if not reasons and threat_level == ThreatLevel.LOW:
            reasons.append("Normal traffic behavior within baseline limits")

        signal_breakdown = {
            "ml_anomaly": round(ml_score, 2),
            "rate_burst": round(rate_burst_score, 2),
            "pattern_concentration": round(pattern_score, 2),
            "error_latency": round(error_latency_score, 2),
            "source_risk": round(source_score, 2),
        }

        return RiskAssessment(
            client_ip=features.client_ip,
            risk_score=composite_score,
            threat_level=threat_level,
            anomaly_probability=round(anomaly_probability, 3),
            features=features,
            signal_breakdown=signal_breakdown,
            contributing_reasons=reasons,
            detector_version=detector_version,
        )
