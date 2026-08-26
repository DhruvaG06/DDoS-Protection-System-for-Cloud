"""Demonstration Script for Phase 2: Behavioral DDoS Detection + Explainable Risk Scoring.

Simulates 3 traffic profiles against the OneChance Detection Engine:
1. Normal Benign User Traffic
2. Volumetric Endpoint Flood (DDoS Attack)
3. Internal Compromised Workload Traffic

Outputs 10-signal feature extraction, RF ML anomaly probability, normalized 0-100 risk score,
threat level (LOW, MEDIUM, HIGH), and human-readable explainability reasoning.
"""

import json
import os
import sys
import time

# Ensure workspace root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from onechance.config import settings
from onechance.core.detector import ModularDetectorEngine
from onechance.core.feature_extractor import FeatureExtractor
from onechance.core.risk_scorer import RiskScorer
from onechance.models.traffic import AttackSourceType, IncomingRequest


def print_banner(text: str) -> None:
    print("\n" + "=" * 75)
    print(f" {text}")
    print("=" * 75)


def run_phase2_demo():
    print_banner("ONECHANCE PHASE 2: BEHAVIORAL DDoS DETECTION & EXPLAINABLE RISK SCORING")
    
    extractor = FeatureExtractor(window_duration_seconds=10.0)
    detector = ModularDetectorEngine(model_path=settings.DETECTOR_MODEL_PATH)
    scorer = RiskScorer()

    print(f"Active Detector Version: {detector.version}")
    print(f"Scikit-learn RF Artifact Loaded: {detector.rf_detector.is_loaded}")
    print("\nTrained Random Forest Feature Importances:")
    for feature, imp in detector.get_feature_importances().items():
        print(f"  - {feature:30s}: {imp:.4f}")

    now = time.time()

    # ---------------------------------------------------------
    # Scenario 1: Normal Benign User Traffic
    # ---------------------------------------------------------
    print_banner("SCENARIO 1: Normal Benign User Traffic (Legitimate Browsing)")
    extractor.clear()
    
    benign_endpoints = ["/api/products", "/api/search", "/api/products", "/api/health"]
    for i in range(5):
        req = IncomingRequest(
            client_ip="203.0.113.45",
            method="GET",
            path=benign_endpoints[i % len(benign_endpoints)],
            timestamp=now + (i * 1.5),
            status_code=200,
            latency_ms=35.0,
            source_type=AttackSourceType.EXTERNAL,
        )
        features = extractor.extract_features(req)

    proba = detector.predict_anomaly_probability(features)
    assessment = scorer.calculate_risk(features, proba, detector.version)

    print(f"Client IP               : {assessment.client_ip}")
    print(f"Request Rate            : {features.request_rate_per_sec:.2f} req/s")
    print(f"Endpoint Concentration  : {features.endpoint_concentration * 100:.1f}%")
    print(f"Endpoint Entropy        : {features.endpoint_entropy:.2f} bits")
    print(f"ML Anomaly Probability  : {assessment.anomaly_probability:.3f}")
    print(f"Risk Score (0 - 100)    : {assessment.risk_score:.2f}")
    print(f"Categorical Threat Level: {assessment.threat_level.value}")
    print("Explainability Reasons  :")
    for r in assessment.contributing_reasons:
        print(f"  * {r}")

    # ---------------------------------------------------------
    # Scenario 2: Volumetric Endpoint Flood (Application-Layer DDoS)
    # ---------------------------------------------------------
    print_banner("SCENARIO 2: Volumetric Endpoint Flood (HTTP GET Flood Attack)")
    extractor.clear()

    # Simulate 150 rapid requests targeting /api/expensive-operation from one IP
    for i in range(150):
        req = IncomingRequest(
            client_ip="198.51.100.99",
            method="GET",
            path="/api/expensive-operation",
            timestamp=now + (i * 0.05),
            status_code=200 if i % 10 != 0 else 503,
            latency_ms=850.0,
            source_type=AttackSourceType.EXTERNAL,
        )
        features = extractor.extract_features(req)

    proba = detector.predict_anomaly_probability(features)
    assessment = scorer.calculate_risk(features, proba, detector.version)

    print(f"Client IP               : {assessment.client_ip}")
    print(f"Requests in Window      : {features.requests_per_source}")
    print(f"Request Rate            : {features.request_rate_per_sec:.2f} req/s")
    print(f"Endpoint Concentration  : {features.endpoint_concentration * 100:.1f}% on target endpoint")
    print(f"Burstiness Multiplier   : {features.burstiness_score:.2f}x")
    print(f"Repeated Pattern Score  : {features.repeated_pattern_score:.2f}")
    print(f"Endpoint Entropy        : {features.endpoint_entropy:.2f} bits (Low entropy anomaly)")
    print(f"ML Anomaly Probability  : {assessment.anomaly_probability:.3f}")
    print(f"Risk Score (0 - 100)    : {assessment.risk_score:.2f}")
    print(f"Categorical Threat Level: {assessment.threat_level.value}")
    print("Explainability Reasons  :")
    for r in assessment.contributing_reasons:
        print(f"  * {r}")

    # ---------------------------------------------------------
    # Scenario 3: Internal Compromised Cloud Workload
    # ---------------------------------------------------------
    print_banner("SCENARIO 3: Compromised Internal Cloud Microservice")
    extractor.clear()

    for i in range(25):
        req = IncomingRequest(
            client_ip="10.0.4.18",
            method="POST",
            path="/api/login",
            timestamp=now + (i * 0.1),
            status_code=401,
            latency_ms=120.0,
            source_type=AttackSourceType.INTERNAL_COMPROMISED,
        )
        features = extractor.extract_features(req)

    proba = detector.predict_anomaly_probability(features)
    assessment = scorer.calculate_risk(features, proba, detector.version)

    print(f"Client IP               : {assessment.client_ip}")
    print(f"Source Type Context     : {features.source_type.value}")
    print(f"HTTP Error Ratio        : {features.error_ratio * 100:.1f}%")
    print(f"ML Anomaly Probability  : {assessment.anomaly_probability:.3f}")
    print(f"Risk Score (0 - 100)    : {assessment.risk_score:.2f}")
    print(f"Categorical Threat Level: {assessment.threat_level.value}")
    print("Explainability Reasons  :")
    for r in assessment.contributing_reasons:
        print(f"  * {r}")

    print_banner("DEMO COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    run_phase2_demo()
