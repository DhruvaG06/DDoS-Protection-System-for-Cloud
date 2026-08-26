"""Synthetic Dataset Generator and Scikit-learn Random Forest Model Trainer for OneChance.

Generates realistic normal vs DDoS attack traffic feature samples and trains a Scikit-learn
RandomForestClassifier for behavioral anomaly detection.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from typing import Tuple


FEATURE_NAMES = [
    "requests_per_source",
    "request_rate_per_sec",
    "endpoint_concentration",
    "burstiness_score",
    "repeated_pattern_score",
    "source_distribution_ratio",
    "endpoint_distribution_ratio",
    "endpoint_entropy",
    "error_ratio",
    "average_latency_ms",
]


def generate_synthetic_training_data(n_samples: int = 1200, random_seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Generate balanced synthetic feature matrix (X) and binary labels (y: 0 = Benign, 1 = Anomalous/Attack)."""
    np.random.seed(random_seed)
    half = n_samples // 2

    # --- 1. Benign Normal Traffic (Label 0) ---
    # Low request rates, balanced endpoint distribution, low error ratio
    normal_req_source = np.random.randint(1, 15, half)
    normal_rate_sec = normal_req_source / 10.0 + np.random.uniform(0.1, 0.5, half)
    normal_concentration = np.random.uniform(0.1, 0.45, half)
    normal_burstiness = np.random.uniform(1.0, 2.5, half)
    normal_repeated = np.random.uniform(0.1, 0.35, half)
    normal_source_dist = np.random.uniform(0.01, 0.25, half)
    normal_endpoint_dist = np.random.uniform(0.4, 0.9, half)
    normal_entropy = np.random.uniform(1.2, 3.5, half)
    normal_error_ratio = np.random.uniform(0.0, 0.08, half)
    normal_latency = np.random.uniform(10.0, 150.0, half)

    X_normal = np.column_stack([
        normal_req_source,
        normal_rate_sec,
        normal_concentration,
        normal_burstiness,
        normal_repeated,
        normal_source_dist,
        normal_endpoint_dist,
        normal_entropy,
        normal_error_ratio,
        normal_latency,
    ])
    y_normal = np.zeros(half, dtype=int)

    # --- 2. Anomalous / Attack Traffic (Label 1) ---
    quarter = half // 3
    
    # Attack Pattern A: Volumetric HTTP Flood / High Burst Rate
    a_req_source = np.random.randint(50, 400, quarter)
    a_rate_sec = a_req_source / 10.0 + np.random.uniform(5.0, 20.0, quarter)
    a_concentration = np.random.uniform(0.5, 0.95, quarter)
    a_burstiness = np.random.uniform(3.5, 12.0, quarter)
    a_repeated = np.random.uniform(0.5, 0.95, quarter)
    a_source_dist = np.random.uniform(0.4, 0.95, quarter)
    a_endpoint_dist = np.random.uniform(0.05, 0.25, quarter)
    a_entropy = np.random.uniform(0.0, 0.5, quarter)
    a_error_ratio = np.random.uniform(0.0, 0.3, quarter)
    a_latency = np.random.uniform(200.0, 2500.0, quarter)

    # Attack Pattern B: Endpoint Focus / Slowloris / Repeat Pattern Flood
    b_req_source = np.random.randint(30, 200, quarter)
    b_rate_sec = b_req_source / 10.0
    b_concentration = np.random.uniform(0.8, 1.0, quarter)
    b_burstiness = np.random.uniform(2.0, 6.0, quarter)
    b_repeated = np.random.uniform(0.8, 1.0, quarter)
    b_source_dist = np.random.uniform(0.3, 0.8, quarter)
    b_endpoint_dist = np.random.uniform(0.01, 0.15, quarter)
    b_entropy = np.random.uniform(0.0, 0.3, quarter)
    b_error_ratio = np.random.uniform(0.0, 0.15, quarter)
    b_latency = np.random.uniform(500.0, 3000.0, quarter)

    # Attack Pattern C: Error-Spike / Probe / Vulnerability Scanning
    c_req_source = np.random.randint(25, 150, half - 2 * quarter)
    c_rate_sec = c_req_source / 10.0
    c_concentration = np.random.uniform(0.3, 0.7, half - 2 * quarter)
    c_burstiness = np.random.uniform(2.0, 5.0, half - 2 * quarter)
    c_repeated = np.random.uniform(0.3, 0.7, half - 2 * quarter)
    c_source_dist = np.random.uniform(0.2, 0.7, half - 2 * quarter)
    c_endpoint_dist = np.random.uniform(0.3, 0.8, half - 2 * quarter)
    c_entropy = np.random.uniform(0.5, 1.5, half - 2 * quarter)
    c_error_ratio = np.random.uniform(0.4, 0.95, half - 2 * quarter)
    c_latency = np.random.uniform(100.0, 1000.0, half - 2 * quarter)

    X_attack = np.vstack([
        np.column_stack([a_req_source, a_rate_sec, a_concentration, a_burstiness, a_repeated, a_source_dist, a_endpoint_dist, a_entropy, a_error_ratio, a_latency]),
        np.column_stack([b_req_source, b_rate_sec, b_concentration, b_burstiness, b_repeated, b_source_dist, b_endpoint_dist, b_entropy, b_error_ratio, b_latency]),
        np.column_stack([c_req_source, c_rate_sec, c_concentration, c_burstiness, c_repeated, c_source_dist, c_endpoint_dist, c_entropy, c_error_ratio, c_latency]),
    ])
    y_attack = np.ones(half, dtype=int)

    X = np.vstack([X_normal, X_attack])
    y = np.concatenate([y_normal, y_attack])

    return X, y


def train_and_save_model(output_path: str = "onechance/models/artifacts/rf_detector.joblib") -> str:
    """Train Random Forest classifier on synthetic dataset and serialize to disk."""
    X, y = generate_synthetic_training_data()

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X, y)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    joblib.dump({
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "version": "v2.0-rf-sklearn",
    }, output_path)

    return output_path


if __name__ == "__main__":
    path = train_and_save_model()
    print(f"Scikit-learn Random Forest DDoS detector model trained and saved to: {path}")
