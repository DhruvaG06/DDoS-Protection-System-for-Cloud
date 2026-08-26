"""Modular Behavioral Anomaly Detection Interface & Machine Learning Engine (Phase 2).

Provides a clean abstract detector interface supporting:
1. HybridDetector: Rule-based heuristics + multi-signal behavioral scoring
2. RandomForestDetector: Trained Scikit-learn Random Forest Classifier
3. ModularDetectorEngine: Automatic model loading, fallback management, and versioning
"""

import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, List
import joblib
import numpy as np

from onechance.models.traffic import AttackSourceType, TrafficFeatures


class BaseDetector(ABC):
    """Abstract base class for OneChance anomaly detectors."""

    @abstractmethod
    def predict_anomaly_probability(self, features: TrafficFeatures) -> float:
        """Calculate anomaly probability (0.0 = benign, 1.0 = severe attack)."""
        pass

    @abstractmethod
    def get_feature_importances(self) -> Dict[str, float]:
        """Return relative feature importances / weights used by detector."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Return detector version string."""
        pass


class HybridDetector(BaseDetector):
    """Hybrid behavioral anomaly detector combining rule-based heuristics & weighted feature metrics."""

    @property
    def version(self) -> str:
        return "v2.0-hybrid-rules"

    def predict_anomaly_probability(self, features: TrafficFeatures) -> float:
        score = 0.0

        # 1. Volumetric Request Rate Score
        rate_contrib = min(1.0, features.request_rate_per_sec / 30.0) * 0.25
        score += rate_contrib

        # 2. Endpoint Concentration Score (High concentration on single URL)
        conc_contrib = (features.endpoint_concentration ** 2) * 0.20
        score += conc_contrib

        # 3. Burstiness Score
        burst_contrib = min(1.0, max(0.0, (features.burstiness_score - 1.0) / 5.0)) * 0.15
        score += burst_contrib

        # 4. Repeated Pattern Score (Identical sequential path repetition)
        repeat_contrib = (features.repeated_pattern_score ** 2) * 0.15
        score += repeat_contrib

        # 5. Low Entropy Anomaly (Flood targeting single endpoint vs diverse endpoints)
        # Low entropy (< 0.5 bits) when request rate > 3.0 indicates targeted flood
        if features.endpoint_entropy < 0.5 and features.request_rate_per_sec > 3.0:
            score += 0.10

        # 6. High Error Ratio (Scans, brute force)
        score += min(1.0, features.error_ratio) * 0.10

        # 7. Internal Compromised Workload Rule
        if features.source_type == AttackSourceType.INTERNAL_COMPROMISED:
            score += 0.30

        return round(min(1.0, max(0.0, score)), 3)

    def get_feature_importances(self) -> Dict[str, float]:
        return {
            "request_rate_per_sec": 0.25,
            "endpoint_concentration": 0.20,
            "burstiness_score": 0.15,
            "repeated_pattern_score": 0.15,
            "endpoint_entropy": 0.10,
            "error_ratio": 0.10,
            "internal_workload_risk": 0.05,
        }


class RandomForestDetector(BaseDetector):
    """Scikit-learn Random Forest Model Detector."""

    def __init__(self, model_path: str = "onechance/models/artifacts/rf_detector.joblib"):
        self.model_path = model_path
        self._model: Optional[Any] = None
        self._feature_names: List[str] = []
        self._version: str = "v2.0-rf-sklearn"
        self._is_loaded: bool = False
        self.load_model()

    def load_model(self) -> None:
        """Load trained Scikit-learn Random Forest artifact from disk."""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                if isinstance(data, dict) and "model" in data:
                    self._model = data["model"]
                    self._feature_names = data.get("feature_names", [])
                    self._version = data.get("version", "v2.0-rf-sklearn")
                else:
                    self._model = data
                self._is_loaded = True
            except Exception as e:
                self._is_loaded = False
        else:
            self._is_loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def version(self) -> str:
        return self._version

    def _extract_feature_vector(self, features: TrafficFeatures) -> np.ndarray:
        """Convert TrafficFeatures pydantic model into 10-dimensional numpy feature vector."""
        return np.array([[
            float(features.requests_per_source),
            float(features.request_rate_per_sec),
            float(features.endpoint_concentration),
            float(features.burstiness_score),
            float(features.repeated_pattern_score),
            float(features.source_distribution_ratio),
            float(features.endpoint_distribution_ratio),
            float(features.endpoint_entropy),
            float(features.error_ratio),
            float(features.average_latency_ms),
        ]])

    def predict_anomaly_probability(self, features: TrafficFeatures) -> float:
        if not self._is_loaded or self._model is None:
            raise RuntimeError("RandomForestDetector model artifact is not loaded.")
        X = self._extract_feature_vector(features)
        proba = float(self._model.predict_proba(X)[0][1])
        return round(min(1.0, max(0.0, proba)), 3)

    def get_feature_importances(self) -> Dict[str, float]:
        if not self._is_loaded or self._model is None or not hasattr(self._model, "feature_importances_"):
            return {}
        importances = self._model.feature_importances_
        feature_names = self._feature_names if self._feature_names else [
            "requests_per_source", "request_rate_per_sec", "endpoint_concentration",
            "burstiness_score", "repeated_pattern_score", "source_distribution_ratio",
            "endpoint_distribution_ratio", "endpoint_entropy", "error_ratio", "average_latency_ms"
        ]
        return {name: round(float(imp), 4) for name, imp in zip(feature_names, importances)}


class ModularDetectorEngine(BaseDetector):
    """Composite detector engine managing dynamic model selection & hybrid fallback."""

    def __init__(self, model_path: str = "onechance/models/artifacts/rf_detector.joblib"):
        self.hybrid_detector = HybridDetector()
        self.rf_detector = RandomForestDetector(model_path=model_path)

    @property
    def active_detector(self) -> BaseDetector:
        if self.rf_detector.is_loaded:
            return self.rf_detector
        return self.hybrid_detector

    @property
    def version(self) -> str:
        return self.active_detector.version

    def predict_anomaly_probability(self, features: TrafficFeatures) -> float:
        return self.active_detector.predict_anomaly_probability(features)

    def get_feature_importances(self) -> Dict[str, float]:
        return self.active_detector.get_feature_importances()


# Alias for backward compatibility with existing components
AnomalyDetector = ModularDetectorEngine
