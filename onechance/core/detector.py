"""Behavioral Anomaly Detection Interface & Placeholder.

Responsible for feeding behavioral features into detection models (e.g., Random Forest classifier / Isolation Forest)
to output an anomaly probability score.
"""

from typing import Any, Dict, Optional
from onechance.models.traffic import TrafficFeatures


class AnomalyDetector:
    """Behavioral anomaly detector interface."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self._model: Optional[Any] = None
        self._is_trained: bool = False

    def load_model(self) -> None:
        """Load trained Scikit-learn model artifacts."""
        # Placeholder for Phase 1 ML model loading
        self._is_trained = False

    def predict_anomaly_probability(self, features: TrafficFeatures) -> float:
        """Calculate the probability (0.0 to 1.0) of a request stream being anomalous.

        In Phase 0, returns a deterministic placeholder score based on basic rate heuristics.
        Phase 1 will wire in the trained Scikit-learn Random Forest model.
        """
        # Placeholder baseline heuristic for testing gateway flow
        if features.request_rate_per_sec > 20.0:
            return min(1.0, features.request_rate_per_sec / 50.0)
        return 0.05

    def get_feature_importances(self) -> Dict[str, float]:
        """Return relative feature importance weights from the detector."""
        return {
            "request_rate": 0.35,
            "burstiness": 0.25,
            "endpoint_entropy": 0.20,
            "repeated_patterns": 0.20,
        }
