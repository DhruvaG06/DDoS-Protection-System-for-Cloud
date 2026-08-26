"""Configuration and environment management for OneChance."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings and configuration parameters."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Gateway Networking
    GATEWAY_HOST: str = "0.0.0.0"
    GATEWAY_PORT: int = 8000
    DEBUG: bool = True
    ENVIRONMENT: str = "development"

    # Protected Target Service (Origin)
    TARGET_SERVICE_URL: str = "http://localhost:8001"
    TARGET_SERVICE_TIMEOUT_SECONDS: float = 5.0

    # Policy & Scoring Thresholds
    RISK_THRESHOLD_CHALLENGE: float = 40.0
    RISK_THRESHOLD_BLOCK: float = 75.0
    RISK_LOW_MAX: float = 39.0
    RISK_MEDIUM_MAX: float = 69.0
    RATE_LIMIT_WINDOW_SECONDS: int = 10
    BURST_THRESHOLD: int = 50
    DETECTOR_MODEL_PATH: str = "onechance/models/artifacts/rf_detector.joblib"

    # Health & Recovery Settings
    HEALTH_CHECK_INTERVAL_SECONDS: float = 3.0
    HEALTH_FAILURE_THRESHOLD: int = 3
    HEALTH_TIMEOUT_SECONDS: float = 2.0
    AUTO_RECOVERY_ENABLED: bool = True


settings = Settings()
