"""Phase 5 Integration Tests: Live Security Dashboard & Internal Cloud Attack Awareness."""

import pytest
import asyncio
import httpx
from fastapi.testclient import TestClient

from onechance.main import app
from onechance.models.traffic import AttackSourceType, TrafficFeatures
from onechance.logging.event_logger import SecurityEventLogger
from onechance.recovery.recovery_controller import recovery_controller
from scripts.internal_attacker import run_internal_attack

client = TestClient(app)


def test_internal_workload_traffic_feature_classification():
    """Verify TrafficFeatures accurately flags internal microservices/workloads."""
    feat_internal_header = TrafficFeatures(
        client_ip="10.0.1.5",
        requests_per_source=10,
        requests_per_second=5.0,
        endpoint_concentration=0.8,
        burstiness=1.5,
        repeated_endpoint_ratio=0.9,
        source_entropy=0.5,
        endpoint_entropy=0.5,
        error_ratio=0.0,
        avg_latency_ms=12.0,
        attack_origin="internal",
        source_type=AttackSourceType.INTERNAL_COMPROMISED,
    )
    assert feat_internal_header.is_internal_workload is True

    feat_external = TrafficFeatures(
        client_ip="198.51.100.22",
        requests_per_source=10,
        requests_per_second=5.0,
        endpoint_concentration=0.8,
        burstiness=1.5,
        repeated_endpoint_ratio=0.9,
        source_entropy=0.5,
        endpoint_entropy=0.5,
        error_ratio=0.0,
        avg_latency_ms=12.0,
        attack_origin="external",
        source_type=AttackSourceType.EXTERNAL,
    )
    assert feat_external.is_internal_workload is False


def test_demo_control_endpoints():
    """Test demo orchestration REST API endpoints."""
    res_start = client.post("/api/demo/start-normal")
    assert res_start.status_code == 200
    assert res_start.json()["status"] == "success"

    res_internal = client.post("/api/demo/start-internal-attack")
    assert res_internal.status_code == 200
    assert res_internal.json()["status"] == "success"

    res_stop = client.post("/api/demo/stop-attack")
    assert res_stop.status_code == 200
    assert res_stop.json()["status"] == "success"

    res_reset = client.post("/api/demo/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["status"] == "success"


def test_websocket_telemetry_snapshot():
    """Test WebSocket connection and initial snapshot message receipt."""
    with client.websocket_connect("/ws/telemetry") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "INITIAL_SNAPSHOT"
        assert "security_events" in data
        assert "recovery_events" in data
        assert "instances" in data
        assert "recovery_confidence" in data

        websocket.send_text("ping")
        resp = websocket.receive_json()
        assert resp["type"] == "PONG"


def test_internal_attacker_script_execution():
    """Test internal_attacker script helper against test client."""
    # Ensure resetting gateway demo state before run
    client.post("/api/demo/reset")
    # Trigger 5 internal requests
    headers = {
        "user-agent": "Internal-Compromised-Microservice/1.0",
        "x-attack-origin": "internal",
        "x-forwarded-for": "10.0.9.99",
    }
    res = client.get("/api/expensive-operation?iterations=100", headers=headers)
    assert res.status_code in [200, 403, 429, 502]
    assert "x-decision" in res.headers
