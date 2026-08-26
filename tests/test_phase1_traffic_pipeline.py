"""Automated Tests for Phase 1: Working Application + Traffic Gateway Pipeline."""

import pytest
import httpx
from fastapi.testclient import TestClient

from onechance.logging.traffic_logger import traffic_logger
from onechance.main import app as gateway_app
from target_service.app import app as target_app


@pytest.fixture
def target_client():
    return TestClient(target_app)


@pytest.fixture
def gateway_client():
    traffic_logger.clear()
    return TestClient(gateway_app)


# ==========================================
# 1. Target Application Direct Tests
# ==========================================

def test_demo_app_root(target_client):
    """Test target application root homepage."""
    response = target_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "OneChance Demo Web Application"
    assert "endpoints" in data


def test_demo_app_health(target_client):
    """Test target application health probe."""
    response = target_client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["is_healthy"] is True
    assert "uptime_seconds" in data
    assert "instance_id" in data


def test_demo_app_products(target_client):
    """Test target application products catalog and filtering."""
    response = target_client.get("/api/products")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0
    assert len(data["products"]) > 0

    # Filter by category
    filtered = target_client.get("/api/products?category=Security")
    assert filtered.status_code == 200
    assert all(p["category"] == "Security" for p in filtered.json()["products"])


def test_demo_app_search(target_client):
    """Test target application product search."""
    response = target_client.get("/api/search?q=Shield")
    assert response.status_code == 200
    data = response.json()
    assert data["results_count"] >= 1
    assert any("Shield" in p["name"] for p in data["results"])


def test_demo_app_login(target_client):
    """Test target application login authentication."""
    response = target_client.post("/api/login", json={"username": "alice", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "authenticated"
    assert "token" in data


def test_demo_app_expensive_op(target_client):
    """Test target application compute-intensive operation."""
    response = target_client.get("/api/expensive-operation?iterations=10000")
    assert response.status_code == 200
    data = response.json()
    assert data["operation"] == "heavy_hash_aggregation"
    assert "computation_time_ms" in data


# ==========================================
# 2. Gateway Proxy & Structured Traffic Logging
# ==========================================

def test_gateway_index(gateway_client):
    """Test gateway index endpoint."""
    response = gateway_client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["gateway"] == "OneChance Reverse Proxy"
    assert "routes" in data


def test_traffic_logging_structure():
    """Test structured traffic logger record fields."""
    traffic_logger.clear()
    record = traffic_logger.log_request(
        request_id="req_test123",
        timestamp=1700000000.0,
        source="192.168.1.50",
        method="GET",
        endpoint="/api/products",
        user_agent="Mozilla/5.0 TestAgent",
        status_code=200,
        latency_ms=12.5,
    )
    assert record.request_id == "req_test123"
    assert record.source == "192.168.1.50"
    assert record.method == "GET"
    assert record.endpoint == "/api/products"
    assert record.user_agent == "Mozilla/5.0 TestAgent"
    assert record.status_code == 200
    assert record.latency_ms == 12.5

    logs = traffic_logger.get_recent_logs()
    assert len(logs) == 1
    assert logs[0]["request_id"] == "req_test123"


def test_gateway_traffic_logs_endpoint(gateway_client):
    """Test retrieval of structured logs from /api/traffic-logs."""
    traffic_logger.clear()
    traffic_logger.log_request(
        request_id="req_abc1",
        timestamp=1700000001.0,
        source="10.0.0.1",
        method="POST",
        endpoint="/api/login",
        user_agent="Curl/7.68.0",
        status_code=200,
        latency_ms=8.2,
    )

    response = gateway_client.get("/api/traffic-logs")
    assert response.status_code == 200
    data = response.json()
    assert data["total_buffered"] >= 1
    assert data["logs"][0]["request_id"] == "req_abc1"
    assert data["logs"][0]["endpoint"] == "/api/login"


@pytest.mark.asyncio
async def test_end_to_end_gateway_proxy_forwarding(monkeypatch):
    """Test gateway proxy forwarding end-to-end to target application."""
    traffic_logger.clear()

    target_transport = httpx.ASGITransport(app=target_app)
    orig_async_client = httpx.AsyncClient

    class CustomMockClient(orig_async_client):
        def __init__(self, *args, **kwargs):
            if "transport" not in kwargs or kwargs["transport"] is None:
                kwargs["transport"] = target_transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", CustomMockClient)

    gateway_transport = httpx.ASGITransport(app=gateway_app)
    async with httpx.AsyncClient(transport=gateway_transport, base_url="http://gateway.local") as client:
        # 1. Test proxied /api/products
        resp = await client.get("/api/products")
        assert resp.status_code == 200
        assert "products" in resp.json()
        assert "x-request-id" in resp.headers
        assert "x-gateway-latency-ms" in resp.headers

        # 2. Test proxied /api/search
        resp = await client.get("/api/search?q=AI")
        assert resp.status_code == 200
        assert resp.json()["query"] == "AI"

        # 3. Test proxied /api/login
        resp = await client.post("/api/login", json={"username": "bob", "password": "password123"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "authenticated"

        # 4. Test proxied /api/expensive-operation
        resp = await client.get("/api/expensive-operation?iterations=5000")
        assert resp.status_code == 200
        assert resp.json()["operation"] == "heavy_hash_aggregation"

        # 5. Verify structured traffic logs were captured
        logs_resp = await client.get("/api/traffic-logs")
        assert logs_resp.status_code == 200
        logs = logs_resp.json()["logs"]
        assert len(logs) >= 4
        # Verify log record fields
        first_log = logs[-1]  # chronologically first
        assert "request_id" in first_log
        assert "timestamp" in first_log
        assert "source" in first_log
        assert "method" in first_log
        assert "endpoint" in first_log
        assert "status_code" in first_log
        assert "latency_ms" in first_log
