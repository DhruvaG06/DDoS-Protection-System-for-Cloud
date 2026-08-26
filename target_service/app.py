"""Demo Web Application (Origin Target Workload).

Provides a realistic set of web endpoints to serve as the protected backend target for OneChance:
- GET /
- GET /api/health
- GET /api/products
- GET /api/search
- POST /api/login
- GET /api/expensive-operation
"""

import asyncio
import os
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Query, Response, status
from pydantic import BaseModel

app = FastAPI(
    title="OneChance Demo Web Application",
    description="Target origin workload providing endpoints for e-commerce, authentication, search, and compute.",
    version="0.1.0",
)

# Simulated database / in-memory product catalog
PRODUCTS_DB = [
    {"id": 1, "name": "Cloud Shield Pro", "category": "Security", "price": 299.00, "in_stock": True},
    {"id": 2, "name": "Edge Defense Node", "category": "Hardware", "price": 1250.00, "in_stock": True},
    {"id": 3, "name": "AI Anomaly Engine License", "category": "Software", "price": 850.00, "in_stock": True},
    {"id": 4, "name": "High-Throughput Gateway Appliance", "category": "Hardware", "price": 3200.00, "in_stock": False},
    {"id": 5, "name": "Autonomous Recovery Orchestrator", "category": "Software", "price": 540.00, "in_stock": True},
]

# In-memory service state (allows simulated failure/recovery)
service_state: Dict[str, Any] = {
    "is_healthy": True,
    "status_message": "Operational",
    "instance_id": os.getenv("INSTANCE_ID", "target-instance-primary"),
    "started_at": time.time(),
    "request_count": 0,
}


class LoginRequest(BaseModel):
    username: str
    password: str


class HealthStatus(BaseModel):
    status: str
    instance_id: str
    uptime_seconds: float
    is_healthy: bool
    status_message: str
    served_requests: int
    timestamp: float


@app.get("/", tags=["Application"])
async def root() -> Dict[str, Any]:
    """Root homepage endpoint."""
    service_state["request_count"] += 1
    return {
        "service": "OneChance Demo Web Application",
        "instance_id": str(service_state["instance_id"]),
        "status": "online" if service_state["is_healthy"] else "degraded",
        "version": "1.0.0",
        "endpoints": [
            "GET /api/health",
            "GET /api/products",
            "GET /api/search?q={query}",
            "POST /api/login",
            "GET /api/expensive-operation",
        ],
    }


@app.get("/api/health", response_model=HealthStatus, tags=["Health"])
@app.get("/health", response_model=HealthStatus, tags=["Health"])
async def health_check(response: Response) -> HealthStatus:
    """Liveness & health probe."""
    uptime = time.time() - float(service_state["started_at"])
    if not service_state["is_healthy"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthStatus(
            status="unhealthy",
            instance_id=str(service_state["instance_id"]),
            uptime_seconds=round(uptime, 2),
            is_healthy=False,
            status_message=str(service_state["status_message"]),
            served_requests=int(service_state["request_count"]),
            timestamp=time.time(),
        )

    return HealthStatus(
        status="healthy",
        instance_id=str(service_state["instance_id"]),
        uptime_seconds=round(uptime, 2),
        is_healthy=True,
        status_message=str(service_state["status_message"]),
        served_requests=int(service_state["request_count"]),
        timestamp=time.time(),
    )


@app.get("/api/products", tags=["E-Commerce"])
async def get_products(category: Optional[str] = None) -> Dict[str, Any]:
    """Return catalog of products."""
    service_state["request_count"] += 1
    results = PRODUCTS_DB
    if category:
        results = [p for p in PRODUCTS_DB if p["category"].lower() == category.lower()]
    return {
        "total": len(results),
        "products": results,
        "instance_id": service_state["instance_id"],
    }


@app.get("/api/search", tags=["E-Commerce"])
async def search_products(q: str = Query(default="", description="Search query string")) -> Dict[str, Any]:
    """Search items in product catalog."""
    service_state["request_count"] += 1
    query_lower = q.lower().strip()
    if not query_lower:
        matched = PRODUCTS_DB
    else:
        matched = [
            p for p in PRODUCTS_DB
            if query_lower in p["name"].lower() or query_lower in p["category"].lower()
        ]
    return {
        "query": q,
        "results_count": len(matched),
        "results": matched,
        "instance_id": service_state["instance_id"],
    }


@app.post("/api/login", tags=["Authentication"])
async def login(credentials: LoginRequest) -> Dict[str, Any]:
    """Simulated login authentication endpoint."""
    service_state["request_count"] += 1
    # Simple mock authentication
    if credentials.username and credentials.password == "password123":
        return {
            "status": "authenticated",
            "username": credentials.username,
            "token": f"mock-jwt-token-{int(time.time())}",
            "expires_in": 3600,
        }
    elif credentials.username:
        # Accept valid non-empty username for demo purposes
        return {
            "status": "authenticated",
            "username": credentials.username,
            "token": f"demo-session-token-{int(time.time())}",
            "expires_in": 3600,
        }
    return {
        "status": "error",
        "message": "Invalid username or credentials",
    }


@app.get("/api/expensive-operation", tags=["Compute"])
async def expensive_operation(iterations: int = Query(default=50000, le=500000)) -> Dict[str, Any]:
    """Simulate a CPU-bound or database-intensive query endpoint."""
    service_state["request_count"] += 1
    start_time = time.time()
    
    # Simulate non-blocking CPU work
    total = sum(i * i for i in range(min(iterations, 200000)))
    await asyncio.sleep(0.05)  # Simulate I/O or DB delay
    
    elapsed_ms = (time.time() - start_time) * 1000.0
    return {
        "operation": "heavy_hash_aggregation",
        "iterations": iterations,
        "computed_checksum": total % 1000000,
        "computation_time_ms": round(elapsed_ms, 2),
        "instance_id": service_state["instance_id"],
    }


@app.post("/api/simulate-failure", tags=["Simulation Controls"])
async def simulate_failure(reason: str = "Simulated crash / resource exhaustion") -> Dict[str, str]:
    """Control hook to simulate an unhealthy container state."""
    service_state["is_healthy"] = False
    service_state["status_message"] = reason
    return {"status": "success", "message": f"Service set to unhealthy: {reason}"}


@app.post("/api/reset-health", tags=["Simulation Controls"])
async def reset_health() -> Dict[str, str]:
    """Control hook to reset container health to healthy state."""
    service_state["is_healthy"] = True
    service_state["status_message"] = "Operational"
    return {"status": "success", "message": "Service health restored to healthy"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("TARGET_SERVICE_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)
