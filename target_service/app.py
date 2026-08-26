"""Demo Web Application (Origin Target Workload).

Provides a realistic set of web endpoints to serve as the protected backend target for OneChance:
- GET /
- GET /api/health
- GET /api/products
- GET /api/search
- POST /api/login
- GET /api/expensive-operation
- POST /api/simulate-failure
- POST /api/reset-health
"""

import asyncio
import os
import sys
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Query, Request, Response, status
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

# Per-instance health state dictionary keyed by instance_id ('app-1', 'app-2', 'app-3')
instance_states: Dict[str, Dict[str, Any]] = {}


def get_instance_state(inst_id: str) -> Dict[str, Any]:
    if inst_id not in instance_states:
        instance_states[inst_id] = {
            "is_healthy": True,
            "status_message": "Operational",
            "instance_id": inst_id,
            "started_at": time.time(),
            "request_count": 0,
        }
    return instance_states[inst_id]


def resolve_instance_id(request: Request) -> str:
    hdr = request.headers.get("x-instance-id")
    if hdr:
        return hdr
    port = request.url.port
    if port == 8002:
        return "app-2"
    elif port == 8003:
        return "app-3"
    elif port == 8001:
        return "app-1"
    return os.getenv("INSTANCE_ID", "app-1")


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
async def root(request: Request) -> Dict[str, Any]:
    """Root homepage endpoint."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    state["request_count"] += 1
    return {
        "service": "OneChance Demo Web Application",
        "instance_id": inst_id,
        "status": "online" if state["is_healthy"] else "degraded",
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
async def health_check(request: Request, response: Response) -> HealthStatus:
    """Liveness & health probe."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    uptime = time.time() - float(state["started_at"])

    if not state["is_healthy"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthStatus(
            status="unhealthy",
            instance_id=inst_id,
            uptime_seconds=round(uptime, 2),
            is_healthy=False,
            status_message=str(state["status_message"]),
            served_requests=int(state["request_count"]),
            timestamp=time.time(),
        )

    return HealthStatus(
        status="healthy",
        instance_id=inst_id,
        uptime_seconds=round(uptime, 2),
        is_healthy=True,
        status_message=str(state["status_message"]),
        served_requests=int(state["request_count"]),
        timestamp=time.time(),
    )


@app.get("/api/products", tags=["E-Commerce"])
async def get_products(request: Request, category: Optional[str] = None) -> Dict[str, Any]:
    """Return catalog of products."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    state["request_count"] += 1
    results = PRODUCTS_DB
    if category:
        results = [p for p in PRODUCTS_DB if p["category"].lower() == category.lower()]
    return {
        "total": len(results),
        "products": results,
        "instance_id": inst_id,
    }


@app.get("/api/search", tags=["E-Commerce"])
async def search_products(request: Request, q: str = Query(default="", description="Search query string")) -> Dict[str, Any]:
    """Search items in product catalog."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    state["request_count"] += 1
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
        "instance_id": inst_id,
    }


@app.post("/api/login", tags=["Authentication"])
async def login(request: Request, credentials: LoginRequest) -> Dict[str, Any]:
    """Simulated login authentication endpoint."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    state["request_count"] += 1
    if credentials.username and credentials.password == "password123":
        return {
            "status": "authenticated",
            "username": credentials.username,
            "token": f"mock-jwt-token-{int(time.time())}",
            "expires_in": 3600,
        }
    elif credentials.username:
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
async def expensive_operation(request: Request, iterations: int = Query(default=50000, le=500000)) -> Dict[str, Any]:
    """Simulate a CPU-bound or database-intensive query endpoint."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    state["request_count"] += 1
    start_time = time.time()

    total = sum(i * i for i in range(min(iterations, 200000)))
    await asyncio.sleep(0.05)

    elapsed_ms = (time.time() - start_time) * 1000.0
    return {
        "operation": "heavy_hash_aggregation",
        "iterations": iterations,
        "computed_checksum": total % 1000000,
        "computation_time_ms": round(elapsed_ms, 2),
        "instance_id": inst_id,
    }


@app.post("/api/simulate-failure", tags=["Simulation Controls"])
async def simulate_failure(request: Request, reason: str = "Simulated crash / resource exhaustion") -> Dict[str, str]:
    """Control hook to simulate an unhealthy container state."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    state["is_healthy"] = False
    state["status_message"] = reason
    return {"status": "success", "message": f"Service '{inst_id}' set to unhealthy: {reason}"}


@app.post("/api/reset-health", tags=["Simulation Controls"])
async def reset_health(request: Request) -> Dict[str, str]:
    """Control hook to reset container health to healthy state."""
    inst_id = resolve_instance_id(request)
    state = get_instance_state(inst_id)
    state["is_healthy"] = True
    state["status_message"] = "Operational"
    return {"status": "success", "message": f"Service '{inst_id}' health restored to healthy"}


if __name__ == "__main__":
    import uvicorn
    import threading

    def run_instance(port_num: int):
        uvicorn.run("target_service.app:app", host="0.0.0.0", port=port_num, log_level="warning")

    target_ports = [8001, 8002, 8003]
    print(f"[TargetFleet] Starting Multi-Instance Target Service Fleet on ports {target_ports}...")
    threads = []
    for p in target_ports:
        t = threading.Thread(target=run_instance, args=(p,), daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("[TargetFleet] Fleet stopped.")

