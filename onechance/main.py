"""OneChance Gateway & Autonomous Response Main Application Entrypoint (Phase 4)."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from onechance.api.routes import router
from onechance.config import settings
from onechance.monitoring.health_monitor import health_monitor
from onechance.recovery.recovery_controller import recovery_controller
from onechance.recovery.service_registry import service_registry

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("onechance.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan lifecycle manager."""
    logger.info("Initializing OneChance Gateway & Autonomous Self-Healing System (Phase 4)...")

    # 1. Initialize Service Registry with configured instances
    for instance_id, url in settings.get_target_instance_configs():
        service_registry.register_instance(
            instance_id=instance_id,
            url=url,
            container_name=f"onechance-{instance_id}",
        )

    # 2. Wire Health Monitor callback to Recovery Controller
    health_monitor.on_unhealthy_callback = lambda inst_id, reason: recovery_controller.execute_autonomous_recovery(
        instance_id=inst_id, trigger_reason=reason
    )

    # 3. Start Health Monitoring loop
    if settings.AUTO_RECOVERY_ENABLED:
        health_monitor.start()

    yield

    # Shutdown
    logger.info("Shutting down OneChance Gateway & Background Tasks...")
    health_monitor.stop()


app = FastAPI(
    title="OneChance DDoS Protection & Autonomous Response Gateway",
    description=(
        "Smart Cloud DDoS Protection System with Autonomous Self-Healing and Service Recovery. "
        "Closed loop workflow: DETECT → ISOLATE → REROUTE → REPLACE → HEALTH CHECK → REINTRODUCE → VERIFY RECOVERY."
    ),
    version="0.4.0",
    lifespan=lifespan,
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Gateway, Telemetry, and Recovery routes
app.include_router(router)


@app.get("/", tags=["Gateway Status"])
async def gateway_index():
    """OneChance Gateway Index & Endpoint Map."""
    return {
        "gateway": "OneChance Reverse Proxy",
        "phase": "Phase 4 - Autonomous Self-Healing & Service Recovery",
        "status": "online",
        "version": "0.4.0",
        "routes": {
            "health": "/api/health",
            "recovery_status": "/api/recovery/status",
            "recovery_events": "/api/recovery/events",
            "simulate_failure": "/api/recovery/simulate-failure",
            "traffic_logs": "/api/traffic-logs",
            "security_events": "/api/security-events",
            "proxied_products": "/api/products",
            "proxied_search": "/api/search?q={query}",
            "proxied_login": "/api/login",
            "proxied_expensive": "/api/expensive-operation",
            "generic_proxy": "/proxy/{path}",
            "docs": "/docs",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "onechance.main:app",
        host=settings.GATEWAY_HOST,
        port=settings.GATEWAY_PORT,
        reload=settings.DEBUG,
    )
