"""OneChance Gateway & Autonomous Response Main Application Entrypoint."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from onechance.api.routes import router
from onechance.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
)
logger = logging.getLogger("onechance.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan lifecycle manager."""
    logger.info("Initializing OneChance Gateway & Reverse Proxy Layer...")
    yield
    logger.info("Shutting down OneChance Gateway...")


app = FastAPI(
    title="OneChance DDoS Protection Gateway",
    description=(
        "Smart Cloud DDoS Protection System Gateway & Reverse Proxy. "
        "Captures structured traffic telemetry for incoming requests before routing to origin services."
    ),
    version="0.1.0",
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

# Include Gateway and Proxy routes
app.include_router(router)


@app.get("/", tags=["Gateway Status"])
async def gateway_index():
    """OneChance Gateway Index & Endpoint Map."""
    return {
        "gateway": "OneChance Reverse Proxy",
        "status": "online",
        "version": "0.1.0",
        "routes": {
            "health": "/api/health",
            "traffic_logs": "/api/traffic-logs",
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
