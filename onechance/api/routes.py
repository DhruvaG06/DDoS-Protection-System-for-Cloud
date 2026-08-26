"""OneChance API Gateway Reverse-Proxy & Traffic Telemetry Routes."""

import json
import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import Response as FastAPIResponse
import httpx

from onechance.config import settings
from onechance.logging.traffic_logger import traffic_logger

router = APIRouter()


async def forward_request(
    path: str,
    request: Request,
) -> FastAPIResponse:
    """Core reverse-proxy forwarder:
    
    1. Capture request metadata (request_id, timestamp, source, method, endpoint, user_agent)
    2. Forward to target application (origin workload)
    3. Measure latency / duration
    4. Capture response status code
    5. Emit structured traffic log
    6. Return response to client with tracing headers
    """
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    start_time = time.time()
    source = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    method = request.method
    endpoint = f"/{path.lstrip('/')}"
    if request.url.query:
        endpoint = f"{endpoint}?{request.url.query}"

    target_base = settings.TARGET_SERVICE_URL.rstrip("/")
    forward_url = f"{target_base}/{path.lstrip('/')}"
    
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    content_bytes = b""
    media_type = "application/json"

    try:
        body = await request.body()
        # Build headers for forwarding (strip host)
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ["host", "content-length"]
        }
        forward_headers["x-request-id"] = request_id
        forward_headers["x-forwarded-for"] = source

        async with httpx.AsyncClient(timeout=settings.TARGET_SERVICE_TIMEOUT_SECONDS) as client:
            backend_resp = await client.request(
                method=method,
                url=forward_url,
                headers=forward_headers,
                content=body,
                params=request.query_params,
            )
            status_code = backend_resp.status_code
            content_bytes = backend_resp.content
            media_type = backend_resp.headers.get("content-type", "application/json")

    except httpx.ConnectError:
        status_code = status.HTTP_502_BAD_GATEWAY
        content_bytes = json.dumps({
            "error": "Bad Gateway",
            "message": f"Could not connect to target service at {target_base}.",
            "request_id": request_id,
            "target_url": forward_url,
        }).encode("utf-8")
    except httpx.TimeoutException:
        status_code = status.HTTP_504_GATEWAY_TIMEOUT
        content_bytes = json.dumps({
            "error": "Gateway Timeout",
            "message": f"Target service timed out after {settings.TARGET_SERVICE_TIMEOUT_SECONDS}s.",
            "request_id": request_id,
            "target_url": forward_url,
        }).encode("utf-8")
    except Exception as e:
        status_code = status.HTTP_502_BAD_GATEWAY
        content_bytes = json.dumps({
            "error": "Proxy Error",
            "message": f"Error forwarding request: {str(e)}",
            "request_id": request_id,
        }).encode("utf-8")

    # Measure latency
    latency_ms = (time.time() - start_time) * 1000.0

    # Record structured traffic log
    traffic_logger.log_request(
        request_id=request_id,
        timestamp=start_time,
        source=source,
        method=method,
        endpoint=endpoint,
        user_agent=user_agent,
        status_code=status_code,
        latency_ms=latency_ms,
    )

    # Return response with tracing headers
    headers = {
        "x-request-id": request_id,
        "x-gateway-latency-ms": f"{latency_ms:.2f}",
    }

    return FastAPIResponse(
        content=content_bytes,
        status_code=status_code,
        media_type=media_type,
        headers=headers,
    )


@router.get("/api/health", tags=["Health"])
async def comprehensive_health() -> Dict[str, Any]:
    """Exposes health information for both Gateway and Target Application."""
    start_time = time.time()
    target_base = settings.TARGET_SERVICE_URL.rstrip("/")
    target_health_url = f"{target_base}/api/health"
    
    target_status = "unreachable"
    target_latency_ms = 0.0
    target_details: Optional[Dict[str, Any]] = None

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(target_health_url)
            target_latency_ms = (time.time() - start_time) * 1000.0
            if resp.status_code == 200:
                target_status = "healthy"
                try:
                    target_details = resp.json()
                except Exception:
                    target_details = {"raw": resp.text}
            else:
                target_status = "degraded"
    except Exception as e:
        target_status = "unreachable"
        target_details = {"error": str(e)}

    return {
        "status": "healthy" if target_status == "healthy" else "degraded",
        "gateway": {
            "status": "online",
            "timestamp": time.time(),
            "environment": settings.ENVIRONMENT,
        },
        "target_application": {
            "status": target_status,
            "url": target_base,
            "latency_ms": round(target_latency_ms, 2),
            "details": target_details,
        },
        "traffic_telemetry": {
            "total_logged_requests": traffic_logger.get_total_logged_count(),
        },
    }


@router.get("/api/traffic-logs", tags=["Traffic Telemetry"])
@router.get("/api/logs", tags=["Traffic Telemetry"])
async def get_traffic_logs(limit: int = Query(default=50, ge=1, le=500)) -> Dict[str, Any]:
    """Retrieve recent structured traffic logs."""
    logs = traffic_logger.get_recent_logs(limit=limit)
    return {
        "total_buffered": traffic_logger.get_total_logged_count(),
        "returned_count": len(logs),
        "logs": logs,
    }


# Forward explicit API routes to target application
@router.get("/api/products", tags=["Demo App (Proxied)"])
async def proxy_products(request: Request) -> FastAPIResponse:
    return await forward_request("api/products", request)


@router.get("/api/search", tags=["Demo App (Proxied)"])
async def proxy_search(request: Request) -> FastAPIResponse:
    return await forward_request("api/search", request)


@router.post("/api/login", tags=["Demo App (Proxied)"])
async def proxy_login(request: Request) -> FastAPIResponse:
    return await forward_request("api/login", request)


@router.get("/api/expensive-operation", tags=["Demo App (Proxied)"])
async def proxy_expensive_op(request: Request) -> FastAPIResponse:
    return await forward_request("api/expensive-operation", request)


# General proxy route for any `/proxy/{path}` or root `/`
@router.api_route(
    "/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    tags=["Generic Ingress Proxy"],
)
async def proxy_wildcard(path: str, request: Request) -> FastAPIResponse:
    return await forward_request(path, request)


@router.get("/app-root", tags=["Demo App (Proxied)"])
async def proxy_root_alias(request: Request) -> FastAPIResponse:
    """Forward to target application root."""
    return await forward_request("", request)
