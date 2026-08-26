import asyncio
import json
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import Response as FastAPIResponse
import httpx
from pydantic import BaseModel, Field

from onechance.config import settings
from onechance.core.detector import ModularDetectorEngine
from onechance.core.feature_extractor import FeatureExtractor
from onechance.core.mitigator import Mitigator
from onechance.core.policy_engine import PolicyEngine
from onechance.core.rate_limiter import RateLimiter
from onechance.core.risk_scorer import RiskScorer
from onechance.logging.event_logger import SecurityEventLogger
from onechance.logging.traffic_logger import traffic_logger
from onechance.models.decisions import ActionEnum, PolicyDecision, RiskAssessment, ThreatLevel
from onechance.models.events import SecurityEvent
from onechance.models.health import InstanceStatus, RecoveryEvent, RecoveryEventType
from onechance.models.traffic import AttackSourceType, IncomingRequest
from onechance.monitoring.health_monitor import health_monitor
from onechance.recovery.recovery_controller import recovery_controller
from onechance.recovery.service_registry import service_registry

router = APIRouter()

# Singletons for Core Engine
feature_extractor = FeatureExtractor(window_duration_seconds=float(settings.RATE_LIMIT_WINDOW_SECONDS))
detector = ModularDetectorEngine(model_path=settings.DETECTOR_MODEL_PATH)
risk_scorer = RiskScorer()
policy_engine = PolicyEngine()
mitigator = Mitigator()
rate_limiter = RateLimiter(default_per_ip_limit=settings.RATE_LIMIT_PER_IP_PER_SEC)
event_logger = SecurityEventLogger()


class TelemetryConnectionManager:
    """Manages active WebSocket connections and broadcasts real-time security telemetry."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, data: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)


ws_manager = TelemetryConnectionManager()
active_demo_state: Dict[str, bool] = {"running": False}


def _on_security_event_broadcast(event: SecurityEvent):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_json({"type": "SECURITY_EVENT", "event": event.model_dump()}),
                loop,
            )
    except Exception:
        pass


def _on_recovery_event_broadcast(event: RecoveryEvent):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_json({"type": "RECOVERY_EVENT", "event": event.model_dump()}),
                loop,
            )
    except Exception:
        pass


event_logger.on_event_callback = _on_security_event_broadcast
recovery_controller.on_event_callback = _on_recovery_event_broadcast


class ChallengeVerifyRequest(BaseModel):
    client_ip: Optional[str] = None
    challenge_token: str


class UnblockRequest(BaseModel):
    client_ip: str


class FailureSimulationRequest(BaseModel):
    instance_id: str = Field(default="app-2", description="ID of application instance to simulate failure on")
    reason: str = Field(default="Controlled container crash / resource starvation demo", description="Explainability reason")


async def forward_request(
    path: str,
    request: Request,
) -> FastAPIResponse:
    """Core reverse-proxy forwarder integrated with:
    - Phase 2: Hybrid Behavioral Detection & Explainable Risk Scoring
    - Phase 3: Adaptive Defense Engine (ALLOW -> CHALLENGE -> BLOCK) & Rate Limiting
    - Phase 4: Service Registry & Multi-Instance Healthy Pool Routing
    """
    request_id = f"req_{uuid.uuid4().hex[:12]}"
    start_time = time.time()
    source = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")
    method = request.method
    endpoint = f"/{path.lstrip('/')}"
    if request.url.query:
        endpoint = f"{endpoint}?{request.url.query}"

    metadata: Dict[str, Any] = {}

    # 1. Fast-Path IP Block Enforcement
    is_blocked, remaining_seconds = mitigator.is_blocked(source)
    if is_blocked:
        block_decision = PolicyDecision(
            decision=ActionEnum.BLOCK,
            action=ActionEnum.BLOCK,
            client_ip=source,
            endpoint=endpoint,
            risk_score=95.0,
            threat_level=ThreatLevel.HIGH,
            action_type="temporary_block",
            reason=f"IP {source} is currently blocked. Block expires in {remaining_seconds}s.",
            reasons=["Active IP mitigation block in effect", "Previous high-risk anomaly or challenge failures"],
            block_duration_seconds=int(remaining_seconds or 60),
            policy_version=policy_engine.policy_version,
        )
        sec_event = SecurityEvent(
            source=source,
            endpoint=endpoint,
            risk_score=block_decision.risk_score,
            threat_level=block_decision.threat_level,
            decision=block_decision.decision,
            action=block_decision.action_type,
            reasons=block_decision.reasons,
            policy_version=block_decision.policy_version,
        )
        event_logger.log_event(sec_event)

        return FastAPIResponse(
            content=json.dumps({
                "error": "Access Blocked",
                "decision": block_decision.decision.value,
                "action": block_decision.action_type,
                "risk_score": block_decision.risk_score,
                "threat_level": block_decision.threat_level.value,
                "block_remaining_seconds": remaining_seconds,
                "reasons": block_decision.reasons,
                "explanation": block_decision.reason,
                "request_id": request_id,
            }).encode("utf-8"),
            status_code=status.HTTP_403_FORBIDDEN,
            media_type="application/json",
            headers={
                "x-request-id": request_id,
                "x-decision": block_decision.decision.value,
                "x-risk-score": str(block_decision.risk_score),
                "x-threat-level": block_decision.threat_level.value,
                "x-policy-version": block_decision.policy_version,
            },
        )

    # 2. Challenge Token Pass-Through Verification
    challenge_token_header = request.headers.get("x-challenge-token")
    if challenge_token_header:
        valid_challenge, _ = mitigator.verify_challenge(source, challenge_token_header)
        if valid_challenge:
            metadata["challenge_verified"] = True

    # 3. Behavioral Feature Extraction (10 Signals)
    attack_source_header = request.headers.get("x-attack-source", "external")
    source_type = (
        AttackSourceType.INTERNAL_COMPROMISED
        if attack_source_header == "internal"
        else AttackSourceType.EXTERNAL
    )
    incoming_req = IncomingRequest(
        client_ip=source,
        method=method,
        path=endpoint,
        headers=dict(request.headers),
        user_agent=user_agent,
        timestamp=start_time,
        source_type=source_type,
    )
    traffic_features = feature_extractor.extract_features(incoming_req)

    # 4. ML / Behavioral Anomaly Detection
    anomaly_probability = detector.predict_anomaly_probability(traffic_features)

    # 5. Explainable Risk Scoring
    risk_assessment = risk_scorer.calculate_risk(
        features=traffic_features,
        anomaly_probability=anomaly_probability,
        detector_version=detector.version,
    )

    # 6. Adaptive Defense Policy Evaluation (3 Tiers)
    policy_decision = policy_engine.evaluate(
        assessment=risk_assessment,
        endpoint=endpoint,
        client_ip=source,
        has_valid_challenge=metadata.get("challenge_verified", False),
    )

    # 7. Mitigation Table Application
    mitigator.apply_decision(policy_decision)

    # 8. Security Event Logging
    sec_event = SecurityEvent(
        source=source,
        endpoint=endpoint,
        risk_score=policy_decision.risk_score,
        threat_level=policy_decision.threat_level,
        decision=policy_decision.decision,
        action=policy_decision.action_type,
        reasons=policy_decision.reasons,
        attack_origin="internal_cloud_workload" if source_type == AttackSourceType.INTERNAL_COMPROMISED else "external_internet",
        policy_version=policy_decision.policy_version,
    )
    event_logger.log_event(sec_event)

    # 9. Handle BLOCK Decision
    if policy_decision.decision == ActionEnum.BLOCK:
        latency_ms = (time.time() - start_time) * 1000.0
        traffic_logger.log_request(
            request_id=request_id,
            timestamp=start_time,
            source=source,
            method=method,
            endpoint=endpoint,
            user_agent=user_agent,
            status_code=status.HTTP_403_FORBIDDEN,
            latency_ms=latency_ms,
        )
        return FastAPIResponse(
            content=json.dumps({
                "error": "Access Blocked",
                "decision": policy_decision.decision.value,
                "action": policy_decision.action_type,
                "risk_score": policy_decision.risk_score,
                "threat_level": policy_decision.threat_level.value,
                "reasons": policy_decision.reasons,
                "explanation": policy_decision.reason,
                "block_duration_seconds": policy_decision.block_duration_seconds,
                "request_id": request_id,
            }).encode("utf-8"),
            status_code=status.HTTP_403_FORBIDDEN,
            media_type="application/json",
            headers={
                "x-request-id": request_id,
                "x-decision": policy_decision.decision.value,
                "x-risk-score": str(policy_decision.risk_score),
                "x-threat-level": policy_decision.threat_level.value,
                "x-policy-version": policy_decision.policy_version,
            },
        )

    # 10. Handle CHALLENGE Decision
    if policy_decision.decision == ActionEnum.CHALLENGE:
        latency_ms = (time.time() - start_time) * 1000.0
        traffic_logger.log_request(
            request_id=request_id,
            timestamp=start_time,
            source=source,
            method=method,
            endpoint=endpoint,
            user_agent=user_agent,
            status_code=status.HTTP_403_FORBIDDEN,
            latency_ms=latency_ms,
        )
        return FastAPIResponse(
            content=json.dumps({
                "error": "Security Challenge Required",
                "decision": policy_decision.decision.value,
                "action": policy_decision.action_type,
                "risk_score": policy_decision.risk_score,
                "threat_level": policy_decision.threat_level.value,
                "challenge_token": policy_decision.challenge_token,
                "instructions": "Pass 'x-challenge-token' header or submit token to /api/challenge/verify.",
                "reasons": policy_decision.reasons,
                "explanation": policy_decision.reason,
                "request_id": request_id,
            }).encode("utf-8"),
            status_code=status.HTTP_403_FORBIDDEN,
            media_type="application/json",
            headers={
                "x-request-id": request_id,
                "x-decision": policy_decision.decision.value,
                "x-risk-score": str(policy_decision.risk_score),
                "x-threat-level": policy_decision.threat_level.value,
                "x-challenge-token": policy_decision.challenge_token or "",
                "x-policy-version": policy_decision.policy_version,
            },
        )

    # 11. ALLOW: Select Active Healthy Target Instance from Service Registry (Phase 4 Multi-Instance Routing)
    target_instance = service_registry.get_active_healthy_instance()
    if target_instance:
        target_base = target_instance.url.rstrip("/")
        target_instance_id = target_instance.instance_id
    else:
        target_base = settings.TARGET_SERVICE_URL.rstrip("/")
        target_instance_id = "default-fallback"

    forward_url = f"{target_base}/{path.lstrip('/')}"
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    content_bytes = b""
    media_type = "application/json"

    try:
        body = await request.body()
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
            "message": f"Could not connect to target service instance '{target_instance_id}' at {target_base}.",
            "target_instance": target_instance_id,
            "request_id": request_id,
        }).encode("utf-8")
    except httpx.TimeoutException:
        status_code = status.HTTP_504_GATEWAY_TIMEOUT
        content_bytes = json.dumps({
            "error": "Gateway Timeout",
            "message": f"Target service instance '{target_instance_id}' timed out after {settings.TARGET_SERVICE_TIMEOUT_SECONDS}s.",
            "target_instance": target_instance_id,
            "request_id": request_id,
        }).encode("utf-8")
    except Exception as e:
        status_code = status.HTTP_502_BAD_GATEWAY
        content_bytes = json.dumps({
            "error": "Proxy Error",
            "message": str(e),
            "target_instance": target_instance_id,
            "request_id": request_id,
        }).encode("utf-8")

    latency_ms = (time.time() - start_time) * 1000.0

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

    headers = {
        "x-request-id": request_id,
        "x-gateway-latency-ms": f"{latency_ms:.2f}",
        "x-decision": policy_decision.decision.value,
        "x-risk-score": str(policy_decision.risk_score),
        "x-threat-level": policy_decision.threat_level.value,
        "x-detector-version": risk_assessment.detector_version,
        "x-policy-version": policy_decision.policy_version,
        "x-target-instance": target_instance_id,
    }

    return FastAPIResponse(
        content=content_bytes,
        status_code=status_code,
        media_type=media_type,
        headers=headers,
    )


# ==========================================================
# Phase 4 Autonomous Self-Healing & Service Recovery Routes
# ==========================================================

@router.get("/api/recovery/status", tags=["Autonomous Self-Healing"])
async def get_recovery_status() -> Dict[str, Any]:
    """Return cluster health snapshot, active instances, and current Recovery Confidence."""
    verification = recovery_controller.calculate_recovery_confidence()
    snapshot = service_registry.get_cluster_snapshot(recovery_confidence=verification.recovery_confidence)
    return {
        "snapshot": snapshot.model_dump(),
        "verification_metrics": verification.model_dump(),
        "active_healthy_pool": [i.instance_id for i in service_registry.get_active_instances()],
    }


@router.get("/api/recovery/events", tags=["Autonomous Self-Healing"])
async def get_recovery_events(limit: int = Query(default=50, ge=1, le=200)) -> Dict[str, Any]:
    """Retrieve chronological autonomous recovery and infrastructure events."""
    events = recovery_controller.get_timeline(limit=limit)
    return {
        "returned_count": len(events),
        "events": [e.model_dump() for e in events],
    }


@router.post("/api/recovery/simulate-failure", tags=["Autonomous Self-Healing"])
async def simulate_failure_endpoint(body: FailureSimulationRequest) -> Dict[str, Any]:
    """Deterministic failure simulation hook: Marks instance unhealthy and triggers autonomous recovery."""
    result = await recovery_controller.simulate_failure(
        instance_id=body.instance_id,
        reason=body.reason,
    )
    return result


@router.post("/api/recovery/reset", tags=["Autonomous Self-Healing"])
async def reset_recovery_endpoint() -> Dict[str, Any]:
    """Reset all instance states and recovery timeline for a fresh demonstration."""
    recovery_controller.reset_recovery_state()
    return {
        "status": "success",
        "message": "Service registry and recovery controller reset to initial HEALTHY state.",
        "active_instances": [i.instance_id for i in service_registry.get_active_instances()],
    }


@router.get("/api/recovery/verify", tags=["Autonomous Self-Healing"])
async def verify_recovery_endpoint() -> Dict[str, Any]:
    """Compute and return the operational Recovery Confidence Score (0–100)."""
    metrics = recovery_controller.calculate_recovery_confidence()
    return metrics.model_dump()


# ==========================================================
# Phase 3 Adaptive Defense API Routes
# ==========================================================

@router.post("/api/challenge/verify", tags=["Adaptive Defense"])
async def verify_challenge_endpoint(body: ChallengeVerifyRequest, request: Request) -> Dict[str, Any]:
    """API endpoint to verify an active security challenge token for a client IP."""
    client_ip = body.client_ip or (request.client.host if request.client else "127.0.0.1")
    valid, failed_count = mitigator.verify_challenge(client_ip, body.challenge_token)

    if valid:
        return {
            "status": "success",
            "message": "Challenge verified successfully. Session authorized.",
            "client_ip": client_ip,
            "decision": ActionEnum.ALLOW.value,
        }
    
    is_blk, remaining = mitigator.is_blocked(client_ip)
    return {
        "status": "failed",
        "message": "Invalid challenge token.",
        "client_ip": client_ip,
        "failed_attempts": failed_count,
        "is_blocked": is_blk,
        "block_remaining_seconds": remaining,
    }


@router.get("/api/security-events", tags=["Adaptive Defense Telemetry"])
async def get_security_events(
    limit: int = Query(default=50, ge=1, le=500),
    decision: Optional[str] = Query(default=None, description="Filter by decision: ALLOW, CHALLENGE, BLOCK"),
    source: Optional[str] = Query(default=None, description="Filter by client IP source"),
) -> Dict[str, Any]:
    """Retrieve buffered security decision events for real-time monitoring dashboard."""
    events = event_logger.get_recent_events(limit=limit, decision_filter=decision, source_filter=source)
    return {
        "returned_count": len(events),
        "events": events,
    }


@router.get("/api/mitigation/status", tags=["Adaptive Defense Status"])
async def get_mitigation_status_route() -> Dict[str, Any]:
    """Return active mitigation table counts, active IP blocks, and challenge states."""
    mitigation_info = mitigator.get_mitigation_status()
    return {
        "policy_version": policy_engine.policy_version,
        "thresholds": {
            "challenge": policy_engine.challenge_threshold,
            "block": policy_engine.block_threshold,
        },
        "mitigation_tables": mitigation_info,
    }


@router.post("/api/mitigation/unblock", tags=["Adaptive Defense Admin"])
async def unblock_ip_endpoint(body: UnblockRequest) -> Dict[str, Any]:
    """Admin API endpoint to manually unblock an IP address."""
    unblocked = mitigator.unblock_ip(body.client_ip)
    return {
        "client_ip": body.client_ip,
        "unblocked": unblocked,
        "message": f"IP {body.client_ip} unblocked." if unblocked else f"IP {body.client_ip} was not actively blocked.",
    }


@router.get("/api/health", tags=["Health"])
async def comprehensive_health() -> Dict[str, Any]:
    """Comprehensive system health including Phase 4 multi-instance cluster status."""
    verification = recovery_controller.calculate_recovery_confidence()
    cluster_snapshot = service_registry.get_cluster_snapshot(recovery_confidence=verification.recovery_confidence)

    return {
        "status": cluster_snapshot.cluster_status.lower(),
        "cluster_status": cluster_snapshot.cluster_status,
        "recovery_confidence": verification.recovery_confidence,
        "gateway": {
            "status": "online",
            "timestamp": time.time(),
            "environment": settings.ENVIRONMENT,
        },
        "detection_engine": {
            "active_version": detector.version,
            "rf_model_loaded": detector.rf_detector.is_loaded,
        },
        "policy_engine": {
            "active_version": policy_engine.policy_version,
            "mitigation_status": mitigator.get_mitigation_status(),
        },
        "cluster_health": cluster_snapshot.model_dump(),
        "telemetry": {
            "total_logged_traffic": traffic_logger.get_total_logged_count(),
            "buffered_security_events": len(event_logger.get_recent_events(limit=500)),
            "buffered_recovery_events": len(recovery_controller.get_timeline(limit=200)),
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


@router.post("/api/detection/assess", tags=["Detection API"])
async def assess_request_risk(request_data: IncomingRequest) -> RiskAssessment:
    """Internal API service interface evaluating risk score, threat level, features & explainability reasons."""
    features = feature_extractor.extract_features(request_data)
    anomaly_prob = detector.predict_anomaly_probability(features)
    return risk_scorer.calculate_risk(features, anomaly_prob, detector.version)


@router.get("/api/detection/status", tags=["Detection API"])
async def get_detection_status() -> Dict[str, Any]:
    """Return active detector status, model state, feature importances, and scoring thresholds."""
    return {
        "detector_version": detector.version,
        "rf_model_loaded": detector.rf_detector.is_loaded,
        "rf_model_path": settings.DETECTOR_MODEL_PATH,
        "feature_importances": detector.get_feature_importances(),
        "thresholds": {
            "low_max": settings.RISK_LOW_MAX,
            "medium_max": settings.RISK_MEDIUM_MAX,
            "challenge_threshold": settings.RISK_THRESHOLD_CHALLENGE,
            "block_threshold": settings.RISK_THRESHOLD_BLOCK,
        },
    }


# Forward explicit API routes to target application pool
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


# ==========================================
# WebSocket Telemetry & Demo Controls (Phase 5)
# ==========================================

@router.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """Real-time WebSocket telemetry stream for Live Security Operations Dashboard."""
    await ws_manager.connect(websocket)
    try:
        sec_events = [e.model_dump() for e in event_logger.get_recent_events(limit=50)]
        rec_events = [e.model_dump() for e in recovery_controller.get_timeline(limit=50)]
        all_instances = [inst.model_dump() for inst in service_registry.get_all_instances()]
        conf = recovery_controller.calculate_recovery_confidence().model_dump()

        await websocket.send_json({
            "type": "INITIAL_SNAPSHOT",
            "security_events": sec_events,
            "recovery_events": rec_events,
            "instances": all_instances,
            "recovery_confidence": conf,
            "timestamp": time.time(),
        })

        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "PONG", "timestamp": time.time()})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


@router.post("/api/demo/start-normal", tags=["Demo Controls"])
async def demo_start_normal():
    """Simulate normal background user traffic."""
    active_demo_state["running"] = False
    await asyncio.sleep(0.1)
    active_demo_state["running"] = True

    def _run_normal():
        client = httpx.Client(base_url=f"http://127.0.0.1:{settings.GATEWAY_PORT}", timeout=3.0)
        endpoints = ["/api/products", "/api/search?q=security", "/app-root"]
        while active_demo_state.get("running", False):
            for ep in endpoints:
                if not active_demo_state.get("running", False):
                    break
                try:
                    client.get(ep, headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0)"})
                except Exception:
                    pass
                time.sleep(0.3)

    threading.Thread(target=_run_normal, daemon=True).start()
    return {"status": "success", "message": "Normal background traffic simulation started"}


@router.post("/api/demo/start-attack", tags=["Demo Controls"])
async def demo_start_attack():
    """Simulate external DDoS flood attack."""
    active_demo_state["running"] = False
    await asyncio.sleep(0.1)
    active_demo_state["running"] = True

    def _run_attack():
        client = httpx.Client(base_url=f"http://127.0.0.1:{settings.GATEWAY_PORT}", timeout=3.0)
        while active_demo_state.get("running", False):
            try:
                client.get("/api/expensive-operation?iterations=5000", headers={"user-agent": "External-Botnet/3.0"})
            except Exception:
                pass
            time.sleep(0.04)

    threading.Thread(target=_run_attack, daemon=True).start()
    return {"status": "success", "message": "External DDoS attack simulation started"}


@router.post("/api/demo/start-internal-attack", tags=["Demo Controls"])
async def demo_start_internal_attack():
    """Simulate internal cloud workload attack."""
    active_demo_state["running"] = False
    await asyncio.sleep(0.1)
    active_demo_state["running"] = True

    def _run_internal():
        client = httpx.Client(base_url=f"http://127.0.0.1:{settings.GATEWAY_PORT}", timeout=3.0)
        headers = {
            "user-agent": "Internal-Compromised-Microservice/1.0",
            "x-attack-origin": "internal",
            "x-forwarded-for": "10.0.9.99",
        }
        while active_demo_state.get("running", False):
            try:
                client.get("/api/expensive-operation?iterations=2000", headers=headers)
            except Exception:
                pass
            time.sleep(0.04)

    threading.Thread(target=_run_internal, daemon=True).start()
    return {"status": "success", "message": "Internal cloud workload attack simulation started"}


@router.post("/api/demo/stop-attack", tags=["Demo Controls"])
async def demo_stop_attack():
    """Stop active simulation traffic threads."""
    active_demo_state["running"] = False
    return {"status": "success", "message": "Simulation traffic stopped"}


@router.post("/api/demo/reset", tags=["Demo Controls"])
async def demo_reset():
    """Reset system state, clear blocklists, and restore service registry."""
    active_demo_state["running"] = False
    mitigator.clear()
    event_logger.clear()
    traffic_logger.clear()
    feature_extractor.clear()
    rate_limiter.clear()
    recovery_controller.reset_recovery_state()

    # Broadcast reset to WebSocket clients
    await ws_manager.broadcast_json({
        "type": "RESET",
        "timestamp": time.time(),
        "instances": [inst.model_dump() for inst in service_registry.get_all_instances()],
        "recovery_confidence": recovery_controller.calculate_recovery_confidence().model_dump(),
    })
    return {"status": "success", "message": "System state reset successfully"}

