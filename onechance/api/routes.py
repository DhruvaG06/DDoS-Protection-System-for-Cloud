"""OneChance API Gateway Reverse-Proxy & Adaptive Defense Routes (Phase 3)."""

import json
import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response, status
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
from onechance.models.traffic import AttackSourceType, IncomingRequest

router = APIRouter()

# Singletons for Feature Extractor, Detector, Risk Scorer, Policy Engine, Mitigator, Rate Limiter & Event Logger
feature_extractor = FeatureExtractor(window_duration_seconds=float(settings.RATE_LIMIT_WINDOW_SECONDS))
detector = ModularDetectorEngine(model_path=settings.DETECTOR_MODEL_PATH)
risk_scorer = RiskScorer()
policy_engine = PolicyEngine()
mitigator = Mitigator()
rate_limiter = RateLimiter(default_per_ip_limit=settings.RATE_LIMIT_PER_IP_PER_SEC)
event_logger = SecurityEventLogger()


class ChallengeVerifyRequest(BaseModel):
    client_ip: Optional[str] = None
    challenge_token: str


class UnblockRequest(BaseModel):
    client_ip: str


async def forward_request(
    path: str,
    request: Request,
) -> FastAPIResponse:
    """Core reverse-proxy forwarder integrated with Phase 3 Adaptive Defense (ALLOW -> CHALLENGE -> BLOCK)."""
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
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
            headers={
                "x-request-id": request_id,
                "x-decision": block_decision.decision.value,
                "x-risk-score": str(block_decision.risk_score),
                "x-threat-level": block_decision.threat_level.value,
                "x-policy-version": block_decision.policy_version,
                "retry-after": str(int(remaining_seconds or 60)),
            },
        )

    # 2. Check Rate Limiter
    is_rl, rl_reason = rate_limiter.is_rate_limited(source, endpoint)
    if is_rl:
        metadata["is_rate_limited"] = True
        metadata["rate_limit_reason"] = rl_reason

    # 3. Check Security Challenge Verification Token in Headers/Query Params
    challenge_token_hdr = request.headers.get("x-challenge-token") or request.query_params.get("challenge_token")
    if challenge_token_hdr:
        valid_tok, failed_count = mitigator.verify_challenge(source, challenge_token_hdr)
        if valid_tok:
            metadata["challenge_verified"] = True
        else:
            metadata["challenge_failed"] = True
            metadata["failed_count"] = failed_count
    elif mitigator.is_session_verified(source):
        metadata["challenge_verified"] = True

    # 4. Phase 2 Feature Extraction & Anomaly Risk Scoring
    inc_req = IncomingRequest(
        client_ip=source,
        method=method,
        path=endpoint,
        user_agent=user_agent,
        timestamp=start_time,
        source_type=AttackSourceType.INTERNAL if ("internal" in user_agent.lower() or source.startswith("10.")) else AttackSourceType.EXTERNAL,
    )
    features = feature_extractor.extract_features(inc_req)
    anomaly_prob = detector.predict_anomaly_probability(features)
    risk_assessment = risk_scorer.calculate_risk(features, anomaly_prob, detector.version)

    # 5. Phase 3 Policy Engine Evaluation
    policy_decision = policy_engine.evaluate(risk_assessment, endpoint=endpoint, request_metadata=metadata)
    mitigator.apply_decision(policy_decision)

    # 6. Log Security Telemetry Event
    attack_origin = "internal_cloud_workload" if features.is_internal_workload else "external_internet"
    service_name = endpoint.split("?")[0].strip("/").split("/")[0] or "gateway_ingress"
    sec_event = SecurityEvent(
        source=source,
        endpoint=endpoint,
        risk_score=policy_decision.risk_score,
        threat_level=policy_decision.threat_level,
        decision=policy_decision.decision,
        action=policy_decision.action_type,
        reasons=policy_decision.reasons,
        attack_origin=attack_origin,
        affected_service=service_name,
        policy_version=policy_decision.policy_version,
    )
    event_logger.log_event(sec_event)

    # 7. Action Execution based on Policy Decision
    if policy_decision.decision == ActionEnum.BLOCK:
        return FastAPIResponse(
            content=json.dumps({
                "error": "Access Blocked by Policy Engine",
                "decision": policy_decision.decision.value,
                "action": policy_decision.action_type,
                "risk_score": policy_decision.risk_score,
                "threat_level": policy_decision.threat_level.value,
                "block_duration_seconds": policy_decision.block_duration_seconds,
                "reasons": policy_decision.reasons,
                "explanation": policy_decision.reason,
                "request_id": request_id,
            }).encode("utf-8"),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json",
            headers={
                "x-request-id": request_id,
                "x-decision": policy_decision.decision.value,
                "x-risk-score": str(policy_decision.risk_score),
                "x-threat-level": policy_decision.threat_level.value,
                "x-policy-version": policy_decision.policy_version,
                "retry-after": str(policy_decision.block_duration_seconds or 60),
            },
        )

    if policy_decision.decision == ActionEnum.CHALLENGE:
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

    # 8. ALLOW: Forward Request to Target Application
    target_base = settings.TARGET_SERVICE_URL.rstrip("/")
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
            "message": f"Could not connect to target service at {target_base}.",
            "request_id": request_id,
        }).encode("utf-8")
    except httpx.TimeoutException:
        status_code = status.HTTP_504_GATEWAY_TIMEOUT
        content_bytes = json.dumps({
            "error": "Gateway Timeout",
            "message": f"Target service timed out after {settings.TARGET_SERVICE_TIMEOUT_SECONDS}s.",
            "request_id": request_id,
        }).encode("utf-8")
    except Exception as e:
        status_code = status.HTTP_502_BAD_GATEWAY
        content_bytes = json.dumps({
            "error": "Proxy Error",
            "message": str(e),
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
    }

    return FastAPIResponse(
        content=content_bytes,
        status_code=status_code,
        media_type=media_type,
        headers=headers,
    )


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
    """Health information including Phase 3 adaptive defense state."""
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
        "detection_engine": {
            "active_version": detector.version,
            "rf_model_loaded": detector.rf_detector.is_loaded,
        },
        "policy_engine": {
            "active_version": policy_engine.policy_version,
            "mitigation_status": mitigator.get_mitigation_status(),
        },
        "target_application": {
            "status": target_status,
            "url": target_base,
            "latency_ms": round(target_latency_ms, 2),
            "details": target_details,
        },
        "telemetry": {
            "total_logged_traffic": traffic_logger.get_total_logged_count(),
            "buffered_security_events": len(event_logger.get_recent_events(limit=500)),
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


@router.api_route(
    "/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    tags=["Generic Ingress Proxy"],
)
async def proxy_wildcard(path: str, request: Request) -> FastAPIResponse:
    return await forward_request(path, request)


@router.get("/app-root", tags=["Demo App (Proxied)"])
async def proxy_root_alias(request: Request) -> FastAPIResponse:
    return await forward_request("", request)
