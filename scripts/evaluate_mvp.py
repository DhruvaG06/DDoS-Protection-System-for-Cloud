"""OneChance — Phase 6: MVP Evaluation & Benchmark Suite.

Executes repeatable end-to-end evaluation runs measuring:
1. Detection Latency & Mitigation Decision Latency
2. Precision, Recall, and F1 Score on Behavioral Test Dataset
3. High-Rate Attack, Behavioral Anomaly, and Internal Cloud Workload Mitigation
4. Autonomous Recovery Timing (Isolation, Replacement, Verification)
5. Service Availability & Zero-Downtime Traffic Rerouting Verification

All metrics are measured directly against the active OneChance Gateway & Engine.
Outputs structured console tables and saves 'logs/evaluation_report.json'.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure repository root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from onechance.core.detector import ModularDetectorEngine
from onechance.core.feature_extractor import FeatureExtractor
from onechance.core.policy_engine import PolicyEngine
from onechance.core.risk_scorer import RiskScorer
from onechance.models.decisions import ActionEnum
from onechance.models.traffic import AttackSourceType, IncomingRequest
from onechance.recovery.recovery_controller import RecoveryController
from onechance.recovery.service_registry import ServiceRegistry

console = Console()
GATEWAY_URL = "http://127.0.0.1:8000"


def evaluate_detector_quality() -> Dict[str, Any]:
    """Evaluate detection engine precision, recall, and F1 score against synthetic ground truth."""
    extractor = FeatureExtractor(window_duration_seconds=5.0)
    detector = ModularDetectorEngine()
    scorer = RiskScorer()
    engine = PolicyEngine()

    ground_truth: List[int] = []  # 0 = Normal, 1 = Attack
    predictions: List[int] = []   # 0 = ALLOW, 1 = CHALLENGE/BLOCK
    latencies_ms: List[float] = []

    # 1. Normal traffic samples (Ground Truth: 0)
    for i in range(25):
        ip = f"192.168.1.{10 + (i % 5)}"
        req = IncomingRequest(
            client_ip=ip,
            method="GET",
            path=f"/api/products?page={i % 3}",
            timestamp=time.time() + (i * 0.1),
            user_agent="Mozilla/5.0 NormalUser",
            source_type=AttackSourceType.EXTERNAL,
        )
        t0 = time.perf_counter()
        features = extractor.extract_features(req)
        anomaly_prob = detector.predict_anomaly_probability(features)
        assessment = scorer.calculate_risk(features, anomaly_prob, detector.version)
        decision = engine.evaluate(assessment, endpoint=req.path)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        ground_truth.append(0)
        predictions.append(1 if decision.decision in [ActionEnum.CHALLENGE, ActionEnum.BLOCK] else 0)

    # 2. High-Rate External Attack (Ground Truth: 1)
    for i in range(30):
        req = IncomingRequest(
            client_ip="203.0.113.88",
            method="GET",
            path="/api/expensive-operation",
            timestamp=time.time() + (i * 0.005),
            user_agent="External-Botnet/3.0",
            source_type=AttackSourceType.EXTERNAL,
        )
        t0 = time.perf_counter()
        features = extractor.extract_features(req)
        anomaly_prob = detector.predict_anomaly_probability(features)
        assessment = scorer.calculate_risk(features, anomaly_prob, detector.version)
        decision = engine.evaluate(assessment, endpoint=req.path)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        ground_truth.append(1)
        predictions.append(1 if decision.decision in [ActionEnum.CHALLENGE, ActionEnum.BLOCK] else 0)

    # 3. Internal Compromised Workload Attack (Ground Truth: 1)
    for i in range(20):
        req = IncomingRequest(
            client_ip="10.0.4.99",
            method="POST",
            path="/api/login",
            timestamp=time.time() + (i * 0.01),
            user_agent="Internal-Worker/1.0",
            source_type=AttackSourceType.INTERNAL_COMPROMISED,
        )
        t0 = time.perf_counter()
        features = extractor.extract_features(req)
        anomaly_prob = detector.predict_anomaly_probability(features)
        assessment = scorer.calculate_risk(features, anomaly_prob, detector.version)
        decision = engine.evaluate(assessment, endpoint=req.path)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        ground_truth.append(1)
        predictions.append(1 if decision.decision in [ActionEnum.CHALLENGE, ActionEnum.BLOCK] else 0)

    # Compute Confusion Matrix
    tp = sum(1 for gt, pr in zip(ground_truth, predictions) if gt == 1 and pr == 1)
    fp = sum(1 for gt, pr in zip(ground_truth, predictions) if gt == 0 and pr == 1)
    tn = sum(1 for gt, pr in zip(ground_truth, predictions) if gt == 0 and pr == 0)
    fn = sum(1 for gt, pr in zip(ground_truth, predictions) if gt == 1 and pr == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0
    avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

    return {
        "samples_evaluated": len(ground_truth),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "average_pipeline_latency_ms": round(avg_latency, 3),
        "max_pipeline_latency_ms": round(max(latencies_ms), 3) if latencies_ms else 0.0,
    }


async def evaluate_gateway_scenarios() -> Dict[str, Any]:
    """Execute live HTTP benchmark against running Gateway."""
    results: Dict[str, Any] = {}

    async with httpx.AsyncClient(timeout=5.0) as client:
        # Reset Gateway
        try:
            await client.post(f"{GATEWAY_URL}/api/demo/reset")
        except Exception:
            pass

        # -------------------------------------------------------------
        # Scenario 1: Normal Ingress Traffic
        # -------------------------------------------------------------
        normal_latencies = []
        normal_statuses = []
        for _ in range(15):
            t0 = time.perf_counter()
            resp = await client.get(f"{GATEWAY_URL}/api/products")
            normal_latencies.append((time.perf_counter() - t0) * 1000.0)
            normal_statuses.append(resp.status_code)
            await asyncio.sleep(0.02)

        normal_allowed = sum(1 for s in normal_statuses if s == 200)
        results["normal_traffic"] = {
            "requests_sent": len(normal_statuses),
            "allowed_count": normal_allowed,
            "success_rate": round(normal_allowed / len(normal_statuses), 3),
            "avg_latency_ms": round(sum(normal_latencies) / len(normal_latencies), 2),
        }

        # -------------------------------------------------------------
        # Scenario 2: External DDoS Flood Attack
        # -------------------------------------------------------------
        attack_statuses = []
        for _ in range(30):
            resp = await client.get(
                f"{GATEWAY_URL}/api/expensive-operation",
                headers={"user-agent": "Botnet-Flood/4.0", "x-forwarded-for": "198.51.100.22"},
            )
            attack_statuses.append(resp.status_code)

        blocked_count = sum(1 for s in attack_statuses if s == 403)
        results["external_attack"] = {
            "requests_sent": len(attack_statuses),
            "mitigated_count": blocked_count,
            "mitigation_rate": round(blocked_count / len(attack_statuses), 3),
        }

        # -------------------------------------------------------------
        # Scenario 3: Internal Compromised Microservice Attack
        # -------------------------------------------------------------
        internal_statuses = []
        for _ in range(25):
            resp = await client.post(
                f"{GATEWAY_URL}/api/login",
                headers={
                    "user-agent": "Internal-Compromised-Worker/1.0",
                    "x-attack-origin": "internal",
                    "x-forwarded-for": "10.0.8.88",
                },
                json={"username": "root", "password": "compromised"},
            )
            internal_statuses.append(resp.status_code)

        internal_blocked = sum(1 for s in internal_statuses if s == 403)
        results["internal_attack"] = {
            "requests_sent": len(internal_statuses),
            "mitigated_count": internal_blocked,
            "mitigation_rate": round(internal_blocked / len(internal_statuses), 3),
        }

        # -------------------------------------------------------------
        # Scenario 4: Autonomous Recovery & Availability Under Failure
        # -------------------------------------------------------------
        t_rec_start = time.perf_counter()
        fail_resp = await client.post(
            f"{GATEWAY_URL}/api/recovery/simulate-failure",
            json={"instance_id": "app-2", "reason": "Benchmark container crash"},
        )
        t_fail_ack = (time.perf_counter() - t_rec_start) * 1000.0

        # Verify availability during isolation
        active_nodes = []
        for _ in range(6):
            r = await client.get(f"{GATEWAY_URL}/api/products")
            node = r.headers.get("x-target-instance", "unknown")
            active_nodes.append(node)

        # Wait for recovery completion
        recovery_verified = False
        t_verified = 0.0
        for _ in range(15):
            await asyncio.sleep(0.3)
            rec_status = await client.get(f"{GATEWAY_URL}/api/recovery/status")
            data = rec_status.json()
            if data.get("verification_metrics", {}).get("recovery_confidence", 0) >= 80.0:
                recovery_verified = True
                t_verified = (time.perf_counter() - t_rec_start) * 1000.0
                break

        results["autonomous_recovery"] = {
            "failure_acknowledgement_ms": round(t_fail_ack, 2),
            "isolated_instance_excluded_from_traffic": "app-2" not in active_nodes,
            "surviving_nodes_served_traffic": list(set(active_nodes)),
            "recovery_verified": recovery_verified,
            "total_recovery_duration_ms": round(t_verified, 2) if recovery_verified else None,
        }

        # Clean reset at end
        await client.post(f"{GATEWAY_URL}/api/demo/reset")

    return results


async def run_evaluation_suite():
    console.print(
        Panel.fit(
            "[bold cyan]ONECHANCE — PHASE 6 MVP EVALUATION SUITE[/bold cyan]\n"
            "[bold white]Closed-Loop Performance, Reliability & Detection Quality Benchmark[/bold white]",
            border_style="cyan",
        )
    )

    console.print("\n[bold green]1. Measuring Detection Quality & Core Pipeline Latency...[/bold green]")
    detector_metrics = evaluate_detector_quality()

    table1 = Table(title="ML & Behavioral Detection Performance", header_style="bold magenta")
    table1.add_column("Metric", style="cyan")
    table1.add_column("Measured Value", style="green")
    table1.add_row("Samples Evaluated", str(detector_metrics["samples_evaluated"]))
    table1.add_row("Precision", f"{detector_metrics['precision'] * 100:.2f}%")
    table1.add_row("Recall", f"{detector_metrics['recall'] * 100:.2f}%")
    table1.add_row("F1 Score", f"{detector_metrics['f1_score']:.4f}")
    table1.add_row("Average Pipeline Latency", f"{detector_metrics['average_pipeline_latency_ms']:.3f} ms")
    table1.add_row("Max Pipeline Latency", f"{detector_metrics['max_pipeline_latency_ms']:.3f} ms")
    console.print(table1)

    console.print("\n[bold green]2. Testing Live Gateway Scenario Benchmarks...[/bold green]")
    try:
        gateway_metrics = await evaluate_gateway_scenarios()

        table2 = Table(title="Gateway Live Attack & Recovery Scenarios", header_style="bold blue")
        table2.add_column("Scenario", style="cyan")
        table2.add_column("Traffic Sent", style="white")
        table2.add_column("Mitigated / Served", style="green")
        table2.add_column("Performance Index", style="yellow")

        table2.add_row(
            "Normal Ingress Traffic",
            f"{gateway_metrics['normal_traffic']['requests_sent']} req",
            f"{gateway_metrics['normal_traffic']['allowed_count']} 200 OK",
            f"Avg {gateway_metrics['normal_traffic']['avg_latency_ms']} ms",
        )
        table2.add_row(
            "External DDoS Attack",
            f"{gateway_metrics['external_attack']['requests_sent']} req",
            f"{gateway_metrics['external_attack']['mitigated_count']} Blocked/Challenged",
            f"{gateway_metrics['external_attack']['mitigation_rate']*100:.1f}% Mitigation Rate",
        )
        table2.add_row(
            "Internal Cloud Attack",
            f"{gateway_metrics['internal_attack']['requests_sent']} req",
            f"{gateway_metrics['internal_attack']['mitigated_count']} Blocked/Challenged",
            f"{gateway_metrics['internal_attack']['mitigation_rate']*100:.1f}% Mitigation Rate",
        )
        table2.add_row(
            "Self-Healing Recovery",
            "app-2 failure",
            f"Surviving Nodes: {gateway_metrics['autonomous_recovery']['surviving_nodes_served_traffic']}",
            f"Recovered in {gateway_metrics['autonomous_recovery']['total_recovery_duration_ms']} ms",
        )
        console.print(table2)

    except Exception as e:
        console.print(f"[yellow]Note: Live gateway benchmark skipped (Gateway not running on :8000). Error: {e}[/yellow]")
        gateway_metrics = {"status": "gateway_not_online"}

    # Save evaluation report artifact
    report_data = {
        "timestamp": time.time(),
        "detector_quality": detector_metrics,
        "gateway_scenarios": gateway_metrics,
    }
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    report_path = log_dir / "evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    console.print(f"\n[bold green][OK] Evaluation report saved to {report_path.as_posix()}[/bold green]\n")


if __name__ == "__main__":
    asyncio.run(run_evaluation_suite())
