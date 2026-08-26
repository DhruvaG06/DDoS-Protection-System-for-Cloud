# OneChance — Smart Cloud DDoS Protection & Autonomous Response System

> **Smart India Hackathon 2026**  
> **Problem Statement**: DDoS Protection System for Cloud: Architecture and Tool  
> **Problem Statement ID**: `DJS_26_SW_05`  
> **Repository**: `DhruvaG06/DDoS-Protection-System-for-Cloud`

---

## 🎯 Core USP

> **OneChance connects behavioral DDoS detection with autonomous service recovery.**

Traditional DDoS mitigations stop at:
$$\text{Detect} \longrightarrow \text{Block}$$

OneChance delivers the complete autonomous closed-loop lifecycle:
$$\text{Traffic} \longrightarrow \text{Behavioral Analysis} \longrightarrow \text{Risk Score} \longrightarrow \text{Allow / Challenge / Block} \longrightarrow \text{Mitigation} \longrightarrow \text{Service Health Monitoring} \longrightarrow \text{Automatic Isolation} \longrightarrow \text{Recovery Verification}$$

---

## 💡 System Innovations & Highlights

1. **Behavioral Anomaly Detection (Beyond Volume Thresholds)**:
   - 10 multi-dimensional extracted signals including request rates, endpoint concentration entropy, burstiness, source distribution, and repeated pattern scores.
   - Modular engine pairing a trained **Random Forest Classifier** with an automatic **Statistical / Heuristic Fail-Safe Fallback**.
2. **Risk-Adaptive 3-Tier Defense Engine**:
   - `ALLOW` (Risk 0–39): Clean traffic forwarded with low latency (`action_type: forward`).
   - `CHALLENGE` (Risk 40–69): Suspicious traffic issued short-lived cryptographic verification tokens (`action_type: challenge_issued`).
   - `BLOCK` (Risk 70–100): High-confidence malicious traffic blocked at the ingress edge (`action_type: temporary_block`).
3. **Autonomous Self-Healing & Closed-Loop Service Recovery**:
   - **DETECT**: Continuous health monitor probes container fleet availability and latency.
   - **ISOLATE**: Immediately detaches degraded containers from ingress routing (`INSTANCE_ISOLATED`).
   - **REROUTE**: Seamlessly redistributes ingress traffic across surviving healthy instances (`TRAFFIC_REROUTED`).
   - **REPLACE**: Automatically triggers clean container process restoration (`REPLACEMENT_STARTED`).
   - **HEALTH CHECK**: Requires $N=3$ consecutive successful probes before clearance (`REPLACEMENT_HEALTHY`).
   - **REINTRODUCE**: Restores verified healthy instances to active load balancing (`INSTANCE_REINTRODUCED`).
   - **VERIFY RECOVERY**: Computes operational **Recovery Confidence Score (0–100)** (`SERVICE_RECOVERY_VERIFIED`).
4. **Internal Compromised Cloud Workload Awareness**:
   - Classifies both external flood traffic and compromised internal microservices (`Attack Origin: INTERNAL WORKLOAD`).
5. **Live Real-Time Security Operations Dashboard**:
   - React + Vite live dashboard with real-time WebSocket telemetry, interactive attack simulators, decision explainability inspector, and infrastructure cluster health panel.

---

## 🏗️ Architecture Overview

```
                      [ Client Traffic / External Attack / Internal Microservice ]
                                                   │
                                                   ▼
                        ┌─────────────────────────────────────────────────────┐
                        │              OneChance API Gateway Layer            │
                        │           (FastAPI Reverse Proxy & Firewall)        │
                        ├─────────────────────────────────────────────────────┤
                        │  • 10-Signal Behavioral Feature Extraction          │
                        │  • Hybrid ML Random Forest Anomaly Detector         │
                        │  • Multi-Signal Explainable Risk Scorer (0-100)     │
                        │  • 3-Tier Adaptive Policy Engine (ALLOW/CHAL/BLOCK) │
                        │  • WebSocket Real-Time Broadcast Server             │
                        └──────────────────────────┬──────────────────────────┘
                                                   │
                                                   ▼ (Routes only to healthy nodes)
                      ┌────────────────────────────┼────────────────────────────┐
                      ▼                            ▼                            ▼
           ┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
           │    app-1 (8001)     │      │    app-2 (8002)     │      │    app-3 (8003)     │
           │  Healthy / Serving  │      │  Healthy / Serving  │      │  Healthy / Serving  │
           └─────────────────────┘      └─────────────────────┘      └─────────────────────┘
                      │                            ▲
                      │         [ISOLATE / REROUTE / RESTORE]
                      └────────────────────────────┘
```

---

## ⏱️ 3-MINUTE JUDGE DEMONSTRATION

Follow these steps for an interactive demonstration of the closed-loop workflow:

### Option A: Web Dashboard Demo (Visual)

1. **Open Dashboard**: Navigate to `http://localhost:5173` in your browser.
2. **Initial State**: Observe all 3 nodes (`app-1`, `app-2`, `app-3`) showing **HEALTHY** and Threat Status **PROTECTED / LOW RISK**.
3. **Normal Traffic**: Click **"Simulate Normal Traffic"** — observe legitimate requests passing with decision `ALLOW` and low risk score.
4. **External DDoS Attack**: Click **"Simulate DDoS Attack"** — observe real-time risk score spike to $>80$, decision transitions to `BLOCK`, and blocked traffic spikes in the live chart.
5. **Internal Attack**: Click **"Simulate Internal Attack"** — observe threat card highlight **Attack Origin: INTERNAL WORKLOAD**.
6. **Simulate Failure**: Click **"Crash app-2"** under Infrastructure Health:
   - Node `app-2` turns **UNHEALTHY** and is automatically **ISOLATED**.
   - Traffic reroutes to `app-1` + `app-3` with **zero dropped requests**.
   - Replacement sequence starts, passes health probes, and reintroduces `app-2`.
   - Recovery verified with **Recovery Confidence Score $>90\%$**.
7. **Reset**: Click **"Reset System State"** — cluster, blocklists, and charts return to clean baseline state.

### Option B: Terminal CLI Master Demo

In a separate terminal, run:
```bash
python scripts/demo_phase6_master.py
```
This executes the 12-step autonomous closed loop with formatted terminal tables and real-time step confirmations.

---

## 📊 Measured Benchmark Results (Phase 6 Evaluation)

Evaluated directly on the running system via `scripts/evaluate_mvp.py` (*no fabricated metrics*):

| Metric Category | Metric Name | Measured Value |
| :--- | :--- | :--- |
| **Detection Quality** | Precision | **100.00%** |
| **Detection Quality** | Recall | **72.00%** |
| **Detection Quality** | F1 Score | **0.8372** |
| **Detection Latency** | Average Pipeline Latency | **5.61 ms** |
| **Detection Latency** | Max Pipeline Latency | **14.78 ms** |
| **Defense Policy** | Ingress Normal Traffic Pass Rate | **100% (200 OK)** |
| **Defense Policy** | DDoS Flood Mitigation Rate | **100% (403 Blocked)** |
| **Self-Healing** | Failure Detection & Isolation Time | **< 15 ms** |
| **Self-Healing** | Replacement & Health Probe Clearance | **3 consecutive probes** |
| **Self-Healing** | Service Availability Under Isolation | **100% uptime across surviving nodes** |

---

## 🚀 How to Run the Project

### System Requirements & Tools
- **Python**: 3.12+ (with `pip`)
- **Node.js**: 18+ (with `npm`)
- **Docker & Docker Compose** (Optional, for containerized run)

---

### Method 1: Run with Docker Compose (Recommended)

```bash
# Build and launch Gateway, Demo App Cluster (app-1, app-2, app-3), and Frontend Dashboard
docker compose up --build
```
- **Gateway & API**: `http://localhost:8000`
- **Live React Dashboard**: `http://localhost:5173`
- **Swagger API Docs**: `http://localhost:8000/docs`

---

### Method 2: Run Standalone / Local Python & Node

#### 1. Install Dependencies
```bash
# Python Backend
pip install -r requirements.txt

# React Dashboard
cd frontend
npm install
cd ..
```

#### 2. Start Services

**Terminal 1 — Target Origin Application Fleet:**
```bash
python -m target_service.app
# Runs on ports 8001, 8002, 8003
```

**Terminal 2 — OneChance Gateway & Autonomous Controller:**
```bash
python -m onechance.main
# Runs on http://localhost:8000
```

**Terminal 3 — Live React Dashboard:**
```bash
cd frontend
npm run dev
# Runs on http://localhost:5173
```

---

## 🧪 Automated Test Suite

Run the full automated test suite covering all 6 development phases:

```bash
python -m pytest -v
```

```
====================== 57 passed in 11.58s ======================
* tests/test_phase0_foundation.py        [6 passed]
* tests/test_phase1_traffic_pipeline.py  [10 passed]
* tests/test_phase2_detection.py         [10 passed]
* tests/test_phase3_defense.py           [11 passed]
* tests/test_phase4_self_healing.py      [10 passed]
* tests/test_phase5_dashboard_internal.py[4 passed]
* tests/test_phase6_final_integration.py [6 passed]
```

To run the offline evaluation benchmark:
```bash
python scripts/evaluate_mvp.py
```

---

## 📋 Final MVP Feature Checklist

- [x] **FastAPI Gateway Reverse Proxy**: Captures telemetry, headers, and request tracing.
- [x] **Demo Target Web Service**: Real endpoints (`/`, `/api/health`, `/api/products`, `/api/search`, `/api/login`, `/api/expensive-operation`).
- [x] **Behavioral Feature Extractor**: 10 sliding-window behavioral signals calculated in real-time.
- [x] **Modular Anomaly Detector**: Random Forest model with statistical fallback mechanism.
- [x] **Explainable Risk Scorer**: Composite 0–100 risk score with human-readable contributing reasons.
- [x] **3-Tier Adaptive Policy Engine**: `ALLOW` $\rightarrow$ `CHALLENGE` $\rightarrow$ `BLOCK` transitions.
- [x] **Mitigation Engine**: Real-time IP blocking tables, challenge verification, and rate limiting.
- [x] **Multi-Container Service Registry**: Dynamic node registry with round-robin distribution.
- [x] **Health Monitor**: Continuous background async probing with failure threshold triggers.
- [x] **Deterministic Failure Simulation**: `POST /api/recovery/simulate-failure` hook.
- [x] **Automatic Workload Isolation**: Detaches unhealthy instances without dropping healthy traffic.
- [x] **Zero-Downtime Traffic Rerouting**: Seamless redistribution over healthy surviving nodes.
- [x] **Container Replacement & Probe Verification**: Requires $N=3$ consecutive successful checks.
- [x] **Reintroduction & Recovery Confidence Score**: Verifies cluster operational recovery (0–100).
- [x] **Internal Cloud Workload Attack Detection**: Detects and flags compromised internal microservices.
- [x] **Live React Dashboard**: Built with Vite, Tailwind/Modern CSS, and Lucide icons.
- [x] **Real-Time WebSocket Stream**: Instant bi-directional security and recovery telemetry.
- [x] **Unified Demo Reset**: One-click reset restoring all registries, events, and metrics.
- [x] **Deterministic Master Demo Script**: Complete 3-minute presentation runner (`demo_phase6_master.py`).
- [x] **Measured Evaluation Benchmark**: Reproducible evaluation suite (`evaluate_mvp.py`).
- [x] **Fail-Safe Robustness**: Verified graceful fallback when ML models are unavailable.
- [x] **Complete Test Suite**: 57/57 unit, integration, and scenario tests passing.

---

## ⚖️ Scope & Honest MVP Boundaries

- **Hackathon MVP Scope**: Built as a clear proof-of-concept for the Smart India Hackathon 2026.
- **Fail-Safe over Enterprise Overkill**: Uses in-memory state tracking and Docker container controls rather than heavy production Kubernetes or AWS multi-region infrastructure.
- **Measured Realism**: Performance figures are benchmarked on local test workloads; we do not claim global enterprise scale or edge CDN parity.
