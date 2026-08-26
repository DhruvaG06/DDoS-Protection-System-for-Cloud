# OneChance — Smart Cloud DDoS Protection & Autonomous Response System

> **Smart India Hackathon 2026**  
> **Problem Statement**: DDoS Protection System for Cloud: Architecture and Tool  
> **Problem Statement ID**: `DJS_26_SW_05`  
> **Repository**: `DhruvaG06/DDoS-Protection-System-for-Cloud`

---

## 🎯 Core USP

> **OneChance connects behavioral DDoS detection with autonomous service recovery.**

The system does not stop at:
$$\text{Detect} \longrightarrow \text{Block}$$

It demonstrates the complete closed-loop workflow:
$$\text{Traffic} \longrightarrow \text{Behavioral Analysis} \longrightarrow \text{Risk Score} \longrightarrow \text{Allow / Challenge / Block} \longrightarrow \text{Mitigation} \longrightarrow \text{Service Health Monitoring} \longrightarrow \text{Automatic Isolation} \longrightarrow \text{Recovery Verification}$$

---

## 💡 Novelty Priorities

1. **Behavioral Detection (Beyond Volume Thresholds)**: 10 extracted behavioral features including request rates, endpoint concentration entropy, burstiness, source distribution, and repeated patterns evaluated using trained Random Forest & statistical fallback detectors.
2. **Risk-Adaptive Response (3 Tiers)**:
   - `ALLOW`: Clean normal traffic forwarded to origin services (`action_type: forward`).
   - `CHALLENGE`: Suspicious traffic requiring verification tokens (`action_type: challenge_issued`).
   - `BLOCK`: Malicious traffic dropped at the ingress edge (`action_type: temporary_block`).
3. **Autonomous Self-Healing & Service Recovery (Phase 4)**:
   - **DETECT**: Continuous multi-instance health monitoring tracks availability, latency, and status codes.
   - **ISOLATE**: Automatically detaches failing/overloaded containers from the active ingress traffic pool.
   - **REROUTE**: Seamlessly redistributes ingress traffic across remaining healthy nodes with zero downtime.
   - **REPLACE**: Initializes container restore and clean restart procedures.
   - **HEALTH CHECK**: Requires $N$ consecutive passed probes before operational clearance.
   - **REINTRODUCE**: Restores verified healthy instances back into the active round-robin distribution pool.
   - **VERIFY RECOVERY**: Calculates an operational **Recovery Confidence Score (0–100)** based on healthy ratio, probe success rate, latency stability, and error indices.
4. **Internal-Cloud Attack Awareness**: Detection capability for both external attack vectors and compromised internal cloud workloads.

---

## 🏗️ Architecture & Component Overview

```
                      [ Client Traffic / Attack Traffic ]
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │   OneChance API Gateway   │
                        │  (FastAPI Reverse Proxy   │
                        │   & Autonomous Recovery)  │
                        └─────────────┬─────────────┘
                                      │  (Routes only to healthy instances)
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
 ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
 │    app-1 (8001)     │   │    app-2 (8002)     │   │    app-3 (8003)     │
 │  Healthy / Serving  │   │  Healthy / Serving  │   │  Healthy / Serving  │
 └─────────────────────┘   └─────────────────────┘   └─────────────────────┘
            │                         ▲
            │       [ISOLATE / REROUTE / RESTORE]
            └─────────────────────────┘
```

---

## 📁 Repository Structure

```
DDoS-Protection-System-for-Cloud/
├── README.md                           # Master project constitution & guide
├── requirements.txt                    # Python dependencies
├── .env.example                        # Configuration template
├── Dockerfile                          # Gateway container definition
├── docker-compose.yml                  # Multi-container cluster orchestration (Gateway + app-1/2/3)
│
├── onechance/                          # Core OneChance Gateway & Autonomous Response
│   ├── __init__.py
│   ├── config.py                       # Settings & multi-instance targets
│   ├── main.py                         # FastAPI gateway entrypoint with lifespan
│   ├── logging/                        # Structured traffic & security logging
│   │   ├── __init__.py
│   │   ├── event_logger.py             # Security decision event ring buffer
│   │   └── traffic_logger.py           # Structured JSON traffic logger
│   ├── models/                         # Domain schemas & enums
│   │   ├── __init__.py
│   │   ├── traffic.py                  # IncomingRequest, TrafficFeatures, TrafficLog
│   │   ├── decisions.py                # ActionEnum, ThreatLevel, RiskAssessment, PolicyDecision
│   │   ├── events.py                   # SecurityEvent
│   │   └── health.py                   # InstanceRecord, InstanceStatus, RecoveryEvent, RecoveryVerificationMetrics
│   ├── core/                           # Intelligence & Mitigation
│   │   ├── __init__.py
│   │   ├── feature_extractor.py        # 10-signal behavioral telemetry extraction
│   │   ├── detector.py                 # Hybrid ML Random Forest & fallback detector
│   │   ├── risk_scorer.py              # Composite risk score calculation (0-100)
│   │   ├── policy_engine.py            # 3-tier risk-adaptive response engine
│   │   ├── rate_limiter.py             # Sliding-window rate limiter
│   │   └── mitigator.py                # In-memory mitigation tables & token verification
│   ├── monitoring/                     # Service health tracking
│   │   ├── __init__.py
│   │   └── health_monitor.py           # Multi-instance health monitor probe loop
│   ├── recovery/                       # Autonomous self-healing
│   │   ├── __init__.py
│   │   ├── service_registry.py         # Multi-instance registry & active routing pool
│   │   └── recovery_controller.py      # Closed-loop recovery orchestrator & confidence scoring
│   └── api/                            # Routing & WebSockets
│       ├── __init__.py
│       ├── routes.py                   # Reverse-proxy & recovery API endpoints
│       └── websockets.py               # Real-time dashboard broadcast manager
│
├── target_service/                     # Demo Protected Target Application (Origin Workload)
│   ├── __init__.py
│   ├── app.py                          # Multi-endpoint target web application with failure hooks
│   └── Dockerfile                      # Target workload container definition
│
├── scripts/                            # Interactive Demonstrations & Simulators
│   └── demo_phase4_self_healing.py     # Terminal demo of complete self-healing workflow
│
└── tests/                              # Automated Unit & Pipeline Tests
    ├── test_phase0_foundation.py
    ├── test_phase1_traffic_pipeline.py
    ├── test_phase2_detection.py
    ├── test_phase3_defense.py
    └── test_phase4_self_healing.py
```

---

## 🚀 Execution & Self-Healing Demo

### 1. Run Automated Test Suite
```bash
python -m pytest -v
# 47 passed across all 5 test suites
```

### 2. Run Interactive Phase 4 Autonomous Self-Healing Demo

#### Step A: Start Gateway in Terminal 1
```bash
python -m onechance.main
```

#### Step B: Run Demo Script in Terminal 2
```bash
python scripts/demo_phase4_self_healing.py
```

---

## 🧪 Phase 4 API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/recovery/status` | `GET` | Cluster health snapshot, active instances, and Recovery Confidence |
| `/api/recovery/events` | `GET` | Chronological list of structured recovery and infrastructure events |
| `/api/recovery/simulate-failure` | `POST` | Deterministic container crash simulation hook on target node |
| `/api/recovery/reset` | `POST` | Reset cluster states and recovery timeline for repeating demos |
| `/api/recovery/verify` | `GET` | Compute and return the operational Recovery Confidence Score (0–100) |
| `/api/health` | `GET` | Comprehensive gateway, detection engine, and cluster health status |

---

## 🗺️ Project Phases

- [x] **Phase 0: Architecture, Interfaces & Project Foundation**
- [x] **Phase 1: Working Application + Traffic Gateway Pipeline**
- [x] **Phase 2: Behavioral Feature Extraction & ML Anomaly Detection Model**
- [x] **Phase 3: Adaptive Defense Engine (ALLOW / CHALLENGE / BLOCK) & Mitigation**
- [x] **Phase 4: Autonomous Self-Healing and Service Recovery**
  - Multi-container cluster orchestration (`app-1`, `app-2`, `app-3`)
  - Dynamic `ServiceRegistry` with active healthy routing pool
  - Continuous `HealthMonitor` with failure threshold detection
  - Autonomous `RecoveryController` pipeline: `DETECT` $\rightarrow$ `ISOLATE` $\rightarrow$ `REROUTE` $\rightarrow$ `REPLACE` $\rightarrow$ `HEALTH CHECK` $\rightarrow$ `REINTRODUCE` $\rightarrow$ `VERIFY RECOVERY`
  - Operational **Recovery Confidence Score (0–100)** calculation
  - Deterministic failure simulation API and complete automated test suite (47/47 tests passing)
- [ ] **Phase 5: Real-Time React Dashboard & Judge Demonstration Workflow**
