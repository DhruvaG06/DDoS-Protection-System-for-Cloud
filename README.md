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

1. **Behavioral Detection (Beyond Volume Thresholds)**: Multi-signal evaluation including request rates, endpoint concentration entropy, burstiness, source distribution, and repeated patterns.
2. **Risk-Adaptive Response (3 Tiers)**:
   - `ALLOW`: Clean normal traffic forwarded to origin services.
   - `CHALLENGE`: Suspicious traffic requiring verification/throttling.
   - `BLOCK`: Malicious traffic dropped at the ingress edge.
3. **Autonomous Self-Healing**: Unhealthy/overloaded container detection $\rightarrow$ Automated isolation $\rightarrow$ Traffic rerouting $\rightarrow$ Replacement container restore $\rightarrow$ Health verification.
4. **Internal-Cloud Attack Awareness**: Detection capability for both external attack vectors and compromised internal cloud workloads.

---

## 🏗️ Architecture & Component Overview

```
                      [ Client Traffic / Attack Traffic ]
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │   OneChance API Gateway   │
                        │    (FastAPI Reverse Proxy)│
                        └─────────────┬─────────────┘
                                      │  (Extracts Structured Telemetry & Tracing)
                                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Demo Web Application                            │
│                     (Target Origin Workload)                           │
│  - GET  /                     (Homepage / Info)                        │
│  - GET  /api/health           (Liveness & Health Status)               │
│  - GET  /api/products         (Product Catalog & Filtering)            │
│  - GET  /api/search           (Product Search)                         │
│  - POST /api/login            (Authentication)                         │
│  - GET  /api/expensive-op     (Compute Workload)                       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
DDoS-Protection-System-for-Cloud/
├── README.md                           # Master project constitution & guide
├── requirements.txt                    # Python dependencies
├── .env.example                        # Configuration template
├── .gitignore                          # Git ignore rules
├── Dockerfile                          # Gateway container definition
├── docker-compose.yml                  # Multi-container orchestration
│
├── onechance/                          # Core OneChance Gateway & Reverse Proxy
│   ├── __init__.py
│   ├── config.py                       # Pydantic Settings & environment loader
│   ├── main.py                         # FastAPI gateway entrypoint
│   ├── logging/                        # Structured traffic logging
│   │   ├── __init__.py
│   │   └── traffic_logger.py           # Structured JSON logger & telemetry buffer
│   ├── models/                         # Domain schemas & enums
│   │   ├── __init__.py
│   │   ├── traffic.py                  # TrafficRecord, IncomingRequest, TrafficFeatures
│   │   ├── decisions.py                # ActionEnum, RiskAssessment, PolicyDecision
│   │   └── health.py                   # InstanceStatus, ServiceHealth, RecoveryEvent
│   ├── core/                           # Intelligence & Mitigation interfaces
│   │   ├── __init__.py
│   │   ├── feature_extractor.py        # Sliding-window behavioral telemetry extraction
│   │   ├── detector.py                 # Anomaly detection model interface
│   │   ├── risk_scorer.py              # Multi-signal composite risk score calculation
│   │   ├── policy_engine.py            # 3-tier risk-adaptive response engine
│   │   └── mitigator.py                # Active blocklist & challenge enforcement
│   ├── monitoring/                     # Service health tracking
│   │   ├── __init__.py
│   │   └── health_monitor.py           # Backend polling probe & failure trigger
│   ├── recovery/                       # Autonomous self-healing
│   │   ├── __init__.py
│   │   └── recovery_controller.py      # Isolate -> Reroute -> Restore -> Verify
│   └── api/                            # Routing & WebSockets
│       ├── __init__.py
│       ├── routes.py                   # Gateway reverse-proxy & telemetry endpoints
│       └── websockets.py               # Real-time dashboard broadcast manager
│
├── target_service/                     # Demo Protected Target Application (Origin Workload)
│   ├── __init__.py
│   ├── app.py                          # Multi-endpoint target web application
│   └── Dockerfile                      # Target workload container definition
│
├── frontend/                           # React Dashboard (Phase placeholder)
│   └── README.md
│
└── tests/                              # Automated Unit & Pipeline Tests
    ├── test_phase0_foundation.py
    └── test_phase1_traffic_pipeline.py
```

---

## 🚀 Quickstart & Local Execution

### 1. Prerequisites
- Python 3.12+ (or Docker Compose)
- Pip

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run with Docker Compose
```bash
docker compose up --build
```

### 4. Run Manually (Local Python)

#### Terminal 1 — Start Target Origin Service:
```bash
python -m target_service.app
# Runs on http://localhost:8001
```

#### Terminal 2 — Start OneChance Gateway:
```bash
python -m onechance.main
# Runs on http://localhost:8000
```

---

## 🧪 Phase 1 Traffic Pipeline Verification

### 1. Access Application Endpoints Through Gateway (`http://localhost:8000`)

```bash
# Gateway Index & Endpoint Map
curl http://localhost:8000/

# Proxied Product Catalog
curl http://localhost:8000/api/products

# Proxied Product Search
curl "http://localhost:8000/api/search?q=Shield"

# Proxied Login Authentication
curl -X POST http://localhost:8000/api/login \
     -H "Content-Type: application/json" \
     -d '{"username": "alice", "password": "password123"}'

# Proxied Expensive Compute Operation
curl "http://localhost:8000/api/expensive-operation?iterations=10000"
```

### 2. Inspect Structured Traffic Logs

```bash
# View buffered structured traffic logs captured by the gateway
curl http://localhost:8000/api/traffic-logs
```

Example JSON structured record:
```json
{
  "request_id": "req_8e9a2f1b4d0c",
  "timestamp": 1787717257.88,
  "source": "127.0.0.1",
  "method": "GET",
  "endpoint": "/api/products",
  "user_agent": "curl/7.88.1",
  "status_code": 200,
  "latency_ms": 4.15
}
```

### 3. Check System Health & Upstream Workload Availability

```bash
curl http://localhost:8000/api/health
```

### 4. Run Automated Test Suite

```bash
python -m pytest -v
```

---

## 🗺️ Project Phases

- [x] **Phase 0: Architecture, Interfaces & Project Foundation**
- [x] **Phase 1: Working Application + Traffic Gateway Pipeline** (Current)
  - Full demo target web application (`/`, `/api/health`, `/api/products`, `/api/search`, `/api/login`, `/api/expensive-operation`)
  - OneChance reverse-proxy gateway capturing request IDs, timestamps, sources, endpoints, user-agents, latency, and status codes
  - Structured traffic logging engine and log inspection endpoint (`/api/traffic-logs`)
  - Multi-container Docker Compose configuration
  - End-to-end automated test suite (16/16 tests passing)
- [ ] **Phase 2: Behavioral Feature Extraction & ML Anomaly Detection Model**
- [ ] **Phase 3: Controlled Attack Simulator (External & Internal Compromised Workload)**
- [ ] **Phase 4: Autonomous Container Self-Healing & Recovery Verification**
- [ ] **Phase 5: Real-Time React Dashboard & Judge Demonstration Workflow**
