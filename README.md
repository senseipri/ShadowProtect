```
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝

██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗
██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║
██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║
██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝
```

# ShadowProtect — Wireshark for AI Agents

> **Real-time intrusion detection AND active protection for multi-agent AI systems.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![PyPI version](https://img.shields.io/badge/pypi-shadowprotect%200.1.0-green)](https://pypi.org/project/shadowprotect/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14-black.svg)](https://nextjs.org)

---

## The Problem

Multi-agent AI systems are the next major attack surface — and nobody is watching.

- **Prompt injection is invisible.** An attacker poisons one agent's input; that agent silently propagates the instruction to every downstream agent in the pipeline. By the time you notice, the entire system is compromised.
- **No observability.** Current agent frameworks expose no equivalent of network packet capture. You cannot see what agents say to each other, which tools they call, or how fast they communicate.
- **Zero protection.** Every existing security tool for AI only *detects* attacks after the fact. ShadowProtect intercepts and *blocks* them before they execute.

---

## The Solution

ShadowProtect wraps your existing agents with a **9-layer detection engine** and a **12-module active protection layer** — with one line of code, no refactoring required.

```
┌──────────────────────────────────────────────────────────────────┐
│  Your Agents (CrewAI / OpenAI / LangChain / any callable)        │
│  ┌────────────┐   ┌────────────┐   ┌────────────┐                │
│  │ Researcher │──▶│  Planner   │──▶│  Executor  │                │
│  └────────────┘   └────────────┘   └────────────┘                │
│         │               │                │                        │
│  ───────┴───────────────┴────────────────┴──────────             │
│              shadowprotect SDK  (pip install shadowprotect)       │
│  ───────────────────────────────────────────────────────         │
│   Input Sanitizer → Scope Enforcer → Rate Limiter → Quarantine   │
│   ─────────────────────────────────────────────────────          │
│              FastAPI Backend  │  9 Detection Layers               │
│   ─────────────────────────────────────────────────────          │
│                Real-Time Dashboard (Next.js 14)                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Installation

### SDK (for your agents)

Install the lightweight Python client from PyPI:

```bash
pip install shadowprotect==0.1.0
```

**Requirements:** Python 3.11+

### Backend + Dashboard (self-hosted)

The backend processes events, runs detectors, and serves the real-time dashboard. Run it alongside your agents:

#### Option 1: Docker (recommended)

```bash
git clone https://github.com/your-org/shadowprotect.git
cd shadowprotect
docker-compose up --build
```

Open **http://localhost:3000** — dashboard is live.

#### Option 2: Manual

```bash
# Backend
cd backend
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
pnpm install
pnpm dev
```

---

## Quick Integration — One Line

```python
from shadowprotect import monitor

# Wrap any agent — zero code changes to your agent
monitored_agent = monitor(your_agent, backend_url="http://localhost:8000")

# Use it exactly as before — transparent proxy
result = await monitored_agent.execute(task)
```

### Framework Examples

#### CrewAI

```python
from crewai import Agent
from shadowprotect import monitor

researcher = Agent(role="Researcher", goal="...", backstory="...")
researcher = monitor(researcher, backend_url="http://localhost:8000")

# Use it exactly as a normal CrewAI Agent
```

#### OpenAI Agents SDK

```python
from agents import Agent
from shadowprotect import monitor

agent = Agent(name="Planner", instructions="...")
agent = monitor(agent, backend_url="http://localhost:8000")
```

#### LangChain

```python
from langchain.chains import LLMChain
from shadowprotect import monitor

chain = LLMChain(llm=llm, prompt=prompt)
chain = monitor(chain, backend_url="http://localhost:8000")

# Patches .invoke(), .run(), .arun(), .ainvoke() automatically
result = await chain.invoke({"input": "..."})
```

#### Raw Python Callable

```python
from shadowprotect import monitor

def my_agent(task: str) -> str:
    return call_llm(task)

monitored = monitor(my_agent, backend_url="http://localhost:8000")
result = await monitored("Summarise this document")
```

---

## What the SDK Emits

Every time a wrapped agent runs, the SDK automatically emits the following events to the backend:

| Event Type | Triggered When |
|---|---|
| `AGENT_START` | Agent begins processing a task |
| `MSG` | Agent produces an output message |
| `TOOL_CALL` | Agent calls an external tool |
| `AGENT_ERROR` | Agent raises an exception |

These events flow through the full 9-layer detection and 12-module protection pipeline in real time.

---

## Detection Capabilities

| Threat Type | Module | Technique | Severity |
|---|---|---|---|
| Direct prompt injection | `injection.py` | 7-tier regex, 50+ patterns | CRITICAL |
| Paraphrased injection | `semantic.py` | TF-IDF + LogisticRegression | HIGH |
| Multi-language attacks | `injection.py` | Cross-language patterns (ES/FR/DE/ZH/AR) | HIGH |
| Encoded/obfuscated payloads | `preprocessor.py` | Recursive decode depth 5 (b64/URL/unicode/hex) | HIGH |
| Homoglyph & invisible chars | `hidden_channels.py` | Unicode map + zero-width strip | MEDIUM |
| Indirect injection (tool output) | `hidden_channels.py` | Scan every TOOL_RESULT event | CRITICAL |
| Tool chain abuse / kill chains | `toolchain.py` | Sequence pattern + 3-step kill chain matching | CRITICAL |
| PII & secret leakage | `exfiltration.py` | Regex + Luhn + data staging detection | CRITICAL |
| Agent collusion | `collusion.py` | Sliding window pair frequency (default 10/60s) | HIGH |
| Behavioural drift & hijack | `behavioural.py` | Z-score baseline + cosine distance shift | HIGH |
| Taint propagation | `taint.py` | Directed graph, 0.7× decay per hop | CRITICAL |
| Multi-vector composite | `engine.py` | Weighted fusion + taint multiplier + multi-detector bonus | CRITICAL |

---

## Active Protection Layer (12 Modules)

ShadowProtect does not just detect — it **blocks** attacks before they execute:

| Module | What It Actively Prevents |
|---|---|
| `InputSanitizer` | Injection payloads reaching the agent (mutates message to `[BLOCKED]`) |
| `InstructionAnchor` | System prompt tampering |
| `ContextCleaner` | Injections hiding in agent memory |
| `ScopeEnforcer` | Agents calling unauthorised tools |
| `RuntimeMonitor` | CPU/memory/file anomalies |
| `DangerousOpBlocker` | `rm -rf`, credential reads, privilege escalation |
| `APIRateLimiter` | Burst attacks and credential probing |
| `MessageVerifier` | MITM and message forgery (HMAC-SHA256) |
| `TaintBlocker` | Quarantines compromised agents, blocks their outbound messages |
| `OutputSanitizer` | PII, API keys, secrets, JWTs in outbound messages |
| `StateSnapshotter` | Rollback to last clean state on compromise |
| `IncidentResponder` | Auto-quarantine + forensic snapshot on CRITICAL verdict |

---

## Testing Attack Scenarios

Use built-in scenarios to test your setup — no real attacker needed.

### Via API

```bash
# Prompt injection + taint propagation
curl -X POST http://localhost:8000/inject \
  -H "Content-Type: application/json" \
  -d '{"scenario": "injection"}'

# Agent collusion detection
curl -X POST http://localhost:8000/inject \
  -H "Content-Type: application/json" \
  -d '{"scenario": "collusion"}'

# Data exfiltration attempt
curl -X POST http://localhost:8000/inject \
  -H "Content-Type: application/json" \
  -d '{"scenario": "exfiltration"}'

# 3-hop lateral movement chain
curl -X POST http://localhost:8000/inject \
  -H "Content-Type: application/json" \
  -d '{"scenario": "lateral_movement"}'
```

### Via Replay (animated in dashboard)

```bash
# Start an animated scenario replay in the dashboard
curl -X POST http://localhost:8000/replay/start \
  -H "Content-Type: application/json" \
  -d '{"scenario": "injection.yaml", "speed": 1.0}'

# Pause / resume
curl -X POST http://localhost:8000/replay/pause
curl -X POST http://localhost:8000/replay/resume
```

### Using SimulatedAgent (for testing without a real LLM)

```python
from shadowprotect.simulate import SimulatedAgent

agent = SimulatedAgent("researcher", backend_url="http://localhost:8000")

# Emit real events
await agent.send_message("planner", "Here is my research summary...")
await agent.call_tool("web_search", {"query": "quantum computing"})

# Or replay a full YAML scenario
await agent.run_scenario("backend/scenarios/injection.yaml", speed=1.5)
```

---

## Custom Detection Rules (Hot-Reload)

Add new detection rules **without restarting** the server:

```yaml
# backend/rules/my_custom_rules.yaml
rules:
  - id: MY-001
    name: "Custom exfil pattern"
    pattern: "upload (all|sensitive|private) (data|files|documents)"
    severity: critical
    description: "Catches custom exfiltration phrasing"
```

```bash
# Reload rules instantly — no restart needed
curl -X POST http://localhost:8000/rules/reload
```

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Backend health check |
| `GET` | `/agents` | List all agents with trust scores |
| `POST` | `/agents/reset` | Reset all trust scores to 100 |
| `GET` | `/agents/{id}/behaviour` | Behaviour summary for an agent |
| `POST` | `/events` | Ingest a single event for analysis |
| `GET` | `/events` | List recent events |
| `GET` | `/alerts` | List recent security alerts |
| `GET` | `/threat-summary` | System-wide threat level and top rules |
| `GET` | `/rules` | List all loaded detection rules |
| `POST` | `/rules/test` | Test text against loaded rules |
| `POST` | `/rules/reload` | Hot-reload rules from disk |
| `GET` | `/scenarios` | List available replay scenarios |
| `POST` | `/replay/start` | Start scenario replay |
| `POST` | `/replay/pause` | Pause replay |
| `POST` | `/replay/resume` | Resume replay |
| `GET` | `/replay/status` | Replay status |
| `POST` | `/inject` | Fire a named attack scenario instantly |
| `WS` | `/ws` | WebSocket for real-time dashboard feed |

---

## Architecture

```
shadowprotect/                   ← pip install shadowprotect
├── __init__.py                  ← exposes monitor()
├── proxy.py                     ← monitor() wrapper (CrewAI/OpenAI/LangChain/callable)
├── emitter.py                   ← HTTP event emitter (async + sync, 3× retry)
└── simulate.py                  ← SimulatedAgent for testing without a real LLM

backend/                         ← self-hosted FastAPI server
├── main.py                      ← event pipeline: Protection → Detection → Broadcast
├── db.py                        ← SQLite persistence (aiosqlite)
├── replay.py                    ← scenario replay controller
├── detection/                   ← 9-detector analysis engine
│   ├── engine.py                ← composite weighted fusion engine
│   ├── injection.py             ← 7-tier regex, 50+ patterns, multilingual
│   ├── semantic.py              ← TF-IDF + LogisticRegression intent classifier
│   ├── preprocessor.py          ← recursive decoder (b64/URL/unicode/hex, depth 5)
│   ├── exfiltration.py          ← PII + Luhn + data staging
│   ├── hidden_channels.py       ← homoglyphs, zero-width chars, tool output scan
│   ├── toolchain.py             ← kill chain sequence detector
│   ├── collusion.py             ← sliding-window pair frequency
│   ├── behavioural.py           ← Z-score baseline + cosine drift
│   └── taint.py                 ← directed taint propagation graph
├── protection/                  ← 12-module active protection layer
│   ├── input_sanitizer.py
│   ├── output_sanitizer.py
│   ├── scope_enforcer.py
│   ├── dangerous_op_blocker.py
│   ├── api_rate_limiter.py
│   ├── taint_blocker.py
│   ├── state_snapshotter.py
│   ├── incident_responder.py
│   ├── instruction_anchor.py
│   ├── context_cleaner.py
│   ├── message_verifier.py
│   └── runtime_monitor.py
├── rules/                       ← hot-reloadable YAML detection rules
└── scenarios/                   ← attack replay scenarios (YAML)
    ├── injection.yaml
    ├── collusion.yaml
    ├── exfiltration.yaml
    └── lateral_movement.yaml

frontend/                        ← Next.js 14 real-time dashboard
├── components/
│   ├── AgentGraph               ← live trust score graph
│   ├── TrustPanel               ← per-agent trust meter
│   ├── AlertFeed                ← real-time alert stream
│   └── ReplayBar                ← scenario replay controls
└── lib/
    ├── store                    ← Zustand state
    └── useWebSocket             ← WebSocket hook for live events
```

---

## How the Protection Pipeline Works

Every event that enters the system flows through this ordered pipeline:

```
Incoming Event
      │
      ▼
[1] InputSanitizer      → blocks injection payloads, mutates to [BLOCKED]
      │
      ▼
[2] ScopeEnforcer       → blocks unauthorised tool calls
      │
      ▼
[3] DangerousOpBlocker  → blocks rm -rf, credential reads, shell pivots
      │
      ▼
[4] APIRateLimiter      → drops burst flooding
      │
      ▼
[5] TaintBlocker        → drops messages from quarantined agents
      │
      ▼
[6] CollusionDetector   → flags high-frequency suspicious agent pairs
      │
      ▼
[7] StateSnapshotter    → saves clean state for rollback
      │
      ▼
[8] Full 9-Layer Engine → composite threat verdict + taint graph update
      │
      ▼
[9] OutputSanitizer     → strips PII/keys/JWTs from outbound messages
      │
      ▼
[10] IncidentResponder  → quarantine + forensic snapshot on CRITICAL
      │
      ▼
   Broadcast to Dashboard (WebSocket) + Persist to SQLite
```

---

## Roadmap

- [ ] **MCP Server support** — monitor Model Context Protocol tool calls natively
- [ ] **OpenTelemetry export** — send spans/metrics to Datadog, Grafana, etc.
- [ ] **LangGraph integration** — deep graph-level monitoring for LangGraph workflows
- [ ] **Anomaly ML model** — train on real agent logs for adaptive baseline detection
- [ ] **Multi-tenant dashboard** — per-team agent namespaces and alert routing
- [ ] **Slack / PagerDuty alerts** — push CRITICAL incidents to your on-call workflow
- [ ] **Agent identity verification** — cryptographic agent certificates, not just HMAC

---

## License

MIT © 2025 ShadowProtect Contributors