# Agent Control Plane (ACP)

A production-grade, security-first platform for governing, monitoring, and autonomously responding to AI agent behaviour at scale. Built as a distributed system of 14 FastAPI microservices backed by PostgreSQL, Redis, Open Policy Agent, and a Groq-powered risk engine — with a React 18 SPA providing real-time SOC visibility.

---

## Table of Contents

1. [System Purpose](#1-system-purpose)
2. [Architecture Overview](#2-architecture-overview)
3. [Microservices Reference](#3-microservices-reference)
4. [Infrastructure Layer](#4-infrastructure-layer)
5. [Frontend SPA](#5-frontend-spa)
6. [Authentication Model](#6-authentication-model)
7. [Request Lifecycle — Tool Execution](#7-request-lifecycle--tool-execution)
8. [Autonomous Response Engine (ARE)](#8-autonomous-response-engine-are)
9. [Incident System](#9-incident-system)
10. [Data Validation Pipeline](#10-data-validation-pipeline)
11. [Security Hardening](#11-security-hardening)
12. [Real-Time SSE Event Flow](#12-real-time-sse-event-flow)
13. [Groq AI Risk Routing](#13-groq-ai-risk-routing)
14. [Kill Switch](#14-kill-switch)
15. [Forensics & Audit](#15-forensics--audit)
16. [Policy Evaluation Chain](#16-policy-evaluation-chain)
17. [Test Suite](#17-test-suite)
18. [Running the Stack](#18-running-the-stack)
19. [Port Reference](#19-port-reference)
20. [Directory Structure](#20-directory-structure)

---

## 1. System Purpose

ACP sits between AI agents and the tools they call. Every tool invocation passes through a multi-phase security pipeline: authentication, rate limiting, OPA policy evaluation, AI-powered risk scoring, kill-switch enforcement, and immutable audit logging — before the tool is allowed to execute. When threats are detected, the Autonomous Response Engine (ARE) fires configured actions (kill, isolate, block, throttle, alert) with sub-second latency, without human intervention.

Core guarantees:
- **Fail-closed by default** — OPA outage, Decision engine failure, or any unhandled exception denies the request, never allows it.
- **Immutable audit trail** — every event is HMAC-chained in Postgres; tampering is cryptographically detectable.
- **Tenant isolation** — five physically separate databases, per-tenant Redis namespacing, cross-tenant response rejection at the API boundary.
- **Zero token in localStorage** — browser auth is httpOnly cookie only; XSS cannot steal credentials.

---

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      BROWSER  (React 18 SPA)                     │
│                                                                  │
│  Auth ──► Router ──► Pages ──► api.js                           │
│  (httpOnly acp_token cookie — never in localStorage)            │
│  Zod v4 schema validation at every API response boundary        │
│  SSE ◄── eventBus ◄── useSSE hook ◄── /events/stream            │
└───────────────────────────┬──────────────────────────────────────┘
                            │  HTTP  :8000
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│               API GATEWAY  (FastAPI · port 8000)                 │
│                                                                  │
│  SecurityMiddleware  (in pipeline order):                        │
│    Step 0 — Global + per-IP rate limit  (Redis)                  │
│    Phase 1 — JWT auth (cookie → Bearer promotion, HS256)         │
│              Redis revocation check (SHA-256 token hash)         │
│    Phase 2 — Idempotency dedup + hierarchical rate limits        │
│    Kill Check — acp:tenant_kill:{tid} → 403 if engaged           │
│    Phase 3 — Behavior signals + OPA policy + allowed_tools       │
│    Phase 4 — Decision Engine (Groq AI risk scoring)              │
│    Phase 5 — HMAC audit write + Redis stream + SSE publish       │
│                                                                  │
│  Management paths (/agents /audit /incidents …) skip Phase 3–5  │
└──────┬───────┬──────┬──────┬───────┬──────┬──────────────────────┘
       │       │      │      │       │      │
       ▼       ▼      ▼      ▼       ▼      ▼
  Registry Identity Policy  Audit Decision Forensics
   :8001   :8002   :8003   :8004   :8010   :8012
                     │               │
                    OPA            Groq API
                   :8181           (cloud)

  API Service :8005  ← incidents · ARE workers · api-keys
  Usage       :8006  ← billing · token costs · invoices
  Behavior    :8007  ← behavioral signals · anomaly scoring
  Intelligence :8008 ← RAG · cross-agent context
  Learning    :8009  ← baseline models · drift detection
  Insight     :8011  ← Groq narrative enrichment (background)
  Groq Worker  —     ← standalone LLM analysis worker
```

---

## 3. Microservices Reference

### Gateway `:8000`
Primary entry point for all traffic. Implements the full security pipeline as a single `SecurityMiddleware` class. Owns SSE streaming (`/events/stream`), kill-switch enforcement, and cross-service reverse proxy. Authenticates every non-skipped request before forwarding.

Key behaviours:
- Cookie → Bearer header promotion so downstream services only ever see `Authorization: Bearer`.
- `_SKIP_PATHS`: `/health`, `/docs`, `/auth/token`, `/auth/agent/token`, `/events/stream`, `/metrics`, `/openapi.json` — no auth applied.
- `_MANAGEMENT_PATH_PREFIXES`: `/agents`, `/audit`, `/billing`, `/incidents`, `/risk`, `/auto-response`, `/decision`, `/forensics`, `/auth`, `/api-keys`, `/system` — auth + rate-limit only, skip OPA and Decision Engine.
- `/execute` path: full 5-phase pipeline.
- Admin with `X-Agent-ID` header sets `agent_via_header=True` — bypasses admin wildcard, applies real agent policy (makes attack simulation meaningful).

### Registry `:8001`
Agent CRUD and permission store. Stores agent metadata and tool permissions. Permission `action` field is enforced as uppercase `ALLOW` or `DENY` — lowercase values are rejected with HTTP 422. The Gateway's `_extract_allowed_tools()` calls this service for each `/execute` request.

### Identity `:8002`
User authentication and JWT lifecycle. Verifies bcrypt passwords, issues HS256 JWTs, revokes tokens (SHA-256 hash → Redis TTL key). Also provisions and verifies agent credentials. All downstream services receive only Bearer tokens — cookies are never forwarded.

Agent credential flow:
1. Admin: `POST /auth/credentials` → provision agent secret.
2. Agent: `POST /auth/agent/token` → JWT with `role=agent`, `agent_id=<uuid>`.

### Policy `:8003`
OPA integration layer. Builds the OPA input document (tenant, agent, tool, risk scores, allowed_tools) and calls OPA at `:8181`. Returns `allow / deny / monitor / throttle / escalate`.

`OPA_FAIL_MODE`:
- `closed` (production default) — deny on OPA failure.
- `open` (dev/staging) — allow on OPA failure.

Circuit breaker: OPEN state → fail-safe `deny`.

### Audit `:8004`
Immutable event log with HMAC hash chain. Each event record stores `event_hash = HMAC(prev_hash + event_json)`. Chain verification is capped at 10,000 rows to prevent OOM on large tenants. Publishes high-risk and deny events to `acp:audit:events` Redis stream for ARE consumption.

Endpoints: logs, search, SOC timeline, chain verification.

### API Service `:8005`
Business logic layer for incidents, ARE rules, and API keys. Runs three background workers:
- `api-incident-worker` — consumes `acp:incidents:queue`, deduplicates (SHA-256 of tenant+agent+tool+trigger+5-min-bucket), creates or bumps `violation_count` on Postgres incident rows.
- `are-workers` — ARE rule evaluation from incident stream.
- `are-audit-workers` — ARE rule evaluation from audit deny/high-risk stream.

### Usage `:8006`
Billing and token cost tracking. Computes cost per token (model-specific rates), calculates ROI vs. uncontrolled execution risk, stores billing records and invoices in Postgres.

### Behavior `:8007`
Extracts behavioural signals from agent activity: call frequency, payload entropy, time-of-day deviation, tool sequence patterns. Produces anomaly scores consumed by the Decision Engine.

### Intelligence `:8008`
RAG (Retrieval-Augmented Generation) layer for cross-agent context. Ingests agent telemetry, stores vectorised context, surfaces correlated risk signals across agents.

### Learning `:8009`
Builds per-agent baseline behaviour models and detects drift. Feeds drift signals into the Decision Engine risk computation.

### Decision `:8010`
Weighted risk orchestration and Groq AI routing. Aggregates `inference_risk + behavior_risk + anomaly_score + cross_agent_risk` into a single weighted score. Routes to fast or deep Groq model based on threshold. Returns `{action, risk_score, reasons[], confidence}`.

Fail-closed: any exception → `403 "Fail-Closed: Decision engine unavailable"` (not 500).

### Insight `:8011`
Background Groq enrichment worker. Generates human-readable narrative explanations for risk events. Stores results in Redis sorted set (`acp:groq:insights:timeline:{tid}` — score = unix timestamp). Publishes `insight_generated` SSE events. Rate-capped with `asyncio.Semaphore(5)`.

### Forensics `:8012`
Replay engine and investigation profiles. Reads audit logs (via HTTP to Audit service — no direct DB access) and reconstructs per-agent event timelines. Computes `avg_risk`, `decision_breakdown`, and `recent_events[]` for each investigation profile.

### Groq Worker (standalone)
Long-running background worker for high-latency LLM analysis tasks that should not block request path processing.

---

## 4. Infrastructure Layer

### PostgreSQL `:5433` (host) → `:5432` (container)
Five physically isolated databases — one per service boundary:

| Database | Owner | Content |
|---|---|---|
| `acp_identity` | identity_user | users, credentials |
| `acp_registry` | registry_user | agents, permissions |
| `acp_audit` | audit_user | audit_logs (hash chain) |
| `acp_api` | api_user | incidents, are_rules, api_keys |
| `acp_usage` | usage_user | billing records, invoices |

No service can connect to another service's database. Cross-service reads happen via HTTP (e.g. Forensics reads Audit logs through the Audit service API).

Schema migrations managed by Alembic per service. Current `acp_api` chain: `81a0f934 → c2b8e4a1 → d4f7a3b2 → e5f8a1b2 → f1a2b3c4d5e6`.

### PgBouncer `:6432`
Transaction-mode connection pooler in front of Postgres. All services connect via PgBouncer (`DATABASE_URL` points to `:6432`). Prevents connection exhaustion under load.

### Redis `:6379`
Central state bus. Used for: rate limiting, token revocation, kill switches, pub/sub SSE events, Redis streams (incident and audit queues), ARE execution locks and cooldowns, per-tenant sorted sets for insights.

Key namespacing (all tenant-scoped where applicable):

| Key Pattern | Purpose | TTL |
|---|---|---|
| `acp:revoked:{sha256(token)}` | Token revocation | Token remaining TTL |
| `acp:tenant_kill:{tid}` | Tenant-wide kill switch | 86400s |
| `acp:{tid}:agent_kill:{aid}` | Per-agent kill | 86400s |
| `acp:ratelimit:{tid}` | Tenant rate limit counter | Rolling |
| `acp:authfail:{ip}` | Auth failure counter (→ 429) | Rolling |
| `acp:jti_last_used:{jti}` | JTI replay window | 50ms burst |
| `acp:{tid}:are:enabled` | ARE global on/off toggle | Persistent |
| `acp:{tid}:are:lock:{aid}:{rid}` | ARE execution lock (SETNX) | 30s |
| `acp:{tid}:are:cooldown:{r}:{s}` | Per-rule cooldown | Configurable |
| `acp:{tid}:are:rate:{rid}:{hour}` | Hourly trigger rate limit | 3600s |
| `acp:{tid}:are:violations:{aid}` | Rolling violations sorted set | Window-based |
| `acp:{tid}:are:pending:{r}:{k}` | Manual approval queue | Until approved |
| `acp:groq:insights:timeline:{tid}` | Insights sorted set (score=ts) | Persistent |
| `acp:incidents:queue` (stream) | Incident event queue | — |
| `acp:audit:events` (stream) | Audit deny/high-risk stream | — |

### Open Policy Agent (OPA) `:8181`
Evaluates `agent_policy.rego` for every `/execute` request. Input document includes: tenant_id, agent_id, tool name, risk scores, allowed_tools list. Returns: `allow / deny / monitor / throttle / escalate`.

OPA is the last line of policy defence before the Decision Engine. In `OPA_FAIL_MODE=closed`, any OPA failure (timeout, non-200, exception) results in a deny.

---

## 5. Frontend SPA

**Stack:** React 18 · Vite · Tailwind CSS · React Router v6 · Zod v4.3.6

### Pages

| Route | Page | Purpose |
|---|---|---|
| `/dashboard` | ExecutiveDashboard | KPI summary, risk trend, top threats, AI insights |
| `/agents` | Agents | Agent registry CRUD, permissions, status |
| `/security` | SecurityDashboard | Live event heatmap, SOC feed, risk timeline |
| `/risk` | RiskEngine | Per-agent risk scores, forensics drill-down |
| `/audit-logs` | AuditLogs | Searchable immutable log, integrity verification |
| `/forensics` | Forensics | Agent investigation profiles, event replay |
| `/policy-builder` | PolicyBuilder | OPA policy simulation, rule testing |
| `/rbac` | RBAC | Role and permission management |
| `/playground` | AgentPlayground | Live tool execution sandbox |
| `/billing` | Billing | Cost analytics, invoices, ROI metrics |
| `/incidents` | Incidents | Incident queue, state machine actions |
| `/auto-response` | AutoResponse | ARE rule CRUD, toggle, simulate, metrics |
| `/kill-switch` | KillSwitch | Tenant-wide and per-agent kill controls |
| `/observability` | Observability | Metrics tiles, decision timeline |
| `/attack-sim` | AttackSimulation | Controlled threat simulation for policy testing |
| `/system-health` | SystemHealth | Service health grid, latency monitoring |
| `/developer` | DeveloperPanel | API explorer, SDK reference |

### Core Systems

- **AuthContext** — holds `isAuthenticated`, `role`, `tenant_id`. Token lives in httpOnly `acp_token` cookie, never accessible to JS.
- **AgentContext** — maintains the agent list, selected agent, and SSE connection lifecycle.
- **useSSE()** — EventSource with exponential backoff reconnect (1s → 2s → 4s … 32s max).
- **eventBus.js** — in-process pub/sub. SSE events from the backend are translated here and re-emitted to page subscribers.
- **authEvents.js** — typed auth failure event emitter. Fires `acp:auth:failure` CustomEvent consumed by App.jsx → IncidentOverlay.
- **IncidentOverlay** — SOC-style alert panel with 12-second countdown to `/login` redirect on auth failure.
- **ErrorBoundary** — catches React render crashes, renders fallback instead of blank screen.

### Real-Time Update Strategy
Every page combines two update mechanisms:
1. **SSE subscription** via `eventBus.on()` — immediate push on backend events.
2. **30-second polling** via `setInterval` — catches missed events and keeps data fresh if SSE reconnects.

Both are cleaned up on component unmount via `useEffect` return function (`clearInterval` + `eventBus.off`).

---

## 6. Authentication Model

### Browser Flow
```
Browser                    Gateway :8000             Identity :8002
   │                            │                          │
   ├── POST /auth/token ────────►│── forward ──────────────►│
   │   {email, password}         │                 bcrypt verify
   │                            │◄── JWT (HS256) ───────────│
   │◄── 200 {tenant_id, role,   │
   │         expires_in}         │
   │    Set-Cookie: acp_token    │  (httpOnly · Secure · SameSite=Lax)
   │
   │  localStorage stores ONLY:
   │  • tenant_id   (non-sensitive identifier)
   │  • user_role
   │  • acp_token_expiry  (epoch ms — for proactive expiry timer)
   │  NEVER: the JWT itself
   │
   ├── GET /agents ─────────────►│
   │   Cookie: acp_token          │  SecurityMiddleware:
   │   X-Tenant-ID: {tid}         │  • extract JWT from cookie
   │   X-Request-ID: <uuid>       │  • promote to Authorization: Bearer
   │   X-Timestamp: <epoch>       │  • verify + revocation check
   │◄── agents[] ────────────────│
```

### SDK / CLI / curl Flow
```
1. POST http://localhost:8002/auth/login  →  {data: {access_token: "..."}}
2. All requests: Authorization: Bearer <token>
                 X-Tenant-ID: <uuid>
   No cookies, no CSRF tokens.
```

### Agent Credential Flow
```
1. Admin: POST /auth/credentials   →  provision agent secret
2. Agent: POST /auth/agent/token   →  JWT {role: "agent", agent_id: <uuid>}
3. Agent: POST /execute
          Authorization: Bearer <agent_jwt>
          X-Tenant-ID: <uuid>
          X-Agent-ID:  <agent_uuid>
          X-ACP-Tool:  <tool_name>
```

### Token Revocation
On logout or admin revoke: `SHA-256(bare_token)` → `SET acp:revoked:{hash}` in Redis with `TTL = token_remaining_seconds`. Every request middleware hashes the incoming token and checks Redis. `extract_bearer_token()` always strips the `"Bearer "` prefix before hashing to prevent bypass.

### Proactive Expiry
`App.jsx` reads `acp_token_expiry` from localStorage on mount, schedules a `setTimeout` for the remaining milliseconds, and fires `emitAuthFailure('session_expired')` when it fires — catches tabs left open past JWT expiry without waiting for a 401 response.

---

## 7. Request Lifecycle — Tool Execution

```
POST /execute
Headers: Authorization: Bearer <jwt>  (or Cookie: acp_token)
         X-Tenant-ID:  <uuid>
         X-Agent-ID:   <agent_uuid>
         X-ACP-Tool:   <tool_name>          ← preferred
         (fallback: /execute/<tool_name> path segment)
         (fallback: "unknown-tool" — NOT read from JSON body)

  Step 0. Early Defence
    • Global rate limit counter (Redis INCR)
    • Per-IP rate limit → 429 if exceeded

  Phase 1. Authentication
    • httpOnly cookie → extract JWT → Bearer header promotion
    • JWT HS256 verify + expiry
    • Redis revocation check: GET acp:revoked:{sha256(tok)}
    • Auth failure counter: repeated 401s → 429 after threshold
    • agent_id extracted from JWT claims
    • Admin JWT (agent_id=UUID(0)) + X-Agent-ID header present
        → override agent_id, set agent_via_header=True

  Phase 2. Input Protections
    • Idempotency: X-Idempotency-Key dedup (tier-based TTL)
    • JTI replay window: SETNX acp:jti_last_used:{jti}  (50ms burst, /execute only)
    • Hierarchical rate limits: global → per-IP → per-tenant → per-agent → per-token

  Kill Switch Check
    • GET acp:tenant_kill:{tid} → 403 if set
    • GET acp:{tid}:agent_kill:{aid} → 403 if set

  RBAC Check
    • "execute_agent" permission required in token
    • role="agent" JWT → allowed on /execute only
    • role="admin"/"security" on /execute → needs execute_agent permission (unless agent_via_header)

  Phase 3. Security Signal Collection
    • Behavior signals from Behavior service (:8007)
    • allowed_tools = GET /agents/{id}/permissions → filter action.upper()=="ALLOW"
    • If agent_via_header=False AND admin → allowed_tools=["*"]
    • OPA evaluation via Policy service → allow/deny/monitor/throttle/escalate
    • InferenceProxy: payload hashing + inference_risk pre-score

  Phase 4. Decision Engine
    • POST Decision service (:8010)
    • Weighted risk = inference_risk + behavior_risk + anomaly_score + cross_agent_risk
    • Groq routing: risk < 0.75 → llama-3.1-8b-instant (~200ms)
                    risk ≥ 0.75 → llama-3.3-70b-versatile (~1–2s)
    • Returns: {action, risk_score, reasons[], confidence}
    • Exception → 403 "Fail-Closed" (never 500)

  Phase 5. Audit + Publish
    • Write AuditLog with HMAC hash chain → Postgres (via Audit service)
    • XADD acp:audit:events if deny OR risk ≥ 0.7  → triggers ARE
    • PUBLISH acp:events:{tid} → SSE → browser
        eventBus.emit('tool_executed')
        eventBus.emit('policy_decision')

Response: { action, risk_score, reasons[], request_id }
```

---

## 8. Autonomous Response Engine (ARE)

The ARE runs inside the API Service (:8005) as background workers consuming two independent Redis streams.

### Ingestion Paths
```
acp:incidents:queue   ← new incident created (gateway middleware XADD)
  consumer group: are-workers

acp:audit:events      ← audit deny or risk ≥ 0.7 (Audit service XADD)
  consumer group: are-audit-workers

Both converge → process_incident()
```

### Evaluation Pipeline
```
1.  ARE enabled?         GET acp:{tid}:are:enabled
2.  Backpressure         XLEN stream > 10,000 → pause 5s, skip cycle
3.  Correlation dedup    acp:{tid}:are:agent_corr:{aid} — skip if same agent within 30s
4.  Load active rules    Postgres ORDER BY priority DESC
5.  AREIndex pre-filter  severity_set + min_risk O(n) check
    (60–80% rules skipped on high-risk flood — avoids full trace overhead)

Per-rule evaluation:
  6.  Suppression?     suppressed_until > now → skip
  7.  Idempotency?     acp:{tid}:are:idemp:{req}:{rid} (TTL 1h)
  8.  Cooldown?        acp:{tid}:are:cooldown:{r}:{scope}
  9.  Rate limit?      acp:{tid}:are:rate:{rid}:{hour} (max_triggers_per_hour)
  10. Window count     ZRANGEBYSCORE violations sorted set within window
  11. _build_trace()   evaluate each condition, record matched/failed
  12. Record latency   ZADD acp:{tid}:are:latency:{rid}
```

### Action Mode Routing
| Mode | Behaviour |
|---|---|
| `auto` | Execute immediately — AREExecutor dispatches all actions |
| `manual` | Store in Redis pending queue + SSE notification; no execution until human approves |
| `suggest` | SSE event only, nothing executed |

### AREExecutor Actions
| Action | Effect |
|---|---|
| `KILL_AGENT` | `SET acp:{tid}:agent_kill:{aid} EX 86400` — blocks all future executions |
| `ISOLATE_AGENT` | `PATCH /agents/{id}` `{status: "suspended"}` via Registry |
| `BLOCK_TOOL` | `POST /agents/{id}/permissions` with `action: "DENY"` |
| `THROTTLE` | `SET acp:{tid}:throttle:{aid} EX 3600` |
| `ALERT` | Slack Block Kit webhook (CRITICAL/HIGH) or generic webhook |

Safety guards:
- `_policy_gate()` calls OPA before any KILL or ISOLATE — fail-closed on exception.
- `SETNX acp:{tid}:are:lock:{aid}:{rid} EX 30s` prevents double-fire from concurrent workers.
- Max 1 KILL/ISOLATE per evaluation cycle (destructive cap).
- `stop_on_match=True` (default) breaks the rule loop after first match.

### ARE Condition DSL

Two formats accepted — both normalised by Pydantic `model_validator` before validation:

**Dict format (canonical):**
```json
{
  "severity_in": ["HIGH", "CRITICAL"],
  "risk_score_gte": 0.75,
  "tool_in": ["payments.write"],
  "agent_id": "*",
  "repeat_offender": true,
  "min_violations": 2,
  "window": "5m"
}
```

**List DSL format (backward-compatible):**
```json
[
  { "field": "severity",   "op": "in",  "value": ["HIGH", "CRITICAL"] },
  { "field": "risk_score", "op": ">=",  "value": 0.75 },
  { "field": "tool",       "op": "in",  "value": ["payments.write"] }
]
```

Supported ops: `==` `!=` `>` `>=` `<` `<=` `in` `not_in`  
Supported fields: `severity` `risk_score` `tool` `agent_id` `violation_count` `violations` `risk_level`

### ARE API Endpoints

```
POST   /auto-response/rules                  create rule (ADMIN+)
GET    /auto-response/rules                  list active rules
GET    /auto-response/rules/{id}             get rule
PATCH  /auto-response/rules/{id}             update rule (creates version snapshot)
DELETE /auto-response/rules/{id}             delete rule (ADMIN+)

GET    /auto-response/rules/{id}/history     version snapshot list
POST   /auto-response/rules/{id}/rollback/{v} restore to version v
POST   /auto-response/rules/{id}/feedback    mark false-positive + optional suppress window

GET    /auto-response/toggle                 get ARE enabled status
POST   /auto-response/toggle                 enable / disable (ADMIN+)

POST   /auto-response/simulate               dry-run against last 24h incidents
POST   /auto-response/replay                 dry-run against historical audit logs
GET    /auto-response/pending                list awaiting manual approval
POST   /auto-response/pending/{key}/approve  approve or reject pending action

GET    /auto-response/metrics                Redis counter roll-ups
GET    /auto-response/latency                p50/p95/p99 per rule
```

---

## 9. Incident System

### Creation Flow
```
Gateway middleware → XADD acp:incidents:queue
    │
    ├── api-incident-worker
    │   sha256(tenant+agent+tool+trigger+5min_bucket) → dedup key
    │   duplicate? → bump violation_count on existing row
    │   new?       → INSERT incidents table
    │
    └── are-workers
        ARE rule evaluation on same event
```

### State Machine
```
OPEN → INVESTIGATING → MITIGATED → RESOLVED
OPEN → INVESTIGATING → ESCALATED → RESOLVED
Invalid transition → HTTP 422 StateTransitionError
```

### Action Types (`POST /incidents/{id}/actions`)
| Type | Effect |
|---|---|
| `KILL_AGENT` | `SET acp:agent_kill:{id}` in Redis (86400s) |
| `BLOCK_AGENT` | Wildcard DENY permission in Registry |
| `ISOLATE` | `PATCH agent status=suspended` in Registry |
| `ESCALATE` | `SET acp:agent_escalated:{id}` Redis flag |
| `REASSIGN` | Updates `assigned_to` field |
| `NOTE` | Appends to timeline, no system effect |

Fields: `type` + `by` (required). `note` is optional.

### Alerting
- `SLACK_WEBHOOK_URL` env var → Slack Block Kit messages for CRITICAL/HIGH incidents.
- `ALERT_WEBHOOK_URL` env var → generic POST webhook.

---

## 10. Data Validation Pipeline

ACP applies three independent validation layers to prevent malformed data from reaching the UI:

```
[Postgres DB]
      │
      ▼
[Pydantic v2 — write-time]            services/api/schemas/auto_response_rule.py
  • AREConditions model:
    - extra="ignore"                  unknown fields silently dropped
    - model_validator(mode="before")  DSL list [] → dict {} normalisation
    - field_validator(mode="before")  null/non-string → empty list
      [123, None, "HIGH"] → ["HIGH"]  isinstance(x, str) filter (not str(x))
  • All list fields: Field(default_factory=list)
  • Incident schema: actions_taken and timeline default to []

      │
      ▼
[Pydantic v2 — read-time]             same schemas applied on every GET response

      │   HTTP response
      ▼
[Zod v4.3.6 — API boundary]           ui/src/lib/schemas.js
  • safeStringList: preprocess → filter(typeof x === 'string')
  • safeObjectList: preprocess → filter(plain objects only)
  • AutoResponseRuleSchema.safeParse(raw)
    on failure: log contract violation, return blankRule(id)
    blankRule: { is_active: false, name: "⚠ contract error", ... }
    never returns raw unvalidated data

      │
      ▼
[normalizeRule() — render-time]       ui/src/pages/AutoResponse.jsx
  • Called inside useState initialiser
  • Merges with makeBlankRule() defaults
  • Guarantees severity_in and tool_in are always arrays before .map()
```

Why three layers instead of one:
- Pydantic write-time: prevents bad data entering the DB.
- Pydantic read-time: catches bad legacy rows already in the DB.
- Zod: catches any contract drift between backend and frontend independently.
- `normalizeRule`: last-resort UI safety so a Zod library bug never causes a render crash.

---

## 11. Security Hardening

| Control | Implementation |
|---|---|
| **XSS token theft prevention** | JWT in httpOnly cookie — JS has zero access |
| **CSRF** | Not applicable — JWT-only model, SameSite=Lax cookie, no form submissions to CSRF |
| **Token revocation** | SHA-256(bare_token) → Redis key, TTL = remaining token life |
| **Auth brute force** | `acp:authfail:{ip}` counter → 429 after threshold |
| **JTI replay** | SETNX 50ms window on `/execute` path — prevents burst replay attacks |
| **Permission casing** | Registry enforces uppercase `ALLOW`/`DENY` — lowercase → 422 |
| **Fail-closed OPA** | `OPA_FAIL_MODE=closed` — deny on any OPA failure |
| **Fail-closed Decision** | Exception → 403 (not 500) |
| **ARE execution lock** | SETNX per agent+rule EX 30s — no double-fire |
| **ARE destructive cap** | Max 1 KILL/ISOLATE per evaluation cycle |
| **Unknown fields** | `extra="ignore"` on AREConditions — unknown keys cannot influence downstream |
| **Audit OOM guard** | Chain verification capped at 10,000 rows |
| **DB isolation** | 5 separate DB users, cross-service access via HTTP only |
| **Container hardening** | All 14 services run as `user: "999:999"` (non-root) |
| **Redis auth (K8s)** | `requirepass` via `secretKeyRef` |
| **JWT key rotation** | Placeholder in K8s Secret — rotate with `openssl rand -base64 32` |
| **Groq concurrency cap** | `asyncio.Semaphore(5)` — prevents 429 cascade |
| **Background task safety** | `_safe_bg(coro)` wraps all `asyncio.create_task()` — exceptions logged, never raised |
| **Input clamping** | `_clamp_int()` on all limit/offset/days query params |
| **Tenant isolation** | Cross-tenant response rejected in `api.js` (`responseTenant !== sessionTenant`) |

---

## 12. Real-Time SSE Event Flow

```
Backend event (tool exec / ARE trigger / kill / insight)
      │
      ▼
Redis PUBLISH acp:events:{tid}  OR  acp:tenant:{tid}:events
      │
      ▼
Gateway /events/stream  (per-tenant subscription)
Auth enforced inline in route handler (not in _SKIP_PATHS middleware)
      │
      ▼
useSSE() hook in browser
  Exponential backoff: 1s → 2s → 4s → … 32s max
      │
      ▼
AgentContext.handleSSEMessage()
      │
      ├── agent_created / updated / deleted  → fetchAgents() + eventBus.emit('agent_changed')
      ├── tool_executed                       → eventBus.emit('tool_executed')
      ├── risk_updated                        → eventBus.emit('risk_updated')
      ├── policy_decision                     → eventBus.emit('policy_decision')
      ├── insight_generated                   → eventBus.emit('insight_generated')
      ├── auto_response_executed              → eventBus.emit('alert') + ARE panel refresh
      └── alert                               → eventBus.emit('alert')

Subscribers (eventBus.on):
  SecurityDashboard  — live risk heatmap + deny feed
  Observability      — metric tiles + decision timeline
  AutoResponse       — pending approval panel + metrics
  AuditLogs          — fetch latest page (if no active search)
  Billing            — refresh summary on tool_executed / policy_decision
  NotificationCenter — badge count + dropdown entries
```

---

## 13. Groq AI Risk Routing

```
Decision Engine aggregates:
  inference_risk   — payload sensitivity (InferenceProxy hash analysis)
  behavior_risk    — agent deviation from baseline (Behavior :8007)
  anomaly_score    — statistical deviation (Learning :8009)
  cross_agent_risk — multi-agent correlation (Intelligence :8008)

  weighted_risk = sum(w_i × signal_i)

  risk < 0.75  →  llama-3.1-8b-instant     ~200ms   (fast triage)
  risk ≥ 0.75  →  llama-3.3-70b-versatile  ~1–2s    (deep analysis)

Background Enrichment (Insight Worker :8011):
  risk < 0.65  →  fast model  (brief narrative)
  risk ≥ 0.65  →  deep model  (detailed risk explanation)
  asyncio.Semaphore(5) — max 5 parallel Groq calls
  Output: Redis sorted set acp:groq:insights:timeline:{tid}
  Event:  insight_generated → SSE → NotificationCenter bell
```

---

## 14. Kill Switch

```
Engage (tenant-wide):
  POST /decision/kill-switch/{tenant_id}  { "action": "engage" }
  → SET acp:tenant_kill:{tid} = "manual_admin_lockdown"  TTL 86400s
  → ALL /execute requests for this tenant → 403

Engage (per-agent):
  Post incident action KILL_AGENT on /incidents/{id}/actions
  → SET acp:{tid}:agent_kill:{aid}  EX 86400
  → Only that agent's executions blocked

Disengage:
  DELETE /decision/kill-switch/{tenant_id}
  → DEL acp:tenant_kill:{tid}
  → Executions resume

Management paths (/agents, /audit, /incidents …) remain accessible
during kill switch — operators can investigate and resolve.
```

---

## 15. Forensics & Audit

### Audit Chain
Every `AuditLog` row: `event_hash = HMAC-SHA256(previous_event_hash + current_event_json)`. Breaking the chain is detectable. `GET /audit/logs/verify` walks the chain and reports the first broken link (capped at 10,000 rows).

### Forensics Drill-Down
From any page with an agent row (AuditLogs, RiskEngine, SecurityDashboard):
1. Click "Investigate" → `navigate('/forensics?agent=<id>')`.
2. Forensics page calls `GET /forensics/investigation/{agent_id}`.
3. Forensics service (:8012) reads last 20 events from Audit via HTTP (not direct DB).
4. Returns: `avg_risk`, `decision_breakdown`, `recent_events[]`.
5. UI renders vertical timeline — DENY/KILL events glow red.

---

## 16. Policy Evaluation Chain

```
Gateway SecurityMiddleware
      │
      ├── _extract_allowed_tools(agent_id)
      │     GET /agents/{id}/permissions  →  Registry (:8001)
      │     filter: permission.action.upper() == "ALLOW"
      │
      └── Policy Service (:8003)
              │
              ├── OPA input document:
              │   { tenant_id, agent_id, tool, risk_score,
              │     inference_risk, behavior_risk, anomaly_score,
              │     policy_allowed, cross_agent_risk,
              │     allowed_tools: ["read_data", ...] }
              │
              └── POST /v1/data/acp/agent  →  OPA (:8181)
                    agent_policy.rego:
                      • tool in allowed_tools OR wildcard *
                      • risk_score ceiling (> 0.85 → DENY)
                      • tool-specific rules
                      • cross-agent correlation risk
                    →  allow / deny / monitor / throttle / escalate

ARE also calls OPA before KILL/ISOLATE:
  AREExecutor._policy_gate() — fail-closed on exception
```

---

## 17. Test Suite

| File | Tests | What it covers |
|---|---|---|
| `tests/test_are.py` | 46 | ARE DSL evaluation, AREIndex pre-filter, `_build_trace`, correlation/backpressure keys, RBAC roles, stream constants |
| `tests/test_audit_fixes.py` | 20 | Token extraction, revocation hash, JSONB cast, `_clamp_int` |
| `tests/test_decision_engine.py` | 24 | Risk clamping, Groq routing thresholds, billing savings, output format |
| `tests/test_production_readiness.py` | 7 | Auth 401/403, tenant isolation, token revocation, fail-closed, env validation |
| `tests/chaos/test_resilience.py` | 2 | Circuit breaker, identity service fallback |
| **Subtotal (no stack required)** | **99** | **All pass: `.venv/bin/python3 -m pytest tests/ -x -q`** |
| `tests/test_system_flow.py` | 1 | Full lifecycle: registry → identity → gateway → decision → audit |
| `tests/e2e/test_full_loop.py` | 2 | E2E security workflow + unauthorized access |
| `tests/e2e/test_security_scenarios.py` | 1 | Multi-scenario threat simulation flows |
| **Total (with stack running)** | **103** | All passing |

Key invariants enforced by the test suite:
- Permission `action` must be uppercase `ALLOW` — registry returns 422 on lowercase.
- `execute_agent` (not `execute_tool`) is the required permission for `/execute`.
- Auth failure rate limiter: tests that hit invalid-token paths accept both `401` and `429`.
- JTI replay: each execute-path test step uses a freshly-issued JWT (fresh login per step).
- Admin agent bypass: attack simulation tests send `X-Agent-ID` header to exercise real agent policy.

---

## 18. Running the Stack

### Prerequisites
- Docker + Docker Compose v2
- Python 3.11+ (unit tests without Docker)

### Start Infrastructure + All Services
```bash
cd acp/infra
docker compose up --build -d
```

### Verify All Services Healthy
```bash
docker compose ps
curl -s http://localhost:8000/health | python3 -m json.tool
```

### Run UI (Development)
```bash
cd acp/ui
npm install
npm run dev
# → http://localhost:5173
```

### Run Unit Tests (No Stack)
```bash
cd acp
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
.venv/bin/python3 -m pytest tests/test_are.py tests/test_audit_fixes.py \
  tests/test_decision_engine.py tests/test_production_readiness.py \
  tests/chaos/test_resilience.py -v
```

### Critical Config: JWT Key Synchronisation
The `JWT_SECRET_KEY` in `acp/.env` and `acp/infra/.env` must be identical:
```bash
grep JWT_SECRET_KEY .env infra/.env   # both lines must match
# Generate new: python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Stop and Clean
```bash
docker compose down          # stop, preserve volumes
docker compose down -v       # stop + delete all data volumes
```

---

## 19. Port Reference

| Component | Port | Protocol |
|---|---|---|
| React UI (Vite dev) | 5173 | HTTP |
| Gateway | 8000 | HTTP |
| Registry | 8001 | HTTP |
| Identity | 8002 | HTTP |
| Policy | 8003 | HTTP |
| Audit | 8004 | HTTP |
| API (incidents · ARE · api-keys) | 8005 | HTTP |
| Usage / Billing | 8006 | HTTP |
| Behavior | 8007 | HTTP |
| Intelligence | 8008 | HTTP |
| Learning | 8009 | HTTP |
| Decision | 8010 | HTTP |
| Insight | 8011 | HTTP |
| Forensics | 8012 | HTTP |
| OPA | 8181 | HTTP |
| OPA Bundle Server | 8182 | HTTP |
| Redis | 6379 | TCP |
| PgBouncer | 6432 | TCP |
| PostgreSQL | 5433 (host) → 5432 | TCP |
| Locust (load test UI) | 8089 | HTTP |
| Groq API | cloud | HTTPS |

All API traffic goes through the Gateway (:8000). Never call internal service ports directly from tests or external tooling except when running integration tests that require identity (:8002) for JWT issuance.

---

## 20. Directory Structure

```
acp/
├── .github/          Issue and PR templates for professional collaboration
├── services/         14 FastAPI microservices (Gateway, Audit, Identity...)
├── infra/            Docker Compose & Kubernetes (K8s) orchestration
├── ui/               React 18 SPA with SOC visibility dashboards
├── sdk/              Python SDK for seamless agent integration
├── docs/             Architectural diagrams, setup guides, and audit reports
├── scripts/          Utility scripts for system initialization and testing
├── tests/            Pytest suite (100+ tests covering unit to E2E)
├── LICENSE           MIT License for open-source distribution
├── pyproject.toml    Python package & dependency management
└── README.md         Core documentation and system reference
```
