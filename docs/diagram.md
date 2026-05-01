# ACP — Agent Control Plane · Architecture Reference

> **Stack:** FastAPI · React/Vite · Redis · PostgreSQL · PgBouncer · OPA · Groq LLM
> **Auth model:** JWT-only (httpOnly cookie for browser, Bearer header for SDK/tests). **No CSRF anywhere.**

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          BROWSER (React SPA)                                │
│                                                                             │
│  Auth ──► Router ──► Pages ──► api.js (fetch + httpOnly acp_token cookie)  │
│           SSE ◄──── eventBus ◄── useSSE hook ◄── /events/stream            │
│           IncidentOverlay ◄── authEvents ◄── 401 / session expiry          │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │  HTTP  (port 8000)
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     API GATEWAY  (FastAPI · port 8000)                      │
│                                                                             │
│  SecurityMiddleware — full pipeline (in order):                             │
│                                                                             │
│  _SKIP_PATHS (no auth):  /health  /docs  /auth/token  /auth/agent/token     │
│                          /events/stream  /metrics  /openapi.json            │
│                                                                             │
│  ── for all other paths ─────────────────────────────────────────────────  │
│  Step 0. Early Defense  — global rate limit + per-IP rate limit (Redis)     │
│  Phase 1. Auth          — httpOnly cookie → Bearer promotion                │
│                           JWT verify (HS256 + expiry)                       │
│                           Redis revocation check (SHA-256 token hash)       │
│                           agent_id extraction; admin+X-Agent-ID override    │
│  Phase 2. Input         — idempotency dedup + hierarchical rate limiting    │
│                           (global / IP / tenant / agent / token)            │
│                                                                             │
│  ── MANAGEMENT FAST PATH ────────────────────────────────────────────────  │
│  _MANAGEMENT_PATH_PREFIXES: /agents /audit /billing /incidents /risk        │
│     /auto-response /decision /forensics /auth /api-keys /system /stream    │
│  → auth + rate-limit already enforced, skip OPA + Decision Engine          │
│  → ADMIN/SECURITY role enforced by individual route handlers                │
│                                                                             │
│  ── EXECUTE PATH (/execute) ─────────────────────────────────────────────  │
│  Kill Check  — acp:tenant_kill:{tid} → 403 if engaged                      │
│  Tool Name   — X-ACP-Tool header  OR  /execute/<tool_name> path            │
│               (NOT from JSON body)                                          │
│  RBAC Check  — requires "execute_agent" in token permissions                │
│               role="agent" JWT allowed here; admin/security blocked         │
│  Phase 3. Security — behavior signals + OPA policy + allowed_tools check   │
│               admin with X-Agent-ID sets agent_via_header=True              │
│               → uses that agent's policies, not admin wildcard              │
│  Phase 4. Decision — risk scoring (Groq) + enforcement verdict              │
│  Phase 5. Audit    — HMAC hash chain write + Redis stream + SSE publish     │
│                                                                             │
│  Routes:  /auth/*  /agents/*  /audit/*  /risk/*  /decision/*               │
│           /forensics/*  /billing/*  /insights/*  /system/*  /events/stream  │
│           /auto-response/*  /incidents/*  /execute  /policy/simulate        │
└──────┬────────┬────────┬─────────┬──────────┬──────────┬────────────────────┘
       │        │        │         │          │          │
       ▼        ▼        ▼         ▼          ▼          ▼
  Registry  Identity  Policy    Audit    Decision   Forensics
   :8001     :8002    :8003     :8004     :8010      :8012
               │        │                   │
               │        ▼                   ▼
               │       OPA               Groq API
               │      :8181            (cloud LLM)
               ▼
          Token revoke
          check / issue
          (Redis + Postgres)

   API Management Service (:8005) — also runs ARE workers (see §6)

   Intelligence Service (:8008)  — context ingestion + RAG layer
   Learning Service (:8009)      — agent behavior baseline learning
   Insight Service (:8011)       — narrative risk explanation workers
```

---

## 2. Full Component Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND  (Vite · React 18)                      │
├───────────────────────┬──────────────────────────────────────────────────┤
│      PAGES            │              CORE SYSTEMS                        │
│                       │                                                  │
│  /dashboard           │  AuthContext      ← httpOnly cookie + expiry     │
│  /agents              │  AgentContext     ← agent list + SSE lifecycle   │
│  /security            │                                                  │
│  /risk                │  eventBus.js      ← pub/sub (SSE domain events)  │
│  /audit-logs          │  authEvents.js    ← typed auth failure signals   │
│  /forensics           │                                                  │
│  /policy-builder      │  useSSE()         ← exp. backoff reconnect       │
│  /rbac                │  useAgents()      ← AgentContext consumer        │
│  /playground          │  useRole()        ← ADMIN / ANALYST / VIEWER     │
│  /observability       │  useAuth()        ← JWT claims from cookie       │
│  /system-health       │                                                  │
│  /billing             │  OVERLAYS                                        │
│  /kill-switch         │  IncidentOverlay  ← SOC auth failure surface     │
│  /developer           │  ErrorBoundary    ← React render crash handler   │
│  /incidents           │  CommandPalette   ← ⌘K navigation                │
│  /auto-response       │  NotificationCenter ← SSE alerts bell           │
│  /attack-sim          │                                                  │
│                       │  API SERVICES (api.js)                           │
│                       │  authService · auditService · registryService    │
│                       │  riskService · forensicsService · billingService │
│                       │  playgroundService · decisionService             │
│                       │  dashboardService · insightService               │
│                       │  policyService · socService · incidentService    │
│                       │  autoResponseService · killSwitchService         │
├───────────────────────┴──────────────────────────────────────────────────┤
│                         LOAD TESTING & PERFORMANCE                       │
├──────────────────────────────────────────────────────────────────────────┤
│  Locust UI (:8089)    ← tests/load/locustfile.py (distributed load)      │
│  Custom Load Script   ← scripts/load_test.py (asyncio concurrency test)   │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Full Component Map

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND  (Vite · React 18)                      │
├───────────────────────┬──────────────────────────────────────────────────┤
│      PAGES            │              CORE SYSTEMS                        │
│                       │                                                  │
│  /dashboard           │  AuthContext      ← httpOnly cookie + expiry     │
│  /agents              │  AgentContext     ← agent list + SSE lifecycle   │
│  /security            │                                                  │
│  /risk                │  eventBus.js      ← pub/sub (SSE domain events)  │
│  /audit-logs          │  authEvents.js    ← typed auth failure signals   │
│  /forensics           │                                                  │
│  /policy-builder      │  useSSE()         ← exp. backoff reconnect       │
│  /rbac                │  useAgents()      ← AgentContext consumer        │
│  /playground          │  useRole()        ← ADMIN / ANALYST / VIEWER     │
│  /observability       │  useAuth()        ← JWT claims from cookie       │
│  /system-health       │                                                  │
│  /billing             │  OVERLAYS                                        │
│  /kill-switch         │  IncidentOverlay  ← SOC auth failure surface     │
│  /developer           │  ErrorBoundary    ← React render crash handler   │
│  /incidents           │  CommandPalette   ← ⌘K navigation                │
│  /auto-response       │  NotificationCenter ← SSE alerts bell           │
│  /attack-sim          │                                                  │
│                       │  API SERVICES (api.js)                           │
│                       │  authService · auditService · registryService    │
│                       │  riskService · forensicsService · billingService │
│                       │  playgroundService · decisionService             │
│                       │  dashboardService · insightService               │
│                       │  policyService · socService · incidentService    │
│                       │  autoResponseService · killSwitchService         │
└───────────────────────┴──────────────────────────────────────────────────┘
```

---

## 3. Backend Services

| Service | Port | Responsibility | DB |
|---------|------|---------------|----|
| **Gateway** | 8000 | Reverse proxy · JWT auth · Rate limit · SSE · Kill-check · OPA routing | Redis |
| **Registry** | 8001 | Agent CRUD · permissions store (action stored as uppercase ALLOW/DENY) | Postgres |
| **Identity** | 8002 | User auth · JWT issue/revoke · token introspect · agent credential issue | Postgres + Redis |
| **Policy** | 8003 | OPA evaluation · policy routing · simulation endpoint | — (calls OPA) |
| **Audit** | 8004 | Immutable log · HMAC hash chain · SOC timeline · ARE event publisher | Postgres |
| **API** | 8005 | Incidents · ARE rules + workers · API keys · Redis stream consumers | Postgres + Redis |
| **Usage** | 8006 | Billing · token cost tracking · invoices · ROI calculation | Postgres |
| **Behavior** | 8007 | Behavioral signal extraction · anomaly scoring | Redis |
| **Decision** | 8010 | Risk engine · Groq AI routing · kill-switch enforcement · fail-closed 403 | Redis |
| **Insight** | 8011 | Background Groq enrichment · per-tenant sorted set timeline | Redis (sorted set) |
| **Forensics** | 8012 | Replay engine · investigation profiles · agent timeline | Postgres (reads Audit) |
| **Intelligence**| 8008 | Context ingestion · RAG vector retrieval · cross-agent intelligence | Redis |
| **Learning** | 8009 | Baseline behavior modeling · drift detection | Redis |
| **Groq Worker**| — | Standalone background worker for high-latency LLM analysis | — |

---

## 4. Infrastructure Layer

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        INFRASTRUCTURE                                   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  REDIS  (port 6379)                                              │   │
│  │                                                                  │   │
│  │  Key / Structure                    Used by                      │   │
│  │  ─────────────────────────────────  ───────────────────────────  │   │
│  │  acp:ratelimit:{tid}                Gateway rate limiter         │   │
│  │  acp:revoked:{sha256(bare_token)}   Token revocation (TTL=expiry)│   │
│  │  acp:authfail:{ip}                  Auth failure counter (429)   │   │
│  │  acp:tenant_kill:{tid}              Tenant kill switch (86400s)  │   │
│  │  acp:agent_kill:{aid}               Per-agent kill (86400s)      │   │
│  │  acp:agent_escalated:{aid}          Escalation flag              │   │
│  │  acp:agent:meta:{id}                Agent metadata cache         │   │
│  │  acp:jti_last_used:{jti}            JTI replay window (setnx)   │   │
│  │                                     [/execute path only]         │   │
│  │  acp:events:{tid}                   Pub/Sub → SSE gateway        │   │
│  │  acp:tenant:{tid}:events            ARE SSE channel              │   │
│  │  acp:groq:insights:{id}             Single insight entry         │   │
│  │  acp:groq:insights:timeline:{tid}   Per-tenant sorted set (ts)  │   │
│  │  acp:idempotency:{id}               Insight / request dedup      │   │
│  │  acp:incident:dedup:{hash}          Incident dedup (TTL 5min)    │   │
│  │  acp:metrics:*                      Dashboard counters           │   │
│  │  acp:{tid}:throttle:{aid}           ARE throttle flag (3600s)    │   │
│  │                                                                  │   │
│  │  ARE Redis keys (all tenant-scoped):                             │   │
│  │  acp:{tid}:are:enabled              ARE global on/off toggle     │   │
│  │  acp:{tid}:are:lock:{aid}:{rid}     Exec lock (SETNX EX 30s)    │   │
│  │  acp:{tid}:are:idemp:{req}:{rid}    Idempotency key (TTL 1h)    │   │
│  │  acp:{tid}:are:cooldown:{r}:{s}     Per-rule cooldown            │   │
│  │  acp:{tid}:are:rate:{r}:{h}         Hourly rate limit counter   │   │
│  │  acp:{tid}:are:violations:{aid}     Rolling window sorted set    │   │
│  │  acp:{tid}:are:metrics:{m}          Prometheus-style counters    │   │
│  │  acp:{tid}:are:latency:{rid}        P99 latency sorted set       │   │
│  │  acp:{tid}:are:agent_corr:{aid}     Correlation dedup (TTL 30s)  │   │
│  │  acp:{tid}:are:pending:{r}:{k}      Manual approval queue        │   │
│  │                                                                  │   │
│  │  STREAMS:                                                        │   │
│  │  acp:incidents:queue                Incident event stream        │   │
│  │    └─ group: api-incident-worker  → creates/deduplicates         │   │
│  │    └─ group: are-workers          → ARE rule evaluation          │   │
│  │  acp:audit:events                   Audit deny/high-risk stream  │   │
│  │    └─ group: are-audit-workers    → ARE second ingestion path    │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌───────────────────────────────┐  ┌───────────────────────────────┐   │
│  │  POSTGRESQL  (5433→5432)      │  │  PGBOUNCER  (port 6432)       │   │
│  │                               │  │                               │   │
│  │  Databases (distinct per svc):│  │  Connection pooling           │   │
│  │  acp_identity  ← users        │  │  Mode: transaction            │   │
│  │  acp_registry  ← agents,perms │  │  Routes → Postgres :5432      │   │
│  │  acp_audit     ← audit_logs   │  │  Each service uses own        │   │
│  │  acp_api       ← incidents,   │  │  DB user/password             │   │
│  │                  are_rules,   │  └───────────────────────────────┘   │
│  │                  api_keys     │                                       │
│  │  acp_usage     ← billing recs │  ┌───────────────────────────────┐   │
│  │                               │  │  OPA  (port 8181)             │   │
│  │  Audit chain:                 │  │                               │   │
│  │  event_hash =                 │  │  Evaluates agent_policy.rego  │   │
│  │    HMAC(prev_hash + event)    │  │  Inputs: risk, tool, agent,   │   │
│  │  verify: SELECT LIMIT 10,000  │  │          permissions, tenant  │   │
│  │  (OOM guard)                  │  │  Output: allow/deny/monitor   │   │
│  │                               │  │           throttle/escalate   │   │
│  │  Permissions: action stored   │  │                               │   │
│  │  as uppercase ALLOW/DENY —    │  │  OPA_FAIL_MODE=closed →       │   │
│  │  registry rejects lowercase   │  │  deny on any failure (default)│   │
│  └───────────────────────────────┘  └───────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  KUBERNETES LAYER (infra/kubernetes)                             │   │
│  │                                                                  │   │
│  │  Component           Manifest Path             Purpose           │   │
│  │  ──────────────────  ────────────────────────  ────────────────  │   │
│  │  NetworkPolicy       network-policy.yaml       Egress/Ingress isolation│   │
│  │  ConfigMap           base/acp-configmap.yaml   Global env vars   │   │
│  │  Secret              base/acp-secret.yaml      JWT/DB credentials│   │
│  │  Gateway Svc         services/gateway.yaml     Port 8000 (LB)    │   │
│  │  Audit Svc           services/audit.yaml       Port 8004         │   │
│  │  Identity Svc        services/identity.yaml    Port 8002         │   │
│  │  Registry Svc        services/registry.yaml    Port 8001         │   │
│  │  Policy Svc          services/policy.yaml      Port 8003         │   │
│  │  Usage Svc           services/usage.yaml       Port 8006         │   │
│  │  API Svc             services/api.yaml         Port 8005         │   │
│  │  OPA Svc             services/opa.yaml         Port 8181         │   │
│  │  UI Svc              services/ui.yaml          Port 5173 (Nginx) │   │
│  │  Postgres Svc        services/postgres.yaml    Port 5432         │   │
│  │  Redis Svc           services/redis.yaml       Port 6379         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Alembic chain (api svc):                                               │
│  81a0f934 → c2b8e4a1 → d4f7a3b2 → e5f8a1b2 → f1a2b3c4d5e6             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Auth Model (JWT-Only — No CSRF)

```
─── BROWSER LOGIN FLOW ──────────────────────────────────────────────────────

Browser                     Gateway :8000              Identity :8002
   │                             │                           │
   │── POST /auth/token ─────────►│                           │
   │   {email, password}          │── forward ───────────────►│
   │                             │                  verify creds + bcrypt
   │                             │◄── JWT (HS256) ────────────│
   │◄── 200 {tenant_id, role,    │                           │
   │         expires_in}          │                           │
   │    Set-Cookie: acp_token     │                           │
   │    (httpOnly · Secure ·      │                           │
   │     SameSite=Lax)            │                           │
   │                             │                           │
   │  localStorage stores:        │                           │
   │  • tenant_id                 │                           │
   │  • user_role                 │                           │
   │  • acp_token_expiry          │                           │
   │  (NEVER the JWT itself)      │                           │
   │                             │                           │
   │── GET /agents ──────────────►│                           │
   │   Cookie: acp_token           │── SecurityMiddleware ────►│
   │   X-Tenant-ID: {tid}          │   cookie → Bearer header  │
   │                              │   JWT verify + revocation │
   │◄── agents[] ────────────────│◄── valid ─────────────────│

─── SDK / TEST / CURL FLOW ──────────────────────────────────────────────────

  1. POST http://localhost:8002/auth/login  →  {data: {access_token: "..."}}
  2. All requests: Authorization: Bearer <token>
                   X-Tenant-ID: <uuid>
  (No cookies, no CSRF tokens — pure Bearer)

─── AGENT CREDENTIAL FLOW ────────────────────────────────────────────────────

  1. Admin: POST /auth/credentials  →  provision agent secret (ADMIN required)
  2. Agent: POST /auth/agent/token  →  {data: {access_token: "..."}}
            JWT contains: role="agent", agent_id=<uuid>
  3. Agent: POST /execute
            Authorization: Bearer <agent_jwt>
            X-Tenant-ID: <uuid>
            X-Agent-ID: <agent_uuid>   ← used by route handler
            X-ACP-Tool: <tool_name>    ← required for tool name extraction

─── TOKEN REVOCATION ─────────────────────────────────────────────────────────

  On logout / admin revoke:
    extract_bearer_token() strips "Bearer " prefix → bare token
    SHA-256(bare_token) → Redis SET acp:revoked:{hash}  TTL=token_expiry
    Every request: middleware hashes the incoming token, checks Redis

─── PROACTIVE EXPIRY ─────────────────────────────────────────────────────────

  App.jsx: setTimeout(remaining_ms) → emitAuthFailure('session_expired')
  IncidentOverlay: 12s countdown → /login redirect
  (catches tabs left open past expiry)

─── ADMIN ON /execute — agent_via_header ─────────────────────────────────────

  Admin JWT has agent_id = UUID(int=0)  [no behavioral history]
  When admin runs attack simulation / playground with X-Agent-ID header:
    middleware overrides agent_id from X-Agent-ID header
    sets request.state.agent_via_header = True
  In security phase:
    agent_via_header=True → skip admin wildcard override
    → use that agent's actual policy + permissions
    → makes attack simulation results meaningful
```

---

## 6. Request Lifecycle — Tool Execution

```
User Action (Playground · Attack Sim · SDK · curl)
        │
        ▼
POST /execute   (or POST /execute/<tool_name>)
Headers required:
  Authorization: Bearer <jwt>   OR   Cookie: acp_token
  X-Tenant-ID: <uuid>
  X-Agent-ID:  <agent_uuid>
  X-ACP-Tool:  <tool_name>      ← preferred; fallback: /execute/<tool> in path
        │
        ▼  SecurityMiddleware
   ┌─────────────────────────────────────────────────────────────┐
   │  Step 0. Early Defense                                      │
   │    • Global rate limit (Redis counter)                      │
   │    • Per-IP rate limit  → 429 if exceeded                   │
   │                                                             │
   │  Phase 1. Authentication                                    │
   │    • httpOnly cookie → extract JWT → Bearer promotion       │
   │    • JWT HS256 verify + expiry check                        │
   │    • Redis revocation check: GET acp:revoked:{sha256(tok)}  │
   │    • Auth failure counter: GET acp:authfail:{ip}            │
   │    • agent_id extracted from JWT claims                     │
   │    • If admin JWT (agent_id=UUID(0)) + X-Agent-ID present:  │
   │        override agent_id, set agent_via_header=True         │
   │                                                             │
   │  Phase 2. Input Protections                                 │
   │    • Idempotency: X-Idempotency-Key dedup (tier-based TTL)  │
   │    • JTI replay window: SETNX acp:jti_last_used:{jti}       │
   │      [/execute path only, 50ms burst window]                │
   │    • Hierarchical rate limits:                              │
   │      global → per-IP → per-tenant → per-agent → per-token  │
   │                                                             │
   │  Kill Switch Check                                          │
   │    • GET acp:tenant_kill:{tid} → 403 if set                 │
   │                                                             │
   │  Tool Name Extraction                                       │
   │    • _get_tool_name(): X-ACP-Tool header (priority)         │
   │      fallback: /execute/<name> path segment                 │
   │      fallback: "unknown-tool"  (NOT from JSON body)         │
   │                                                             │
   │  RBAC Check                                                 │
   │    • "execute_agent" must be in token permissions           │
   │    • role="agent" JWT → allowed on /execute only            │
   │    • role="admin"/"security" on /execute without            │
   │        agent_via_header → execute_agent from permissions    │
   │                                                             │
   │  Phase 3. Security Signal Collection                        │
   │    • Behavior signals from Behavior service (:8007)         │
   │    • allowed_tools = _extract_allowed_tools(agent_id)       │
   │      (checks Registry; action must be uppercase "ALLOW")    │
   │    • If agent_via_header=False AND admin wildcard (*):       │
   │        allowed_tools = ["*"]  (admin sees all tools)        │
   │    • OPA policy evaluation via Policy service (:8003)       │
   │    • InferenceProxy: payload hashing + risk pre-score       │
   │                                                             │
   │  Phase 4. Decision Engine                                   │
   │    • POST to Decision service (:8010)                       │
   │    • Risk signals: inference_risk + behavior_risk +         │
   │        anomaly_score + cross_agent_risk                     │
   │    • Groq routing:                                          │
   │        risk < 0.75 → llama-3.1-8b-instant   (~200ms)        │
   │        risk ≥ 0.75 → llama-3.3-70b-versatile (~1s)         │
   │    • Returns: action + risk_score + reasons + confidence     │
   │    • Fail-closed: exception → 403 "Fail-Closed"             │
   │                                                             │
   │  Phase 5. Audit + Publish                                   │
   │    • Write AuditLog (HMAC hash chain → Postgres)            │
   │    • XADD acp:audit:events (if deny OR risk ≥ 0.7) → ARE   │
   │    • PUBLISH acp:events:{tid} → SSE → browser              │
   │        eventBus.emit('tool_executed')                        │
   │        eventBus.emit('policy_decision')                      │
   └─────────────────────────────────────────────────────────────┘
                            │
                            ▼
              Response: { action, risk, reasons, request_id }
              UI updates: SecurityDashboard · Observability · AuditLogs
```

---

## 7. Autonomous Response Engine (ARE)

```
ARE Ingestion — Two independent paths:
        │
        ├── Stream 1: acp:incidents:queue
        │   consumer group: are-workers
        │   (new incident created → evaluate rules)
        │
        └── Stream 2: acp:audit:events
            consumer group: are-audit-workers
            (Audit svc publishes on deny OR risk ≥ 0.7)

        Both paths → process_incident()

┌───────────────────────────────────────────────────────────────┐
│  process_incident()  — evaluation pipeline                    │
│                                                               │
│  1.  ARE enabled?         GET acp:{tid}:are:enabled           │
│  2.  Backpressure check   XLEN stream > 10,000 → skip 5s      │
│  3.  Correlation dedup    acp:{tid}:are:agent_corr:{aid}      │
│      (skip if same agent processed within 30s)                │
│  4.  Load active rules from Postgres ORDER BY priority DESC   │
│  5.  AREIndex pre-filter  severity_set + min_risk check       │
│      → O(n) skip before full trace evaluation                 │
│      → 60-80% rules skipped on high-risk flood               │
│                                                               │
│  Per-rule loop:                                               │
│    6.  Suppression?  suppressed_until > now → skip            │
│    7.  Idempotency?  acp:{tid}:are:idemp:{req}:{rid} (TTL 1h) │
│    8.  Cooldown?     acp:{tid}:are:cooldown:{r}:{scope}       │
│    9.  Rate limit?   acp:{tid}:are:rate:{rid}:{hour}          │
│   10.  Window count  Redis ZSET violations sorted set         │
│   11.  _build_trace()  DSL conditions matched/failed          │
│   12.  Record latency  acp:{tid}:are:latency:{rid} ZSET       │
│                                                               │
│  Action mode routing:                                         │
│    suggest  → SSE event only, no execution                    │
│    manual   → store pending in Redis + SSE, no execution      │
│               key: acp:{tid}:are:pending:{rule_id}:{req_id}   │
│               JSON includes: approval_key, incident, actions  │
│    auto     → AREExecutor.execute() per action                │
│                                                               │
│  All outcomes logged:                                         │
│    triggered / no_match / suppressed / cooldown /             │
│    rate_limited / suggest / manual_pending                    │
│    → POST /audit/logs (Audit service)                         │
│                                                               │
│  stop_on_match=True → break after first matching rule         │
└───────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────┐
│  AREExecutor.execute()  — enforcement layer                   │
│                                                               │
│  1. _policy_gate()   POST /policy/evaluate (OPA)             │
│     fail-closed for KILL/ISOLATE: exception → deny            │
│  2. _execution_lock() SETNX acp:{tid}:are:lock:{aid}:{rid}   │
│     EX 30s — prevents double-fire from concurrent workers    │
│  3. Dispatch:                                                 │
│     KILL_AGENT    → SET acp:{tid}:agent_kill:{aid} EX 86400  │
│     ISOLATE_AGENT → PATCH /agents/{id} {status: suspended}   │
│     BLOCK_TOOL    → POST /agents/{id}/permissions DENY        │
│     THROTTLE      → SET acp:{tid}:throttle:{aid} EX 3600     │
│     ALERT         → Slack webhook (Block Kit) or webhook URL  │
│                                                               │
│  Destructive cap: max 1 KILL/ISOLATE per rule evaluation      │
│  Lock contention → skip (logged info, not error)             │
└───────────────────────────────────────────────────────────────┘
                    │
                    ▼
          PUBLISH acp:tenant:{tid}:events
          → Gateway SSE → Browser: auto_response_executed
```

---

## 8. ARE Condition DSL

```
New DSL (list of conditions):
  [
    { "field": "risk_score",  "op": ">=",    "value": 0.8 },
    { "field": "severity",    "op": "in",    "value": ["HIGH", "CRITICAL"] },
    { "field": "violations",  "op": ">=",    "value": 3 },
    { "field": "tool",        "op": "not_in","value": ["benign.read"] }
  ]

  Supported ops:  == | != | > | >= | < | <= | in | not_in
  Supported fields: severity | risk_score | tool | agent_id
                    violation_count | violations | risk_level

Legacy blob (backward-compatible):
  {
    "severity_in": ["HIGH", "CRITICAL"],
    "risk_score_gte": 0.7,
    "tool_in": ["payments.write"],
    "agent_id": "*",
    "repeat_offender": true,
    "min_violations": 2,
    "window": "5m"
  }

AREIndex pre-filter:
  Extracts severity_set + min_risk from BOTH formats.
  Cheap O(n) comparison before full _build_trace() evaluation.
  Typical result: 60-80% of rules skipped on high-traffic flood events.
```

---

## 9. ARE API Endpoints

```
CRUD:
  POST   /auto-response/rules                create rule (ADMIN+)
  GET    /auto-response/rules                list active rules
  GET    /auto-response/rules/{id}           get rule
  PATCH  /auto-response/rules/{id}           update rule (creates version snapshot)
  DELETE /auto-response/rules/{id}           delete rule (ADMIN+)

Versioning:
  GET    /auto-response/rules/{id}/history        snapshot list (newest first)
  POST   /auto-response/rules/{id}/rollback/{v}   restore version v

Toggle:
  GET    /auto-response/toggle                get ARE enabled status
  POST   /auto-response/toggle                enable / disable ARE (ADMIN+)

Operations:
  POST   /auto-response/simulate              dry-run against historical incidents
  POST   /auto-response/replay                dry-run against historical audit logs
  POST   /auto-response/rules/{id}/feedback   false-positive + suppress window
  GET    /auto-response/pending               list pending manual approvals
  POST   /auto-response/pending/{key}/approve approve or reject pending action

Observability:
  GET    /auto-response/metrics               Redis counter roll-ups
  GET    /auto-response/latency               p50/p95/p99 per rule

Pending approval key format:
  "{rule_id}:{request_id}"
  Stored in Redis JSON payload + backfilled from key name for older entries.
  Frontend uses item.approval_key (never reconstructs manually).

RBAC: create / delete / toggle require role ADMIN | SUPER_ADMIN | SYSTEM
```

---

## 10. Incident System

```
Incident creation flow:
  Gateway middleware → XADD acp:incidents:queue
                           │
              ┌────────────┴──────────────┐
              ▼                           ▼
  api-incident-worker                are-workers
  (dedup + create incident)     (evaluate ARE rules)
              │
              ▼
  sha256(tenant + agent + tool + trigger + 5min_bucket) → dedup key
  duplicate → bump violation_count
  new       → INSERT incidents table

State machine:
  OPEN → INVESTIGATING → MITIGATED | ESCALATED → RESOLVED
  Invalid transition → HTTP 422 StateTransitionError

Action effects (POST /incidents/{id}/actions):
  KILL_AGENT    → SET acp:agent_kill:{id} Redis (86400s)
  BLOCK_AGENT   → wildcard DENY permission (registry)
  ISOLATE       → PATCH agent status=suspended (registry)
  ESCALATE      → SET acp:agent_escalated:{id} Redis flag
  Fields: type + by (not "action_type")

Alerting:
  SLACK_WEBHOOK_URL → Slack Block Kit (CRITICAL/HIGH only)
  ALERT_WEBHOOK_URL → generic POST webhook

SOC Feed (Incidents UI → /audit/logs/soc-timeline):
  Returns: deny + kill + escalate + risk≥0.7 events
  Merged timeline, sorted newest-first
```

---

## 11. SSE Real-Time Event Flow

```
Backend event (tool exec / kill switch / ARE trigger / billing update)
        │
        ▼
Redis PUBLISH → acp:events:{tenant_id}  OR  acp:tenant:{tid}:events
        │
        ▼
Gateway /events/stream  (per-tenant subscription, no auth in _SKIP_PATHS —
                          auth enforced inline in the route handler)
        │
        ▼
EventSource connection in browser
        │
useSSE() hook  (exponential backoff: 1s → 2s → 4s … 32s max)
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
                │
                ▼
        Subscribers (eventBus.on):
        • SecurityDashboard   — refresh heatmap + live log
        • NotificationCenter  — badge count + dropdown entry
        • Observability       — metric tiles + risk timeline
        • AutoResponse        — pending panel + metrics refresh
        • AuditLogs           — fetch latest page (if no active search)
        • Billing             — refresh summary on tool_executed / policy_decision
```

---

## 12. Auth Failure Event Architecture

```
api.js (HTTP layer)
   │
   ├── 401 response received
   │        └──► emitAuthFailure({ reason: 'unauthorized', url, statusCode: 401 })
   │
   └── session_expired (pre-request gate via acp_token_expiry in localStorage)
            └──► emitAuthFailure({ reason: 'session_expired', url })

authEvents.js  ← single canonical emitter
   └── window.dispatchEvent(CustomEvent 'acp:auth:failure', {
           incidentId, reason, reasonLabel,
           url, statusCode, timestamp
       })

App.jsx  ←  window.addEventListener('acp:auth:failure')
   └── handleIncident(detail)
           ├── clearSessionMetadata()       // wipe localStorage
           ├── setAuth({ isAuthenticated: false })
           └── setIncident(detail)
                   └──► IncidentOverlay renders:
                           • red-glow SOC panel
                           • 12s countdown progress bar
                           • incident ID + reason + path
                           • "Re-authenticate" / "Copy Report" buttons
                           • auto-redirect to /login on countdown end

Proactive expiry timer (App.jsx):
   setTimeout(remaining_ms) → same handleIncident path
   (catches sessions expired while tab is open)
```

---

## 13. Forensics Drill-Down Flow

```
AuditLogs page                    Forensics page
   │                                    │
   │  click "Investigate" on a row      │
   └──► navigate('/forensics?agent=<id>')
                                        │
                                GET /forensics/investigation/{agent_id}
                                        │
                                Forensics Service (:8012)
                                        │
                          SELECT audit_logs WHERE agent_id=? AND tenant_id=?
                          (last 20 events, tenant-scoped)
                                        │
                          Compute: avg_risk, decision_breakdown, recent_events[]
                                        │
                                        ▼
                          Vertical Timeline renders:
                          • Each event = timeline card
                          • DENY / KILL → red glow box-shadow
                          • Risk bar per event
                          • Reasons list
                          • Decision breakdown KPIs (allow/deny/monitor counts)

Also triggered from:
  • RiskEngine page    → navigate('/forensics?agent=<id>')
  • SecurityDashboard  → navigate('/forensics?agent=<id>')
  • AgentRegistry      → ExternalLink button per agent row
```

---

## 14. Policy Evaluation Chain

```
Incoming /execute request
        │
        ▼
Gateway SecurityMiddleware._handle_security_phase()
        │
        ├── _extract_allowed_tools(agent_id)
        │     GET /agents/{id}/permissions  →  Registry (:8001)
        │     Filter: permission.action.upper() == "ALLOW"
        │     (Registry stores action as uppercase — lowercase rejected with 422)
        │
        └──► Policy Service (:8003)
                │
                ├── Build OPA input:
                │       {
                │         tenant_id, agent_id, tool,
                │         risk_score, inference_risk,
                │         behavior_risk, anomaly_score,
                │         policy_allowed, cross_agent_risk,
                │         allowed_tools: ["data_query", ...]  ← from Registry
                │       }
                │
                └──► POST /v1/data/acp/agent  →  OPA (:8181)
                                │
                    agent_policy.rego evaluates:
                      • tool in allowed_tools (or wildcard *)
                      • risk_score ceiling (> 0.85 → DENY)
                      • tool-specific rules
                      • cross-agent correlation risk
                                │
                                ▼
                    Decision: allow / deny / monitor / throttle / escalate
                                │
                                ▼
                    OPA_FAIL_MODE:
                      closed (default) → deny on any failure (production-safe)
                      open             → allow on failure (dev/staging only)

                    Circuit breaker OPEN  → fail-safe "deny"
                    Circuit breaker CLOSED → use OPA result

ARE also calls OPA before destructive KILL/ISOLATE:
  AREExecutor._policy_gate() → fail-closed on exception
```

---

## 15. Kill Switch Flow

```
Operator: "Engage Kill Switch" button  (/kill-switch page)
        │
        ▼
POST /decision/kill-switch/{tenant_id}  { action: "engage" }
        │
Gateway → Decision Service (:8010)
        │
        └──► SET acp:tenant_kill:{tid} = "manual_admin_lockdown"  TTL 86400s

Next incoming /execute for that tenant:
        │
SecurityMiddleware:
  GET acp:tenant_kill:{tid}  →  value found
        │
        └──► 403  "Tenant blocked due to security violation"
             ALL tool executions blocked for this tenant
             Management paths (/agents, /audit, etc.) remain accessible

Disengage:
  DELETE /decision/kill-switch/{tenant_id}
  → DEL acp:tenant_kill:{tid}
  → executions resume

ARE also sets per-agent kill (narrower):
  KILL_AGENT action → SET acp:{tid}:agent_kill:{aid}  EX 86400
  Gateway checks per-agent flag for each /execute request → 403 for that agent only
  Kill switch = tenant-wide; agent kill = agent-scoped
```

---

## 16. Groq AI Risk Routing

```
Decision Engine (:8010) receives execution request
        │
        ▼
Compute weighted risk from signals:
  inference_risk   = payload sensitivity score  (InferenceProxy)
  behavior_risk    = agent behavioral deviation (Behavior :8007)
  anomaly_score    = statistical deviation from baseline
  cross_agent_risk = multi-agent correlation score

  weighted_risk = weighted_sum(signals)
        │
        ├── risk < 0.75  →  llama-3.1-8b-instant    (fast,  ~200ms)
        └── risk ≥ 0.75  →  llama-3.3-70b-versatile (deep,  ~1–2s)
                │
                ▼
        Groq response: { action, risk, reasons[], confidence }
                │
                ▼
Background Enrichment — Insight Worker (:8011):
  risk < 0.65  →  fast model
  risk ≥ 0.65  →  deep model (narrative generation)
  asyncio.Semaphore(5) — max 5 parallel Groq calls per worker
  Output stored in:
    Redis key:        acp:groq:insights:{id}
    Redis sorted set: acp:groq:insights:timeline:{tid}  (score = unix_ts)
  Published: insight_generated → SSE → NotificationCenter bell

Rate-limit guard:
  Semaphore prevents Groq 429 cascade on burst traffic
  _safe_bg() wraps all create_task() calls → exceptions logged, not raised
```

---

## 17. Security Hardening

```
JWT-Only Auth (No CSRF):
  • Browser: httpOnly acp_token cookie — JS cannot read it (XSS-safe)
  • Cookie promoted to Authorization: Bearer inside gateway — downstream
    services receive only Bearer, never cookies
  • No X-CSRF-Token header on any endpoint — model relies entirely on JWT

Token Revocation:
  • extract_bearer_token() strips "Bearer " before SHA-256 hashing
  • All revocation paths use bare token — prefix-stripping prevents bypass
  • Revocation key: acp:revoked:{sha256(bare_token)}  TTL = token remaining TTL

Auth Failure Rate Limiting:
  • acp:authfail:{ip} counter — repeated 401s trigger 429 after threshold
  • Tests that test invalid-token paths accept (401, 429) as valid responses

JTI Replay Protection:
  • SETNX acp:jti_last_used:{jti} — atomic first-use claim
  • 50ms burst window, scoped to /execute path only (not management CRUD)
  • E2E tests use fresh login (fresh JTI) for each execute-path step

Permission Action Casing:
  • Registry stores and requires: action = "ALLOW" or "DENY" (uppercase)
  • _extract_allowed_tools() uses: action.upper() == "ALLOW"
  • Any code/test sending lowercase "allow" gets 422 from Registry

Agent Role on /execute:
  • role="agent" JWT tokens are allowed on /execute only
  • All other paths (management) require ADMIN / SECURITY
  • Gateway: if not (is_execute_path and role == "agent"): → 403

Admin Agent Bypass:
  • Admin JWT has agent_id = UUID(int=0) — no behavioral profile
  • On /execute with X-Agent-ID: override agent_id from header
  • agent_via_header=True → skip admin wildcard (*) override in security phase
  • Ensures attack simulation/playground tests real agent policy, not admin bypass

Input Clamping:
  • _clamp_int() on: audit limit/offset, timeline days, threat limit
  • Prevents resource exhaustion from unbounded query params

OPA Fail Mode:
  • closed (production default) → deny on OPA outage
  • open (dev/staging) → allow on OPA outage
  • Wired into opa_client.py for all 3 failure paths: non-200 / result=None / exception

Decision Engine Fail-Closed:
  • evaluate_decision() exception → 403 "Fail-Closed: Decision engine unavailable"
  • (not 500 — prevents leaking internal error details)

ARE Backpressure:
  • XLEN stream > 10,000 → pause 5s, skip evaluation cycle
  • Prevents cascade when incident flood occurs

ARE Execution Locks:
  • SETNX per agent+rule (EX 30s) — prevents double-fire from concurrent workers
  • Destructive cap: max 1 KILL/ISOLATE per rule evaluation cycle

Audit Integrity OOM Guard:
  • verify_audit_chain() SELECT LIMIT 10,000
  • Chain verification capped — prevents full-table scan on large tenants

Database Isolation:
  • Distinct DB user + password per service (registry / identity / audit / api / usage)
  • No shared postgres superuser password in application code
  • Cross-service DB access forbidden — Forensics reads Audit via HTTP, not direct DB

Container Hardening:
  • All 14 Python services: user: "999:999" (appuser, non-root)
  • Redis in K8s: requirepass via secretKeyRef
  • JWT_SECRET_KEY in K8s: placeholder — rotate with: openssl rand -base64 32

Groq Concurrency:
  • asyncio.Semaphore(5) on GroqWorker — caps parallel Groq API calls
  • Prevents 429 cascade on burst events

Background Task Safety:
  • _safe_bg(coro) wraps all asyncio.create_task() (7 sites)
  • Catches + logs exceptions from fire-and-forget tasks
```

---

## 18. Component Interaction Summary

```
                     ┌──────────────────────────────────────────────┐
                     │              BROWSER                          │
                     │                                              │
                     │   ┌─────────┐   ┌──────────────────────┐   │
                     │   │AuthCtx  │   │   AgentContext        │   │
                     │   │tenant_id│   │   agents[]           │   │
                     │   │role     │   │   selectedAgent      │   │
                     │   │expiry   │   │   sseConnected ●─────┼───┼──► useSSE()
                     │   └────┬────┘   └──────────┬───────────┘   │        │
                     │        │                   │               │        │
                     │   ┌────▼────────────────────▼───────────┐  │        │
                     │   │              eventBus                │  │        │
                     │   │  risk_updated   tool_executed        │  │        │
                     │   │  policy_decision  alert              │  │        │
                     │   │  agent_changed  insight_generated    │  │        │
                     │   │  auto_response_executed              │  │        │
                     │   └──────────────────────────────────────┘  │        │
                     │        │                                    │        │
                     │   ┌────▼────────────────────────────────┐  │        │
                     │   │  SecurityDashboard  NotificationCtr  │  │        │
                     │   │  Observability      AuditLogs        │  │        │
                     │   │  Forensics          PolicyBuilder     │  │        │
                     │   │  Incidents          AutoResponse      │  │        │
                     │   │  AttackSimulation   KillSwitch        │  │        │
                     │   │  RiskEngine         Billing           │  │        │
                     │   │  Agents             DeveloperPanel    │  │        │
                     │   └─────────────────────────────────────┘  │        │
                     │                                             │        │
                     │   authEvents ──► IncidentOverlay            │        │
                     │   ErrorBoundary (wraps entire app)         │        │
                     └──────────────────┬──────────────────────────┘        │
                                        │ api.js (fetch + httpOnly cookie)  │
                                        ▼                                   ▼
                               GATEWAY :8000  ◄──────────────── /events/stream
                                        │
              ┌──────────┬──────────────┼──────────────┬─────────────┐
              ▼          ▼              ▼              ▼             ▼
         Registry    Identity        Audit         Decision      Forensics
          :8001       :8002          :8004           :8010         :8012
              │          │              │              │
              │          │              │ XADD acp:audit:events
              │ Perms     │ JWT issue/   │              │ Groq
              │ (ALLOW/   │ revoke       │              │ routing
              │  DENY)    │              │              │
              └──────────┴──────────────┴──────────────┘
                                        │
                            ┌───────────┴────────────────────────────────┐
                            ▼                                            ▼
                       PostgreSQL                               Redis :6379
                       (via PgBouncer)                (cache · pub/sub · streams ·
                        :6432 → :5432                  rate limit · KV · ARE state ·
                        5 isolated DBs                  revocation · kill flags)
                                                                         │
                                                          ┌──────────────┘
                                                          ▼
                                                API Service :8005
                                                ├── api-incident-worker
                                                ├── ARE worker (incidents stream)
                                                └── ARE audit worker (audit stream)
```

---

## 19. Test Suite

| File | Count | Coverage |
|------|-------|----------|
| `tests/test_are.py` | 46 | ARE DSL, AREIndex, _build_trace, correlation/backpressure keys, RBAC roles, stream constants |
| `tests/test_audit_fixes.py` | 20 | Token extraction, revocation hash, JSONB cast, _clamp_int |
| `tests/test_decision_engine.py` | 24 | Risk clamping, Groq routing thresholds, billing savings, output format |
| `tests/test_production_readiness.py` | 7 | Auth 401/403, tenant isolation, token revocation, fail-closed, env validation |
| `tests/chaos/test_resilience.py` | 2 | Circuit breaker, identity fallback |
| **Subtotal (no stack)** | **99** | **All passing without Docker** |
| `tests/test_system_flow.py` | 1 | Full lifecycle: registry → identity → gateway → decision → audit |
| `tests/e2e/test_full_loop.py` | 2 | E2E security workflow + unauthorized access |
| `tests/e2e/test_security_scenarios.py` | 1 | Multi-scenario security flows |
| **Total (with stack)** | **103** | **All passing with Docker stack running** |

Key behavioral invariants the tests enforce:
- Permission `action` must be uppercase `ALLOW` (not `allow`) — registry 422 on lowercase
- `execute_agent` (not `execute_tool`) is the required permission action for /execute
- Auth failure rate limiter means repeated 401s may return 429 — tests accept both
- JTI replay: each execute-path test step uses a freshly-issued JWT
- Admin agent bypass: attack simulation tests use `X-Agent-ID` header to test real agent policy

---

## 20. Port Reference

| Component | Port | Protocol |
|-----------|------|----------|
| React UI (dev) | 5173 | HTTP |
| Gateway | 8000 | HTTP |
| Registry | 8001 | HTTP |
| Identity | 8002 | HTTP |
| Policy | 8003 | HTTP |
| Audit | 8004 | HTTP |
| API (incidents · ARE · api-keys) | 8005 | HTTP |
| Usage / Billing | 8006 | HTTP |
| Behavior | 8007 | HTTP |
| Decision | 8010 | HTTP |
| Insight | 8011 | HTTP |
| Forensics | 8012 | HTTP |
| OPA | 8181 | HTTP |
| OPA Bundle Server | 8182 | HTTP |
| Redis | 6379 | TCP |
| PgBouncer | 6432 | TCP |
| PostgreSQL | 5433 (host) → 5432 (container) | TCP |
| Locust Web UI (load test) | 8089 | HTTP |
| Groq API | cloud | HTTPS |

---

## 21. Full Project Directory Map

```
/ (Root)
├── acp/
│   ├── services/ (The Brain & Muscle)
│   │   ├── api/          ← Incident management, ARE workers, API keys
│   │   ├── audit/        ← Immutable logging, HMAC chain, Audit verify
│   │   ├── behavior/     ← Signal extraction, anomaly scoring
│   │   ├── billing/      ← Token costs, ROI, invoices
│   │   ├── decision/     ← Risk orchestration, Groq routing, Kill-switch
│   │   ├── forensics/    ← Replay engine, timeline reconstruction
│   │   ├── gateway/      ← Security middleware, rate limit, SSE, Auth
│   │   ├── groq_worker/  ← Dedicated LLM analysis workers
│   │   ├── identity/     ← JWT issue/revoke, user/agent credentials
│   │   ├── insight/      ← Narrative generation, background enrichment
│   │   ├── intelligence/ ← RAG, cross-agent context, memory layer
│   │   ├── learning/     ← Baseline models, drift detection
│   │   ├── policy/       ← OPA integration, simulation, Rego management
│   │   ├── registry/     ← Agent CRUD, tool permissions (RBAC)
│   │   └── usage/        ← Resource tracking, billing storage
│   ├── infra/ (The Foundation)
│   │   ├── kubernetes/   ← K8s manifests (base, services, network policies)
│   │   ├── docker-compose.yml ← Production-ready local stack
│   │   ├── pgbouncer.ini ← Postgres connection pooler config
│   │   └── opa-config.yaml ← Open Policy Agent distributed config
│   ├── ui/ (The Interface)
│   │   ├── src/          ← React 18, Vite, Mythos Design System
│   │   └── Dockerfile    ← Nginx-based frontend container
│   ├── sdk/ (The Connector)
│   │   └── python/       ← Official ACP Python SDK for agents
│   ├── scripts/ (Automation)
│   │   ├── load_test.py  ← AsyncIO-based concurrency validator
│   │   └── run_audit.py  ← Security audit automation
│   ├── tests/ (The Guardrails)
│   │   ├── load/         ← locustfile.py for distributed load testing
│   │   ├── e2e/          ← Full-system security integration tests
│   │   ├── chaos/        ← Resilience and failure mode tests
│   │   └── ...           ← Unit and functional service tests
│   └── diagram.md        ← You are here
└── README.md             ← High-level project entry point
```
