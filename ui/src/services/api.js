import { emitAuthFailure } from "../lib/authEvents";
import { parseRule, parseRuleList } from "../lib/schemas";

// In dev: empty string → relative URLs → Vite proxy routes to :8000 (same-origin, no CORS/cookie issues).
// In production (Docker/k8s): set VITE_GATEWAY_URL=https://your-gateway or leave empty for nginx proxy.
const API_BASE = import.meta.env.VITE_GATEWAY_URL || "";

/**
 * ACP API Client
 *
 * C-6/UI-9 FIX: Token is NO LONGER stored in localStorage.
 * Authentication is handled exclusively via the httpOnly `acp_token` cookie
 * set by the Gateway on login. This eliminates the XSS token-theft vector.
 *
 * Session metadata (tenant_id, expiry, user_email) is stored in localStorage
 * as non-sensitive identifiers only — not the token itself.
 */

export const setSessionMetadata = (data) => {
  if (data.tenant_id) localStorage.setItem("tenant_id", data.tenant_id);
  if (data.user_email) localStorage.setItem("user_email", data.user_email);
  if (data.role) localStorage.setItem("user_role", String(data.role).toUpperCase());
  if (data.agent_id) localStorage.setItem("agent_id", data.agent_id);
  if (data.expires_in) {
    localStorage.setItem("acp_token_expiry", String(Date.now() + data.expires_in * 1000));
  }
};

export const clearSessionMetadata = () => {
  localStorage.removeItem("tenant_id");
  localStorage.removeItem("user_email");
  localStorage.removeItem("acp_token_expiry");
  localStorage.removeItem("user_role");
  localStorage.removeItem("agent_id");
};

export const isSessionValid = () => {
  const expiry = parseInt(localStorage.getItem("acp_token_expiry") || "0", 10);
  return expiry > Date.now();
};

const request = async (url, options = {}, retry = 1) => {
  try {
    const tenantId = localStorage.getItem("tenant_id");

    // AUTH GATE: Block requests (except auth/health) if session is expired or missing
    const isAuthPath =
      url.includes("/auth/token") ||
      url.includes("/health");

    if (!isSessionValid() && !isAuthPath) {
      console.warn("API_GATED: Session expired or not found.", url);
      emitAuthFailure({ reason: "session_expired", url });
      throw new Error("UNAUTHENTICATED: Session expired.");
    }

    const headers = {
      "Content-Type": "application/json",
      ...(tenantId && { "X-Tenant-ID": tenantId }),
      "X-Request-ID": crypto.randomUUID(),
      "X-Timestamp": Date.now().toString(),
      ...(options.headers || {}),
    };

    const base = options.overrideBase || API_BASE;
    const finalUrl = url.startsWith("http") ? url : `${base}${url}`;

    const res = await fetch(finalUrl, {
      ...options,
      headers,
      credentials: "include", // Always send httpOnly cookies
    });

    if (res.status === 401) {
      console.error(`AUTHENTICATION_REQUIRED [401] ${url}`);
      clearSessionMetadata();
      if (window.location.pathname !== "/login") {
        emitAuthFailure({ reason: "unauthorized", url, statusCode: 401 });
      }
      // Throw a special sentinel so the catch block knows NOT to retry
      const authErr = new Error("UNAUTHORIZED: Session expired or credentials invalid.");
      authErr._noRetry = true;
      throw authErr;
    }

    if (res.status === 429) {
      const txt = await res.text().catch(() => "");
      let msg = "Too many requests — please wait a moment and try again.";
      try { const p = JSON.parse(txt); msg = p.detail || p.error || msg; } catch {}
      console.warn(`RATE_LIMITED [429] ${url}:`, msg);
      const rlErr = new Error(msg);
      rlErr._noRetry = true;
      throw rlErr;
    }

    if (!res.ok) {
      const errorText = await res.text();
      let parsedError = errorText;
      try {
        const parsed = JSON.parse(errorText);
        parsedError = parsed.error || parsed.detail || errorText;
      } catch (e) {}
      console.error(`API_ERROR [${res.status}] ${url}:`, parsedError);
      const apiErr = new Error(parsedError || "API Error");
      // 4xx client errors are not retryable (the request was wrong, not transient)
      if (res.status >= 400 && res.status < 500) apiErr._noRetry = true;
      throw apiErr;
    }

    const text = await res.text();
    const json = text ? JSON.parse(text) : {};

    // Multi-Tenant Isolation: reject responses that carry a different tenant_id
    const sessionTenant = localStorage.getItem("tenant_id");
    const responseTenant = json?.data?.tenant_id ?? json?.tenant_id;
    if (sessionTenant && responseTenant && responseTenant !== sessionTenant) {
      console.error("TENANT_MISMATCH: response tenant differs from session", { responseTenant, sessionTenant });
      emitAuthFailure({ reason: "tenant_mismatch", url, statusCode: 403 });
      throw new Error("TENANT_MISMATCH: Cross-tenant data rejected");
    }

    return json;
  } catch (err) {
    if (err.name === "TypeError" && err.message === "Failed to fetch") {
      console.error(`NETWORK_ERROR: Cannot reach ${API_BASE}. Check backend services.`);
    } else {
      console.error(`REQUEST_FAILED ${url}:`, err);
    }
    // Only retry on transient network errors — never on 4xx or auth failures
    if (retry > 0 && !err._noRetry && err.name === "TypeError") {
      return request(url, options, retry - 1);
    }
    throw err;
  }
};


// Auth Service
export const authService = {
  login: async (data) => {
    console.info("AUTHENTICATION_ATTEMPT", { email: data.email });

    // Login uses raw fetch so we don't hit the session gate
    const res = await fetch(`${API_BASE}/auth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email: data.email, password: data.password }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Login failed");
    }

    const json = await res.json();

    // Token goes into the httpOnly cookie (set by the gateway) — NOT localStorage
    const tenantId = json?.tenant_id || json?.data?.tenant_id;
    const expiresIn = json?.expires_in || json?.data?.expires_in || 900;
    const role = json?.role || json?.data?.role;

    setSessionMetadata({ tenant_id: tenantId, expires_in: expiresIn, role });

    console.info("AUTHENTICATION_SUCCESS", { tenantId, role });

    return {
      data: {
        tenant_id: tenantId,
        expires_in: expiresIn,
        role,
        user: json?.user || json?.data?.user,
      },
    };
  },

  logout: async () => {
    try {
      await fetch(`${API_BASE}/auth/logout`, { method: "POST", credentials: "include" });
    } finally {
      clearSessionMetadata();
    }
  },

  getHealth: () => request("/health"),
  getMe: () => request("/auth/me"),
};

// Common API object — only methods actually called by components live here.
// All other operations use their service-specific exports below.
export const api = {
  ...authService,
  getApiKeys: () => request("/api-keys"),
  createApiKey: (data) => request("/api-keys", { method: "POST", body: JSON.stringify(data) }),
  revokeApiKey: (id) => request(`/api-keys/${id}`, { method: "DELETE" }),
  getBilling: () => request("/billing/summary"),
  getRisk: () => request("/risk/summary"),
};

export const auditService = {
  getSummary: () => request("/audit/logs/summary"),
  getLogs: (limit = 10, offset = 0) => request(`/audit/logs?limit=${limit}&offset=${offset}`),
  searchLogs: (params) => request("/audit/logs/search", { method: "POST", body: JSON.stringify(params) }),
  verifyIntegrity: () => request("/audit/logs/verify"),
};

export const registryService = {
  listAgents: (params = {}) => {
    const query = new URLSearchParams(params).toString();
    return request(`/agents${query ? "?" + query : ""}`);
  },
  getAgent: (id) => request(`/agents/${id}`),
  createAgent: (data) => request("/agents", { method: "POST", body: JSON.stringify(data) }),
  updateAgent: (id, data) => request(`/agents/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
  deleteAgent: (id) => request(`/agents/${id}`, { method: "DELETE" }),
  addPermission: (id, data) => request(`/agents/${id}/permissions`, { method: "POST", body: JSON.stringify(data) }),
  listPermissions: (id) => request(`/agents/${id}/permissions`),
  revokePermission: (agentId, permId) =>
    request(`/agents/${agentId}/permissions/${permId}`, { method: "DELETE" }),
};

export const riskService = {
  getSummary: () => request("/risk/summary"),
  listAgents: () => request("/agents"),
  getTimeline: () => request("/risk/timeline"),
  getTopThreats: () => request("/risk/top-threats"),
  getInsights: () => request("/insights/recent"),
};

export const forensicsService = {
  replayAgent: (id) => request(`/forensics/replay/${id}`),
  getInvestigation: (id) => request(`/forensics/investigation/${id}`),
  listInvestigations: () => request("/forensics/investigation"),
};

export const billingService = {
  getSummary: () => request("/billing/summary"),
  getInvoices: () => request("/billing/invoices"),
};

export const playgroundService = {
  execute: (agentId, tool, payload, options = {}) =>
    request("/execute", {
      method: "POST",
      body: JSON.stringify({ tool, payload }),
      ...options,
      headers: {
        "X-Agent-ID": agentId,
        "X-ACP-Tool":  tool,
        ...(options.headers || {}),
      },
    }),
};

export const decisionService = {
  getHistory: (limit = 20) => request(`/decision/history?limit=${limit}`),
  getSummary: () => request("/decision/summary"),
};

export const dashboardService = {
  getState: () => request('/dashboard/state'),
  getSystemHealth: () => request('/system/health'),
}

export const insightService = {
  getRecent: (limit = 20) => request(`/insights/recent?limit=${limit}`),
};

export const policyService = {
  simulate: (payload) => request("/policy/simulate", {
    method: "POST",
    body: JSON.stringify(payload),
  }),
};

export const socService = {
  getTimeline: (limit = 60) => request(`/audit/logs/soc-timeline?limit=${limit}`),
};

export const incidentService = {
  getSummary: () => request("/incidents/summary"),
  list: (params = {}) => {
    const q = new URLSearchParams();
    if (params.status)   q.set("status",   params.status);
    if (params.severity) q.set("severity", params.severity);
    if (params.limit)    q.set("limit",    params.limit);
    if (params.offset)   q.set("offset",   params.offset);
    const qs = q.toString();
    return request(`/incidents${qs ? `?${qs}` : ""}`);
  },
  get: (id) => request(`/incidents/${id}`),
  update: (id, payload) => request(`/incidents/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  }),
  addAction: (id, payload) => request(`/incidents/${id}/actions`, {
    method: "POST",
    body: JSON.stringify(payload),
  }),
};

export const autoResponseService = {
  listRules: async () => {
    const res = await request('/auto-response/rules')
    if (res?.data) res.data = parseRuleList(res.data)
    return res
  },
  getRule: async (id) => {
    const res = await request(`/auto-response/rules/${id}`)
    if (res?.data) res.data = parseRule(res.data)
    return res
  },
  createRule: async (data) => {
    const res = await request('/auto-response/rules', { method: 'POST', body: JSON.stringify(data) })
    if (res?.data) res.data = parseRule(res.data)
    return res
  },
  updateRule: async (id, data) => {
    const res = await request(`/auto-response/rules/${id}`, { method: 'PATCH', body: JSON.stringify(data) })
    if (res?.data) res.data = parseRule(res.data)
    return res
  },
  deleteRule:     (id)           => request(`/auto-response/rules/${id}`, { method: 'DELETE' }),
  getStatus:      ()             => request('/auto-response/toggle'),
  toggle:         (enabled)      => request('/auto-response/toggle', { method: 'POST', body: JSON.stringify({ enabled }) }),
  simulate:       (data)         => request('/auto-response/simulate', { method: 'POST', body: JSON.stringify(data) }),
  getHistory:     (id)           => request(`/auto-response/rules/${id}/history`),
  rollback:       (id, version)  => request(`/auto-response/rules/${id}/rollback/${version}`, { method: 'POST' }),
  feedback:       (id, data)     => request(`/auto-response/rules/${id}/feedback`, { method: 'POST', body: JSON.stringify(data) }),
  getMetrics:     ()             => request('/auto-response/metrics'),
  listPending:    ()             => request('/auto-response/pending'),
  approvePending: (key, data)    => request(`/auto-response/pending/${key}/approve`, { method: 'POST', body: JSON.stringify(data) }),
  replay:         (data)         => request('/auto-response/replay', { method: 'POST', body: JSON.stringify(data) }),
  getLatency:     ()             => request('/auto-response/latency'),
};

export const killSwitchService = {
  getStatus: (tenantId) => request(`/decision/kill-switch/${tenantId}`),
  triggerKill: (tenantId) =>
    request(`/decision/kill-switch/${tenantId}`, {
      method: "POST",
      body: JSON.stringify({ action: "engage" }),
    }),
  toggle: (tenantId, action) =>
    request(`/decision/kill-switch/${tenantId}`, {
      method: action === "engage" ? "POST" : "DELETE",
      body: action === "engage" ? JSON.stringify({ action: "engage" }) : undefined,
    }),
  resetKill: (tenantId) => request(`/decision/kill-switch/${tenantId}`, { method: "DELETE" }),
};
