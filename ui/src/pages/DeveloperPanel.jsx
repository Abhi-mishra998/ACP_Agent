import React, { useState, useEffect, useRef } from 'react'
import { Code2, Key, Copy, Check, Plus, Trash2, Eye, EyeOff, Terminal, Book, RefreshCw, AlertTriangle } from 'lucide-react'
import Card from '../components/Common/Card'
import SkeletonLoader from '../components/Common/SkeletonLoader'
import Modal from '../components/Common/Modal'
import Button from '../components/Common/Button'
import { api } from '../services/api'
import { useAuth } from '../hooks/useAuth'

const GW = typeof window !== 'undefined'
  ? (import.meta.env.VITE_GATEWAY_URL || window.location.origin)
  : 'http://localhost:8000'

/* ── Copy button ────────────────────────────────────────────────────────────── */
function CopyButton({ text, className = '' }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={copied ? 'Copied' : 'Copy to clipboard'}
      className={`p-1.5 rounded transition-colors ${copied ? 'text-green-400' : 'text-neutral-500 hover:text-white'} ${className}`}
    >
      {copied ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
    </button>
  )
}

/* ── Code block ─────────────────────────────────────────────────────────────── */
function CodeBlock({ code, language = 'bash' }) {
  return (
    <div className="relative rounded-xl bg-black/40 border border-white/5 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/5">
        <span className="label-standard">{language}</span>
        <CopyButton text={code} />
      </div>
      <pre className="px-4 py-3 text-xs font-mono text-green-400 overflow-x-auto whitespace-pre-wrap leading-relaxed">
        {code}
      </pre>
    </div>
  )
}

/* ── Constants ──────────────────────────────────────────────────────────────── */
const TABS = ['API Keys', 'cURL Examples', 'SDK Guide', 'Endpoint Reference']

const ENDPOINTS = [
  { method: 'POST',   path: '/auth/token',                  auth: false, description: 'User login — returns JWT' },
  { method: 'POST',   path: '/auth/refresh',                auth: true,  description: 'Refresh access token' },
  { method: 'POST',   path: '/auth/logout',                 auth: true,  description: 'Invalidate session' },
  { method: 'GET',    path: '/agents',                      auth: true,  description: 'List all agents' },
  { method: 'POST',   path: '/agents',                      auth: true,  description: 'Register new agent' },
  { method: 'GET',    path: '/agents/:id',                  auth: true,  description: 'Get agent details' },
  { method: 'PATCH',  path: '/agents/:id',                  auth: true,  description: 'Update agent' },
  { method: 'DELETE', path: '/agents/:id',                  auth: true,  description: 'Delete agent' },
  { method: 'POST',   path: '/agents/:id/permissions',      auth: true,  description: 'Grant tool permission' },
  { method: 'POST',   path: '/execute',                     auth: true,  description: 'Execute tool through decision engine' },
  { method: 'GET',    path: '/audit/logs',                  auth: true,  description: 'List audit log entries' },
  { method: 'POST',   path: '/audit/logs/search',           auth: true,  description: 'Search/filter audit logs' },
  { method: 'GET',    path: '/audit/logs/verify',           auth: true,  description: 'Verify cryptographic chain integrity' },
  { method: 'GET',    path: '/risk/summary',                auth: true,  description: 'Risk summary metrics' },
  { method: 'GET',    path: '/risk/timeline',               auth: true,  description: '7-day risk timeline' },
  { method: 'GET',    path: '/decision/history',            auth: true,  description: 'Recent decision history' },
  { method: 'GET',    path: '/decision/kill-switch/:tid',   auth: true,  description: 'Kill switch status' },
  { method: 'POST',   path: '/decision/kill-switch/:tid',   auth: true,  description: 'Engage kill switch (ADMIN/SECURITY)' },
  { method: 'DELETE', path: '/decision/kill-switch/:tid',   auth: true,  description: 'Disengage kill switch' },
  { method: 'GET',    path: '/forensics/replay/:agentId',   auth: true,  description: 'Forensic replay for agent' },
  { method: 'GET',    path: '/forensics/investigation',     auth: true,  description: 'List high-risk investigations' },
  { method: 'GET',    path: '/billing/summary',             auth: true,  description: 'Billing and ROI summary' },
  { method: 'GET',    path: '/api-keys',                    auth: true,  description: 'List API keys' },
  { method: 'POST',   path: '/api-keys',                    auth: true,  description: 'Create API key' },
  { method: 'DELETE', path: '/api-keys/:id',                auth: true,  description: 'Revoke API key' },
]

const METHOD_COLORS = {
  GET:    'text-green-400  bg-green-500/10  border-green-500/20',
  POST:   'text-blue-400   bg-blue-500/10   border-blue-500/20',
  PATCH:  'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  DELETE: 'text-red-400    bg-red-500/10    border-red-500/20',
}

/* ── Component ──────────────────────────────────────────────────────────────── */
export default function DeveloperPanel() {
  const { tenant_id } = useAuth()
  const mounted = useRef(true)
  const [tab,         setTab]         = useState(0)
  const [apiKeys,     setApiKeys]     = useState([])
  const [keysLoading, setKeysLoading] = useState(true)
  const [creating,    setCreating]    = useState(false)
  const [newKeyName,  setNewKeyName]  = useState('')
  const [showCreate,  setShowCreate]  = useState(false)
  const [visibleKeys, setVisibleKeys] = useState({})
  const [revoking,    setRevoking]    = useState({})
  const [revokeTarget, setRevokeTarget] = useState(null)

  const tid              = tenant_id || 'YOUR_TENANT_ID'
  // Token is stored in httpOnly cookie — not accessible from JS (XSS protection)
  const tokenPlaceholder = '<httpOnly cookie — not exposed to JS>'

  const loadKeys = () => {
    setKeysLoading(true)
    api.getApiKeys()
      .then(res => { if (mounted.current) setApiKeys(res?.data || res || []) })
      .catch(() => { if (mounted.current) setApiKeys([]) })
      .finally(() => { if (mounted.current) setKeysLoading(false) })
  }

  useEffect(() => {
    mounted.current = true
    loadKeys()
    return () => { mounted.current = false }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const createKey = async () => {
    if (!newKeyName.trim()) return
    setCreating(true)
    try {
      await api.createApiKey({ name: newKeyName.trim() })
      setNewKeyName('')
      setShowCreate(false)
      loadKeys()
    } catch {}
    finally { if (mounted.current) setCreating(false) }
  }

  const revokeKey = async () => {
    if (!revokeTarget) return
    setRevoking(r => ({ ...r, [revokeTarget.id]: true }))
    try { await api.revokeApiKey(revokeTarget.id); loadKeys() }
    catch {}
    finally {
      if (mounted.current) setRevoking(r => ({ ...r, [revokeTarget.id]: false }))
      setRevokeTarget(null)
    }
  }

  const CURL_EXAMPLES = [
    {
      title: 'Login',
      code: `curl -X POST ${GW}/auth/token \\
  -H "Content-Type: application/json" \\
  -d '{"email":"admin@example.com","password":"your_password"}'`,
    },
    {
      title: 'Execute Tool',
      code: `curl -X POST ${GW}/execute \\
  -H "Authorization: Bearer ${tokenPlaceholder}" \\
  -H "X-Tenant-ID: ${tid}" \\
  -H "X-Agent-ID: YOUR_AGENT_ID" \\
  -H "Content-Type: application/json" \\
  -d '{"tool":"data.query","payload":{"query":"SELECT 1"}}'`,
    },
    {
      title: 'List Agents',
      code: `curl ${GW}/agents \\
  -H "Authorization: Bearer ${tokenPlaceholder}" \\
  -H "X-Tenant-ID: ${tid}"`,
    },
    {
      title: 'Search Audit Logs',
      code: `curl -X POST ${GW}/audit/logs/search \\
  -H "Authorization: Bearer ${tokenPlaceholder}" \\
  -H "X-Tenant-ID: ${tid}" \\
  -H "Content-Type: application/json" \\
  -d '{"decision":"deny","limit":50}'`,
    },
    {
      title: 'Get Risk Summary',
      code: `curl ${GW}/risk/summary \\
  -H "Authorization: Bearer ${tokenPlaceholder}" \\
  -H "X-Tenant-ID: ${tid}"`,
    },
  ]

  const SDK_PYTHON = `from acp_sdk import ACPClient
import asyncio

async def main():
    async with ACPClient(
        agent_id="YOUR_AGENT_ID",
        secret="YOUR_AGENT_SECRET",
        gateway_url="${GW}",
        identity_url="${GW}",
    ) as client:
        await client.authenticate(tenant_id="${tid}")
        result = await client.execute_tool(
            tool_name="data.query",
            payload={"query": "SELECT 1"},
        )
        print(f"Decision: {result['action']}, Risk: {result['risk']}")

asyncio.run(main())`

  const SDK_JS = `import { ACPClient } from '@acp/sdk';

const client = new ACPClient({
  agentId: 'YOUR_AGENT_ID',
  secret: 'YOUR_AGENT_SECRET',
  gatewayUrl: '${GW}',
});

await client.authenticate('${tid}');
const result = await client.executeTool('data.query', { query: 'SELECT 1' });
console.log(\`Decision: \${result.action}, Risk: \${result.risk}\`);`

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Developer Panel</h1>
          <p className="text-xs text-neutral-500 mt-0.5">API keys, integration examples, and endpoint reference</p>
        </div>
      </div>

      {/* ── Tabs ── */}
      <div
        className="flex gap-1 p-1 bg-[#080808] border border-white/5 rounded-xl w-fit"
        role="tablist"
        aria-label="Developer panel sections"
      >
        {TABS.map((t, i) => (
          <button
            key={i}
            type="button"
            role="tab"
            aria-selected={tab === i}
            onClick={() => setTab(i)}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-colors ${
              tab === i ? 'bg-white text-black' : 'text-neutral-500 hover:text-white'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* ── API Keys ── */}
      {tab === 0 && (
        <Card title="API Keys" icon={Key}>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <p className="text-xs text-neutral-500">API keys allow programmatic access to the gateway.</p>
              <Button size="sm" onClick={() => setShowCreate(!showCreate)}>
                <Plus size={13} aria-hidden="true" /> New Key
              </Button>
            </div>

            {showCreate && (
              <div className="flex items-center gap-3 p-4 rounded-xl bg-white/[0.02] border border-white/5">
                <input
                  type="text"
                  value={newKeyName}
                  onChange={e => setNewKeyName(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && createKey()}
                  placeholder="Key name (e.g. prod-service)"
                  aria-label="New API key name"
                  className="input-standard flex-1 h-9 font-mono"
                />
                <Button
                  size="sm"
                  loading={creating}
                  disabled={creating || !newKeyName.trim()}
                  onClick={createKey}
                >
                  {creating ? 'Creating…' : 'Create'}
                </Button>
              </div>
            )}

            {keysLoading ? (
              <SkeletonLoader variant="row" count={3} />
            ) : apiKeys.length === 0 ? (
              <div className="flex items-center justify-center h-20 text-neutral-600 text-xs">No API keys yet</div>
            ) : (
              <div className="space-y-2">
                {apiKeys.map(k => (
                  <div key={k.id} className="flex items-center gap-4 p-3 rounded-xl bg-white/[0.02] border border-white/5">
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold text-white">{k.name}</p>
                      <p className="text-xs text-neutral-600 font-mono mt-0.5">
                        {visibleKeys[k.id] ? (k.key || k.id) : '••••••••••••••••••••••••••••••••'}
                      </p>
                    </div>
                    <span className={`text-xs font-bold ${k.status === 'active' ? 'text-green-400' : 'text-neutral-500'}`}>
                      {k.status || 'active'}
                    </span>
                    <p className="text-xs text-neutral-600 hidden sm:block">
                      {k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}
                    </p>
                    <div className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => setVisibleKeys(v => ({ ...v, [k.id]: !v[k.id] }))}
                        aria-label={visibleKeys[k.id] ? 'Hide key' : 'Show key'}
                        className="p-1.5 text-neutral-500 hover:text-white transition-colors"
                      >
                        {visibleKeys[k.id] ? <EyeOff size={13} aria-hidden="true" /> : <Eye size={13} aria-hidden="true" />}
                      </button>
                      <CopyButton text={k.key || k.id} />
                      <button
                        type="button"
                        onClick={() => setRevokeTarget({ id: k.id, name: k.name })}
                        disabled={revoking[k.id]}
                        aria-label={`Revoke API key ${k.name}`}
                        className="p-1.5 text-neutral-500 hover:text-red-400 transition-colors disabled:opacity-40"
                      >
                        <Trash2 size={13} aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
      )}

      {/* ── cURL Examples ── */}
      {tab === 1 && (
        <div className="space-y-5">
          {CURL_EXAMPLES.map((ex, i) => (
            <div key={i}>
              <p className="text-xs font-bold text-neutral-400 mb-2 uppercase tracking-widest">{ex.title}</p>
              <CodeBlock code={ex.code} language="bash" />
            </div>
          ))}
        </div>
      )}

      {/* ── SDK Guide ── */}
      {tab === 2 && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl bg-blue-500/5 border border-blue-500/10 text-xs text-blue-300">
            The ACP SDK wraps the gateway API with automatic authentication, idempotency keys, and typed error handling.
          </div>
          <div>
            <p className="text-xs font-bold text-neutral-400 mb-2 uppercase tracking-widest">Python SDK</p>
            <CodeBlock code={SDK_PYTHON} language="python" />
          </div>
          <div>
            <p className="text-xs font-bold text-neutral-400 mb-2 uppercase tracking-widest">JavaScript SDK</p>
            <CodeBlock code={SDK_JS} language="javascript" />
          </div>
          <Card title="Required Headers">
            <div className="space-y-0 text-xs font-mono">
              {[
                ['Authorization',  'Bearer <JWT>',                        'Required for all authenticated endpoints'],
                ['X-Tenant-ID',    '<uuid>',                              'Tenant isolation — must match JWT claim'],
                ['X-Agent-ID',     '<agent-uuid or "dashboard-agent">',   'Agent context for policy evaluation'],
                ['X-Request-ID',   '<uuid>',                              'Distributed tracing (auto-generated by SDK)'],
                ['Content-Type',   'application/json',                    'Required for POST/PATCH requests'],
              ].map(([name, val, desc]) => (
                <div key={name} className="flex gap-4 py-2.5 border-b border-white/[0.04] last:border-0">
                  <span className="text-white w-32 shrink-0">{name}</span>
                  <span className="text-green-400 flex-1">{val}</span>
                  <span className="text-neutral-600 hidden md:block">{desc}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {/* ── Endpoint Reference ── */}
      {tab === 3 && (
        <Card title="API Endpoint Reference" icon={Book}>
          <div className="table-scroll">
            <table className="table-base min-w-[600px]" role="table">
              <thead>
                <tr>
                  {['Method', 'Path', 'Auth', 'Description'].map(h => (
                    <th key={h} className="table-th first:pl-5">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ENDPOINTS.map((ep, i) => (
                  <tr key={i} className="table-row">
                    <td className="table-td first:pl-5">
                      <span className={`status-badge ${METHOD_COLORS[ep.method] ?? 'text-neutral-400 bg-white/5 border-white/10'}`}>
                        {ep.method}
                      </span>
                    </td>
                    <td className="table-td font-mono text-white">{ep.path}</td>
                    <td className="table-td">
                      <span className={`text-xs font-bold ${ep.auth ? 'text-yellow-400' : 'text-green-400'}`}>
                        {ep.auth ? 'JWT' : 'None'}
                      </span>
                    </td>
                    <td className="table-td text-neutral-400">{ep.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ── Revoke confirmation modal ── */}
      <Modal
        isOpen={!!revokeTarget}
        title="Revoke API Key"
        onClose={() => setRevokeTarget(null)}
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setRevokeTarget(null)}>Cancel</Button>
            <Button
              variant="danger"
              size="sm"
              loading={revoking[revokeTarget?.id]}
              onClick={revokeKey}
            >
              Revoke Key
            </Button>
          </>
        }
      >
        <p className="text-sm text-neutral-300">
          Revoke API key <span className="font-bold text-white">"{revokeTarget?.name}"</span>?
        </p>
        <p className="text-xs text-neutral-500 mt-2">
          This cannot be undone. Any service using this key will lose access immediately.
        </p>
      </Modal>
    </div>
  )
}
