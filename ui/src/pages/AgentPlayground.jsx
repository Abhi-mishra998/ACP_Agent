import React, { useState, useEffect, useRef } from 'react'
import { Terminal, Play, AlertTriangle, Clock, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import Card from '../components/Common/Card'
import SkeletonLoader from '../components/Common/SkeletonLoader'
import { playgroundService } from '../services/api'
import { useAgents } from '../hooks/useAgents'

const DECISION_META = {
  allow:    { label: 'ALLOW',    bg: 'bg-green-500/10',  text: 'text-green-400',  border: 'border-green-500/20'  },
  monitor:  { label: 'MONITOR',  bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/20' },
  throttle: { label: 'THROTTLE', bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20' },
  escalate: { label: 'ESCALATE', bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/20' },
  deny:     { label: 'DENY',     bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border-red-500/20'    },
  kill:     { label: 'KILL',     bg: 'bg-red-900/20',    text: 'text-red-300',    border: 'border-red-700/30'    },
}

const SIGNAL_COLORS = {
  inference:   '#ef4444',
  behavior:    '#f97316',
  anomaly:     '#eab308',
  cost:        '#3b82f6',
  cross_agent: '#8b5cf6',
}

function SignalBar({ label, value, color }) {
  const pct = Math.round((value || 0) * 100)
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-neutral-500 w-24 capitalize">{label.replace('_', ' ')}</span>
      <div className="flex-1 h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, background: color }}
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
        />
      </div>
      <span className="text-xs font-mono text-neutral-400 w-10 text-right">{(value || 0).toFixed(2)}</span>
    </div>
  )
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })}
      aria-label="Copy to clipboard"
      className="p-1.5 rounded text-neutral-500 hover:text-white hover:bg-white/[0.05] transition-colors"
    >
      {copied ? <Check size={12} className="text-green-400" aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
    </button>
  )
}

const DEFAULT_PAYLOAD = JSON.stringify({ query: 'SELECT 1' }, null, 2)

export default function AgentPlayground() {
  const { agents, selectedAgentId, setSelectedAgentId, agentsLoading } = useAgents()
  const mounted = useRef(true)

  // Local alias — playground can override selection without affecting global context
  const [localAgentId, setLocalAgentId] = useState('')
  const [tool,          setTool]          = useState('data.query')
  const [payload,       setPayload]       = useState(DEFAULT_PAYLOAD)
  const [payloadError,  setPayloadError]  = useState(null)
  const [executing,     setExecuting]     = useState(false)
  const [result,        setResult]        = useState(null)
  const [execError,     setExecError]     = useState(null)
  const [rawOpen,       setRawOpen]       = useState(false)
  const [history,       setHistory]       = useState([])

  // Sync local selection with global context selection
  useEffect(() => {
    if (selectedAgentId && !localAgentId) {
      setLocalAgentId(selectedAgentId)
    }
  }, [selectedAgentId]) // eslint-disable-line react-hooks/exhaustive-deps

  const selectedAgent = localAgentId

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  const validatePayload = (val) => {
    try { JSON.parse(val); setPayloadError(null); return true }
    catch (e) { setPayloadError(e.message); return false }
  }

  const execute = async () => {
    if (!selectedAgent) { setExecError('Select an agent'); return }
    if (!tool.trim())   { setExecError('Enter a tool name'); return }
    if (!validatePayload(payload)) return

    setExecuting(true)
    setExecError(null)
    setResult(null)

    const startMs = Date.now()
    console.info('EXECUTE_REQUEST:', { agent_id: selectedAgent, tool: tool.trim() })
    try {
      const data = await playgroundService.execute(selectedAgent, tool.trim(), JSON.parse(payload))
      const latency = Date.now() - startMs

      if (!mounted.current) return

      console.info('EXECUTE_RESPONSE:', { action: data?.action, risk: data?.risk, request_id: data?.request_id })

      const decision = data?.action || data?.decision || 'allow'
      setHistory(prev => [{
        timestamp: new Date().toLocaleTimeString(),
        agent: selectedAgent, tool: tool.trim(), decision,
        risk: data?.risk ?? null, latency, status: 200,
      }, ...prev].slice(0, 10))

      setResult({ ...data, _latency: latency, _status: 200 })
    } catch (err) {
      if (!mounted.current) return
      console.error('EXECUTE_FAILED:', err.message)
      const latency = Date.now() - startMs
      setHistory(prev => [{
        timestamp: new Date().toLocaleTimeString(),
        agent: selectedAgent, tool: tool.trim(), decision: 'deny',
        risk: null, latency, status: 403,
      }, ...prev].slice(0, 10))
      setExecError(err.message)
    } finally {
      if (mounted.current) setExecuting(false)
    }
  }

  const agentName = (id) => agents.find((a) => a.id === id)?.name || id?.slice(0, 8) || '—'

  const decision = result?.action?.toLowerCase() || result?.decision?.toLowerCase()
  const decMeta  = DECISION_META[decision] || DECISION_META.monitor

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Agent Playground</h1>
          <p className="text-xs text-neutral-500 mt-0.5">Execute requests against the decision engine and inspect policy results</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* ── Input panel ── */}
        <div className="lg:col-span-2 space-y-4">
          <Card title="Request Config" icon={Terminal}>
            <div className="space-y-5">
              {/* Agent selector */}
              <div className="space-y-1.5">
                <label htmlFor="pg-agent" className="label-standard">Agent</label>
                {agentsLoading ? (
                  <SkeletonLoader variant="card" className="h-9" />
                ) : (
                  <select
                    id="pg-agent"
                    value={localAgentId}
                    onChange={(e) => {
                      setLocalAgentId(e.target.value)
                      setSelectedAgentId(e.target.value)
                      console.info('PLAYGROUND_AGENT_SELECTED:', e.target.value)
                    }}
                    className="input-standard h-9"
                  >
                    <option value="">— select agent —</option>
                    {agents.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} · {(a.status || 'unknown').toLowerCase()}
                      </option>
                    ))}
                  </select>
                )}
                {agents.length === 0 && !agentsLoading && (
                  <p className="text-xs text-red-400">No agents registered. Create an agent first.</p>
                )}
              </div>

              {/* Tool name */}
              <div className="space-y-1.5">
                <label htmlFor="pg-tool" className="label-standard">Tool Name</label>
                <input
                  id="pg-tool"
                  type="text"
                  value={tool}
                  onChange={e => setTool(e.target.value)}
                  placeholder="e.g. data.query, restart_server"
                  className="input-standard h-9 font-mono"
                />
              </div>

              {/* Payload */}
              <div className="space-y-1.5">
                <label htmlFor="pg-payload" className="label-standard">Payload (JSON)</label>
                <textarea
                  id="pg-payload"
                  value={payload}
                  onChange={e => { setPayload(e.target.value); validatePayload(e.target.value) }}
                  rows={6}
                  spellCheck={false}
                  aria-invalid={!!payloadError}
                  aria-describedby={payloadError ? 'pg-payload-error' : undefined}
                  className={`input-standard py-2 font-mono resize-none text-xs ${payloadError ? 'border-red-500/40 focus:border-red-500/60' : ''}`}
                />
                {payloadError && (
                  <p id="pg-payload-error" className="text-xs text-red-400">Invalid JSON: {payloadError}</p>
                )}
              </div>

              {execError && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/5 border border-red-500/10 text-xs text-red-400" role="alert">
                  <AlertTriangle size={13} aria-hidden="true" /> {execError}
                </div>
              )}

              <button
                type="button"
                onClick={execute}
                disabled={executing || !!payloadError}
                aria-busy={executing}
                className="w-full h-10 rounded-lg bg-white text-black text-xs font-bold uppercase tracking-wide hover:bg-neutral-200 transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
              >
                {executing ? (
                  <><div className="w-3.5 h-3.5 border-2 border-black/30 border-t-black rounded-full animate-spin" aria-hidden="true" /> Executing…</>
                ) : (
                  <><Play size={13} aria-hidden="true" /> Execute</>
                )}
              </button>
            </div>
          </Card>
        </div>

        {/* ── Results panel ── */}
        <div className="lg:col-span-3 space-y-4">
          {result ? (
            <>
              {/* Decision verdict */}
              <div className={`p-5 rounded-xl border ${decMeta.bg} ${decMeta.border} space-y-4`}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="label-standard mb-1">Decision</p>
                    <p className={`text-3xl font-black tracking-tight ${decMeta.text}`}>{decMeta.label}</p>
                  </div>
                  <div className="text-right">
                    <p className="label-standard mb-1">Risk Score</p>
                    <p className={`text-2xl font-black font-mono ${
                      (result.risk || 0) >= 0.7 ? 'text-red-400' :
                      (result.risk || 0) >= 0.4 ? 'text-yellow-400' : 'text-green-400'
                    }`}>
                      {result.risk != null ? result.risk.toFixed(3) : '—'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs text-neutral-500 font-mono pt-3 border-t border-white/5">
                  <span>Confidence: {result.confidence != null ? (result.confidence * 100).toFixed(0) + '%' : '—'}</span>
                  <span>Latency: {result._latency}ms</span>
                  <span>HTTP: {result._status}</span>
                </div>
              </div>

              {/* Decision reasons */}
              {result.reasons?.length > 0 && (
                <Card title="Decision Reasons">
                  <ul className="space-y-1.5">
                    {result.reasons.map((r, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs text-neutral-300">
                        <ChevronRight size={12} className="text-neutral-600 mt-0.5 shrink-0" aria-hidden="true" />
                        {r}
                      </li>
                    ))}
                  </ul>
                </Card>
              )}

              {/* Signal breakdown */}
              {result.signals && (
                <Card title="Risk Signal Breakdown">
                  <div className="space-y-3">
                    {Object.entries(SIGNAL_COLORS).map(([key, color]) =>
                      result.signals[key] != null && (
                        <SignalBar key={key} label={key} value={result.signals[key]} color={color} />
                      )
                    )}
                    {result.signals.policy_adjustment != null && (
                      <div className="pt-2 border-t border-white/5 text-xs text-neutral-600 font-mono">
                        Policy adjustment: {result.signals.policy_adjustment > 0 ? '+' : ''}{result.signals.policy_adjustment?.toFixed(3)}
                      </div>
                    )}
                  </div>
                </Card>
              )}

              {/* Raw JSON */}
              <div className="rounded-xl border border-white/5 overflow-hidden">
                <button
                  type="button"
                  onClick={() => setRawOpen(!rawOpen)}
                  aria-expanded={rawOpen}
                  className="w-full flex items-center justify-between px-4 py-3 text-xs font-bold text-neutral-500 hover:text-white hover:bg-white/[0.02] transition-colors uppercase tracking-widest"
                >
                  Raw Response
                  {rawOpen ? <ChevronDown size={13} aria-hidden="true" /> : <ChevronRight size={13} aria-hidden="true" />}
                </button>
                {rawOpen && (
                  <div className="relative">
                    <div className="absolute top-2 right-2 z-10">
                      <CopyButton text={JSON.stringify(result, null, 2)} />
                    </div>
                    <pre className="px-4 pb-4 pt-8 text-xs text-green-400 font-mono overflow-x-auto max-h-64 bg-black/20">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-neutral-600 space-y-3 border border-white/5 rounded-xl">
              <Terminal size={28} aria-hidden="true" />
              <p className="text-sm">Configure and execute a request</p>
              <p className="text-xs">Results will appear here</p>
            </div>
          )}
        </div>
      </div>

      {/* ── Execution history ── */}
      {history.length > 0 && (
        <Card title="Execution History" icon={Clock}>
          <div className="table-scroll">
            <table className="table-base min-w-[600px]" role="table">
              <thead>
                <tr>
                  {['Time', 'Agent', 'Tool', 'Decision', 'Risk', 'Latency', 'HTTP'].map(h => (
                    <th key={h} className="table-th first:pl-5">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => {
                  const dm = DECISION_META[h.decision?.toLowerCase()] || DECISION_META.monitor
                  return (
                    <tr key={i} className="table-row">
                      <td className="table-td first:pl-5 font-mono">{h.timestamp}</td>
                      <td className="table-td font-mono text-white">{agentName(h.agent)}</td>
                      <td className="table-td text-neutral-400">{h.tool}</td>
                      <td className="table-td">
                        <span className={`status-badge ${dm.bg} ${dm.text} ${dm.border}`}>{dm.label}</span>
                      </td>
                      <td className="table-td font-mono">{h.risk != null ? h.risk.toFixed(3) : '—'}</td>
                      <td className="table-td font-mono text-neutral-500">{h.latency}ms</td>
                      <td className="table-td">
                        <span className={`text-xs font-bold ${h.status < 300 ? 'text-green-400' : 'text-red-400'}`}>
                          {h.status}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}
