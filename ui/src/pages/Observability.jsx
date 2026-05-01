import React, { useState, useEffect, useRef, useMemo } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import {
  Activity, Shield, Zap, Brain, AlertTriangle, CheckCircle,
  XCircle, TrendingUp, Users, Radio,
} from 'lucide-react'
import { auditService, decisionService, riskService } from '../services/api'
import { useAgents } from '../hooks/useAgents'
import { useAuth } from '../hooks/useAuth'
import { eventBus } from '../lib/eventBus'

// ── Action & threat style maps ─────────────────────────────────────────────────

const ACTION_STYLE = {
  allow:    { label: 'ALLOW',    color: 'text-green-400',   bg: 'bg-green-500/10',   dot: 'bg-green-500' },
  monitor:  { label: 'MONITOR',  color: 'text-blue-400',    bg: 'bg-blue-500/10',    dot: 'bg-blue-500' },
  throttle: { label: 'THROTTLE', color: 'text-yellow-400',  bg: 'bg-yellow-500/10',  dot: 'bg-yellow-500' },
  escalate: { label: 'ESCALATE', color: 'text-orange-400',  bg: 'bg-orange-500/10',  dot: 'bg-orange-500' },
  block:    { label: 'BLOCK',    color: 'text-red-400',     bg: 'bg-red-500/10',     dot: 'bg-red-500' },
  deny:     { label: 'DENY',     color: 'text-red-400',     bg: 'bg-red-500/10',     dot: 'bg-red-500' },
  kill:     { label: 'KILL',     color: 'text-red-500',     bg: 'bg-red-500/20',     dot: 'bg-red-600' },
}

const THREAT_STYLE = {
  PROMPT_INJECTION:   { color: 'text-purple-400', bg: 'bg-purple-500/10',  border: 'border-purple-500/20' },
  DATA_EXFILTRATION:  { color: 'text-red-400',    bg: 'bg-red-500/10',     border: 'border-red-500/20' },
  COST_ABUSE:         { color: 'text-yellow-400', bg: 'bg-yellow-500/10',  border: 'border-yellow-500/20' },
  COORDINATED_ATTACK: { color: 'text-red-500',    bg: 'bg-red-500/20',     border: 'border-red-500/30' },
  ANOMALOUS_BEHAVIOR: { color: 'text-orange-400', bg: 'bg-orange-500/10',  border: 'border-orange-500/20' },
  POLICY_VIOLATION:   { color: 'text-blue-400',   bg: 'bg-blue-500/10',    border: 'border-blue-500/20' },
  BENIGN_ANOMALY:     { color: 'text-neutral-400', bg: 'bg-neutral-500/10', border: 'border-neutral-500/20' },
  BENIGN:             { color: 'text-neutral-400', bg: 'bg-neutral-500/10', border: 'border-neutral-500/20' },
}

const SIGNAL_DEFS = [
  { key: 'inference_risk',   label: 'Inference',    weight: 0.35 },
  { key: 'behavior_risk',    label: 'Behavior',     weight: 0.30 },
  { key: 'anomaly_score',    label: 'Anomaly',      weight: 0.15 },
  { key: 'cost_risk',        label: 'Cost',         weight: 0.10 },
  { key: 'cross_agent_risk', label: 'Cross-Agent',  weight: 0.10 },
]

const STATUS_STYLE = {
  active:      { color: 'text-green-400',   dot: 'bg-green-500',   label: 'ACTIVE' },
  quarantined: { color: 'text-red-400',     dot: 'bg-red-500',     label: 'QUARAN' },
  terminated:  { color: 'text-neutral-500', dot: 'bg-neutral-500', label: 'TERM' },
  inactive:    { color: 'text-neutral-500', dot: 'bg-neutral-600', label: 'INACT' },
}

const MAX_FEED     = 50
const MAX_INSIGHTS = 20
const MAX_TIMELINE = 40

// ── Utility helpers ─────────────────────────────────────────────────────────────

function riskColor(v) {
  if (v >= 0.75) return 'text-red-400'
  if (v >= 0.50) return 'text-orange-400'
  if (v >= 0.30) return 'text-yellow-400'
  return 'text-green-400'
}

function riskBarHex(v) {
  if (v >= 0.75) return '#ef4444'
  if (v >= 0.50) return '#f97316'
  if (v >= 0.30) return '#eab308'
  return '#22c55e'
}

function fmtHHMMSS(ts) {
  if (!ts) return '—'
  const d = ts > 1e12 ? new Date(ts) : new Date(ts * 1000)
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function fmtRelative(ts) {
  if (!ts) return ''
  const ms = ts > 1e12 ? ts : ts * 1000
  const sec = Math.max(0, Math.floor((Date.now() - ms) / 1000))
  if (sec < 60) return `${sec}s ago`
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`
  return `${Math.floor(sec / 3600)}h ago`
}

// ── MetricTile ──────────────────────────────────────────────────────────────────

function MetricTile({ label, value, icon: Icon, valueClass = 'text-white', flashKey, flashSet }) {
  const [lit, setLit] = useState(false)
  const prevFlash = useRef(false)

  useEffect(() => {
    if (flashSet.has(flashKey) && !prevFlash.current) {
      setLit(true)
      prevFlash.current = true
      const t = setTimeout(() => { setLit(false); prevFlash.current = false }, 500)
      return () => clearTimeout(t)
    }
  })

  return (
    <div className={`
      bg-[var(--bg-surface)] border rounded-xl p-4 flex flex-col gap-1.5
      transition-all duration-300
      ${lit ? 'border-white/20 shadow-[0_0_12px_rgba(255,255,255,0.06)]' : 'border-[var(--border-subtle)]'}
    `}>
      <div className="flex items-center gap-1.5">
        {Icon && <Icon size={12} className="text-neutral-600 shrink-0" />}
        <span className="text-[10px] font-mono text-neutral-600 uppercase tracking-widest truncate">{label}</span>
      </div>
      <span className={`text-xl font-bold font-mono tabular-nums ${valueClass}`}>{value}</span>
    </div>
  )
}

// ── LiveDecisionFeed ────────────────────────────────────────────────────────────

function LiveDecisionFeed({ decisions, agentMap }) {
  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-xl flex flex-col h-full">
      <div className="px-4 py-3 border-b border-[var(--border-subtle)] flex items-center gap-2 shrink-0">
        <Radio size={12} className="text-green-400 animate-pulse" />
        <span className="text-xs font-semibold text-white">Live Decision Feed</span>
        <span className="ml-auto text-[10px] font-mono text-neutral-600 tabular-nums">{decisions.length}</span>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-[var(--border-subtle)] min-h-0">
        {decisions.length === 0 ? (
          <div className="p-6 text-center text-neutral-600 text-[10px] font-mono">
            Awaiting decisions…
          </div>
        ) : decisions.map((d, i) => {
          const style  = ACTION_STYLE[(d.action || '').toLowerCase()] || ACTION_STYLE.allow
          const risk   = typeof d.risk === 'number' ? d.risk : typeof d.risk_score === 'number' ? d.risk_score : 0
          const name   = agentMap[d.agent_id] || (d.agent_id ? d.agent_id.slice(0, 10) : '—')
          const reason = (d.reasons || [])[0] || d.reason || ''

          return (
            <div
              key={d.request_id || d.id || i}
              className={`px-4 py-2.5 flex items-start gap-3 transition-colors duration-300 ${
                i === 0 && d._live ? 'bg-white/[0.02]' : ''
              }`}
            >
              <div className={`mt-[5px] w-1.5 h-1.5 rounded-full shrink-0 ${style.dot}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
                  <span className="text-neutral-600 shrink-0">{fmtHHMMSS(d.ts || d.timestamp)}</span>
                  <span className="text-neutral-400 truncate max-w-[110px]">{name}</span>
                  <span className="text-neutral-500 truncate max-w-[80px]">{d.tool || '—'}</span>
                </div>
                <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                  <span className={`text-[10px] font-mono font-bold ${style.color}`}>{style.label}</span>
                  <span className={`text-[10px] font-mono ${riskColor(risk)}`}>
                    {risk.toFixed ? risk.toFixed(3) : risk}
                  </span>
                  {reason && (
                    <span className="text-[10px] text-neutral-600 truncate max-w-[180px]">{reason}</span>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── RiskSignalPanel ─────────────────────────────────────────────────────────────

function RiskSignalPanel({ signals, composite, tool, agentId }) {
  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-xl flex flex-col">
      <div className="px-4 py-3 border-b border-[var(--border-subtle)] flex items-center gap-2">
        <Zap size={12} className="text-yellow-400" />
        <span className="text-xs font-semibold text-white">Risk Signal Breakdown</span>
        {composite != null && (
          <span className={`ml-auto text-xs font-bold font-mono ${riskColor(composite)}`}>
            {composite.toFixed(3)}
          </span>
        )}
      </div>

      {(tool || agentId) && (
        <div className="px-4 pt-3 pb-0 flex gap-3 text-[10px] font-mono text-neutral-600">
          {tool && <span className="truncate">tool: {tool}</span>}
          {agentId && <span className="truncate">agent: {agentId.slice(0, 10)}</span>}
        </div>
      )}

      <div className="p-4 space-y-3">
        {SIGNAL_DEFS.map(({ key, label, weight }) => {
          const val = signals ? (signals[key] ?? 0) : 0
          const pct = Math.min(Math.round(val * 100), 100)
          return (
            <div key={key}>
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-neutral-400 w-[90px]">{label}</span>
                  <span className="text-[10px] text-neutral-700">×{weight.toFixed(2)}</span>
                </div>
                <span className={`text-[10px] font-mono font-bold tabular-nums ${riskColor(val)}`}>
                  {val.toFixed ? val.toFixed(3) : '—'}
                </span>
              </div>
              <div className="h-1.5 rounded-full bg-white/[0.04] overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700 ease-out"
                  style={{ width: `${pct}%`, backgroundColor: riskBarHex(val) }}
                />
              </div>
            </div>
          )
        })}

        {composite != null && (
          <div className="border-t border-[var(--border-subtle)] pt-3">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-mono text-neutral-300 font-semibold">Composite</span>
              <span className={`text-[10px] font-mono font-bold tabular-nums ${riskColor(composite)}`}>
                {composite.toFixed(3)}
              </span>
            </div>
            <div className="h-2 rounded-full bg-white/[0.04] overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{ width: `${Math.min(composite * 100, 100)}%`, backgroundColor: riskBarHex(composite) }}
              />
            </div>
          </div>
        )}

        {!signals && (
          <p className="text-[10px] text-neutral-600 text-center py-2 font-mono">
            Awaiting signal data…
          </p>
        )}
      </div>
    </div>
  )
}

// ── InsightStream ───────────────────────────────────────────────────────────────

function InsightStream({ insights }) {
  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-xl flex flex-col h-full">
      <div className="px-4 py-3 border-b border-[var(--border-subtle)] flex items-center gap-2 shrink-0">
        <Brain size={12} className="text-purple-400" />
        <span className="text-xs font-semibold text-white">AI Threat Insights</span>
        <span className="ml-auto text-[10px] font-mono text-neutral-600">Groq LLM</span>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-[var(--border-subtle)] min-h-0">
        {insights.length === 0 ? (
          <div className="p-6 text-center text-neutral-600 text-[10px] font-mono leading-relaxed">
            No insights yet.<br />AI analysis runs automatically on blocked events.
          </div>
        ) : insights.map((ins, i) => {
          const tStyle = THREAT_STYLE[ins.threat_classification] || THREAT_STYLE.BENIGN
          const rStyle = ACTION_STYLE[(ins.recommendation || '').toLowerCase()] || {}

          return (
            <div
              key={ins.event_id || i}
              className={`px-4 py-3 ${i === 0 && ins._live ? 'bg-white/[0.02]' : ''}`}
            >
              <div className="flex items-start gap-2 flex-wrap mb-1.5">
                <span className={`
                  text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border
                  ${tStyle.color} ${tStyle.bg} ${tStyle.border}
                `}>
                  {(ins.threat_classification || 'UNKNOWN').replace(/_/g, ' ')}
                </span>
                {ins.recommendation && (
                  <span className={`text-[10px] font-mono font-bold ${rStyle.color || 'text-neutral-400'}`}>
                    → {ins.recommendation}
                  </span>
                )}
                {ins.confidence && (
                  <span className="text-[10px] font-mono text-neutral-600">{ins.confidence}</span>
                )}
                <span className="ml-auto text-[10px] font-mono text-neutral-700 shrink-0">
                  {fmtRelative(ins.ts || ins._ts)}
                </span>
              </div>
              <p className="text-[10px] text-neutral-400 leading-relaxed line-clamp-2">
                {ins.narrative || ins.root_cause || '—'}
              </p>
              {(ins.agent_id || ins.tool) && (
                <div className="mt-1 flex gap-3 text-[10px] font-mono text-neutral-700">
                  {ins.agent_id && <span>agent: {ins.agent_id.slice(0, 10)}</span>}
                  {ins.tool && <span>tool: {ins.tool}</span>}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── AgentHealthGrid ─────────────────────────────────────────────────────────────

function AgentHealthGrid({ agents, agentRiskMap }) {
  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-xl flex flex-col">
      <div className="px-4 py-3 border-b border-[var(--border-subtle)] flex items-center gap-2">
        <Users size={12} className="text-blue-400" />
        <span className="text-xs font-semibold text-white">Agent Health</span>
        <span className="ml-auto text-[10px] font-mono text-neutral-600">{agents.length}</span>
      </div>

      <div className="overflow-y-auto max-h-[200px] divide-y divide-[var(--border-subtle)]">
        {agents.length === 0 ? (
          <div className="p-4 text-center text-neutral-600 text-[10px] font-mono">
            No agents registered
          </div>
        ) : agents.map((agent) => {
          const st      = STATUS_STYLE[(agent.status || '').toLowerCase()] || STATUS_STYLE.inactive
          const liveRisk = agentRiskMap[agent.id]
          return (
            <div key={agent.id} className="px-4 py-2 flex items-center gap-3">
              <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${st.dot}`} />
              <span className="text-[10px] font-mono text-neutral-300 truncate flex-1 min-w-0">
                {agent.name || agent.id?.slice(0, 14)}
              </span>
              <span className={`text-[10px] font-mono shrink-0 ${st.color}`}>{st.label}</span>
              {liveRisk != null && (
                <span className={`text-[10px] font-mono font-bold tabular-nums shrink-0 ${riskColor(liveRisk)}`}>
                  {liveRisk.toFixed(2)}
                </span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── RiskTimeline chart ─────────────────────────────────────────────────────────

function RiskTimeline({ data }) {
  return (
    <div className="bg-[var(--bg-surface)] border border-[var(--border-subtle)] rounded-xl">
      <div className="px-4 py-3 border-b border-[var(--border-subtle)] flex items-center gap-2">
        <TrendingUp size={12} className="text-cyan-400" />
        <span className="text-xs font-semibold text-white">Risk Score Timeline</span>
        <span className="ml-auto text-[10px] font-mono text-neutral-600">last {data.length} decisions</span>
      </div>
      <div className="p-4">
        <ResponsiveContainer width="100%" height={110}>
          <AreaChart data={data} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
            <defs>
              <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="2 4"
              stroke="rgba(255,255,255,0.04)"
              vertical={false}
            />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 9, fill: '#404040', fontFamily: 'monospace' }}
              axisLine={false}
              tickLine={false}
              interval="preserveStartEnd"
            />
            <YAxis
              domain={[0, 1]}
              tick={{ fontSize: 9, fill: '#404040', fontFamily: 'monospace' }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => v.toFixed(1)}
            />
            <Tooltip
              contentStyle={{
                background: '#0a0a0a',
                border: '1px solid #262626',
                borderRadius: 6,
                fontSize: 11,
                fontFamily: 'monospace',
                padding: '6px 10px',
              }}
              formatter={(v) => [v.toFixed(3), 'risk']}
              labelStyle={{ color: '#525252' }}
            />
            <Area
              type="monotone"
              dataKey="risk"
              stroke="#ef4444"
              strokeWidth={1.5}
              fill="url(#riskGrad)"
              dot={false}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

// ── Observability Page ─────────────────────────────────────────────────────────

export default function Observability() {
  const { agents } = useAgents()
  const { isAuthenticated } = useAuth()

  const [metrics, setMetrics]           = useState({ total: 0, allowed: 0, blocked: 0, escalated: 0, kill: 0 })
  const [flashSet, setFlashSet]         = useState(new Set())
  const [decisions, setDecisions]       = useState([])
  const [lastSignals, setLastSignals]   = useState(null)
  const [lastComposite, setLastComposite] = useState(null)
  const [lastTool, setLastTool]         = useState(null)
  const [lastAgentId, setLastAgentId]   = useState(null)
  const [insights, setInsights]         = useState([])
  const [riskTimeline, setRiskTimeline] = useState([])
  const [agentRiskMap, setAgentRiskMap] = useState({})
  const [lastEventTime, setLastEventTime] = useState(null)
  const tickRef = useRef(0)

  const agentMap = useMemo(() => {
    const m = {}
    agents.forEach((a) => { m[a.id] = a.name || a.id?.slice(0, 10) })
    return m
  }, [agents])

  // ── Initial data load + 30-second polling ─────────────────────────────────
  useEffect(() => {
    if (!isAuthenticated) return

    const loadData = () => {
      auditService.getSummary().then((res) => {
        const d = res?.data || res || {}
        setMetrics({
          total:     d.total_calls        || 0,
          allowed:   d.allowed_requests   || 0,
          blocked:   d.threats_blocked    || 0,
          escalated: 0,
          kill:      0,
        })
      }).catch(() => {})

      decisionService.getHistory(50).then((res) => {
        const items = res?.data?.items || res?.items || []
        const feed = items.map((i) => ({
          ...i,
          _live: false,
          ts: i.timestamp,
          action: i.decision,
          risk: i.risk_score || 0,
        }))
        setDecisions(feed)

        const timeline = [...feed].reverse().slice(-MAX_TIMELINE).map((item, idx) => ({
          label: fmtHHMMSS(item.ts || item.timestamp),
          risk:  item.risk || 0,
          action: item.action,
          idx,
        }))
        setRiskTimeline(timeline)
      }).catch(() => {})

      riskService.getInsights().then((res) => {
        const raw  = res?.data
        const list = Array.isArray(raw) ? raw : Array.isArray(raw?.insights) ? raw.insights : Array.isArray(res) ? res : []
        setInsights(list.map((i) => ({ ...i, _ts: Date.now(), _live: false })))
      }).catch(() => {})
    }

    loadData()
    const interval = setInterval(loadData, 30_000)
    return () => clearInterval(interval)
  }, [isAuthenticated])

  // ── SSE: tool_executed (via eventBus from AgentContext) ───────────────────
  useEffect(() => {
    const handler = (d) => {
      if (!d) return

      setLastEventTime(Date.now())

      const action = (d.action || '').toLowerCase()

      const keys = new Set(['total'])
      if (action === 'allow')                           keys.add('allowed')
      else if (action === 'block' || action === 'deny') keys.add('blocked')
      else if (action === 'escalate')                   keys.add('escalated')
      else if (action === 'kill')                       keys.add('kill')
      setFlashSet(keys)
      const tid = ++tickRef.current
      setTimeout(() => setFlashSet((prev) => {
        if (tickRef.current !== tid) return prev
        return new Set()
      }), 550)

      setMetrics((prev) => ({
        total:     prev.total + 1,
        allowed:   prev.allowed   + (action === 'allow' ? 1 : 0),
        blocked:   prev.blocked   + (['block', 'deny'].includes(action) ? 1 : 0),
        escalated: prev.escalated + (action === 'escalate' ? 1 : 0),
        kill:      prev.kill      + (action === 'kill' ? 1 : 0),
      }))

      const newEntry = {
        request_id: d.request_id,
        agent_id:   d.agent_id,
        tool:       d.tool,
        action:     d.action,
        risk:       d.risk || 0,
        reasons:    d.reasons || [],
        ts:         d.ts ? d.ts * 1000 : Date.now(),
        _live:      true,
      }
      setDecisions((prev) => [newEntry, ...prev.slice(0, MAX_FEED - 1)])

      if (d.signals && Object.keys(d.signals).length > 0) {
        setLastSignals(d.signals)
        setLastComposite(d.risk || 0)
        setLastTool(d.tool || null)
        setLastAgentId(d.agent_id || null)
      }

      if (d.agent_id && d.risk != null) {
        setAgentRiskMap((prev) => ({ ...prev, [d.agent_id]: d.risk }))
      }

      setRiskTimeline((prev) => {
        const entry = {
          label:  fmtHHMMSS(Date.now()),
          risk:   d.risk || 0,
          action: d.action,
        }
        return [...prev.slice(-(MAX_TIMELINE - 1)), entry]
      })
    }

    return eventBus.on('tool_executed', handler)
  }, [])

  // ── SSE: insight_generated (via eventBus from AgentContext) ───────────────
  useEffect(() => {
    return eventBus.on('insight_generated', (d) => {
      if (!d) return
      setInsights((prev) => [{ ...d, _ts: Date.now(), _live: true }, ...prev.slice(0, MAX_INSIGHTS - 1)])
    })
  }, [])

  // ── Derived ────────────────────────────────────────────────────────────────
  const avgRisk = riskTimeline.length > 0
    ? (riskTimeline.reduce((s, r) => s + r.risk, 0) / riskTimeline.length)
    : null

  const secondsAgo = lastEventTime
    ? Math.max(0, Math.floor((Date.now() - lastEventTime) / 1000))
    : null

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col gap-4">

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-sm font-bold text-white tracking-tight">Real-Time Observability</h1>
          <p className="text-[10px] text-neutral-500 mt-0.5 font-mono">
            Live decisions · risk signals · AI threat intelligence
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {secondsAgo != null && (
            <span className="text-[10px] font-mono text-neutral-600">
              last event {secondsAgo < 60 ? `${secondsAgo}s ago` : `${Math.floor(secondsAgo / 60)}m ago`}
            </span>
          )}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/10 border border-green-500/20">
            <div className={`w-1.5 h-1.5 rounded-full ${isAuthenticated ? 'bg-green-500 animate-pulse' : 'bg-neutral-500'}`} />
            <span className={`text-[10px] font-mono font-bold ${isAuthenticated ? 'text-green-400' : 'text-neutral-500'}`}>
              {isAuthenticated ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      {/* ── Metric tiles ── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
        <MetricTile
          label="Total Decisions" icon={Activity}
          value={metrics.total.toLocaleString()}
          flashKey="total" flashSet={flashSet}
        />
        <MetricTile
          label="Allowed" icon={CheckCircle}
          value={metrics.allowed.toLocaleString()}
          valueClass="text-green-400"
          flashKey="allowed" flashSet={flashSet}
        />
        <MetricTile
          label="Blocked" icon={XCircle}
          value={metrics.blocked.toLocaleString()}
          valueClass="text-red-400"
          flashKey="blocked" flashSet={flashSet}
        />
        <MetricTile
          label="Escalated" icon={AlertTriangle}
          value={metrics.escalated.toLocaleString()}
          valueClass="text-orange-400"
          flashKey="escalated" flashSet={flashSet}
        />
        <MetricTile
          label="Kill Events" icon={Shield}
          value={metrics.kill.toLocaleString()}
          valueClass="text-red-500"
          flashKey="kill" flashSet={flashSet}
        />
        <MetricTile
          label="Avg Risk" icon={TrendingUp}
          value={avgRisk != null ? avgRisk.toFixed(3) : '—'}
          valueClass={avgRisk != null ? riskColor(avgRisk) : 'text-neutral-500'}
          flashKey="avg" flashSet={flashSet}
        />
      </div>

      {/* ── Row 2: Decision feed + Signal breakdown ── */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        <div className="xl:col-span-3" style={{ minHeight: 320, maxHeight: 360 }}>
          <LiveDecisionFeed decisions={decisions} agentMap={agentMap} />
        </div>
        <div className="xl:col-span-2">
          <RiskSignalPanel
            signals={lastSignals}
            composite={lastComposite}
            tool={lastTool}
            agentId={lastAgentId}
          />
        </div>
      </div>

      {/* ── Row 3: AI Insights + Agent Health ── */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
        <div className="xl:col-span-3" style={{ minHeight: 260, maxHeight: 320 }}>
          <InsightStream insights={insights} />
        </div>
        <div className="xl:col-span-2">
          <AgentHealthGrid agents={agents} agentRiskMap={agentRiskMap} />
        </div>
      </div>

      {/* ── Row 4: Risk timeline chart ── */}
      <RiskTimeline data={riskTimeline} />

    </div>
  )
}
