import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, AlertTriangle, TrendingUp, Brain, RefreshCw, ExternalLink } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import Card from '../components/Common/Card'
import SkeletonLoader from '../components/Common/SkeletonLoader'
import { riskService } from '../services/api'

/* ── Risk badge ────────────────────────────────────────────────────────────── */
const RISK_LEVEL_STYLES = {
  CRITICAL: 'text-red-400    bg-red-500/10    border-red-500/20',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  MEDIUM:   'text-amber-400  bg-amber-500/10  border-amber-500/20',
  MONITOR:  'text-blue-400   bg-blue-500/10   border-blue-500/20',
  LOW:      'text-green-400  bg-green-500/10  border-green-500/20',
}

function RiskBadge({ level }) {
  const l = (level ?? 'MONITOR').toUpperCase()
  return (
    <span className={`status-badge ${RISK_LEVEL_STYLES[l] ?? RISK_LEVEL_STYLES.MONITOR}`}>
      {l}
    </span>
  )
}

/* ── Confidence color ──────────────────────────────────────────────────────── */
const CONF_COLOR = { HIGH: 'text-green-400', MEDIUM: 'text-amber-400', LOW: 'text-red-400' }

/* ── Weight table ──────────────────────────────────────────────────────────── */
const WEIGHTS = [
  { label: 'Inference',   key: 'inference',   pct: 35, color: '#ef4444' },
  { label: 'Behavior',    key: 'behavior',    pct: 30, color: '#f97316' },
  { label: 'Anomaly',     key: 'anomaly',     pct: 15, color: '#eab308' },
  { label: 'Cost',        key: 'cost',        pct: 10, color: '#3b82f6' },
  { label: 'Cross-Agent', key: 'cross_agent', pct: 10, color: '#8b5cf6' },
]

/* ── Component ─────────────────────────────────────────────────────────────── */
export default function RiskEngine() {
  const navigate = useNavigate()
  const mounted  = useRef(true)

  const [summary,     setSummary]     = useState(null)
  const [timeline,    setTimeline]    = useState([])
  const [threats,     setThreats]     = useState([])
  const [insights,    setInsights]    = useState([])
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const load = async () => {
    try {
      const [sumRes, timeRes, threatRes, insightRes] = await Promise.allSettled([
        riskService.getSummary(),
        riskService.getTimeline(),
        riskService.getTopThreats(),
        riskService.getInsights(),
      ])
      if (!mounted.current) return

      if (sumRes.status     === 'fulfilled') setSummary(sumRes.value?.data || sumRes.value)
      if (timeRes.status    === 'fulfilled') setTimeline(timeRes.value?.data || timeRes.value || [])
      if (threatRes.status  === 'fulfilled') setThreats(threatRes.value?.data || threatRes.value || [])
      if (insightRes.status === 'fulfilled') {
        const ins = insightRes.value
        const list = ins?.data?.insights || (Array.isArray(ins?.data) ? ins.data : null) || ins?.insights || []
        setInsights(Array.isArray(list) ? list : [])
      }

      setLastRefresh(new Date())
      setError(null)
    } catch (err) {
      if (mounted.current) setError(err.message)
    } finally {
      if (mounted.current) setLoading(false)
    }
  }

  useEffect(() => {
    mounted.current = true
    load()
    const interval = setInterval(load, 30_000)
    return () => { mounted.current = false; clearInterval(interval) }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[...Array(3)].map((_, i) => <SkeletonLoader key={i} variant="card" />)}
      </div>
      <SkeletonLoader variant="card" />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SkeletonLoader variant="card" />
        <SkeletonLoader variant="card" />
      </div>
    </div>
  )

  const highRisk = threats.filter((t) => (t.avg_risk ?? 0) >= 0.7)

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Risk Engine</h1>
          <p className="text-xs text-neutral-500 mt-0.5">Weighted risk scoring, AI insights, and threat intelligence</p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-neutral-600 font-mono" aria-live="polite">
              Synced {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={load}
            aria-label="Refresh risk data"
            className="p-2 rounded-lg text-neutral-500 hover:text-white hover:bg-white/[0.05] transition-colors"
          >
            <RefreshCw size={15} aria-hidden="true" />
          </button>
        </div>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="error-banner" role="alert">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="text-red-400 shrink-0" aria-hidden="true" />
            <p className="text-xs text-red-400">{error}</p>
          </div>
          <button onClick={load} className="text-xs text-red-400 underline">Retry</button>
        </div>
      )}

      {/* ── Summary KPIs ── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card
          title="Threats Blocked"
          value={summary?.threats_blocked?.toLocaleString() ?? '—'}
          icon={Zap}
          subtitle="Total blocked actions"
        />
        <Card
          title="High Risk Agents"
          value={summary?.high_risk_agents?.toLocaleString() ?? '—'}
          icon={AlertTriangle}
          subtitle="Score ≥ 0.70"
        />
        <Card
          title="Avg Risk Score"
          value={summary?.avg_risk_score != null ? summary.avg_risk_score.toFixed(3) : '—'}
          icon={TrendingUp}
          subtitle="Rolling average"
        />
      </div>

      {/* ── Timeline chart ── */}
      <Card title="7-Day Risk Timeline" icon={TrendingUp}>
        {timeline.length > 0 ? (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={timeline} margin={{ top: 8, right: 8, bottom: 8, left: -24 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
              <XAxis dataKey="date" tick={{ fill: '#525252', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 1]} tick={{ fill: '#525252', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#111', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#fff' }}
              />
              <Line type="monotone" dataKey="avg_risk" stroke="#ef4444" strokeWidth={2} dot={false} name="Avg Risk" />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-40 text-neutral-600 text-xs">
            No timeline data
          </div>
        )}
      </Card>

      {/* ── Agents + formula ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* High risk agents */}
        <Card title={`High Risk Agents (≥ 0.70)`} icon={AlertTriangle}>
          {highRisk.length > 0 ? (
            <div className="space-y-2">
              {highRisk.slice(0, 8).map((t, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 p-2.5 rounded-lg bg-white/[0.02] border border-white/[0.04] group"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono text-white truncate">{t.agent_id?.slice(0, 18) ?? '—'}</p>
                    <p className="text-xs text-neutral-600 mt-0.5">{t.threat_count ?? 0} events</p>
                  </div>
                  <RiskBadge level={
                    t.risk_level ??
                    ((t.avg_risk ?? 0) >= 0.9 ? 'CRITICAL' : (t.avg_risk ?? 0) >= 0.7 ? 'HIGH' : 'MEDIUM')
                  } />
                  <button
                    onClick={() => navigate(`/forensics?agent=${t.agent_id}`)}
                    aria-label={`View forensics for agent ${t.agent_id?.slice(0, 8)}`}
                    className="p-1.5 rounded text-neutral-600 hover:text-white hover:bg-white/[0.05] transition-colors opacity-0 group-hover:opacity-100"
                  >
                    <ExternalLink size={12} aria-hidden="true" />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 text-neutral-600 text-xs">
              No high-risk agents detected
            </div>
          )}
        </Card>

        {/* Risk formula */}
        <Card title="Risk Scoring Formula" icon={Brain}>
          <div className="space-y-3">
            {WEIGHTS.map((w) => (
              <div key={w.key} className="space-y-1.5">
                <div className="flex justify-between">
                  <span className="text-xs text-neutral-400">{w.label}</span>
                  <span className="text-xs font-bold" style={{ color: w.color }}>{w.pct}%</span>
                </div>
                <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${w.pct}%`, backgroundColor: w.color }}
                    role="progressbar"
                    aria-valuenow={w.pct}
                    aria-valuemin={0}
                    aria-valuemax={100}
                  />
                </div>
              </div>
            ))}
            <div className="pt-3 border-t border-white/[0.05] space-y-1 font-mono text-xs text-neutral-600">
              <p>Signal ≥ 0.95 → floor score at 0.95</p>
              <p>Policy DENY → floor score at 0.70</p>
              <p>Learning discount: up to −0.20 (FP rate)</p>
            </div>
          </div>
        </Card>
      </div>

      {/* ── AI Insights ── */}
      {insights.length > 0 && (
        <Card title="AI Threat Insights (Groq)" icon={Brain}>
          <div className="space-y-3">
            {insights.slice(0, 5).map((ins, i) => (
              <div key={i} className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.05] space-y-2 hover:border-white/[0.08] transition-colors">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <span className="text-xs font-bold text-white uppercase tracking-wide">
                    {ins.threat_classification ?? 'Unknown'}
                  </span>
                  <span className={`text-xs font-bold ${CONF_COLOR[(ins.confidence ?? '').toUpperCase()] ?? 'text-neutral-400'}`}>
                    {ins.confidence ?? '—'} Confidence
                  </span>
                </div>
                <p className="text-xs text-neutral-400 leading-relaxed">
                  {ins.narrative ?? ins.recommendation ?? '—'}
                </p>
                {ins.root_cause && (
                  <p className="text-xs text-neutral-600">
                    Root cause: {ins.root_cause}
                  </p>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
