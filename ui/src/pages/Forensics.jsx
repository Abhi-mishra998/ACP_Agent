import React, { useState, useEffect, useRef } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { forensicsService } from '../services/api'
import {
  Search, BrainCircuit, Activity, ShieldAlert,
  FileText, ChevronRight, Database, Fingerprint,
  Zap, ShieldCheck, AlertTriangle, Clock,
  TrendingDown, TrendingUp, ArrowLeft,
} from 'lucide-react'
import Card from '../components/Common/Card'
import Button from '../components/Common/Button'
import SkeletonLoader from '../components/Common/SkeletonLoader'

const DECISION_STYLES = {
  allow:    { cls: 'text-green-400  bg-green-500/10  border-green-500/20',  glow: 'rgba(34,197,94,0.3)'   },
  deny:     { cls: 'text-red-400    bg-red-500/10    border-red-500/20',    glow: 'rgba(239,68,68,0.4)'   },
  monitor:  { cls: 'text-blue-400   bg-blue-500/10   border-blue-500/20',   glow: 'rgba(59,130,246,0.3)'  },
  throttle: { cls: 'text-amber-400  bg-amber-500/10  border-amber-500/20',  glow: 'rgba(245,158,11,0.3)'  },
  escalate: { cls: 'text-purple-400 bg-purple-500/10 border-purple-500/20', glow: 'rgba(168,85,247,0.3)'  },
  kill:     { cls: 'text-red-300    bg-red-900/20    border-red-700/30',    glow: 'rgba(239,68,68,0.5)'   },
}

function DecisionBadge({ decision }) {
  const d    = (decision || 'unknown').toLowerCase()
  const meta = DECISION_STYLES[d] ?? { cls: 'text-neutral-400 bg-white/5 border-white/10', glow: 'transparent' }
  return (
    <span
      className={`status-badge ${meta.cls}`}
      style={d === 'deny' || d === 'kill' ? { boxShadow: `0 0 10px ${meta.glow}` } : undefined}
    >
      {d.toUpperCase()}
    </span>
  )
}

function RiskBar({ score }) {
  const pct   = Math.min(100, Math.round((score ?? 0) * 100))
  const color = pct >= 70 ? 'bg-red-500' : pct >= 40 ? 'bg-amber-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 h-1 bg-white/[0.06] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-neutral-500 tabular-nums w-8 text-right">{(score ?? 0).toFixed(2)}</span>
    </div>
  )
}

function TimelineEvent({ event, isLast, idx }) {
  const d    = (event.decision || 'unknown').toLowerCase()
  const meta = DECISION_STYLES[d] ?? { cls: 'text-neutral-400 bg-white/5 border-white/10', glow: 'transparent' }
  const isDanger = d === 'deny' || d === 'kill' || d === 'escalate'

  return (
    <div className="flex gap-4">
      {/* Spine */}
      <div className="flex flex-col items-center">
        <div
          className={`w-8 h-8 rounded-full border-2 flex items-center justify-center shrink-0 text-xs font-bold transition-all
            ${isDanger
              ? 'border-red-500/50 bg-red-500/10 text-red-400'
              : 'border-[var(--border-default)] bg-[var(--bg-surface-elevated)] text-neutral-500'
            }`}
          style={isDanger ? { boxShadow: `0 0 16px ${meta.glow}` } : undefined}
          aria-hidden="true"
        >
          {idx + 1}
        </div>
        {!isLast && (
          <div className={`w-px flex-1 mt-2 ${isDanger ? 'bg-red-500/20' : 'bg-[var(--border-subtle)]'}`} aria-hidden="true" />
        )}
      </div>

      {/* Content */}
      <div className={`
        flex-1 mb-4 p-4 rounded-xl border transition-all
        ${isDanger
          ? 'bg-red-500/[0.04] border-red-500/15 hover:border-red-500/25'
          : 'bg-[var(--bg-surface)] border-[var(--border-subtle)] hover:border-[var(--border-default)]'
        }
      `}>
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 flex-wrap">
            <DecisionBadge decision={event.decision} />
            <span className="text-xs font-bold text-white font-mono">{event.tool || '—'}</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-neutral-600 font-mono">
            <Clock size={10} aria-hidden="true" />
            {event.timestamp ? new Date(event.timestamp).toLocaleString('en-US', {
              month: 'short', day: '2-digit',
              hour: '2-digit', minute: '2-digit', second: '2-digit',
            }) : '—'}
          </div>
        </div>

        <div className="mt-3 flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-neutral-600 uppercase tracking-wide">Risk</span>
            <RiskBar score={event.risk_score} />
          </div>
        </div>

        {Array.isArray(event.reasons) && event.reasons.length > 0 && (
          <div className="mt-3 space-y-1">
            {event.reasons.slice(0, 3).map((r, i) => (
              <div key={i} className="flex items-start gap-2">
                <ChevronRight size={10} className="text-neutral-600 mt-0.5 shrink-0" aria-hidden="true" />
                <span className="text-[11px] text-neutral-500 italic leading-relaxed">{r}</span>
              </div>
            ))}
          </div>
        )}

        {isDanger && (
          <div
            className="mt-3 text-[10px] font-bold uppercase tracking-widest text-red-400"
            style={{ textShadow: '0 0 12px rgba(239,68,68,0.4)' }}
          >
            ⚠ Threat Detected
          </div>
        )}
      </div>
    </div>
  )
}

export default function Forensics() {
  const location = useLocation()
  const navigate = useNavigate()
  const [agentId, setAgentId]     = useState('')
  const [profile, setProfile]     = useState(null)
  const [loading, setLoading]     = useState(false)
  const [error,   setError]       = useState('')
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const id = params.get('agent')
    if (id) { setAgentId(id); triggerInvestigation(id) }
  }, [location.search]) // eslint-disable-line react-hooks/exhaustive-deps

  const triggerInvestigation = async (id) => {
    if (!id?.trim()) return
    setLoading(true)
    setError('')
    setProfile(null)
    try {
      const res = await forensicsService.getInvestigation(id)
      if (mountedRef.current) setProfile(res.data || res)
    } catch (err) {
      if (mountedRef.current) setError(err.message || 'Investigation failed — no data found for this agent.')
    } finally {
      if (mountedRef.current) setLoading(false)
    }
  }

  const handleSearch = (e) => {
    e.preventDefault()
    triggerInvestigation(agentId)
  }

  const hasFromParam = !!new URLSearchParams(location.search).get('agent')

  const events        = profile?.recent_events || []
  const decisionBreak = profile?.decision_breakdown || {}
  const totalEvents   = profile?.total_events ?? 0
  const avgRisk       = profile?.avg_risk_score ?? 0
  const denyCount     = decisionBreak.deny || 0
  const allowCount    = decisionBreak.allow || 0

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="page-header">
        <div className="flex items-center gap-3">
          {hasFromParam && (
            <button
              onClick={() => navigate(-1)}
              aria-label="Go back"
              className="p-1.5 rounded-lg text-neutral-500 hover:text-white hover:bg-white/[0.05] transition-colors"
            >
              <ArrowLeft size={16} aria-hidden="true" />
            </button>
          )}
          <BrainCircuit size={22} className="text-neutral-400" aria-hidden="true" />
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Behavioral Forensics</h1>
            <p className="text-xs text-neutral-500 mt-0.5">Click-to-drill-down incident investigation</p>
          </div>
        </div>
      </div>

      {/* Search */}
      <Card title="Forensic Recall" icon={Search}>
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-600" aria-hidden="true" />
            <input
              type="text"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              placeholder="Agent UUID — or click 'Investigate' from Audit Logs"
              aria-label="Agent ID to investigate"
              className="input-standard pl-9 h-10 font-mono"
            />
          </div>
          <Button type="submit" loading={loading} disabled={!agentId.trim()}>
            <ChevronRight size={14} aria-hidden="true" />
            Investigate
          </Button>
        </form>
      </Card>

      {error && (
        <div className="error-banner" role="alert">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="text-red-400 shrink-0" aria-hidden="true" />
            <p className="text-xs text-red-400">{error}</p>
          </div>
        </div>
      )}

      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => <SkeletonLoader key={i} variant="card" />)}
        </div>
      )}

      {profile && (
        <div className="space-y-6 animate-fade-in">
          {/* Profile KPIs */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Card
              title="Total Events"
              value={totalEvents.toLocaleString()}
              icon={Activity}
              subtitle="All recorded actions"
            />
            <Card
              title="Avg Risk Score"
              value={avgRisk.toFixed(3)}
              icon={Zap}
              subtitle="Across all executions"
            />
            <Card
              title="Threats Blocked"
              value={denyCount.toLocaleString()}
              icon={ShieldAlert}
              subtitle="Deny decisions"
            />
            <Card
              title="Allowed Actions"
              value={allowCount.toLocaleString()}
              icon={ShieldCheck}
              subtitle="Approved executions"
            />
          </div>

          {/* Decision breakdown */}
          {Object.keys(decisionBreak).length > 0 && (
            <Card title="Decision Breakdown" icon={Activity}>
              <div className="flex items-center gap-3 flex-wrap">
                {Object.entries(decisionBreak).map(([decision, count]) => {
                  const d    = decision.toLowerCase()
                  const meta = DECISION_STYLES[d] ?? { cls: 'text-neutral-400 bg-white/5 border-white/10' }
                  return (
                    <div key={decision} className={`px-3 py-2 rounded-xl border ${meta.cls} flex flex-col items-center`}>
                      <span className="text-xl font-black">{count}</span>
                      <span className="text-[10px] font-bold uppercase tracking-wide opacity-70">{decision}</span>
                    </div>
                  )
                })}
              </div>
            </Card>
          )}

          {/* Forensic Timeline */}
          <div>
            <div className="section-header mb-4">
              <Clock size={14} className="text-neutral-600" aria-hidden="true" />
              Forensic Timeline
              <span className="text-neutral-600 text-[10px] font-normal ml-1">(most recent first)</span>
            </div>

            {events.length === 0 ? (
              <div className="py-16 text-center border border-dashed border-[var(--border-subtle)] rounded-xl text-xs text-neutral-600">
                <Fingerprint size={28} className="mx-auto mb-3 opacity-20" aria-hidden="true" />
                No events recorded for this agent.
              </div>
            ) : (
              <div role="list" aria-label="Forensic timeline">
                {events.map((event, idx) => (
                  <TimelineEvent
                    key={event.id || idx}
                    event={event}
                    idx={idx}
                    isLast={idx === events.length - 1}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Archive status */}
          <div className="p-4 bg-white/[0.01] border border-white/5 rounded-xl flex items-center gap-3">
            <Database size={14} className="text-neutral-500 shrink-0" aria-hidden="true" />
            <span className="text-xs text-neutral-500">
              Investigation covers last {events.length} events of {totalEvents.toLocaleString()} total for agent{' '}
              <span className="font-mono text-neutral-400">{profile?.agent_id?.slice(0, 12)}…</span>
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

